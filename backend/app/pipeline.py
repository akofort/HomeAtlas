"""The full scan: probe the network, merge into the inventory, let the LLM identify the leftovers,
then rewrite the documentation.

Runs as a background task with progress written to the `scans` row, because a /24 sweep takes
minutes and the browser must not hold a request open that long. Every phase is individually
non-fatal apart from discovery itself: a missing Docker socket, a failed LLM call or a broken
documentation run each degrade to a warning on the scan, so a scan never ends with nothing to show.
"""
from __future__ import annotations

import traceback

import ipaddress

from . import classify, db, discovery, docker_probe, docs, oui, probe_auth


def _extra_targets(settings: dict, subnets_hint: list[str]) -> list[str]:
    """Hosts to probe that the subnet sweep would never reach.

    Two sources. Explicitly configured targets (Einstellungen -> Netzwerk-Scan), and the addresses
    of devices someone already entered by hand -- a router at 10.1.1.1 while the LAN is
    192.168.1.0/24, or a VM behind a bridge. Without this, a hand-created entry could never be
    enriched: it would sit in the inventory with a name and nothing else forever.
    """
    targets: list[str] = [t.strip() for t in (settings.get("scanExtraTargets") or []) if t.strip()]

    networks = []
    for subnet in subnets_hint:
        try:
            networks.append(ipaddress.ip_network(subnet, strict=False))
        except ValueError:
            continue

    for system in db.list_systems():
        address = (system.get("ip") or "").strip()
        if not address or address in targets:
            continue
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        # Inside a scanned subnet it is covered already; outside it needs to be named explicitly.
        if not any(parsed in network for network in networks):
            targets.append(address)
    return targets


async def _probe_with_credentials(log) -> tuple[int, list[str]]:
    """Logs into the devices whose stored credentials were explicitly cleared for it and records
    what it read. Strictly read-only -- see probe_auth.

    Facts learned here are written into `extra.probe` for display, and are additionally used to
    fill `purpose`, `os` and `model` **only where those are still empty**. An authenticated read is
    more authoritative than a port guess, but it must not overwrite what a human typed.
    """
    warnings: list[str] = []
    probed = 0
    settings = db.get_settings()
    used_fallback = 0

    for system in db.list_systems():
        accounts = db.list_probe_accounts(system["id"])
        if not accounts:
            # Only where nothing device-specific is stored, and only where probe_auth's guardrails
            # allow it (right kind of device, matching port actually open).
            fallback = probe_auth.fallback_account(settings, system)
            if fallback is None:
                continue
            accounts = [fallback]
            used_fallback += 1
        try:
            outcome = await probe_auth.probe_system(system, accounts)
        except Exception as exc:  # noqa: BLE001 -- one unreachable device must not end the scan
            warnings.append(f"Abfrage von {system['name']} fehlgeschlagen: {exc}")
            continue

        if not outcome["ran"]:
            for label, result in (outcome.get("results") or {}).items():
                if not result.get("ok") and result.get("error"):
                    warnings.append(f"{system['name']} ({label}): {result['error']}")
            continue

        patch: dict = {"extra": {**(system.get("extra") or {}), "probe": outcome["results"]}}
        if outcome.get("purpose") and not system.get("purpose"):
            patch["purpose"] = outcome["purpose"]

        facts = {key: value["value"] for result in outcome["results"].values() if result.get("ok")
                 for key, value in result.get("facts", {}).items()}
        if facts.get("os") and not system.get("os"):
            patch["os"] = facts["os"].splitlines()[0][:120]
        if facts.get("model") and not system.get("model"):
            patch["model"] = facts["model"].strip()[:100]
        if facts.get("modelName") and not system.get("model"):
            patch["model"] = facts["modelName"].strip()[:100]

        db.update_system(system["id"], patch)
        probed += 1
        log(f"Abgefragt: {system['name']} ({', '.join(outcome['results'])})")

    if used_fallback:
        log(f"Standard-Zugang bei {used_fallback} Gerät(en) ohne eigenen Zugang versucht")
    return probed, warnings


async def run_full_scan(scan_id: str) -> None:
    settings = db.get_settings()
    warnings: list[str] = []
    created = updated = 0

    def progress(phase: str, percent: int, log_line: str | None = None) -> None:
        db.update_scan(scan_id, phase=phase, progress=percent, log_line=log_line)

    def log(line: str) -> None:
        db.update_scan(scan_id, log_line=line)

    try:
        # The vendor database makes every later step better (it feeds the rule-based guess and the
        # LLM's evidence), so it is refreshed first -- but never at the cost of the scan.
        if not oui.is_downloaded():
            progress("Hersteller-Datenbank laden", 1, "Lade IEEE-Herstellerdatenbank")
            ok, message = await oui.refresh_from_ieee()
            log(f"Hersteller-Datenbank: {message}")
            if not ok:
                warnings.append(f"Hersteller-Datenbank nicht geladen: {message}")

        configured_subnets = settings.get("scanSubnets") or discovery.local_subnets()
        extra = _extra_targets(settings, configured_subnets)
        if extra:
            log(f"Zusätzliche Einzelziele außerhalb der Bereiche: {', '.join(extra[:10])}")

        result = await discovery.discover(settings, progress, extra_targets=extra)
        findings = result["findings"]
        warnings += result["warnings"]

        if settings.get("scanEnableDocker", True):
            progress("Container erfassen", 86, "Frage Docker ab")
            docker_result = await docker_probe.probe(result.get("hostIp", ""))
            if docker_result["ok"]:
                findings += docker_result["systems"]
                log(f"Docker: {len(docker_result['systems'])} Container gefunden")
            elif docker_probe.socket_available():
                warnings.append(docker_result["error"])
            else:
                log("Docker-Socket nicht eingebunden -- Container werden übersprungen")

        if settings.get("scanUseLlm", True):
            progress("Geräte einordnen (KI)", 89, "KI-Einordnung unbekannter Geräte")
            classifications, classify_warnings = await classify.classify(findings, settings, log)
            warnings += classify_warnings
            findings = [
                classify.apply(f, classifications[f["ip"]]) if f.get("ip") in classifications else f
                for f in findings
            ]

        progress("Inventar aktualisieren", 94, None)
        seen_ids: set[str] = set()
        for finding in findings:
            system, was_created = db.upsert_discovered_system(finding)
            seen_ids.add(system["id"])
            created += 1 if was_created else 0
            updated += 0 if was_created else 1
        db.mark_systems_offline(seen_ids)
        log(f"Inventar: {created} neu, {updated} aktualisiert")

        # Anything critical is worth watching continuously -- that is what "critical" means. Done
        # here rather than in the UI so it also covers devices a scan just promoted.
        newly_monitored = 0
        for system in db.list_systems():
            if system["importance"] == "critical" and not system["monitored"] and system["ip"]:
                db.update_system(system["id"], {"monitored": 1})
                newly_monitored += 1
        if newly_monitored:
            log(f"{newly_monitored} wichtige Geräte zur Dauerüberwachung hinzugefügt")

        probed = 0
        if settings.get("scanUseCredentials", True):
            progress("Geräte mit hinterlegtem Zugang abfragen", 93, None)
            probed, probe_warnings = await _probe_with_credentials(log)
            warnings += probe_warnings
        else:
            log("Auslesen per Zugangsdaten ist in den Einstellungen abgeschaltet")

        progress("Dokumentation schreiben", 96, None)
        try:
            pages = await docs.generate(db.get_settings(), use_llm=settings.get("scanUseLlm", True), log=log)
            log(f"{len(pages)} Kapitel geschrieben")
        except Exception as exc:  # noqa: BLE001 -- the inventory is already saved and is the
            # valuable part; a failed documentation pass must not discard it.
            warnings.append(f"Dokumentation konnte nicht vollständig erzeugt werden: {exc}")

        summary = {
            "devicesFound": len(findings),
            "created": created,
            "updated": updated,
            "probed": probed,
            "routedTargets": result.get("routedTargets") or [],
            "subnets": result["subnets"],
            "gateway": result["gateway"],
            "dnsServers": result["dnsServers"],
            "counts": result["counts"],
            "warnings": warnings,
        }
        db.finish_scan(scan_id, "completed", summary)
        progress("Fertig", 100, "Scan abgeschlossen")
    except Exception as exc:  # noqa: BLE001 -- background task; the failure has to land in the row
        db.update_scan(scan_id, log_line=f"FEHLER: {exc}\n{traceback.format_exc(limit=3)}")
        db.finish_scan(scan_id, "failed", {"error": str(exc), "warnings": warnings})
