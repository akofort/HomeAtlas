"""The full scan: probe the network, merge into the inventory, let the LLM identify the leftovers,
then rewrite the documentation.

Runs as a background task with progress written to the `scans` row, because a /24 sweep takes
minutes and the browser must not hold a request open that long. Every phase is individually
non-fatal apart from discovery itself: a missing Docker socket, a failed LLM call or a broken
documentation run each degrade to a warning on the scan, so a scan never ends with nothing to show.
"""
from __future__ import annotations

import traceback

from . import classify, db, discovery, docker_probe, docs, oui


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

        result = await discovery.discover(settings, progress)
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
