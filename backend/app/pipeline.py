"""The full scan: probe the network, merge into the inventory, let the LLM identify the leftovers,
then rewrite the documentation.

Runs as a background task with progress written to the `scans` row, because a /24 sweep takes
minutes and the browser must not hold a request open that long. Every phase is individually
non-fatal apart from discovery itself: a missing Docker socket, a failed LLM call or a broken
documentation run each degrade to a warning on the scan, so a scan never ends with nothing to show.
"""
from __future__ import annotations

import asyncio
import contextlib
import re
import traceback

import ipaddress
from datetime import datetime, timedelta, timezone

from . import (
    adguard_probe, classify, crypto, db, discovery, docker_probe, docs, omada_probe, oui, probe_auth,
    proxmox_probe,
)


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


async def _probe_with_credentials(log) -> tuple[int, list[str], dict[str, str], list[dict]]:
    """Logs into the devices whose stored credentials were explicitly cleared for it and records
    what it read. Strictly read-only -- see probe_auth.

    Facts learned here are written into `extra.probe` for display, and are additionally used to
    fill `purpose`, `os` and `model` **only where those are still empty**. An authenticated read is
    more authoritative than a port guess, but it must not overwrite what a human typed.

    The third return value is every IP->MAC pair read from a router's own ARP/host-list table
    (see probe_auth.extract_arp_entries) -- routers only, since that is the one place such a table
    covers the whole LAN rather than just what this host itself could see. The fourth is every
    printer toner/ink reading Home Assistant reported (see probe_auth.extract_printer_supplies) --
    gathered from whichever system the HA credential is attached to (usually the smart-home hub,
    not a printer itself), which is why matching them to a printer happens separately afterwards.
    """
    warnings: list[str] = []
    probed = 0
    learned_arp: dict[str, str] = {}
    printer_supplies: list[dict] = []
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
            db.add_device_error_event(system["id"], "error", f"Abfrage fehlgeschlagen: {exc}")
            continue

        # Collected regardless of whether *some* credential on this system succeeded -- a system
        # with both a working SSH account and a Home Assistant account whose token just expired
        # used to have that second failure silently swallowed here (only visible at all once every
        # credential on the row failed), which is exactly backwards for something an admin needs
        # to notice and fix. Logged both to the scan-wide `warnings` (gone after the next scan) and
        # against the device itself (see db.add_device_error_event) -- someone troubleshooting one
        # specific switch/host should not have to dig through the last scan's log to find out an
        # SSH timeout is why its config backup stopped updating.
        for label, result in (outcome.get("results") or {}).items():
            if not result.get("ok") and result.get("error"):
                warnings.append(f"{system['name']} ({label}): {result['error']}")
                db.add_device_error_event(system["id"], "error", f"{label}: {result['error']}")
            # Set even on an otherwise-ok result (e.g. probe_ssh's per-command timeouts) -- a
            # switch whose config export timed out while its other commands succeeded still needs
            # that specific failure visible on the device, not just buried in an overall "ok".
            for warning in result.get("warnings") or []:
                db.add_device_error_event(system["id"], "warning", f"{label}: {warning}")
        if not outcome["ran"]:
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
        if probe_auth.persist_config_backups(system, outcome):
            log(f"Konfiguration von {system['name']} gesichert")
        if system.get("kind") == "router":
            learned_arp.update(probe_auth.extract_arp_entries(outcome))
        printer_supplies += probe_auth.extract_printer_supplies(outcome)

    if used_fallback:
        log(f"Standard-Zugang bei {used_fallback} Gerät(en) ohne eigenen Zugang versucht")
    return probed, warnings, learned_arp, printer_supplies


async def _learn_devices_from_arp(learned_arp: dict[str, str], log) -> int:
    """Adds inventory entries for IP/MAC pairs a router's own ARP or host-list table revealed that
    the network sweep itself never saw -- a sleeping device, one behind a firewall that blocks the
    scan's own pings/port probes, or simply on a segment this host can reach an SSH/TR-064
    credential for but not ping directly. Each new entry gets the same reverse-DNS naming
    discovery.py already gives every device it finds itself, rather than sitting unnamed until a
    later full scan happens to rediscover it on its own.
    """
    if not learned_arp:
        return 0
    known_macs = {s["mac"] for s in db.list_systems() if s.get("mac")}
    known_ips = {s["ip"] for s in db.list_systems() if s.get("ip")}
    new_pairs = {ip: mac for ip, mac in learned_arp.items()
                 if mac not in known_macs and ip not in known_ips}
    if not new_pairs:
        return 0

    hostnames = dict(zip(new_pairs, await asyncio.gather(
        *(discovery.reverse_dns(ip) for ip in new_pairs))))
    for ip, mac in new_pairs.items():
        vendor = oui.lookup(mac)
        hostname = hostnames.get(ip, "")
        name = (hostname.split(".")[0][:80] if hostname
                else f"{vendor.split()[0]} ({ip.rsplit('.', 1)[-1]})" if vendor else ip)
        db.upsert_discovered_system({
            "discoveryKey": f"mac:{mac}",
            "kind": "other",
            "name": name,
            "hostname": hostname,
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "purpose": ("Über die ARP-/Host-Tabelle des Gateways gefunden, aber noch nicht "
                        "vollständig eingeordnet -- der nächste Netzwerk-Scan füllt den Rest, "
                        "sobald das Gerät selbst antwortet."),
            "status": "online",
            "importance": "normal",
            "discovered": 1,
            "discoverySource": "gateway-arp",
            "openPorts": [],
            "services": [],
            "extra": {"randomizedMac": oui.is_locally_administered(mac), "guessConfident": False},
        })
    log(f"{len(new_pairs)} weitere(s) Gerät(e) über die ARP-/Host-Tabelle des Gateways gefunden")
    return len(new_pairs)


_WORD_RE = re.compile(r"[a-z0-9]+")


def _tokens(*parts: str) -> set[str]:
    return {w for p in parts for w in _WORD_RE.findall(p.lower()) if len(w) >= 3}


def _match_printer_supplies(supplies: list[dict], printers: list[dict]) -> dict[str, list[dict]]:
    """Groups toner/ink readings by which printer in the inventory they most likely belong to.

    Home Assistant's own printer name is the only link back to the inventory -- there is no shared
    ID between "what HA calls it" and "what this app calls it" -- so this is a best-effort token
    overlap between the HA sensor's friendly name and each printer's name/vendor/model, not an
    exact match. A household with exactly one printer skips the guessing entirely and attaches
    everything to it, since that is by far the common case and token matching has the most room to
    fail on a printer named something HA's own device name shares no words with at all.
    """
    if not supplies or not printers:
        return {}
    if len(printers) == 1:
        return {printers[0]["id"]: supplies}

    printer_tokens = [(p["id"], _tokens(p.get("name", ""), p.get("vendor", ""), p.get("model", "")))
                       for p in printers]
    by_printer: dict[str, list[dict]] = {}
    for supply in supplies:
        supply_tokens = _tokens(supply["name"])
        best_id, best_overlap = None, 0
        for printer_id, tokens in printer_tokens:
            overlap = len(supply_tokens & tokens)
            if overlap > best_overlap:
                best_id, best_overlap = printer_id, overlap
        if best_id:
            by_printer.setdefault(best_id, []).append(supply)
    return by_printer


def _apply_printer_supplies(printer_supplies: list[dict], log) -> int:
    """Persists matched toner/ink readings onto each printer's own `extra.printerSupplies`, so
    SystemDetailPage can render them at the device they actually belong to instead of only in the
    generic facts block of whatever system holds the Home Assistant credential."""
    printers = [s for s in db.list_systems() if s["kind"] == "printer"]
    by_printer = _match_printer_supplies(printer_supplies, printers)
    for printer_id, supplies in by_printer.items():
        printer = db.get_system(printer_id)
        if printer is None:
            continue
        db.update_system(printer_id, {"extra": {**(printer.get("extra") or {}), "printerSupplies": supplies}})
    if by_printer:
        log(f"Verbrauchsmaterial-Stand für {len(by_printer)} Drucker aus Home Assistant übernommen")
    return len(by_printer)


def _assign_proxmox_parents(guests: list[dict], fallback_host_id: str | None) -> None:
    """Points each Proxmox guest's `parentId` at its own node's system row, so a guest ends up
    nested under the node it actually runs on rather than always under whichever single host the
    credential happens to be attached to -- the credential is attached to *one* HomeAtlas system
    row, but a cluster can run guests across several nodes at several addresses.

    Matched by hostname/name against the guest's own `extra.proxmox.node` (set by
    proxmox_probe.probe) -- the same "known name, no shared id" situation `_match_printer_supplies`
    above already deals with, just for hosts instead of printers. Falls back to the credential's
    own host when no separate row for that node exists yet, which is also the correct answer for
    the common single-node setup (there, every guest's node *is* that one host).
    """
    node_hosts = {
        (s.get("hostname") or s.get("name") or "").strip().lower(): s["id"]
        for s in db.list_systems() if s["kind"] in ("server", "nas")
    }
    for guest in guests:
        node = ((guest.get("extra") or {}).get("proxmox") or {}).get("node", "")
        guest["parentId"] = node_hosts.get(node.strip().lower()) or fallback_host_id


def _link_omada_topology() -> int:
    """Resolves each Omada finding's `extra.omada.uplinkMac` (set by omada_probe.py, on APs,
    switches and clients alike) to the inventory id of the device it points at, and records that
    as `parentId`. Can only happen after the whole batch is upserted -- the target device's own
    row might not have existed a moment earlier in the very same scan -- which is why this is a
    separate pass rather than something omada_probe.py could set directly. topology.py's network
    section then chains by `parentId` the same way the router chain already does, so an AP or
    client shows up under the switch/AP it is actually plugged/associated into instead of a flat,
    unordered row.
    """
    systems = db.list_systems()
    by_mac = {s["mac"]: s["id"] for s in systems if s.get("mac")}
    linked = 0
    for system in systems:
        uplink_mac = ((system.get("extra") or {}).get("omada") or {}).get("uplinkMac")
        if not uplink_mac:
            continue
        target_id = by_mac.get(uplink_mac)
        if not target_id or target_id == system["id"] or system.get("parentId") == target_id:
            continue
        db.update_system(system["id"], {"parentId": target_id})
        linked += 1
    return linked


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

        if settings.get("scanEnableOmada", True):
            omada_accounts = [a for a in db.list_accounts()
                              if a.get("category") == "omada" and a.get("allowProbe")]
            if omada_accounts:
                progress("Omada-Geräte erfassen", 87, "Frage Omada Controller ab")
            for account in omada_accounts:
                client_id = account.get("username") or ""
                client_secret = crypto.decrypt(account.get("secretEnc") or "")
                omada_result = await omada_probe.probe(account.get("url") or "", client_id, client_secret)
                if omada_result["ok"]:
                    findings += omada_result["systems"]
                    log(f"Omada ({account['label']}): {len(omada_result['systems'])} Geräte/Clients gefunden")
                else:
                    warnings.append(f"Omada Controller ({account['label']}): {omada_result['error']}")
                    if account.get("systemId"):
                        db.add_device_error_event(account["systemId"], "error", omada_result["error"])

        if settings.get("scanEnableProxmox", True):
            proxmox_accounts = [a for a in db.list_accounts()
                               if a.get("category") == "proxmox" and a.get("allowProbe")]
            if proxmox_accounts:
                progress("Proxmox-Gäste erfassen", 88, "Frage Proxmox-Host ab")
            for account in proxmox_accounts:
                token_id = account.get("username") or ""
                token_secret = crypto.decrypt(account.get("secretEnc") or "")
                proxmox_result = await proxmox_probe.probe(account.get("url") or "", token_id, token_secret)
                if proxmox_result["ok"]:
                    _assign_proxmox_parents(proxmox_result["systems"], account.get("systemId"))
                    findings += proxmox_result["systems"]
                    log(f"Proxmox ({account['label']}): {len(proxmox_result['systems'])} Gäste gefunden")
                else:
                    warnings.append(f"Proxmox-Host ({account['label']}): {proxmox_result['error']}")
                    if account.get("systemId"):
                        db.add_device_error_event(account["systemId"], "error", proxmox_result["error"])

        if settings.get("scanEnableAdguard", True):
            adguard_accounts = [a for a in db.list_accounts()
                                if a.get("category") == "adguard" and a.get("allowProbe")]
            if adguard_accounts:
                progress("AdGuard Home erfassen", 88, "Frage AdGuard Home ab")
            for account in adguard_accounts:
                username = account.get("username") or ""
                password = crypto.decrypt(account.get("secretEnc") or "")
                adguard_result = await adguard_probe.probe(account.get("url") or "", username, password)
                if adguard_result["ok"]:
                    findings += adguard_result["systems"]
                    log(f"AdGuard Home ({account['label']}): {len(adguard_result['systems'])} "
                        "Client(s)/Lease(s) übernommen")
                    if account.get("systemId") and adguard_result.get("stats"):
                        host = db.get_system(account["systemId"])
                        if host is not None:
                            db.update_system(account["systemId"], {
                                "extra": {**(host.get("extra") or {}), "adguard": adguard_result["stats"]},
                            })
                else:
                    warnings.append(f"AdGuard Home ({account['label']}): {adguard_result['error']}")
                    if account.get("systemId"):
                        db.add_device_error_event(account["systemId"], "error", adguard_result["error"])

        if settings.get("scanUseLlm", True):
            progress("Geräte einordnen (KI)", 89, "KI-Einordnung unbekannter Geräte")
            classifications, classify_warnings = await classify.classify(findings, settings, log)
            warnings += classify_warnings
            findings = [
                classify.apply(f, classifications[f["ip"]]) if f.get("ip") in classifications else f
                for f in findings
            ]

        # A name shared by several distinct devices in this scan reads as duplicates in the
        # inventory even though each one is a real, separate device with its own MAC/IP/discovery
        # key -- some devices (many Shelly units, for one) serve the exact same generic <title> on
        # their local web UI, and the LLM step above can independently suggest the same generic
        # name for visually-identical devices it never compares against each other. Fixed up once,
        # here, after every source (network scan, Docker, Omada, Proxmox) and the LLM step have
        # all had their say -- doing this any earlier just gets overwritten by a later step.
        name_counts: dict[str, int] = {}
        for f in findings:
            name_counts[f["name"]] = name_counts.get(f["name"], 0) + 1
        # The IP's last octet alone still collides for Docker containers, which all share their
        # host's IP -- a running count within the (name, suffix) group keeps every entry unique
        # even when two containers on the same host end up with the same LLM-suggested name.
        group_counts: dict[tuple[str, str], int] = {}
        for f in findings:
            if name_counts[f["name"]] > 1 and f.get("ip"):
                suffix = f["ip"].rsplit(".", 1)[-1]
                group_counts[(f["name"], suffix)] = group_counts.get((f["name"], suffix), 0) + 1
                occurrence = group_counts[(f["name"], suffix)]
                f["name"] = f"{f['name']} ({suffix}{f'-{occurrence}' if occurrence > 1 else ''})"

        progress("Inventar aktualisieren", 94, None)
        seen_ids: set[str] = set()
        for finding in findings:
            system, was_created = db.upsert_discovered_system(finding)
            seen_ids.add(system["id"])
            created += 1 if was_created else 0
            updated += 0 if was_created else 1
        db.mark_systems_offline(seen_ids)
        log(f"Inventar: {created} neu, {updated} aktualisiert")

        host_ip = result.get("hostIp", "")
        if host_ip:
            linked = db.link_containers_to_host(host_ip)
            if linked:
                log(f"{linked} Container dem Host {host_ip} zugeordnet")

        linked_omada = _link_omada_topology()
        if linked_omada:
            log(f"{linked_omada} Omada-Gerät(e)/Client(s) im Netzplan mit ihrem Uplink verknüpft")

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
            probed, probe_warnings, learned_arp, printer_supplies = await _probe_with_credentials(log)
            warnings += probe_warnings
            if learned_arp:
                await _learn_devices_from_arp(learned_arp, log)
            if printer_supplies:
                _apply_printer_supplies(printer_supplies, log)
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


# ---------------------------------------------------------------------------------------------
# Scheduler -- an optional, opt-in timer around run_full_scan (which is also how config backups
# happen, see probe_auth.persist_config_backups above). Same start/stop/loop shape as monitor.py's
# Monitor: settings are re-read every tick, so flipping "scanAutoEnabled" or changing the interval
# in SettingsPage takes effect within one poll, not only after a restart or the previous
# (possibly day-long) interval elapses.
# ---------------------------------------------------------------------------------------------

# How often the loop wakes to check whether a scan is *due* -- not the scan interval itself.
_SCHEDULER_POLL_SECONDS = 300


class Scheduler:
    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self.last_error: str = ""

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    async def _loop(self) -> None:
        while True:
            try:
                await self._maybe_run()
                self.last_error = ""
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 -- the loop has to outlive any single failure
                self.last_error = str(exc)
            await asyncio.sleep(_SCHEDULER_POLL_SECONDS)

    async def _maybe_run(self) -> None:
        settings = db.get_settings()
        if not settings.get("scanAutoEnabled", False):
            return
        if db.running_scan() is not None:
            return  # a manual (or already-running automatic) scan takes priority -- never queue a second one
        interval_hours = max(1, min(24 * 30, int(settings.get("scanAutoIntervalHours") or 24)))
        latest = db.latest_scan()
        if latest is not None:
            started = datetime.strptime(latest["startedAt"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) - started < timedelta(hours=interval_hours):
                return  # last scan (manual or automatic) is still recent enough
        scan_id = db.create_scan("automatisch (Zeitplan)")
        await run_full_scan(scan_id)

    def status(self) -> dict:
        return {"running": self._task is not None and not self._task.done(), "lastError": self.last_error}


scheduler = Scheduler()
