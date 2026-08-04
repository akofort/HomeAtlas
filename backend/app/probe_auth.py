"""Authentifiziertes Sondieren -- ausschließlich lesend.

The user asked for this explicitly: when a credential for a device is stored, log in and gather
what helps, **but never change anything**. That "never" has to be a property of the code, not a
promise in a docstring, because the credentials involved are usually root or router-admin. Four
things enforce it:

1. **A hardcoded command allowlist.** `_SSH_COMMANDS` (and its platform variants,
   `_SSH_COMMANDS_MIKROTIK`/`_SSH_COMMANDS_ARUBA`/`_SSH_COMMANDS_ARUBA_CX`/`_SSH_COMMANDS_CISCO`/
   `_SSH_COMMANDS_TPLINK`) are module constants.
   There is no setting, no API parameter and no LLM tool that can add to them. Making it
   configurable would turn this into a remote-execution feature with a nice UI, which is
   precisely what it must not be.
2. **Every command is read-only** and non-interactive: no package manager, no service control, no
   redirect, no `sudo`, no RouterOS/ArubaOS/IOS config-mode command, no `/export show-sensitive`,
   no `enable`.
   Failures are expected and swallowed (`2>/dev/null`) so a missing binary never turns into a
   retry with something more aggressive.
3. **HTTP is GET-only**, TR-064 uses only `GetInfo`-style SOAP actions -- the `Set*` half of that
   API is never constructed -- and SNMP (`probe_snmp`) only ever runs `snmpget`/`snmpwalk`, never
   `snmpset`.
4. **Opt-in per credential.** Nothing here runs unless a human ticked `allowProbe` on that
   specific stored credential (see `db.list_probe_accounts`).

`persist_config_backups` is the one exception to "this module never touches storage": it saves a
device's own config export as history (`db.deviceConfigVersions`), encrypted, since that text can
carry secrets. There is deliberately no restore path back to the device -- that would mean writing
configuration to hardware, which is exactly what this module exists to never do.

Host keys are deliberately not verified: HomeAtlas has no trust store, and the alternative --
refusing to connect to every device on first contact -- would make the feature useless on the very
network it is meant to document. The connection is to equipment on the user's own LAN, initiated
by the user. This is stated in the README rather than hidden.
"""
from __future__ import annotations

import asyncio
import re
import xml.etree.ElementTree as ElementTree

import httpx

from . import crypto, db

_SSH_TIMEOUT = 15.0
_HTTP_TIMEOUT = httpx.Timeout(10.0, connect=5.0)

# (Schlüssel, Beschriftung, Befehl). Read-only, non-interactive, bounded output. Constant by
# design -- see the module docstring.
_SSH_COMMANDS: tuple[tuple[str, str, str], ...] = (
    ("hostname", "Hostname", "hostname"),
    ("os", "Betriebssystem",
     "grep -E '^(PRETTY_NAME|NAME|VERSION)=' /etc/os-release 2>/dev/null | head -3 || uname -sr"),
    ("kernel", "Kernel", "uname -sr"),
    ("model", "Hardware",
     "cat /sys/firmware/devicetree/base/model 2>/dev/null "
     "|| cat /sys/devices/virtual/dmi/id/product_name 2>/dev/null"),
    ("virt", "Virtualisierung", "systemd-detect-virt 2>/dev/null"),
    ("uptime", "Laufzeit", "uptime -p 2>/dev/null || uptime"),
    ("cpu", "Prozessorkerne", "nproc 2>/dev/null"),
    ("memory", "Arbeitsspeicher", "free -h 2>/dev/null | awk 'NR==2{print $2\" gesamt, \"$3\" belegt\"}'"),
    ("disks", "Speicherplatz",
     "df -h -x tmpfs -x devtmpfs -x overlay --output=target,size,used,pcent 2>/dev/null | head -8"),
    ("ip", "Netzwerkadressen", "ip -4 -o addr show scope global 2>/dev/null | awk '{print $2\" \"$4}' | head -6"),
    # Read by pipeline.py's gateway-ARP step (see probe_auth.parse_arp_pairs) to find devices the
    # scan's own ping/ARP sweep never saw -- most useful when this credential is attached to the
    # router itself, whose neighbour table sees the whole LAN, not just what answered this host.
    ("arp_table", "ARP-/Nachbartabelle",
     "ip neigh show 2>/dev/null | grep lladdr | head -200 || arp -an 2>/dev/null | head -200"),
    ("docker", "Docker-Container",
     "docker ps --format '{{.Names}} ({{.Image}}) {{.Status}}' 2>/dev/null | head -25"),
    ("services", "Laufende Dienste",
     "systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null "
     "| awk '{print $1}' | head -20"),
    # Speculative, same as the "docker" line above: harmless empty output on any host that isn't
    # running a TP-Link Omada Software Controller (official Linux installer's own backup path).
    # Base64-encoded because the backup itself is a binary blob, not text -- deviceConfigVersions'
    # `content` column is TEXT, same trick used for storing any binary secret as a string elsewhere
    # in this app. `-w0` avoids line-wrapping so the whole thing round-trips as one field.
    ("omada_backup", "Omada-Controller-Sicherung (neueste Datei, Base64)",
     "ls -1t /opt/tplink/EAPController/data/backup/*.cfg 2>/dev/null | head -1 "
     "| xargs -r base64 -w0 2>/dev/null"),
)

# What each command's presence suggests about the device's role, used to fill `purpose` when
# nothing else did.
_ROLE_HINTS: tuple[tuple[str, str, str], ...] = (
    ("docker", "docker", "Server, auf dem Anwendungen in Docker-Containern laufen"),
    ("virt", "kvm|qemu|vmware|xen|microsoft", "Virtuelle Maschine"),
    ("virt", "lxc|docker", "Container"),
)

# Platform-specific read-only command sets, same shape and same invariant as `_SSH_COMMANDS`
# above: a RouterOS, ArubaOS or Cisco IOS CLI does not understand POSIX shell, so probing a
# switch/router with the Linux-oriented set would just fail silently and collect nothing useful.
_SSH_COMMANDS_MIKROTIK: tuple[tuple[str, str, str], ...] = (
    ("identity", "Geräte-Identität", "/system identity print"),
    ("resource", "System", "/system resource print"),
    ("routerboard", "Hardware", "/system routerboard print"),
    ("vlan", "VLANs", "/interface vlan print detail without-paging"),
    ("bridge_ports", "Bridge-Ports (VLAN-Zuordnung)", "/interface bridge port print detail without-paging"),
    ("neighbors", "Nachbargeräte (LLDP/CDP/MNDP)", "/ip neighbor print detail without-paging"),
    ("interfaces", "Schnittstellen", "/interface print detail without-paging"),
    # Which subnet(s) this router actually has an address in -- topology.py's Layer-3 plan reads
    # this to place a multi-homed router next to every subnet it bridges, not just the one its
    # single stored `ip` field happens to fall into.
    ("ip_addresses", "IP-Adressen je Schnittstelle", "/ip address print without-paging"),
    ("arp_table", "ARP-Tabelle", "/ip arp print detail without-paging"),
    # Never "/export show-sensitive" -- that writes out stored PPPoE/WiFi passwords in cleartext,
    # which would break the "secrets never exposed" invariant this whole module exists to uphold.
    ("config_export", "Vollständige Konfiguration", "/export compact"),
)

# Classic ArubaOS-Switch (ProCurve-derived) CLI enables its own "-- MORE --" pager by default.
# "no page" turns it off -- unlike TP-Link's "no clipaging" (see _TPLINK_DISABLE_PAGING below),
# it needs no config-mode detour, but it is still a per-session setting, and each of probe_ssh's
# commands opens its own fresh, non-interactive exec channel (see the Cisco comment above -- same
# limitation, same reason). So it still has to be folded into the same command string as the thing
# it's protecting rather than sent as its own earlier command, which would already be gone by the
# time the next channel opens. Without this, "show running-config" on a switch with more than one
# screen of config either hangs until _SSH_TIMEOUT kills the channel, losing the whole backup, or
# comes back truncated at the first page.
_ARUBA_DISABLE_PAGING = "no page\n"

_SSH_COMMANDS_ARUBA: tuple[tuple[str, str, str], ...] = (
    ("system", "System", _ARUBA_DISABLE_PAGING + "show system-information"),
    ("vlan", "VLANs", _ARUBA_DISABLE_PAGING + "show vlan"),
    ("vlan_ports", "VLAN-Port-Zuordnung", _ARUBA_DISABLE_PAGING + "show vlan ports all detail"),
    ("neighbors", "Nachbargeräte (LLDP)", _ARUBA_DISABLE_PAGING + "show lldp info remote-device"),
    ("interfaces", "Schnittstellen", _ARUBA_DISABLE_PAGING + "show interfaces brief"),
    # Same reasoning as Mikrotik's "ip_addresses" above -- which subnet(s) this device routes for.
    ("ip_addresses", "IP-Adressen je VLAN", _ARUBA_DISABLE_PAGING + "show ip"),
    ("arp_table", "ARP-Tabelle", _ARUBA_DISABLE_PAGING + "show arp"),
    ("config_export", "Vollständige Konfiguration", _ARUBA_DISABLE_PAGING + "show running-config"),
)

# ArubaOS-CX (the newer, REST-first line: 6300/6400/8320/8325/8400 and similar) is a different NOS
# from classic ArubaOS-Switch above and speaks its own command grammar, not the ProCurve-derived
# one -- "show system", not "show system-information"; "show lldp neighbor-info", not "show lldp
# info remote-device"; and so on. Its pager-disable command differs too: "no paging" (this NOS's
# own name for the same setting), same per-session/per-channel non-persistence as ArubaOS-Switch's
# "no page" above, same fold-into-one-command fix for the same reason.
_ARUBA_CX_DISABLE_PAGING = "no paging\n"

_SSH_COMMANDS_ARUBA_CX: tuple[tuple[str, str, str], ...] = (
    ("system", "System", _ARUBA_CX_DISABLE_PAGING + "show system"),
    ("vlan", "VLANs", _ARUBA_CX_DISABLE_PAGING + "show vlan"),
    ("neighbors", "Nachbargeräte (LLDP)", _ARUBA_CX_DISABLE_PAGING + "show lldp neighbor-info"),
    ("interfaces", "Schnittstellen", _ARUBA_CX_DISABLE_PAGING + "show interface brief"),
    # Same reasoning as Mikrotik's "ip_addresses" above -- which subnet(s) this device routes for.
    ("ip_addresses", "IP-Adressen je VLAN", _ARUBA_CX_DISABLE_PAGING + "show interface vlan"),
    ("arp_table", "ARP-Tabelle", _ARUBA_CX_DISABLE_PAGING + "show arp"),
    ("config_export", "Vollständige Konfiguration", _ARUBA_CX_DISABLE_PAGING + "show running-config"),
)

_SSH_COMMANDS_CISCO: tuple[tuple[str, str, str], ...] = (
    # Classic Cisco IOS/IOS-XE CLI. Assumes the SSH login already lands in privilege level 15 (no
    # "enable" step) -- probe_ssh's one-shot-exec-per-command model has no way to answer an enable
    # password prompt anyway, since each command below runs in its own fresh exec channel rather
    # than a shared interactive shell.
    # "| no-more" is IOS's own output modifier for suppressing the "--More--" pager, so pagination
    # never needs a "terminal length 0" step beforehand -- that setting only lives for the duration
    # of one exec channel here, which would be gone again by the next command anyway.
    ("system", "System", "show version | no-more"),
    ("vlan", "VLANs", "show vlan brief | no-more"),
    ("neighbors", "Nachbargeräte (CDP)", "show cdp neighbors detail | no-more"),
    ("interfaces", "Schnittstellen", "show interfaces status | no-more"),
    # Same reasoning as Mikrotik's "ip_addresses" above -- which subnet(s) this device routes for.
    ("ip_addresses", "IP-Adressen je Schnittstelle", "show ip interface brief | no-more"),
    ("arp_table", "ARP-Tabelle", "show ip arp | no-more"),
    ("config_export", "Vollständige Konfiguration", "show running-config | no-more"),
)

# TP-Link JetStream/Omada-managed switch CLI (T1600G/TL-SG-series) enables its own "--More--"
# pager by default and -- unlike IOS's "| no-more" -- has no per-command output-format flag to
# suppress it. The only way to turn it off is the stateful, config-mode command "no clipaging",
# and a stateful setting sent as its own earlier command would already be gone by the time the
# next command opens its own fresh exec channel (see the Cisco comment above -- same non-
# interactive, one-shot-exec-per-command model, same limitation). So it has to be folded into the
# very same multi-line command string as the thing it's protecting, sent as one exec request:
# TP-Link's CLI (like Cisco's) feeds a multi-line exec payload to its command parser one line at a
# time, the same as a human typing at the prompt would, which is what makes "configure" / "no
# clipaging" / "exit" take effect before "show ..." runs in that same channel. Without this,
# any output longer than one screen (a switch with more than a handful of VLANs/ports/neighbors,
# or any non-trivial running-config) either hangs until _SSH_TIMEOUT kills the channel -- losing
# the whole fact, config backup included -- or comes back truncated at the first page.
_TPLINK_DISABLE_PAGING = "configure\nno clipaging\nexit\n"

_SSH_COMMANDS_TPLINK: tuple[tuple[str, str, str], ...] = (
    ("system", "System", _TPLINK_DISABLE_PAGING + "show system-info"),
    ("vlan", "VLANs", _TPLINK_DISABLE_PAGING + "show vlan"),
    ("neighbors", "Nachbargeräte (LLDP)", _TPLINK_DISABLE_PAGING + "show lldp neighbor-information"),
    ("interfaces", "Schnittstellen", _TPLINK_DISABLE_PAGING + "show interface status"),
    ("arp_table", "ARP-Tabelle", _TPLINK_DISABLE_PAGING + "show arp"),
    ("config_export", "Vollständige Konfiguration", _TPLINK_DISABLE_PAGING + "show running-config"),
)

# Facts holding a full device config export -- picked up by `extract_config_backups` below and
# fed into deviceConfigVersions. Kept separate from the general truncation limit (see probe_ssh)
# because a whole router/switch config is the point of collecting it, not a side note.
_CONFIG_BACKUP_KEYS = {"config_export", "omada_backup"}

# Base64-encoded binary backups (currently just "omada_backup") need a much larger ceiling than
# text config exports -- a few hundred KB of raw backup easily becomes >60000 base64 characters,
# and unlike a truncated text config (still partially readable), a truncated base64 string decodes
# to corrupt garbage. So these get their own, far larger limit, and a fact that still hits that
# limit is dropped entirely rather than stored truncated -- a missing backup is safer than one that
# silently doesn't restore.
_BINARY_BACKUP_KEYS = {"omada_backup"}
_BINARY_BACKUP_LIMIT = 4_000_000


def _detect_platform(system: dict) -> str:
    """String heuristic on what the device claims to be, same pattern as the FRITZ!Box check in
    probe_system below -- an account's category never implies a device's platform."""
    haystack = " ".join([
        system.get("vendor", ""), system.get("model", ""), system.get("name", ""), system.get("os", ""),
    ]).lower()
    if "mikrotik" in haystack or "routeros" in haystack:
        return "mikrotik"
    # ArubaOS-Switch is the renamed HP ProCurve CLI (see `_SSH_COMMANDS_ARUBA`'s own docstring) --
    # older or relabelled hardware still reports itself as "HP"/"Hewlett Packard"/"ProCurve" in
    # OUI/mDNS/banner data rather than "Aruba". Without this branch such a switch fell through to
    # the generic Linux command set below, which means nothing to its CLI, and probing it silently
    # returned no facts at all instead of an error pointing at why.
    if "aruba" in haystack or "procurve" in haystack or "hewlett" in haystack or re.search(r"\bhp\b", haystack):
        # ArubaOS-CX (the newer, REST-first line -- 6300/6400/8320/8325/8400 and similar) speaks a
        # different command grammar from classic ArubaOS-Switch, so it needs its own branch rather
        # than falling through to `_SSH_COMMANDS_ARUBA`'s ProCurve-derived syntax, which it doesn't
        # understand. Checked before the generic "aruba" match below since a CX device's own
        # strings ("Aruba CX 6300", sysDescr mentioning "ArubaOS-CX") contain both signals.
        if re.search(r"\barubaos-cx\b|\baos-cx\b|\bcx\b", haystack):
            return "arubacx"
        return "aruba"
    if "cisco" in haystack:
        return "cisco"
    # Same failure mode as HP above: a TP-Link JetStream/Omada-managed switch has its own CLI, not
    # a POSIX shell, and fell through to the generic Linux set with no matching branch at all.
    if "tp-link" in haystack or "tplink" in haystack or "jetstream" in haystack:
        return "tplink"
    return ""


def _normalize_config_text(text: str) -> str:
    """Strips comment lines before comparing two config exports for equality. Mikrotik's `/export`
    starts with a comment line carrying the export's own timestamp, which would otherwise make
    every scan look like a change and defeat the point of only keeping history when something
    actually moved. The stored version keeps the original text -- only the comparison is blind to
    these lines."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def _decode_secret(account: dict) -> tuple[str, str]:
    return crypto.decrypt(account.get("secretEnc") or ""), crypto.decrypt(account.get("passphraseEnc") or "")


# ---------------------------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------------------------

async def probe_ssh(host: str, account: dict, platform: str = "") -> dict:
    """Runs the fixed read-only command set over SSH. Returns {"ok", "facts", "error"}.

    `platform` picks which command set applies -- Linux-oriented by default, or one of the
    RouterOS/ArubaOS/Cisco IOS sets above once `_detect_platform` recognises the target device."""
    try:
        import asyncssh
    except ImportError:
        return {"ok": False, "error": "asyncssh ist nicht installiert -- SSH-Sondierung nicht möglich.", "facts": {}}

    secret, passphrase = _decode_secret(account)
    username = (account.get("username") or "root").strip()
    port = int(account.get("port") or 0) or 22
    is_key = (account.get("category") == "sshkey") or "PRIVATE KEY" in secret

    connect_args: dict = {
        "host": host,
        "port": port,
        "username": username,
        # No trust store exists; see module docstring.
        "known_hosts": None,
        "connect_timeout": 10,
    }
    try:
        if is_key:
            key = asyncssh.import_private_key(secret, passphrase or None)
            connect_args["client_keys"] = [key]
            # Without this asyncssh may silently fall back to the container's own ~/.ssh keys,
            # which would make a failed probe look like a success with the wrong identity.
            connect_args["password"] = None
        else:
            connect_args["password"] = secret
            connect_args["client_keys"] = []
    except (ValueError, KeyError) as exc:
        return {"ok": False, "error": f"Der hinterlegte SSH-Schlüssel ließ sich nicht lesen: {exc}", "facts": {}}

    commands = {
        "mikrotik": _SSH_COMMANDS_MIKROTIK, "aruba": _SSH_COMMANDS_ARUBA,
        "arubacx": _SSH_COMMANDS_ARUBA_CX, "cisco": _SSH_COMMANDS_CISCO,
        "tplink": _SSH_COMMANDS_TPLINK,
    }.get(platform, _SSH_COMMANDS)

    facts: dict[str, dict] = {}
    try:
        async with asyncssh.connect(**connect_args) as connection:
            for key_name, label, command in commands:
                try:
                    result = await asyncio.wait_for(
                        connection.run(command, check=False), timeout=_SSH_TIMEOUT
                    )
                except Exception:  # noqa: BLE001 -- one command failing (missing binary, no
                    # permission, timeout) must not abort the probe; the rest is still worth having.
                    continue
                output = (result.stdout or "").strip()
                if output:
                    if key_name in _BINARY_BACKUP_KEYS:
                        if len(output) >= _BINARY_BACKUP_LIMIT:
                            continue  # would decode to garbage -- see _BINARY_BACKUP_LIMIT's docstring
                        limit = _BINARY_BACKUP_LIMIT
                    elif key_name in _CONFIG_BACKUP_KEYS:
                        # A full device config export is the point of collecting it, not a side
                        # note -- give it a much wider bound than the other, single-fact commands.
                        limit = 60000
                    else:
                        limit = 1200
                    facts[key_name] = {"label": label, "value": output[:limit]}
    except Exception as exc:  # noqa: BLE001 -- asyncssh raises a wide family of connection errors
        return {"ok": False, "error": f"SSH-Verbindung zu {host}:{port} fehlgeschlagen: {exc}", "facts": {}}

    if not facts:
        return {"ok": False, "error": "Verbindung stand, aber kein Befehl lieferte eine Ausgabe.", "facts": {}}
    return {"ok": True, "error": "", "facts": facts}


# ---------------------------------------------------------------------------------------------
# HTTP (Basic/Digest), GET only
# ---------------------------------------------------------------------------------------------

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_VERSION_RE = re.compile(
    r"(?:version|firmware|release)[\s:v]*([0-9]+(?:\.[0-9]+){1,3})", re.IGNORECASE
)


async def probe_http(url: str, account: dict) -> dict:
    """Fetches one page with the stored credentials. GET only -- no form is ever submitted."""
    if not url.startswith(("http://", "https://")):
        return {"ok": False, "error": "Keine gültige Adresse hinterlegt.", "facts": {}}
    secret, _ = _decode_secret(account)
    username = account.get("username") or ""
    if not username and not secret:
        return {"ok": False, "error": "Kein Benutzername und kein Passwort hinterlegt.", "facts": {}}

    # Tracked separately so an unreachable host doesn't get reported as "credentials rejected" --
    # that sends someone off to check a password when the real problem is the network.
    reached = False
    last_transport_error = ""

    for auth_label, auth in (
        ("Basic", httpx.BasicAuth(username, secret)),
        ("Digest", httpx.DigestAuth(username, secret)),
    ):
        try:
            async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, verify=False,
                                         follow_redirects=True, auth=auth) as client:
                response = await client.get(url)
        except (httpx.HTTPError, OSError) as exc:
            last_transport_error = f"{exc.__class__.__name__}: {exc}"
            continue
        reached = True
        if response.status_code in (401, 403):
            continue

        facts: dict = {}
        title_match = _TITLE_RE.search(response.text[:20000]) if response.text else None
        if title_match:
            facts["title"] = {"label": "Seitentitel", "value": re.sub(r"\s+", " ", title_match.group(1)).strip()[:150]}
        if response.headers.get("server"):
            facts["server"] = {"label": "Server-Kennung", "value": response.headers["server"][:120]}
        version_match = _VERSION_RE.search(response.text[:20000]) if response.text else None
        if version_match:
            facts["version"] = {"label": "Erkannte Version", "value": version_match.group(1)}
        facts["auth"] = {"label": "Anmeldung", "value": f"{auth_label} erfolgreich (HTTP {response.status_code})"}
        return {"ok": True, "error": "", "facts": facts}

    if not reached:
        return {"ok": False, "facts": {},
                "error": f"{url} war nicht erreichbar ({last_transport_error or 'keine Antwort'})."}
    return {"ok": False, "facts": {},
            "error": "Die Weboberfläche antwortet, hat die hinterlegten Zugangsdaten aber abgelehnt "
                     "(weder Basic- noch Digest-Anmeldung)."}


# ---------------------------------------------------------------------------------------------
# Home Assistant (REST API, Long-Lived Access Token)
# ---------------------------------------------------------------------------------------------

_HA_TIMEOUT = httpx.Timeout(15.0, connect=5.0)
_HA_AUTOMATION_LIMIT = 60  # bounds how many per-automation config fetches one probe makes

# (Auslöser-Typ, deutsche Kurzform). Only the type is named, never the exact entity/condition --
# enough for someone scanning documentation to know *what kind* of thing sets an automation off.
_HA_TRIGGER_LABELS = {
    "state": "Zustandsänderung", "numeric_state": "Messwert-Schwelle", "time": "Uhrzeit",
    "time_pattern": "Zeitmuster", "sun": "Sonnenstand", "event": "Ereignis", "webhook": "Webhook",
    "template": "Vorlage (Template)", "device": "Geräte-Trigger", "zone": "Zonen-Wechsel",
    "geo_location": "Standort", "calendar": "Kalender", "mqtt": "MQTT",
    "homeassistant": "Start/Beenden von Home Assistant", "tag": "NFC-Tag",
    "persistent_notification": "Benachrichtigung",
}
_HA_SERVICE_LABELS = {
    "turn_on": "einschalten", "turn_off": "ausschalten", "toggle": "umschalten",
    "set_temperature": "Temperatur einstellen", "open_cover": "öffnen", "close_cover": "schließen",
    "lock": "verriegeln", "unlock": "entriegeln", "notify": "benachrichtigen",
    "send_message": "Nachricht senden",
}

# entity_id is the only signal that holds across printer integrations -- device_class and unit
# vary (some report "%", some a raw HP/Brother supply code that isn't a percentage at all).
_HA_SUPPLY_RE = re.compile(r"(toner|ink|cartridge|drum)", re.IGNORECASE)
_HA_SUPPLY_LINE_RE = re.compile(r"^- (.+): ([0-9]+(?:[.,][0-9]+)?)\s*%$")


def _ha_printer_supplies(states: list) -> list[dict]:
    """Printer toner/ink/drum-level sensors HA already exposes (its own printer integrations, or
    SNMP OIDs someone wired up by hand as sensors). Read-only, same as everything else here --
    this only reads `sensor.*` state, never calls a service."""
    supplies = []
    for state in states:
        if not isinstance(state, dict):
            continue
        entity_id = state.get("entity_id", "")
        if not entity_id.startswith("sensor.") or not _HA_SUPPLY_RE.search(entity_id):
            continue
        value = state.get("state", "")
        if value in ("unknown", "unavailable", ""):
            continue
        attrs = state.get("attributes") or {}
        supplies.append({
            "name": attrs.get("friendly_name") or entity_id,
            "value": value,
            "unit": attrs.get("unit_of_measurement") or "",
        })
    return supplies


def _ha_trigger_summary(triggers: object) -> str:
    if not isinstance(triggers, list):
        return ""
    labels: list[str] = []
    for trig in triggers:
        if not isinstance(trig, dict):
            continue
        kind = trig.get("trigger") or trig.get("platform") or ""
        label = _HA_TRIGGER_LABELS.get(kind, kind)
        if label and label not in labels:
            labels.append(label)
    return ", ".join(labels)


def _ha_action_summary(actions: object) -> str:
    if not isinstance(actions, list):
        return ""
    labels: list[str] = []
    for act in actions:
        if not isinstance(act, dict):
            continue
        call = act.get("action") or act.get("service") or ""
        if not call:
            continue
        domain, _, service = call.partition(".")
        verb = _HA_SERVICE_LABELS.get(service, service)
        label = f"{domain} {verb}".strip() if domain else verb
        if label and label not in labels:
            labels.append(label)
    return ", ".join(labels)


async def _ha_self_check(client: httpx.AsyncClient, base_url: str) -> str:
    """Confirms the endpoint actually is a Home Assistant instance answering this token, before
    anything else is asked of it. HA's root `/api/` route -- unlike `/api/states` -- exists purely
    as a health/identity check and always replies `{"message": "API running"}` once the token is
    accepted, so checking it first turns "wrong URL, some other web server answered" or "token
    rejected" into one specific, actionable message here instead of a confusing JSON-parse failure
    two calls later while trying to read automation data that was never coming. Returns an error
    string, or "" once the check passed.
    """
    try:
        response = await client.get(f"{base_url}/api/")
    except httpx.HTTPError as exc:
        return f"Home Assistant unter {base_url} nicht erreichbar: {exc}"
    if response.status_code in (401, 403):
        return (f"Home Assistant hat das Zugriffstoken abgelehnt (HTTP {response.status_code}). "
                "Ein neues Long-Lived Access Token erzeugen (Profil -> Sicherheit) und hier "
                "hinterlegen.")
    if response.status_code >= 400:
        return f"Home Assistant antwortet auf {base_url}/api/ mit HTTP {response.status_code}."
    try:
        payload = response.json()
    except ValueError:
        payload = None
    if not isinstance(payload, dict) or payload.get("message") != "API running":
        return (f"{base_url}/api/ hat nicht wie die Home-Assistant-API geantwortet -- Adresse "
                "prüfen (Basis-URL ohne „/api“, z. B. http://homeassistant.local:8123).")
    return ""


async def probe_homeassistant(url: str, account: dict) -> dict:
    """Reads a Home Assistant instance's own REST API with a Long-Lived Access Token: every
    automation with its on/off status and a short description of what it does, plus printer
    toner/ink levels (see `extract_printer_supplies`) and, if the KNX integration is set up, its
    connection details. Read-only -- only GET is ever called; nothing here can flip a switch, run
    a service, or edit an automation.

    A native `description` an automation was given in its own config is always the best answer to
    "what does this do" and is used verbatim when present -- only automations without one fall
    back to a short, rule-based trigger/action summary. That fallback is deliberately modest (a
    type/service list, not real natural-language understanding of arbitrary trigger/condition/
    action trees), the same trade-off topology.py's neighbour parsers make elsewhere in this app.
    """
    token, _ = _decode_secret(account)
    base_url = (url or "").rstrip("/")
    if not base_url:
        return {"ok": False, "error": "Keine Adresse für Home Assistant hinterlegt.", "facts": {}}
    if not token:
        return {"ok": False, "error": "Kein Zugriffstoken hinterlegt.", "facts": {}}

    facts: dict[str, dict] = {}
    headers = {"Authorization": f"Bearer {token}"}
    try:
        async with httpx.AsyncClient(timeout=_HA_TIMEOUT, verify=False, headers=headers) as client:
            self_check_error = await _ha_self_check(client, base_url)
            if self_check_error:
                return {"ok": False, "error": self_check_error, "facts": {}}

            response = await client.get(f"{base_url}/api/states")
            if response.status_code in (401, 403):
                return {"ok": False, "facts": {}, "error": (
                    f"Home Assistant hat das Zugriffstoken abgelehnt (HTTP {response.status_code}) "
                    "beim Abruf der Zustände."
                )}
            response.raise_for_status()
            states = response.json()
            if not isinstance(states, list):
                raise ValueError("Unerwartete Antwort (keine Liste).")

            # The KNX integration's own diagnostic device exposes these as ordinary sensors --
            # simpler and more portable than reading its config entry, and confirmed against a
            # real KNX-enabled instance during development.
            knx_states = {s["entity_id"]: s.get("state", "") for s in states
                          if isinstance(s, dict) and "knx_interface" in s.get("entity_id", "")}
            if knx_states:
                def _knx(suffix: str) -> str:
                    return next((v for k, v in knx_states.items() if k.endswith(suffix)), "")

                knx_lines = ["KNX ist über die Home-Assistant-Integration angebunden.",
                            f"Verbindungstyp: {_knx('connection_type') or 'unbekannt'}"]
                if _knx("individual_address"):
                    knx_lines.append(f"Physikalische Adresse: {_knx('individual_address')}")
                if _knx("connected_since"):
                    knx_lines.append(f"Verbunden seit: {_knx('connected_since')}")
                facts["knx"] = {"label": "KNX-Anbindung", "value": "\n".join(knx_lines)}

            # Every automation, not just the enabled ones -- a disabled automation is exactly the
            # kind of thing someone troubleshooting "warum tut X nicht mehr" needs to see, and
            # dropping it here would hide the answer.
            automation_states = [
                s for s in states
                if isinstance(s, dict) and s.get("entity_id", "").startswith("automation.")
            ][:_HA_AUTOMATION_LIMIT]

            lines = []
            for state in automation_states:
                attrs = state.get("attributes") or {}
                name = attrs.get("friendly_name") or state["entity_id"]
                status = "ein" if state.get("state") == "on" else "aus"
                config_id = attrs.get("id")
                description = ""
                if config_id:
                    try:
                        config_response = await client.get(
                            f"{base_url}/api/config/automation/config/{config_id}"
                        )
                        if config_response.status_code == 200:
                            config = config_response.json()
                            if isinstance(config, dict):
                                description = (config.get("description") or "").strip()
                                if not description:
                                    trigger_text = _ha_trigger_summary(
                                        config.get("triggers") or config.get("trigger") or [])
                                    action_text = _ha_action_summary(
                                        config.get("actions") or config.get("action") or [])
                                    description = "; ".join(p for p in (
                                        f"Auslöser: {trigger_text}" if trigger_text else "",
                                        f"Aktion: {action_text}" if action_text else "",
                                    ) if p)
                    except (httpx.HTTPError, ValueError):
                        pass  # one automation's config failing must not drop the rest
                lines.append(f"- {name} ({status}): {description}" if description else f"- {name} ({status})")

            if lines:
                facts["automations"] = {"label": f"Automationen ({len(lines)})",
                                        "value": "\n".join(lines)[:20000]}

            supplies = _ha_printer_supplies(states)
            if supplies:
                # Format is deliberately parseable back out by `extract_printer_supplies` below
                # (a leading "- name: value%" per line) as well as human-readable in the generic
                # facts view -- one representation, not two data channels to keep in sync.
                supply_lines = [f"- {s['name']}: {s['value']}{s['unit']}" for s in supplies]
                facts["printerSupplies"] = {"label": f"Drucker-Verbrauchsmaterial ({len(supplies)})",
                                            "value": "\n".join(supply_lines)[:5000]}
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        return {"ok": False, "error": f"Home Assistant unter {base_url} nicht erreichbar: {exc}", "facts": {}}

    if not facts:
        return {"ok": False, "error": "Verbindung stand, aber keine aktiven Automationen oder "
                                      "KNX-Daten gefunden.", "facts": {}}
    return {"ok": True, "error": "", "facts": facts}


# ---------------------------------------------------------------------------------------------
# SNMP (v2c community string only), for switches that have no SSH management at all
# ---------------------------------------------------------------------------------------------

_SNMP_TIMEOUT = 10.0
_SNMP_PORT = 161

# (Schlüssel, Beschriftung, OID, ist_walk). Same allowlist posture as `_SSH_COMMANDS`: only
# `snmpget`/`snmpwalk` are ever invoked, never `snmpset` -- there is no code path that can write.
_SNMP_OIDS: tuple[tuple[str, str, str, bool], ...] = (
    ("sysName", "Systemname", "1.3.6.1.2.1.1.5.0", False),
    ("sysDescr", "Systembeschreibung", "1.3.6.1.2.1.1.1.0", False),
    ("interfaces", "Schnittstellen", "1.3.6.1.2.1.2.2.1.2", True),  # IF-MIB ifDescr
    ("lldpNeighbors", "Nachbargeräte (LLDP)", "1.0.8802.1.1.2.1.4.1.1", True),  # LLDP-MIB remote table
    ("vlans", "VLANs (Q-BRIDGE-MIB)", "1.3.6.1.2.1.17.7.1.4.3.1", True),  # dot1qVlanStaticTable
    ("arpTable", "ARP-Tabelle (IP-NET-TO-MEDIA-MIB)", "1.3.6.1.2.1.4.22.1.2", True),  # ipNetToMediaPhysAddress
)


async def _snmp_run(*args: str) -> str:
    """Fixed argv via exec, never a shell string -- `args` are only ever the constants above plus
    the target host/community, never anything composed from free-form user input."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
    except OSError:  # snmpget/snmpwalk not installed -- treated as "no output", like a missing
        # binary already is in the SSH command loop.
        return ""
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=_SNMP_TIMEOUT)
    except asyncio.TimeoutError:
        proc.kill()
        return ""
    return stdout.decode("utf-8", errors="replace").strip()


async def probe_snmp(host: str, account: dict, kind: str = "") -> dict:
    """Walks a fixed OID set with the stored community string. Read-only by construction: an SNMP
    SET has no counterpart anywhere in this function. Output is kept as raw walk text rather than
    parsed into structured VLAN/neighbor tables -- formats vary enough between net-snmp versions
    and vendor MIB implementations that a parser would be more fragile than useful here.

    `kind` additionally triggers a toner/ink read (see `_snmp_printer_supplies`) when the
    credential is attached to a `printer`-kind system -- worth a special case, unlike the VLAN/
    neighbor facts above, because it feeds `extract_printer_supplies`/pipeline.py's inventory
    update rather than just the generic facts view, and needs one specific, structured shape
    (`printerSupplies`, same "- name: value%" format `probe_homeassistant` already produces) to do
    that."""
    community, _ = _decode_secret(account)
    if not community:
        return {"ok": False, "error": "Keine Community-Zeichenkette hinterlegt.", "facts": {}}
    port = int(account.get("port") or 0) or _SNMP_PORT
    target = f"{host}:{port}"

    facts: dict[str, dict] = {}
    for key, label, oid, is_walk in _SNMP_OIDS:
        binary = "snmpwalk" if is_walk else "snmpget"
        output = await _snmp_run(binary, "-v2c", "-c", community, "-t", "3", "-r", "1", target, oid)
        if output and "Timeout" not in output and "No Such" not in output:
            facts[key] = {"label": label, "value": output[:20000]}

    if kind == "printer":
        supplies = await _snmp_printer_supplies(target, community)
        if supplies:
            supply_lines = [f"- {s['name']}: {s['percent']}%" for s in supplies]
            facts["printerSupplies"] = {"label": f"Drucker-Verbrauchsmaterial ({len(supplies)})",
                                        "value": "\n".join(supply_lines)[:5000]}

    if not facts:
        return {"ok": False, "facts": {}, "error": (
            f"Keine SNMP-Antwort von {target}. Community-Zeichenkette prüfen oder ob SNMP auf dem "
            "Gerät aktiviert ist."
        )}
    return {"ok": True, "error": "", "facts": facts}


# ---------------------------------------------------------------------------------------------
# Printer toner/ink levels via SNMP -- standard Printer-MIB first, a Brother private OID as
# fallback for firmware that leaves the standard table unpopulated. Community string and port come
# from the same "snmp"-category account as the rest of `probe_snmp` -- there is deliberately no
# separate credential type or hardcoded "public" community for this, so it stays covered by the
# same opt-in-per-credential rule as everything else in this module (see module docstring, point
# 4); "public" is simply the value a household typically stores in that account, same as any other
# SNMP-managed device here.
# ---------------------------------------------------------------------------------------------

_PRINTER_MIB_DESCR_OID = "1.3.6.1.2.1.43.11.1.1.6"  # prtMarkerSuppliesDescription
_PRINTER_MIB_LEVEL_OID = "1.3.6.1.2.1.43.11.1.1.9"  # prtMarkerSuppliesLevel
_PRINTER_MIB_MAX_OID = "1.3.6.1.2.1.43.11.1.1.8"    # prtMarkerSuppliesMaxCapacity

# Brother's private enterprise MIB (1.3.6.1.4.1.2435), tried only when the standard Printer-MIB
# above reports nothing usable. Some Brother firmware leaves prtMarkerSuppliesLevel/MaxCapacity at
# -3/-2 ("not used"/"unknown", RFC 3805) for every supply even though the device tracks real
# percentages internally, and exposes those instead through this single OctetString:
# `brInfoMaintenance`, one packed record per consumable -- 1 id byte, a 2-byte "01 04" record
# marker, then a 4-byte big-endian value in 0.01% steps (9700 = 97.00%), with runs of 0xFF padding
# (both the inter-record gap and the table's own end-of-data marker look like this) between
# records. Brother publishes no MIB for this table and the layout is reverse-engineered from field
# reports, known to vary between models -- see `parse_brother_maintenance`'s docstring for how
# that uncertainty is handled.
_BROTHER_MAINTENANCE_OID = "1.3.6.1.4.1.2435.2.3.9.4.2.1.5.5.8.0"


def _parse_printer_mib_walk(text: str, base_oid: str) -> dict[str, str]:
    """Row-index -> raw value from one `snmpwalk -O n <base_oid>` output. The index is whatever
    follows `base_oid` in each returned OID -- Printer-MIB's supplies table key (host-resource
    device index + supply index) varies by vendor/model, so nothing here assumes a fixed shape for
    it beyond "it's the table's own row key", the same posture `probe_snmp` already takes on
    VLAN/neighbor output."""
    prefix = base_oid.strip(".") + "."
    values: dict[str, str] = {}
    for line in text.splitlines():
        oid_part, sep, rest = line.partition("=")
        if not sep:
            continue
        oid = oid_part.strip().lstrip(".")
        if not oid.startswith(prefix):
            continue
        index = oid[len(prefix):]
        value = rest.split(":", 1)[-1].strip().strip('"') if ":" in rest else rest.strip()
        if index:
            values[index] = value
    return values


def parse_printer_mib_supplies(descr_text: str, level_text: str, max_text: str) -> list[dict]:
    """(name, percent) pairs from standard Printer-MIB (RFC 3805) supplies-table walks, matched by
    their shared row index across the three separate `snmpwalk` outputs -- one for
    prtMarkerSuppliesDescription, one for prtMarkerSuppliesLevel, one for prtMarkerSuppliesMax
    Capacity. Negative level/capacity values are RFC-defined sentinels (-1 unknown, -2
    unrestricted/no fixed capacity, -3 not used), not real readings, and are skipped -- a printer
    reporting only sentinels here is exactly the case `parse_brother_maintenance` exists for."""
    descriptions = _parse_printer_mib_walk(descr_text, _PRINTER_MIB_DESCR_OID)
    levels = _parse_printer_mib_walk(level_text, _PRINTER_MIB_LEVEL_OID)
    capacities = _parse_printer_mib_walk(max_text, _PRINTER_MIB_MAX_OID)

    supplies: list[dict] = []
    for index, level_raw in levels.items():
        capacity_raw = capacities.get(index)
        if capacity_raw is None:
            continue
        try:
            level, capacity = int(level_raw), int(capacity_raw)
        except ValueError:
            continue
        if level < 0 or capacity <= 0:
            continue
        name = descriptions.get(index) or f"Verbrauchsmaterial {index}"
        percent = max(0.0, min(100.0, round(level * 100 / capacity, 1)))
        supplies.append({"name": name, "percent": percent})
    return supplies


def _brother_maintenance_bytes(hex_text: str) -> bytes:
    """Raw bytes from an `snmpget -O x` Hex-STRING line (`Hex-STRING: 01 04 00 00 25 40 FF ...`) --
    empty if the OID doesn't exist on this device or the reply isn't an octet string at all."""
    match = re.search(r"Hex-STRING:\s*([0-9A-Fa-f ]+)", hex_text)
    if not match:
        return b""
    try:
        return bytes(int(b, 16) for b in match.group(1).split())
    except ValueError:
        return b""


def parse_brother_maintenance(hex_text: str) -> list[dict]:
    """Toner/drum percentages from Brother's private brInfoMaintenance blob (see
    `_BROTHER_MAINTENANCE_OID`'s docstring for the reverse-engineered layout). Parses
    record-by-record rather than all-or-nothing, since one malformed or unrecognised record must
    not hide the rest -- but a record whose marker doesn't match or whose value falls outside a
    sane 0-100% range is dropped rather than stored as a wrong-looking percentage, same "no data
    beats wrong data" posture `_BINARY_BACKUP_LIMIT` already takes on truncated backups above.
    Runs of 0xFF (inter-record padding and the table's own end marker look identical) are skipped
    wherever they appear rather than matched as one fixed-width terminator, since which of the two
    a given run is doesn't change how it should be handled -- both just mean "no record starts
    here"."""
    data = _brother_maintenance_bytes(hex_text)
    supplies: list[dict] = []
    pos = 0
    while pos < len(data):
        while pos < len(data) and data[pos] == 0xFF:
            pos += 1
        if pos + 7 > len(data):
            break
        record_id, marker, value = data[pos], data[pos + 1:pos + 3], data[pos + 3:pos + 7]
        pos += 7
        if marker != b"\x01\x04":
            continue
        percent = round(int.from_bytes(value, "big") / 100, 1)
        if 0 <= percent <= 100:
            supplies.append({"name": f"Verbrauchsmaterial {record_id}", "percent": percent})
    return supplies


async def _snmp_printer_supplies(target: str, community: str) -> list[dict]:
    """Standard Printer-MIB first, Brother's private OID only as a fallback -- see
    `parse_printer_mib_supplies`/`parse_brother_maintenance` for why each exists and how each is
    parsed."""
    descr = await _snmp_run("snmpwalk", "-v2c", "-c", community, "-t", "3", "-r", "1", "-O", "n",
                            target, _PRINTER_MIB_DESCR_OID)
    level = await _snmp_run("snmpwalk", "-v2c", "-c", community, "-t", "3", "-r", "1", "-O", "n",
                            target, _PRINTER_MIB_LEVEL_OID)
    maxcap = await _snmp_run("snmpwalk", "-v2c", "-c", community, "-t", "3", "-r", "1", "-O", "n",
                             target, _PRINTER_MIB_MAX_OID)
    supplies = parse_printer_mib_supplies(descr, level, maxcap)
    if supplies:
        return supplies

    hex_text = await _snmp_run("snmpget", "-v2c", "-c", community, "-t", "3", "-r", "1", "-O", "x",
                               target, _BROTHER_MAINTENANCE_OID)
    return parse_brother_maintenance(hex_text)


# ---------------------------------------------------------------------------------------------
# FRITZ!Box TR-064
# ---------------------------------------------------------------------------------------------

_TR064_PORT = 49000
_STRIP_NS = re.compile(r"\{[^}]*\}")


def _xml_text(root: ElementTree.Element, tag: str) -> str:
    for element in root.iter():
        if _STRIP_NS.sub("", element.tag) == tag and element.text:
            return element.text.strip()
    return ""


async def probe_fritzbox(host: str, account: dict | None) -> dict:
    """AVM routers expose TR-064 on 49000. `tr64desc.xml` needs no login and already yields model
    and friendly name; `DeviceInfo:GetInfo` needs one and adds firmware, serial and uptime.

    Only GetInfo actions are used. The Set* half of TR-064 is never constructed anywhere in this
    file, which is what makes "read-only" checkable rather than a claim.
    """
    facts: dict = {}
    base = f"http://{host}:{_TR064_PORT}"

    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            description = await client.get(f"{base}/tr64desc.xml")
        if description.status_code < 400:
            root = ElementTree.fromstring(description.text)
            for tag, label in (("friendlyName", "Gerätename"), ("modelName", "Modell"),
                               ("modelNumber", "Modellnummer"), ("manufacturer", "Hersteller")):
                value = _xml_text(root, tag)
                if value:
                    facts[tag] = {"label": label, "value": value[:120]}
    except (httpx.HTTPError, ElementTree.ParseError, OSError, ValueError):
        pass

    if account is not None:
        secret, _ = _decode_secret(account)
        username = account.get("username") or ""
        envelope = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            '<u:GetInfo xmlns:u="urn:dslforum-org:service:DeviceInfo:1" />'
            "</s:Body></s:Envelope>"
        )
        try:
            async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT,
                                         auth=httpx.DigestAuth(username, secret)) as client:
                response = await client.post(
                    f"{base}/upnp/control/deviceinfo",
                    content=envelope.encode(),
                    headers={
                        "Content-Type": 'text/xml; charset="utf-8"',
                        "SoapAction": "urn:dslforum-org:service:DeviceInfo:1#GetInfo",
                    },
                )
            if response.status_code < 400:
                root = ElementTree.fromstring(response.text)
                for tag, label in (("NewSoftwareVersion", "Firmware"), ("NewSerialNumber", "Seriennummer"),
                                   ("NewModelName", "Modell"), ("NewDescription", "Beschreibung"),
                                   ("NewUpTime", "Laufzeit (Sekunden)")):
                    value = _xml_text(root, tag)
                    if value:
                        facts[tag] = {"label": label, "value": value[:120]}
        except (httpx.HTTPError, ElementTree.ParseError, OSError, ValueError):
            pass

        # The FRITZ!Box's own known-hosts table -- effectively its ARP/DHCP-lease table, and a
        # more authoritative source of IP<->MAC pairs than this app's own ARP read
        # (discovery.arp_table) since it also knows about devices asleep or on Wi-Fi that never
        # answered this host's own ping/port probes. `X_AVM-DE_GetHostListPath` is one call
        # instead of looping `GetGenericHostEntry` per index -- it hands back a URL to an XML
        # dump of every host the router has ever leased or seen on the LAN side.
        try:
            host_envelope = (
                '<?xml version="1.0" encoding="utf-8"?>'
                '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
                '<u:X_AVM-DE_GetHostListPath xmlns:u="urn:dslforum-org:service:Hosts:1" />'
                "</s:Body></s:Envelope>"
            )
            async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT,
                                         auth=httpx.DigestAuth(username, secret)) as client:
                path_response = await client.post(
                    f"{base}/upnp/control/hosts",
                    content=host_envelope.encode(),
                    headers={
                        "Content-Type": 'text/xml; charset="utf-8"',
                        "SoapAction": "urn:dslforum-org:service:Hosts:1#X_AVM-DE_GetHostListPath",
                    },
                )
            path = _xml_text(ElementTree.fromstring(path_response.text), "NewX_AVM-DE_HostListPath") \
                if path_response.status_code < 400 else ""
            if path:
                async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT,
                                             auth=httpx.DigestAuth(username, secret)) as client:
                    list_response = await client.get(f"{base}{path}")
                if list_response.status_code < 400:
                    lines = []
                    for item in ElementTree.fromstring(list_response.text).iter():
                        if _STRIP_NS.sub("", item.tag) != "Item":
                            continue
                        ip, mac = _xml_text(item, "IPAddress"), _xml_text(item, "MACAddress")
                        if not ip or not mac:
                            continue
                        name = _xml_text(item, "HostName") or "unbenannt"
                        active = "aktiv" if _xml_text(item, "Active") == "1" else "inaktiv"
                        lines.append(f"{ip} {mac} {name} ({active})")
                    if lines:
                        facts["hostList"] = {
                            "label": f"Bekannte Geräte laut FRITZ!Box ({len(lines)})",
                            "value": "\n".join(lines)[:20000],
                        }
        except (httpx.HTTPError, ElementTree.ParseError, OSError, ValueError):
            pass

    if not facts:
        return {"ok": False, "facts": {},
                "error": ("Keine TR-064-Antwort. In der FRITZ!Box unter Heimnetz -> Netzwerk -> "
                          "Netzwerkeinstellungen muss „Zugriff für Anwendungen zulassen“ aktiv sein.")}
    return {"ok": True, "error": "", "facts": facts}


# ---------------------------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------------------------

def _derive_purpose(results: dict) -> str:
    """Turns probe output into a one-line purpose, for devices that still have none."""
    facts = {k: v["value"].lower() for source in results.values() if source.get("ok")
             for k, v in source.get("facts", {}).items()}
    for key, pattern, purpose in _ROLE_HINTS:
        value = facts.get(key, "")
        if value and re.search(pattern, value):
            return purpose
    if "docker" in facts:
        return "Server mit Docker-Containern"
    return ""


def fallback_account(settings: dict, system: dict) -> dict | None:
    """The configured default credential, as an account-shaped dict -- or None if it must not be
    used for this device.

    Guardrails, because unlike a per-device credential this one gets offered to many machines:

    * Off unless explicitly enabled, and skipped entirely for any device that already has its own
      credential (the caller checks that).
    * Only offered where the matching service is actually open: SSH needs port 22 (or the
      configured one) in the scan results. Without that check this would be credential spraying
      across the whole subnet, and repeated failures can lock accounts out on some devices.
    * Never used against a router or an unidentified device -- those are the ones most likely to
      lock out or alarm, and least likely to share a household SSH login.
    """
    if not settings.get("defaultCredentialEnabled"):
        return None
    secret = settings.get("defaultCredentialSecretEnc") or ""
    if not secret:
        return None
    if system.get("kind") not in ("server", "nas", "vm", "pc", "container"):
        return None

    port = int(settings.get("defaultCredentialPort") or 0) or 22
    if port not in (system.get("openPorts") or []):
        return None

    return {
        "id": "__default__",
        "label": "Standard-Zugang",
        "category": "sshkey" if settings.get("defaultCredentialIsKey") else "login",
        "username": settings.get("defaultCredentialUsername") or "root",
        "secretEnc": secret,
        "passphraseEnc": settings.get("defaultCredentialPassphraseEnc") or "",
        "url": "",
        "port": port,
        "allowProbe": 1,
    }


async def probe_system(system: dict, accounts: list[dict]) -> dict:
    """Runs every applicable probe for one device. `accounts` must already be filtered to
    credentials cleared for probing."""
    host = (system.get("ip") or system.get("hostname") or "").strip()
    if not host:
        return {"ran": False, "results": {}, "reason": "Keine Adresse hinterlegt."}

    results: dict[str, dict] = {}
    is_fritzbox = "fritz" in " ".join(
        [system.get("vendor", ""), system.get("model", ""), system.get("name", "")]
    ).lower()
    platform = _detect_platform(system)

    # TR-064 works partly without a login, so it runs for AVM hardware regardless.
    if is_fritzbox or system.get("kind") == "router":
        router_account = next((a for a in accounts if a.get("category") in ("login", "router")), None)
        result = await probe_fritzbox(host, router_account)
        if result["ok"]:
            results["tr064"] = result

    for account in accounts:
        category = account.get("category")
        if category == "sshkey" or (category == "login" and (account.get("port") or 0) in (22, 0)):
            # A detected Mikrotik/Aruba widens this beyond the usual Linux-host kinds -- a
            # router/switch admin login is exactly the "login" shape SSH probing was built for,
            # it just never had a matching platform to run non-Linux commands against before.
            if category == "sshkey" or platform or system.get("kind") in ("server", "nas", "vm", "pc", "container"):
                result = await probe_ssh(host, account, platform)
                if result["ok"]:
                    results[f"ssh:{account['label']}"] = result
                elif "ssh" not in results:
                    results[f"ssh:{account['label']}"] = result
        if category == "snmp":
            result = await probe_snmp(host, account, system.get("kind", ""))
            if result["ok"]:
                results[f"snmp:{account['label']}"] = result
            elif "snmp" not in results:
                results[f"snmp:{account['label']}"] = result
        if category == "homeassistant":
            result = await probe_homeassistant(account.get("url") or system.get("url"), account)
            if result["ok"]:
                results[f"ha:{account['label']}"] = result
            elif "ha" not in results:
                results[f"ha:{account['label']}"] = result
        url = account.get("url") or system.get("url")
        if url and category in ("login", "apikey"):
            result = await probe_http(url, account)
            if result["ok"]:
                results[f"http:{account['label']}"] = result

    return {"ran": bool(results), "results": results, "purpose": _derive_purpose(results), "reason": ""}


# ---------------------------------------------------------------------------------------------
# ARP/host-list parsing -- turns whatever raw text `arp_table`/`arpTable`/`hostList` facts hold
# (Linux `ip neigh`/`arp -an`, RouterOS `/ip arp print`, ArubaOS `show arp`, Cisco `show ip arp`,
# an SNMP ipNetToMediaTable walk, or a FRITZ!Box host list) into IP -> MAC pairs.
# ---------------------------------------------------------------------------------------------

# Every one of the formats above prints exactly one MAC per record, just in a different notation
# -- colon/dash-separated (Linux, RouterOS, generic), Cisco's dotted triples (aabb.ccdd.eeff),
# ArubaOS/ProCurve's dashed hex-sextets (aabbcc-ddeeff), or an SNMP walk's space-separated octets.
# Matching all four and normalizing afterwards is simpler and more robust than a parser per vendor,
# because unlike topology.py's neighbour parsers (which also need a *name*), an ARP record only
# ever needs "is there an IP and a MAC on this line", and that shape is the same everywhere.
_ARP_MAC_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b"),
    re.compile(r"\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b"),
    re.compile(r"\b[0-9A-Fa-f]{6}-[0-9A-Fa-f]{6}\b"),
    re.compile(r"\b([0-9A-Fa-f]{2}\s){5}[0-9A-Fa-f]{2}\b"),
)
# A plain ARP dump has the IP as a standalone 4-octet run. An SNMP walk instead embeds it at the
# *end* of a longer numeric run (the OID index is `<ifIndex>.<ip1>.<ip2>.<ip3>.<ip4>`), so matching
# only 4 groups would grab "<ifIndex>.<ip1>.<ip2>.<ip3>" instead -- a real IP with its first octet
# silently replaced by the SNMP table's row index. Matching the whole run and keeping only its last
# four groups handles both shapes with one regex.
_ARP_NUMERIC_RUN_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3,}\b")
_ARP_FACT_KEYS = {"arp_table", "arpTable", "hostList"}


def _extract_mac(text: str) -> str:
    for pattern in _ARP_MAC_PATTERNS:
        match = pattern.search(text)
        if match:
            digits = re.sub(r"[^0-9A-Fa-f]", "", match.group(0))
            if len(digits) == 12:
                return ":".join(digits[i:i + 2] for i in range(0, 12, 2)).lower()
    return ""


def _extract_ip(text: str) -> str:
    match = _ARP_NUMERIC_RUN_RE.search(text)
    if not match:
        return ""
    octets = match.group(0).split(".")[-4:]
    return ".".join(octets) if all(0 <= int(o) <= 255 for o in octets) else ""


def parse_arp_pairs(text: str) -> dict[str, str]:
    """IP -> normalized-lowercase MAC for every line that carries both. A header, separator or
    incomplete-entry line simply has no match and is skipped, so this degrades gracefully on a
    format it wasn't written against, same posture as topology.py's LLDP parsers."""
    pairs: dict[str, str] = {}
    for line in text.splitlines():
        ip = _extract_ip(line)
        if not ip or ip in ("0.0.0.0", "255.255.255.255"):
            continue
        mac = _extract_mac(line)
        if mac:
            pairs[ip] = mac
    return pairs


def extract_arp_entries(outcome: dict) -> dict[str, str]:
    """IP -> MAC pairs from any ARP/host-list fact a probe outcome collected. Pure function, same
    shape and same reason as `extract_config_backups` -- the caller (pipeline.py) decides what a
    newly-learned device becomes; this module only ever reads."""
    pairs: dict[str, str] = {}
    for result in outcome.get("results", {}).values():
        if not result.get("ok"):
            continue
        for key, fact in result.get("facts", {}).items():
            if key in _ARP_FACT_KEYS:
                pairs.update(parse_arp_pairs(fact["value"]))
    return pairs


def extract_printer_supplies(outcome: dict) -> list[dict]:
    """(name, percent) pairs from any `printerSupplies` fact a probe outcome collected -- pure
    function, same shape as `extract_arp_entries`. Only percentage readings are returned: a raw
    HP/Brother supply code isn't something a progress bar can render, and the generic facts view
    (see `probe_homeassistant`) already shows the reading as-is regardless. Matching a supply to
    a specific printer in the inventory is pipeline.py's job, not this module's -- it never touches
    the inventory."""
    supplies: list[dict] = []
    for result in outcome.get("results", {}).values():
        if not result.get("ok"):
            continue
        fact = result.get("facts", {}).get("printerSupplies")
        if not fact:
            continue
        for line in fact["value"].splitlines():
            match = _HA_SUPPLY_LINE_RE.match(line)
            if match:
                supplies.append({"name": match.group(1), "percent": float(match.group(2).replace(",", "."))})
    return supplies


def extract_config_backups(system: dict, outcome: dict) -> list[tuple[str, str, str]]:
    """(label, content, source) triples for any full-config-export fact in a probe outcome. Pure
    function -- no db import, so this module stays exactly what its docstring claims: it reads
    devices, it does not touch storage. The caller (main.py, pipeline.py) decides what to persist."""
    backups: list[tuple[str, str, str]] = []
    for source, result in outcome.get("results", {}).items():
        if not result.get("ok"):
            continue
        for key, fact in result.get("facts", {}).items():
            if key in _CONFIG_BACKUP_KEYS:
                backups.append((f"{system.get('name', 'Gerät')} – {fact['label']}", fact["value"], source))
    return backups


def persist_config_backups(system: dict, outcome: dict) -> int:
    """Stores any full-config-export facts from a probe outcome as a new deviceConfigVersions row
    -- but only when the content actually changed (comparing normalized text, see
    `_normalize_config_text`), so a scan that finds nothing different doesn't grow the history.
    Called from both probe call sites (main.py's manual probe endpoint, pipeline.py's scheduled
    scan) so the logic lives once. Content is encrypted before it ever reaches the database -- a
    device export can carry secrets (SNMP community strings, RADIUS shared secrets, WiFi keys),
    the same threat model as `accounts.secretEnc`. Returns how many new versions were written."""
    saved = 0
    for label, content, source in extract_config_backups(system, outcome):
        existing = next((v for v in db.list_device_config_versions(system["id"]) if v["label"] == label), None)
        changed = True
        if existing is not None:
            previous = db.get_device_config_version(existing["id"])
            if previous is not None:
                changed = _normalize_config_text(crypto.decrypt(previous["content"])) != _normalize_config_text(content)
        if changed:
            db.save_device_config_version(system["id"], label, crypto.encrypt(content), source)
            saved += 1
    return saved
