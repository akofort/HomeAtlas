"""Authentifiziertes Sondieren -- ausschließlich lesend.

The user asked for this explicitly: when a credential for a device is stored, log in and gather
what helps, **but never change anything**. That "never" has to be a property of the code, not a
promise in a docstring, because the credentials involved are usually root or router-admin. Four
things enforce it:

1. **A hardcoded command allowlist.** `_SSH_COMMANDS` (and its platform variants,
   `_SSH_COMMANDS_MIKROTIK`/`_SSH_COMMANDS_ARUBA`/`_SSH_COMMANDS_CISCO`) are module constants.
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
    # Never "/export show-sensitive" -- that writes out stored PPPoE/WiFi passwords in cleartext,
    # which would break the "secrets never exposed" invariant this whole module exists to uphold.
    ("config_export", "Vollständige Konfiguration", "/export compact"),
)

_SSH_COMMANDS_ARUBA: tuple[tuple[str, str, str], ...] = (
    # Classic ArubaOS-Switch (ProCurve-derived) CLI. ArubaOS-CX, the newer REST-first line, uses a
    # different command grammar and is not covered here -- SNMP (see probe_snmp) is the fallback.
    ("system", "System", "show system-information"),
    ("vlan", "VLANs", "show vlan"),
    ("vlan_ports", "VLAN-Port-Zuordnung", "show vlan ports all detail"),
    ("neighbors", "Nachbargeräte (LLDP)", "show lldp info remote-device"),
    ("interfaces", "Schnittstellen", "show interfaces brief"),
    ("config_export", "Vollständige Konfiguration", "show running-config"),
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
    ("config_export", "Vollständige Konfiguration", "show running-config | no-more"),
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
    if "aruba" in haystack:
        return "aruba"
    if "cisco" in haystack:
        return "cisco"
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
        "mikrotik": _SSH_COMMANDS_MIKROTIK, "aruba": _SSH_COMMANDS_ARUBA, "cisco": _SSH_COMMANDS_CISCO,
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


async def probe_snmp(host: str, account: dict) -> dict:
    """Walks a fixed OID set with the stored community string. Read-only by construction: an SNMP
    SET has no counterpart anywhere in this function. Output is kept as raw walk text rather than
    parsed into structured VLAN/neighbor tables -- formats vary enough between net-snmp versions
    and vendor MIB implementations that a parser would be more fragile than useful here."""
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

    if not facts:
        return {"ok": False, "facts": {}, "error": (
            f"Keine SNMP-Antwort von {target}. Community-Zeichenkette prüfen oder ob SNMP auf dem "
            "Gerät aktiviert ist."
        )}
    return {"ok": True, "error": "", "facts": facts}


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
            result = await probe_snmp(host, account)
            if result["ok"]:
                results[f"snmp:{account['label']}"] = result
            elif "snmp" not in results:
                results[f"snmp:{account['label']}"] = result
        url = account.get("url") or system.get("url")
        if url and category in ("login", "apikey"):
            result = await probe_http(url, account)
            if result["ok"]:
                results[f"http:{account['label']}"] = result

    return {"ran": bool(results), "results": results, "purpose": _derive_purpose(results), "reason": ""}


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
