"""Authentifiziertes Sondieren -- ausschließlich lesend.

The user asked for this explicitly: when a credential for a device is stored, log in and gather
what helps, **but never change anything**. That "never" has to be a property of the code, not a
promise in a docstring, because the credentials involved are usually root or router-admin. Four
things enforce it:

1. **A hardcoded command allowlist.** `_SSH_COMMANDS` is a module constant. There is no setting,
   no API parameter and no LLM tool that can add to it. Making it configurable would turn this
   into a remote-execution feature with a nice UI, which is precisely what it must not be.
2. **Every command is read-only** and non-interactive: no package manager, no service control, no
   redirect, no `sudo`. Failures are expected and swallowed (`2>/dev/null`) so a missing binary
   never turns into a retry with something more aggressive.
3. **HTTP is GET-only**, and TR-064 uses only `GetInfo`-style SOAP actions -- the `Set*` half of
   that API is never constructed.
4. **Opt-in per credential.** Nothing here runs unless a human ticked `allowProbe` on that
   specific stored credential (see `db.list_probe_accounts`).

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

from . import crypto

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
)

# What each command's presence suggests about the device's role, used to fill `purpose` when
# nothing else did.
_ROLE_HINTS: tuple[tuple[str, str, str], ...] = (
    ("docker", "docker", "Server, auf dem Anwendungen in Docker-Containern laufen"),
    ("virt", "kvm|qemu|vmware|xen|microsoft", "Virtuelle Maschine"),
    ("virt", "lxc|docker", "Container"),
)


def _decode_secret(account: dict) -> tuple[str, str]:
    return crypto.decrypt(account.get("secretEnc") or ""), crypto.decrypt(account.get("passphraseEnc") or "")


# ---------------------------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------------------------

async def probe_ssh(host: str, account: dict) -> dict:
    """Runs the fixed read-only command set over SSH. Returns {"ok", "facts", "error"}."""
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

    facts: dict[str, dict] = {}
    try:
        async with asyncssh.connect(**connect_args) as connection:
            for key_name, label, command in _SSH_COMMANDS:
                try:
                    result = await asyncio.wait_for(
                        connection.run(command, check=False), timeout=_SSH_TIMEOUT
                    )
                except Exception:  # noqa: BLE001 -- one command failing (missing binary, no
                    # permission, timeout) must not abort the probe; the rest is still worth having.
                    continue
                output = (result.stdout or "").strip()
                if output:
                    facts[key_name] = {"label": label, "value": output[:1200]}
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

    # TR-064 works partly without a login, so it runs for AVM hardware regardless.
    if is_fritzbox or system.get("kind") == "router":
        router_account = next((a for a in accounts if a.get("category") in ("login", "router")), None)
        result = await probe_fritzbox(host, router_account)
        if result["ok"]:
            results["tr064"] = result

    for account in accounts:
        category = account.get("category")
        if category == "sshkey" or (category == "login" and (account.get("port") or 0) in (22, 0)):
            if category == "sshkey" or system.get("kind") in ("server", "nas", "vm", "pc", "container"):
                result = await probe_ssh(host, account)
                if result["ok"]:
                    results[f"ssh:{account['label']}"] = result
                elif "ssh" not in results:
                    results[f"ssh:{account['label']}"] = result
        url = account.get("url") or system.get("url")
        if url and category in ("login", "apikey"):
            result = await probe_http(url, account)
            if result["ok"]:
                results[f"http:{account['label']}"] = result

    return {"ran": bool(results), "results": results, "purpose": _derive_purpose(results), "reason": ""}
