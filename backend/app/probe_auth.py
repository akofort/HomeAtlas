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
2. **Every command is read-only**, and every *other* platform's set is non-interactive: no package
   manager, no service control, no redirect, no `sudo`, no RouterOS/ArubaOS/IOS *config*-mode
   command, no `/export show-sensitive`. The one narrow exception is classic ArubaOS-Switch's own
   `enable` (see `probe_ssh_aruba`): on that CLI an SSH session always lands in restricted Operator
   context regardless of the account's own privilege, and Operator context can't run `show running-
   config` at all -- `enable` there only raises the ceiling on which *read* commands are visible,
   it does not open configuration mode (`configure terminal` stays just as banned as everywhere
   else), and nothing after it in the allowlist is anything but another `show`. It is also never
   given a password to answer a Manager-credential prompt with -- a switch that challenges it for
   one is left exactly as it was, not retried with a guessed or reused secret.
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
import logging
import re
import xml.etree.ElementTree as ElementTree
from datetime import datetime

import httpx

from . import crypto, db

# Diagnostic-only -- never used to decide behaviour, just to make an otherwise-invisible fallback
# decision (see `merge_brother_toner_levels`) traceable in the server log. Child of "homeatlas" so
# it inherits main.py's `logging.basicConfig` formatting/level without configuring its own handler.
_logger = logging.getLogger("homeatlas.probe_auth")

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

# Classic ArubaOS-Switch (ProCurve-derived) CLI. Two things make it unable to use the same
# one-exec-channel-per-command model every other platform in this file uses (see the Cisco
# comment below for what that model is):
#
# 1. Every new session -- exec or shell alike -- opens with a mandatory HPE copyright banner
#    ending in "Press any key to continue", which the switch will not go past without an actual
#    keystroke on the channel. `connection.run(command)` hands `command` to the switch as one
#    opaque exec request rather than paced keystrokes typed at a live prompt, so that keypress
#    never actually arrives and the switch closes the channel having processed nothing else in
#    it -- confirmed against real hardware: the banner text itself came back *as* a fact's
#    captured output, meaning none of the folded commands ran, not just the pager-sensitive one.
# 2. Even past the banner, an SSH session on this CLI starts in restricted Operator context
#    ("Switch>"), which can't run "show running-config" (or several of the other facts below) at
#    all -- "enable" is required first, and on a switch with AAA/RADIUS or a separate Manager
#    password configured, that "enable" itself prompts for its own Username/Password apart from
#    the SSH login (confirmed against real hardware) that this module has no business answering:
#    it isn't given a stored Manager credential to answer with (see module docstring point 2), and
#    guessing or reusing the SSH login secret as a manager password would mean silently attempting
#    authentication with a credential the human never authorised for that purpose. So the intended
#    setup is a dedicated SSH login account that already carries Manager rights: `enable` is only
#    even attempted (see `probe_ssh_aruba` below) when the session is still at the Operator prompt
#    after login, without ever supplying a password of its own, and if the switch challenges it for
#    one anyway, that specific fact is skipped with a clear warning rather than typing anything at
#    it. "no page" (paging is on by default here) is sent once per session as well, since -- like
#    "enable" -- it's a per-session setting that doesn't apply to the exec-per-command model either.
_SSH_COMMANDS_ARUBA: tuple[tuple[str, str, str], ...] = (
    ("system", "System", "show system-information"),
    ("vlan", "VLANs", "show vlan"),
    ("vlan_ports", "VLAN-Port-Zuordnung", "show vlan ports all detail"),
    ("neighbors", "Nachbargeräte (LLDP)", "show lldp info remote-device"),
    ("interfaces", "Schnittstellen", "show interfaces brief"),
    # Same reasoning as Mikrotik's "ip_addresses" above -- which subnet(s) this device routes for.
    ("ip_addresses", "IP-Adressen je VLAN", "show ip"),
    ("arp_table", "ARP-Tabelle", "show arp"),
    ("config_export", "Vollständige Konfiguration", "show running-config"),
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

# Embedded switch CLIs (ArubaOS-CX, Cisco IOS, TP-Link JetStream) commonly only run their vendor
# command parser -- and, critically, only honour the pager-disable command folded into the same
# exec payload above -- when the SSH session actually has a pseudo-terminal attached; without one,
# some vendors' sshd either returns nothing at all for these commands or still paginates "show
# running-config" despite "no page"/"no clipaging" having been sent, since paging state is itself
# tied to the (non-existent) tty. RouterOS/Mikrotik is deliberately excluded: it disables paging
# per-command via its own "without-paging" flag rather than a stateful session command, so it never
# needed a pty in the first place, and the plain Linux command set doesn't either. Classic Aruba
# ("aruba") is also excluded -- it never goes through this exec-per-command loop at all, see
# probe_ssh_aruba below, which requests its own pty directly.
_PTY_PLATFORMS = {"arubacx", "cisco", "tplink"}

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


def _bounded_fact(key_name: str, output: str) -> str | None:
    """Truncates one command's output before it's stored as a fact (or, for a binary backup
    that's already past saving, drops it entirely) -- shared by probe_ssh's per-platform exec loop
    and probe_ssh_aruba's interactive session below, so the two never drift on what "too long"
    means for the same fact keys."""
    if not output:
        return None
    if key_name in _BINARY_BACKUP_KEYS:
        if len(output) >= _BINARY_BACKUP_LIMIT:
            return None  # would decode to garbage -- see _BINARY_BACKUP_LIMIT's own comment
        return output[:_BINARY_BACKUP_LIMIT]
    if key_name in _CONFIG_BACKUP_KEYS:
        # A full device config export is the point of collecting it, not a side note -- give it a
        # much wider bound than the other, single-fact commands.
        return output[:60000]
    return output[:1200]


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

# How long a read may wait for the next chunk before an ArubaOS-Switch command is considered
# finished -- stands in for a prompt regex, since the real prompt text is hostname-dependent and
# not known in advance. Kept short: on an interactive pty, output for one command genuinely does
# go quiet the moment the switch is done and waiting for the next line.
_ARUBA_IDLE_READ_SECONDS = 0.6
# Ceiling for the *whole* Aruba session (banner + enable + every command below), not per command --
# one slow/hanging step can only ever cost what's left of this budget, not the full idle window
# again for every fact after it.
_ARUBA_SESSION_TIMEOUT = 45.0
# A short, single-word line ending in '>' or '#' -- ArubaOS-Switch's Operator/Manager prompts.
# Hostnames can't contain spaces; 32 characters covers any realistic device name.
_ARUBA_PROMPT_RE = re.compile(r"^\S{1,32}[>#]\s*$")
_ARUBA_CREDENTIAL_PROMPT_RE = re.compile(r"(username|password)\s*:?\s*$", re.IGNORECASE)


async def _aruba_read_idle(stream, deadline: float) -> str:
    """Reads whatever the switch sends until output goes quiet for `_ARUBA_IDLE_READ_SECONDS`,
    bounded by the absolute `deadline` (a `loop.time()` value) for the whole session."""
    loop = asyncio.get_event_loop()
    chunks: list[str] = []
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            break
        try:
            chunk = await asyncio.wait_for(stream.read(65536), timeout=min(_ARUBA_IDLE_READ_SECONDS, remaining))
        except asyncio.TimeoutError:
            break
        if not chunk:  # remote closed the stream
            break
        chunks.append(chunk)
    return "".join(chunks)


def _aruba_last_line(text: str) -> str:
    lines = [line.strip() for line in text.replace("\r", "").split("\n") if line.strip()]
    return lines[-1] if lines else ""


def _strip_aruba_echo_and_prompt(raw: str, sent_command: str) -> str:
    """A pty session echoes back whatever was typed, and the switch's own prompt reappears once a
    command finishes -- neither belongs in the stored fact. Only strips a leading line that's an
    exact echo of what we sent and a trailing prompt-shaped line, so anything the switch itself
    prints is left alone even if it doesn't match either shape."""
    lines = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if lines and lines[0].strip() == sent_command.strip():
        lines = lines[1:]
    while lines and _ARUBA_PROMPT_RE.match(lines[-1].strip()):
        lines.pop()
    return "\n".join(lines).strip()


async def probe_ssh_aruba(connection, warnings: list[str]) -> dict[str, dict]:
    """Runs `_SSH_COMMANDS_ARUBA` over one persistent interactive shell instead of the one-exec-
    channel-per-command model `probe_ssh` uses for every other platform -- see that constant's own
    comment for why classic ArubaOS-Switch needs this. Never raises: any failure here just means
    fewer (or no) facts, exactly like a failed command does in the generic loop."""
    facts: dict[str, dict] = {}
    loop = asyncio.get_event_loop()
    deadline = loop.time() + _ARUBA_SESSION_TIMEOUT
    try:
        process = await connection.create_process(term_type="vt100")
    except Exception as exc:  # noqa: BLE001 -- channel setup failing must not abort the whole probe
        warnings.append(f"Interaktive Sitzung ließ sich nicht öffnen: {exc}")
        return facts

    async with process:
        try:
            # Dismiss the mandatory copyright banner's "Press any key to continue" -- any byte
            # does, so a bare newline is enough.
            await _aruba_read_idle(process.stdout, deadline)
            process.stdin.write("\n")
            await process.stdin.drain()
            greeting = await _aruba_read_idle(process.stdout, deadline)

            if _aruba_last_line(greeting).endswith(">"):
                # Still at the Operator prompt -- try "enable" once, but never answer a credential
                # prompt with anything: this module is never handed a Manager password to answer
                # with (see module docstring point 2 and _SSH_COMMANDS_ARUBA's own comment), so a
                # switch that challenges "enable" for one is left exactly as it was, with a clear
                # reason logged instead of a silently empty config backup.
                process.stdin.write("enable\n")
                await process.stdin.drain()
                reply = await _aruba_read_idle(process.stdout, deadline)
                if _ARUBA_CREDENTIAL_PROMPT_RE.search(_aruba_last_line(reply)):
                    warnings.append(
                        "„enable“ verlangt eigene Manager-Zugangsdaten, die dieser Zugang nicht "
                        "mitbringt -- auf diesem Switch reicht der hinterlegte Zugang allein nicht "
                        "für „show running-config“ & Co. Ein SSH-Zugang, der schon mit Manager-"
                        "Rechten anmeldet, löst das ohne „enable“."
                    )
                    return facts

            process.stdin.write("no page\n")
            await process.stdin.drain()
            await _aruba_read_idle(process.stdout, deadline)

            for key_name, label, command in _SSH_COMMANDS_ARUBA:
                if loop.time() >= deadline:
                    warnings.append(f"„{label}“ wurde wegen Zeitüberschreitung der Sitzung übersprungen.")
                    continue
                process.stdin.write(command + "\n")
                await process.stdin.drain()
                raw = await _aruba_read_idle(process.stdout, deadline)
                output = _strip_aruba_echo_and_prompt(raw, command)
                bounded = _bounded_fact(key_name, output)
                if bounded is not None:
                    facts[key_name] = {"label": label, "value": bounded}
        except Exception as exc:  # noqa: BLE001 -- a broken session must still return what we have
            warnings.append(f"Interaktive Sitzung abgebrochen: {exc}")

    return facts


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
        "mikrotik": _SSH_COMMANDS_MIKROTIK,
        "arubacx": _SSH_COMMANDS_ARUBA_CX, "cisco": _SSH_COMMANDS_CISCO,
        "tplink": _SSH_COMMANDS_TPLINK,
    }.get(platform, _SSH_COMMANDS)
    # See _PTY_PLATFORMS' own comment -- vt100 is the lowest-common-denominator terminal type every
    # vendor CLI below already understands from a plain SSH client connecting.
    term_type = "vt100" if platform in _PTY_PLATFORMS else None

    facts: dict[str, dict] = {}
    # Per-command failures a human troubleshooting this device would want to know about --
    # surfaced via probe_system's returned dict and, from there, logged against the device by
    # pipeline.py, rather than silently disappearing into the generic "continue" below the way an
    # expected/harmless failure (missing binary, no permission) already does.
    warnings: list[str] = []
    try:
        async with asyncssh.connect(**connect_args) as connection:
            # Classic ArubaOS-Switch never goes through the exec-per-command loop below at all --
            # see _SSH_COMMANDS_ARUBA's own comment for why it needs its own interactive session.
            if platform == "aruba":
                facts = await probe_ssh_aruba(connection, warnings)
            else:
                for key_name, label, command in commands:
                    try:
                        result = await asyncio.wait_for(
                            connection.run(command, check=False, term_type=term_type), timeout=_SSH_TIMEOUT
                        )
                    except asyncio.TimeoutError:
                        warnings.append(
                            f"„{label}“ hat innerhalb von {_SSH_TIMEOUT:.0f} Sekunden nicht geantwortet "
                            "(SSH-Prompt hängt vermutlich an einer Pager- oder Bestätigungsabfrage)."
                        )
                        continue
                    except Exception:  # noqa: BLE001 -- one command failing (missing binary, no
                        # permission) must not abort the probe; the rest is still worth having.
                        continue
                    bounded = _bounded_fact(key_name, (result.stdout or "").strip())
                    if bounded is not None:
                        facts[key_name] = {"label": label, "value": bounded}
    except Exception as exc:  # noqa: BLE001 -- asyncssh raises a wide family of connection errors
        return {"ok": False, "error": f"SSH-Verbindung zu {host}:{port} fehlgeschlagen: {exc}", "facts": {}}

    if not facts:
        error = "Verbindung stand, aber kein Befehl lieferte eine Ausgabe."
        if warnings:
            error += " " + " ".join(warnings)
        return {"ok": False, "error": error, "facts": {}, "warnings": warnings}
    return {"ok": True, "error": "", "facts": facts, "warnings": warnings}


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


def _ha_format_last_triggered(value: str) -> str:
    """Best-effort "DD.MM.YYYY HH:MM" rendering of HA's ISO-8601 `last_triggered` attribute --
    falls back to the raw value on anything that doesn't parse rather than dropping it, since even
    an unparsed timestamp is more useful to someone reading the doc than silence."""
    if not value:
        return ""
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).strftime("%d.%m.%Y %H:%M")
    except ValueError:
        return value


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
                # HA's own automation.* state always carries this attribute (null if it has never
                # fired) -- reading it straight off the state avoids a second per-automation call
                # for something the /api/states response already has.
                last_triggered = attrs.get("last_triggered") or ""
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
                line = f"- {name} ({status}): {description}" if description else f"- {name} ({status})"
                triggered_text = _ha_format_last_triggered(last_triggered)
                if triggered_text:
                    line += f" [zuletzt ausgelöst: {triggered_text}]"
                lines.append(line)

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


async def list_ha_switchables(url: str, account: dict) -> dict:
    """Lists every `switch.*`/`light.*` entity Home Assistant knows about, for resolving a name
    like "Wohnzimmerlicht" to the exact entity_id `switch_admin.ha_set_switch` needs. Read-only --
    one `GET /api/states` call, same as `probe_homeassistant` already makes, just filtered and
    projected differently. Scope matches `switch_admin._HA_ALLOWED_DOMAINS`: only the two domains
    that can actually be flipped stay in the result, so a caller never has to separately learn
    which entities are off-limits."""
    token, _ = _decode_secret(account)
    base_url = (url or "").rstrip("/")
    if not base_url:
        return {"ok": False, "error": "Keine Adresse für Home Assistant hinterlegt.", "entities": []}
    if not token:
        return {"ok": False, "error": "Kein Zugriffstoken hinterlegt.", "entities": []}

    headers = {"Authorization": f"Bearer {token}"}
    try:
        async with httpx.AsyncClient(timeout=_HA_TIMEOUT, verify=False, headers=headers) as client:
            self_check_error = await _ha_self_check(client, base_url)
            if self_check_error:
                return {"ok": False, "error": self_check_error, "entities": []}
            response = await client.get(f"{base_url}/api/states")
            if response.status_code in (401, 403):
                return {"ok": False, "entities": [], "error": (
                    f"Home Assistant hat das Zugriffstoken abgelehnt (HTTP {response.status_code}) "
                    "beim Abruf der Zustände."
                )}
            response.raise_for_status()
            states = response.json()
            if not isinstance(states, list):
                raise ValueError("Unerwartete Antwort (keine Liste).")
    except (httpx.HTTPError, ValueError) as exc:
        return {"ok": False, "error": f"Home Assistant unter {base_url} nicht erreichbar: {exc}", "entities": []}

    entities = [
        {"entityId": s["entity_id"], "name": (s.get("attributes") or {}).get("friendly_name") or s["entity_id"],
         "state": s.get("state", "")}
        for s in states
        if isinstance(s, dict) and s.get("entity_id", "").split(".", 1)[0] in ("switch", "light")
    ]
    return {"ok": True, "error": "", "entities": entities}


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
        toner = supplies["toner_levels"]
        maintenance = supplies["consumables_maintenance"]
        # Fact key "printerSupplies" is kept as-is -- it's what extract_printer_supplies (and, via
        # pipeline._apply_printer_supplies, the toner gauge on the device page) already reads, and
        # it is now toner_levels exclusively rather than a mix of toner and drum/belt readings.
        if toner:
            lines = [f"- {s['name']}: {s['percent']}%" for s in toner]
            facts["printerSupplies"] = {"label": f"Toner-Füllstand ({len(toner)})",
                                        "value": "\n".join(lines)[:5000]}
        if maintenance:
            lines = [f"- {s['name']}: {s['percent']}%" for s in maintenance]
            facts["consumablesMaintenance"] = {"label": f"Wartungsteile ({len(maintenance)})",
                                               "value": "\n".join(lines)[:5000]}

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
_PRINTER_MIB_TYPE_OID = "1.3.6.1.2.1.43.11.1.1.5"   # prtMarkerSuppliesType

# RFC 3805 PrtMarkerSuppliesTypeTC's "toner" value -- used to keep drum/OPC units (9), transfer
# belts (20), waste toner (4), fusers (15), ... out of `parse_printer_mib_maintenance_supplies`'s
# sibling function `merge_brother_toner_levels`/`_standard_mib_toner_fallback` matches by colour
# name instead of this column (see their own docstrings for why), but `consumables_maintenance`
# still needs to know what to leave out of "everything that isn't toner".
_PRINTER_MIB_TYPE_TONER = "3"

# RFC 3805 sentinels specific to prtMarkerSuppliesLevel (the -1/-2/-3 family means something
# slightly different on other Printer-MIB columns, but this is the one relevant here): a negative
# value is a *status code*, never a percentage, and must never be fed into the level/capacity
# division below no matter how "valid-looking" the surrounding data is. Kept only for log
# messages -- the actual skip-negative-values behaviour lives in `_percent_from_level_capacity`
# regardless of whether a given code is in this table or not.
_PRINTER_MIB_LEVEL_STATUS = {"-1": "unbekannt", "-2": "Normal/OK", "-3": "Toner niedrig (Low)"}

# Brother's private enterprise MIB (1.3.6.1.4.1.2435): one plain-integer (0-100) OID per toner
# colour, queried directly rather than walked. (Anzeigename, OID, Suchwort). The search word is
# used to find that colour's own row in the *standard* Printer-MIB table (`prtMarkerSuppliesDescription`
# text is vendor free text but is written in English regardless of the device's UI language, e.g.
# "Magenta Toner Cartridge" -- matching against the German display name would never hit) for
# `merge_brother_toner_levels`'s fallback -- see its own docstring for when and why that fallback
# fires.
_BROTHER_TONER_OIDS: tuple[tuple[str, str, str], ...] = (
    ("Toner Schwarz", "1.3.6.1.4.1.2435.2.3.9.4.2.1.5.5.8.0", "black"),
    ("Toner Magenta", "1.3.6.1.4.1.2435.2.3.9.4.2.1.5.5.9.0", "magenta"),
    ("Toner Cyan", "1.3.6.1.4.1.2435.2.3.9.4.2.1.5.5.10.0", "cyan"),
    ("Toner Gelb", "1.3.6.1.4.1.2435.2.3.9.4.2.1.5.5.11.0", "yellow"),
)


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


def _percent_from_level_capacity(level_raw: str | None, capacity_raw: str | None) -> float | None:
    """0-100 percent from one Printer-MIB row's raw prtMarkerSuppliesLevel/MaxCapacity strings, or
    None when either is missing/unparseable, or Level is negative -- RFC 3805 defines negative
    Level values as status codes (-1 unknown, -2 "Normal/OK" on this device's firmware, -3 "Toner
    niedrig" -- see `_PRINTER_MIB_LEVEL_STATUS`), never a literal reading, so `-3 / capacity * 100`
    must never be computed as if it were one. A non-positive capacity is likewise not a real
    "supply holds this much" figure (0, or RFC 3805's own -1/-2 sentinels on that column) and is
    rejected the same way. Shared by the type-filtered whole-table parse below and Brother's
    per-colour toner fallback, so the two never disagree on what counts as a real reading."""
    if level_raw is None or capacity_raw is None:
        return None
    try:
        level, capacity = int(level_raw), int(capacity_raw)
    except ValueError:
        return None
    if level < 0 or capacity <= 0:
        return None
    return max(0.0, min(100.0, round(level * 100 / capacity, 1)))


def parse_printer_mib_maintenance_supplies(
    descr_text: str, level_text: str, max_text: str, type_text: str,
) -> list[dict]:
    """(name, percent) pairs for every supply the standard Printer-MIB reports that ISN'T toner --
    drums/OPC units, transfer belts, waste-toner boxes, fusers, and so on -- matched by the row
    index shared across the four separate `snmpwalk` outputs (description, level, max capacity,
    type). Optional, supplementary "how worn is this part" context (see `_snmp_printer_supplies`'s
    `consumables_maintenance`) -- unlike toner_levels (see `merge_brother_toner_levels`, which
    matches toner by colour name rather than this column), it is never wired to a "running low,
    reorder" gauge, so a row whose type is unknown/wasn't read at all is kept rather than dropped:
    there is no toner gauge here to accidentally miscolour."""
    descriptions = _parse_printer_mib_walk(descr_text, _PRINTER_MIB_DESCR_OID)
    levels = _parse_printer_mib_walk(level_text, _PRINTER_MIB_LEVEL_OID)
    capacities = _parse_printer_mib_walk(max_text, _PRINTER_MIB_MAX_OID)
    types = _parse_printer_mib_walk(type_text, _PRINTER_MIB_TYPE_OID)

    supplies: list[dict] = []
    for index, level_raw in levels.items():
        if types.get(index) == _PRINTER_MIB_TYPE_TONER:
            continue
        percent = _percent_from_level_capacity(level_raw, capacities.get(index))
        if percent is None:
            continue
        name = descriptions.get(index) or f"Verbrauchsmaterial {index}"
        supplies.append({"name": name, "percent": percent})
    return supplies


def _parse_brother_toner_reply(text: str) -> float | None:
    """Percentage from one Brother `brInfoTonerLevel*`-style OID reply -- a plain `INTEGER: <0-100>`
    `snmpget` reply, not a packed blob. None for anything that isn't a usable in-range integer
    (missing OID, "No Such Object", a negative or >100 value some firmware uses as its own
    not-applicable sentinel). A reply of exactly 0 is still returned here (this function only
    checks "is this a syntactically valid percentage") -- whether 0 should actually be trusted or
    treated as a misread is `merge_brother_toner_levels`'s decision, not this parser's."""
    match = re.search(r"INTEGER:\s*(-?\d+)", text)
    if not match:
        return None
    value = int(match.group(1))
    return float(value) if 0 <= value <= 100 else None


def _describe_level(level_raw: str | None) -> str:
    """Raw prtMarkerSuppliesLevel value plus, for the RFC 3805 status codes, what it actually means
    -- e.g. "-3 (Toner niedrig (Low))" -- so a log line naming it doesn't require looking up
    `_PRINTER_MIB_LEVEL_STATUS` by hand to understand."""
    if level_raw is None:
        return "kein Wert"
    status = _PRINTER_MIB_LEVEL_STATUS.get(level_raw)
    return f"{level_raw} ({status})" if status else level_raw


def _standard_mib_toner_fallback(
    descr_text: str, level_text: str, max_text: str, keyword: str,
) -> tuple[float | None, dict[str, str | None]]:
    """(percent, raw) for the one Printer-MIB supplies-table row whose own description contains
    `keyword` (English colour name, case-insensitive) -- `merge_brother_toner_levels`'s fallback
    when Brother's direct OID for that colour gave nothing trustworthy. Matching by description
    text rather than an exact key is inherently a best guess (`prtMarkerSuppliesDescription` is
    vendor free text -- "Magenta Toner Cartridge", a TN-xxx part number, ...), the same trade-off
    `pipeline._match_printer_supplies` already accepts for Home Assistant sensor names. `raw`
    always carries {"index", "level", "maxCapacity"}, even when no percent could be computed, so
    the exact reading behind a dropped or fallback value is loggable, not just the final number."""
    descriptions = _parse_printer_mib_walk(descr_text, _PRINTER_MIB_DESCR_OID)
    levels = _parse_printer_mib_walk(level_text, _PRINTER_MIB_LEVEL_OID)
    capacities = _parse_printer_mib_walk(max_text, _PRINTER_MIB_MAX_OID)

    index = next((i for i, name in descriptions.items() if keyword.lower() in name.lower()), None)
    if index is None:
        return None, {"index": None, "level": None, "maxCapacity": None}
    raw = {"index": index, "level": levels.get(index), "maxCapacity": capacities.get(index)}
    return _percent_from_level_capacity(raw["level"], raw["maxCapacity"]), raw


def merge_brother_toner_levels(
    readings: dict[str, str], descr_text: str, level_text: str, max_text: str,
) -> list[dict]:
    """Final (name, percent) list for the four Brother toner colours (`_BROTHER_TONER_OIDS`,
    `readings` keyed by the same label each was queried under). The direct per-colour OID wins when
    it gives a usable, *nonzero* reading. When it comes back missing or exactly 0 -- Brother
    firmware is known to occasionally misreport one colour that way even while the other three read
    correctly, which is the concrete bug this exists to fix (Magenta showing as a false 0.0%) --
    the same colour's standard Printer-MIB row is tried instead (`_standard_mib_toner_fallback`,
    matched by colour name, independent of whatever the *other* colours' direct OIDs returned).
    Every fallback decision is logged with the raw SNMP index/level/maxCapacity behind it, so a
    wrong-looking percentage is traceable to the exact reading that produced it rather than only
    visible after the fact in the UI. On devices that don't answer these Brother-private OIDs at
    all (any non-Brother printer), every reading is empty/"No Such Object", `_parse_brother_toner_
    reply` returns None for all four, and this transparently becomes a per-colour version of the
    standard-Printer-MIB read -- the Brother-specific step never has to be skipped explicitly."""
    keywords = {label: keyword for label, _oid, keyword in _BROTHER_TONER_OIDS}
    supplies: list[dict] = []
    for label, raw_text in readings.items():
        percent = _parse_brother_toner_reply(raw_text)
        if percent is None or percent == 0:
            fallback_percent, raw = _standard_mib_toner_fallback(
                descr_text, level_text, max_text, keywords.get(label, label))
            _logger.info(
                "Toner %s: direkte Brother-OID lieferte %s -- Fallback über Printer-MIB "
                "(Index=%s, Level=%s, MaxCapacity=%s) -> %s",
                label, "keinen Wert" if percent is None else "0",
                raw["index"], _describe_level(raw["level"]), raw["maxCapacity"],
                "kein Wert" if fallback_percent is None else f"{fallback_percent}%",
            )
            # Always overwritten, never merely "if it improves on the old value" -- an untrusted 0
            # from the direct OID must not survive as the final answer just because the fallback
            # also came up empty; "no data" (None, dropped below) beats a value already known to be
            # unreliable.
            percent = fallback_percent
        if percent is not None:
            supplies.append({"name": label, "percent": percent})
    return supplies


async def _snmp_printer_supplies(target: str, community: str) -> dict[str, list[dict]]:
    """Returns {"toner_levels": [...], "consumables_maintenance": [...]}. toner_levels always goes
    through the per-colour Brother-OID-with-Printer-MIB-fallback merge (`merge_brother_toner_
    levels`) -- Brother's private OIDs are harmless no-ops on non-Brother hardware (an unanswered
    OID falls straight through to that same colour's standard-MIB row), so this one path covers
    both cases rather than an all-or-nothing "try the whole standard table, else try Brother
    wholesale" that let one bad colour (Magenta reading 0%) hide the other three, or a bad standard
    row hide an otherwise-fine Brother reading. consumables_maintenance has no vendor-specific
    fallback -- drum/belt wear is supplementary context, not worth a private-OID effort the way
    toner (the thing that actually blocks printing) is."""
    descr = await _snmp_run("snmpwalk", "-v2c", "-c", community, "-t", "3", "-r", "1", "-O", "n",
                            target, _PRINTER_MIB_DESCR_OID)
    level = await _snmp_run("snmpwalk", "-v2c", "-c", community, "-t", "3", "-r", "1", "-O", "n",
                            target, _PRINTER_MIB_LEVEL_OID)
    maxcap = await _snmp_run("snmpwalk", "-v2c", "-c", community, "-t", "3", "-r", "1", "-O", "n",
                             target, _PRINTER_MIB_MAX_OID)
    type_ = await _snmp_run("snmpwalk", "-v2c", "-c", community, "-t", "3", "-r", "1", "-O", "n",
                            target, _PRINTER_MIB_TYPE_OID)

    maintenance = parse_printer_mib_maintenance_supplies(descr, level, maxcap, type_)

    readings = {
        label: await _snmp_run("snmpget", "-v2c", "-c", community, "-t", "3", "-r", "1", target, oid)
        for label, oid, _keyword in _BROTHER_TONER_OIDS
    }
    toner = merge_brother_toner_levels(readings, descr, level, maxcap)

    return {"toner_levels": toner, "consumables_maintenance": maintenance}


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
