"""Write-capable remote administration -- the counterpart `probe_auth.py` explicitly is not.

Everything here changes something on a remote device (installs a key, opens an interactive shell,
starts/stops a container or Proxmox guest over SSH, reboots a host) or is meant only to feed such
an action. `probe_auth.py`'s entire reason to exist is to be provably read-only; mixing write paths
into it would make that claim false. So this module stands apart, and never imports from
`probe_auth.py` (nor is it imported by it) even though the SSH connection setup below is
near-identical -- the duplication is deliberate, not an oversight: `probe_auth.py`'s import graph
must never touch a module that can write to a device. `reboot_fritzbox` is the one function here
that writes over HTTP (a TR-064 SOAP action) rather than SSH -- same duplication-over-import
reasoning applies to its overlap with `probe_auth.probe_fritzbox`'s read-only GetInfo calls.

Reachable only from `main.py`'s admin-gated REST/WebSocket routes. Never imported by `tools.py`
(the LLM's tool-calling surface) -- a human clicking a button in the browser is the only caller
these functions may ever have. If a future change adds an import from `tools.py` here, that is the
bug, not a refactor to build on.

Host keys are deliberately not verified (`known_hosts=None`), same stated invariant as
`probe_auth.py`: HomeAtlas has no trust store, and refusing to connect to every device on first
contact would make the feature useless on the very network it documents.
"""
from __future__ import annotations

import shlex

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from . import crypto

_SSH_TIMEOUT = 15.0
_AUTHORIZED_KEYS_PATH = ".ssh/authorized_keys"
_SSH_DIR_PATH = ".ssh"

# Same allowlist discipline as probe_auth._SSH_COMMANDS, just for a write action: this is the
# only place the three literals below are ever chosen from, never free text.
_DOCKER_ACTIONS = ("start", "stop", "restart")

# Duplicate of probe_auth._TR064_PORT -- see module docstring for why this file never imports
# probe_auth.
_TR064_PORT = 49000


def generate_keypair(comment: str = "") -> tuple[str, str]:
    """Ed25519 keypair. Returns (private key as OpenSSH PEM text, public key as an
    'ssh-ed25519 <base64> <comment>' line ready to drop into authorized_keys). No passphrase on
    the generated key -- the private key is already encrypted at rest via crypto.py (same as any
    other stored secret), and a second passphrase the deploy flow would then also have to carry
    around adds friction without adding real protection here."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_line = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode()
    if comment:
        public_line = f"{public_line} {comment}"
    return private_pem, public_line


def _decode_secret(account: dict) -> tuple[str, str]:
    """Local copy of probe_auth._decode_secret's logic -- see module docstring for why this isn't
    a shared import."""
    return crypto.decrypt(account.get("secretEnc") or ""), crypto.decrypt(account.get("passphraseEnc") or "")


def _docker_error(stderr: str, username: str) -> str:
    """`docker ps`/`docker <action>` over SSH fails exactly one common way on a household NAS or
    Pi: the SSH user isn't in the `docker` group, so the CLI can't reach the socket. Docker's own
    message for that ("permission denied while trying to connect to the Docker daemon socket")
    is accurate but doesn't say what to do about it -- and unlike a wrong password or an
    unreachable host, this one has one well-known, one-line fix worth spelling out."""
    text = stderr.strip()
    if "permission denied" in text.lower() and "docker.sock" in text.lower():
        return (
            f"Der Benutzer „{username}“ hat keinen Zugriff auf den Docker-Socket auf diesem Gerät. "
            f"Auf dem Zielgerät einmal ausführen: sudo usermod -aG docker {username} -- danach neu "
            "anmelden (SSH-Verbindung trennen und neu aufbauen), damit die Gruppenmitgliedschaft wirkt."
        )
    return text or "docker-Befehl fehlgeschlagen."


def _connect_args(host: str, account: dict, port: int = 0) -> dict:
    """Local copy of probe_auth.probe_ssh's connection setup -- same key-vs-password branching,
    same `known_hosts=None`. See module docstring for why this is duplicated, not imported."""
    import asyncssh

    secret, passphrase = _decode_secret(account)
    username = (account.get("username") or "root").strip()
    resolved_port = port or int(account.get("port") or 0) or 22
    is_key = (account.get("category") == "sshkey") or "PRIVATE KEY" in secret

    connect_args: dict = {
        "host": host, "port": resolved_port, "username": username,
        "known_hosts": None, "connect_timeout": 10,
    }
    if is_key:
        connect_args["client_keys"] = [asyncssh.import_private_key(secret, passphrase or None)]
        connect_args["password"] = None
    else:
        connect_args["password"] = secret
        connect_args["client_keys"] = []
    return connect_args


async def deploy_public_key(host: str, account: dict, public_key: str, port: int = 0) -> dict:
    """Logs in with `account` (an existing, already-trusted credential -- password or another
    key), then read-modify-write appends `public_key` to ~/.ssh/authorized_keys via SFTP.
    Idempotent: {"ok": True, "changed": False} if the exact line is already present. Creates
    ~/.ssh (0700) if missing, sets authorized_keys to 0600. Never a blind overwrite -- the
    existing file (if any) is read first and the new line is appended to it, never replacing it.
    Returns {"ok", "changed", "error"}, never raises -- same posture as probe_auth's probe_*
    functions, since a failed deploy is an expected, reportable outcome, not a bug."""
    try:
        import asyncssh
    except ImportError:
        return {"ok": False, "changed": False, "error": "asyncssh ist nicht installiert."}

    public_key = public_key.strip()
    try:
        connect_args = _connect_args(host, account, port)
    except (ValueError, KeyError) as exc:
        return {"ok": False, "changed": False, "error": f"Der hinterlegte Zugang ließ sich nicht lesen: {exc}"}

    try:
        async with asyncssh.connect(**connect_args) as connection:
            async with connection.start_sftp_client() as sftp:
                if not await sftp.exists(_SSH_DIR_PATH):
                    await sftp.makedirs(_SSH_DIR_PATH, exist_ok=True)
                    await sftp.chmod(_SSH_DIR_PATH, 0o700)

                existing = ""
                if await sftp.exists(_AUTHORIZED_KEYS_PATH):
                    async with sftp.open(_AUTHORIZED_KEYS_PATH, "r") as f:
                        existing = await f.read()

                if any(line.strip() == public_key for line in existing.splitlines()):
                    return {"ok": True, "changed": False, "error": ""}

                new_content = existing if (not existing or existing.endswith("\n")) else existing + "\n"
                new_content += public_key + "\n"
                async with sftp.open(_AUTHORIZED_KEYS_PATH, "w") as f:
                    await f.write(new_content)
                await sftp.chmod(_AUTHORIZED_KEYS_PATH, 0o600)
                return {"ok": True, "changed": True, "error": ""}
    except Exception as exc:  # noqa: BLE001 -- a wide family of connection/SFTP errors is expected
        # (wrong password, host unreachable, no SFTP subsystem); report it, don't crash the caller.
        return {"ok": False, "changed": False, "error": f"Verbindung zu {host} fehlgeschlagen: {exc}"}


async def open_ssh_pty(host: str, account: dict, port: int = 0, cols: int = 80, rows: int = 24):
    """Opens an interactive PTY session for the WebSocket relay in main.py to consume. Unlike
    probe_auth's probe_ssh, this RAISES on failure -- there is exactly one caller (the WS route)
    and it needs the exception text to report back over the socket, not a swallowed {"ok": False}.

    Returns (connection, process); the caller owns closing both.

    `encoding=None` is required so stdin/stdout/stderr are bytes, not str -- a multibyte UTF-8
    character can otherwise split across two reads and corrupt in transit."""
    import asyncssh

    connect_args = _connect_args(host, account, port)
    connection = await asyncssh.connect(**connect_args)
    try:
        process = await connection.create_process(
            term_type="xterm-256color", term_size=(cols, rows), encoding=None,
        )
    except Exception:
        connection.close()
        raise
    return connection, process


async def list_remote_containers(host: str, account: dict, port: int = 0) -> dict:
    """Docker containers on a remote host, reached over SSH with a stored credential -- for the
    container picker in the UI when controlling containers on hosts other than the one HomeAtlas
    itself runs on. Structured, unlike probe_auth's existing 'docker' fact (an opaque text blob
    meant for a human to read, not for code to parse)."""
    import asyncssh

    try:
        connect_args = _connect_args(host, account, port)
    except (ValueError, KeyError) as exc:
        return {"ok": False, "error": f"Der hinterlegte Zugang ließ sich nicht lesen: {exc}", "containers": []}

    command = "docker ps -a --format '{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}'"
    try:
        async with asyncssh.connect(**connect_args) as connection:
            result = await connection.run(command, check=False)
    except Exception as exc:  # noqa: BLE001 -- connection errors are an expected, reportable outcome
        return {"ok": False, "error": f"Verbindung zu {host} fehlgeschlagen: {exc}", "containers": []}

    if result.exit_status != 0:
        return {"ok": False, "error": _docker_error(result.stderr or "", connect_args["username"]), "containers": []}

    containers = []
    for line in (result.stdout or "").splitlines():
        parts = line.split("\t")
        if len(parts) == 5:
            containers.append({
                "id": parts[0], "name": parts[1], "image": parts[2],
                "state": parts[3], "status": parts[4],
            })
    return {"ok": True, "error": "", "containers": containers}


async def remote_container_logs(host: str, account: dict, container_id: str, port: int = 0, tail: int = 200) -> dict:
    """The last `tail` lines of a remote container's Docker logs, fetched once over SSH rather
    than followed live -- an ordinary `connection.run()` (request/response) is enough for that and
    avoids building a second streaming/relay path next to the local `docker_admin.stream_logs`
    one, which talks to the Docker socket directly and has no SSH equivalent here."""
    import asyncssh

    try:
        connect_args = _connect_args(host, account, port)
    except (ValueError, KeyError) as exc:
        return {"ok": False, "error": f"Der hinterlegte Zugang ließ sich nicht lesen: {exc}", "text": ""}

    command = f"docker logs --tail {int(tail)} {shlex.quote(container_id)} 2>&1"
    try:
        async with asyncssh.connect(**connect_args) as connection:
            result = await connection.run(command, check=False)
    except Exception as exc:  # noqa: BLE001 -- connection errors are an expected, reportable outcome
        return {"ok": False, "error": f"Verbindung zu {host} fehlgeschlagen: {exc}", "text": ""}

    if result.exit_status != 0:
        return {"ok": False, "error": _docker_error(result.stdout or "", connect_args["username"]), "text": ""}
    return {"ok": True, "error": "", "text": result.stdout or "(keine Ausgabe)"}


def _parse_pct_list(text: str) -> list[dict]:
    """LXC containers from `pct list`'s own table (`VMID  Status  [Lock]  Name` -- the Lock column
    only appears when a guest currently has one). Column count therefore varies, so this reads the
    first token as VMID, the second as Status, and the *last* as Name rather than assuming a fixed
    width -- LXC hostnames don't contain spaces, so "last token" is always the name regardless of
    whether Lock was present. `node` is left empty -- `pct list` never names the local node, unlike
    the REST listing in proxmox_probe.list_guests -- so the frontend's node-dependent actions
    (web console) stay disabled for SSH-sourced entries; start/stop/restart and `pct exec`-based
    logs don't need a node name, only the vmid."""
    containers = []
    for line in text.splitlines()[1:]:  # [0] is the header row
        parts = line.split()
        if len(parts) < 3 or not parts[0].isdigit():
            continue
        vmid, status, name = parts[0], parts[1], parts[-1]
        containers.append({
            # ":" not "/" -- see proxmox_probe.list_guests' matching comment.
            "id": f"lxc:{vmid}", "name": name, "image": "LXC-Container",
            "state": "running" if status == "running" else "stopped", "status": status,
            "ip": "", "node": "", "vmid": vmid, "kind": "container",
        })
    return containers


def _parse_qm_list(text: str) -> list[dict]:
    """VMs from `qm list`'s own fixed-column table: VMID, Name, Status, Mem(MB), Bootdisk(GB), PID.
    `node` is left empty -- see `_parse_pct_list`'s docstring for why."""
    containers = []
    for line in text.splitlines()[1:]:  # [0] is the header row
        parts = line.split()
        if len(parts) < 3 or not parts[0].isdigit():
            continue
        vmid, name, status = parts[0], parts[1], parts[2]
        containers.append({
            # ":" not "/" -- see proxmox_probe.list_guests' matching comment.
            "id": f"qemu:{vmid}", "name": name, "image": "VM (QEMU/KVM)",
            "state": "running" if status == "running" else "stopped", "status": status,
            "ip": "", "node": "", "vmid": vmid, "kind": "vm",
        })
    return containers


async def list_remote_proxmox_guests(host: str, account: dict, port: int = 0) -> dict:
    """LXC containers (`pct list`) and VMs (`qm list`) on a Proxmox host, reached over SSH with a
    stored credential -- the SSH fallback for main.py's `list_remote_containers` route when
    `proxmox_probe.list_guests`'s REST call fails (or no Proxmox API token is stored at all, only
    an SSH login). Deliberately never `docker ps` -- a Proxmox host manages VMs/containers through
    `pct`/`qm`, not Docker, and has no Docker CLI installed at all; that mismatch is exactly the bug
    this function exists to avoid ("bash: line 1: docker: command not found")."""
    import asyncssh

    try:
        connect_args = _connect_args(host, account, port)
    except (ValueError, KeyError) as exc:
        return {"ok": False, "error": f"Der hinterlegte Zugang ließ sich nicht lesen: {exc}", "containers": []}

    try:
        async with asyncssh.connect(**connect_args) as connection:
            lxc_result = await connection.run("pct list", check=False)
            vm_result = await connection.run("qm list", check=False)
    except Exception as exc:  # noqa: BLE001 -- connection errors are an expected, reportable outcome
        return {"ok": False, "error": f"Verbindung zu {host} fehlgeschlagen: {exc}", "containers": []}

    if lxc_result.exit_status != 0 and vm_result.exit_status != 0:
        stderr = (lxc_result.stderr or vm_result.stderr or "").strip()
        return {"ok": False, "containers": [], "error": (
            stderr or "„pct list“/„qm list“ fehlgeschlagen -- ist dies wirklich ein Proxmox-Host?"
        )}

    containers = (
        (_parse_pct_list(lxc_result.stdout or "") if lxc_result.exit_status == 0 else [])
        + (_parse_qm_list(vm_result.stdout or "") if vm_result.exit_status == 0 else [])
    )
    return {"ok": True, "error": "", "containers": containers}


# Same mapping as proxmox_admin._ACTIONS -- duplicated rather than imported, same reasoning as the
# rest of this module (see its docstring): proxmox_admin is itself a write-capable module and this
# file already stands apart from every read-only module it has a counterpart to.
_PROXMOX_GUEST_ACTIONS = {"start": "start", "stop": "shutdown", "restart": "reboot"}


async def run_remote_proxmox_guest_command(host: str, account: dict, kind: str, vmid: str,
                                           action: str, port: int = 0) -> dict:
    """SSH fallback for starting/stopping/restarting one VM or LXC guest -- used when
    proxmox_admin.guest_action's REST call fails, or no Proxmox API-token account is stored at
    all, only an SSH login to the Proxmox host itself. Uses the native `pct`/`qm` subcommands,
    never `docker` -- same reasoning as `list_remote_proxmox_guests`."""
    import asyncssh

    proxmox_action = _PROXMOX_GUEST_ACTIONS.get(action)
    if proxmox_action is None:
        return {"ok": False, "error": f"Unbekannte Aktion '{action}'."}
    try:
        connect_args = _connect_args(host, account, port)
    except (ValueError, KeyError) as exc:
        return {"ok": False, "error": f"Der hinterlegte Zugang ließ sich nicht lesen: {exc}"}

    tool = "pct" if kind == "container" else "qm"
    command = f"{tool} {proxmox_action} {shlex.quote(str(vmid))}"
    try:
        async with asyncssh.connect(**connect_args) as connection:
            result = await connection.run(command, check=False)
    except Exception as exc:  # noqa: BLE001 -- connection errors are an expected, reportable outcome
        return {"ok": False, "error": f"Verbindung zu {host} fehlgeschlagen: {exc}"}

    if result.exit_status != 0:
        return {"ok": False, "error": (result.stderr or f"{command} fehlgeschlagen.").strip()}
    return {"ok": True, "error": ""}


async def run_remote_lxc_journalctl(host: str, account: dict, vmid: str, port: int = 0, lines: int = 200) -> dict:
    """Real system-log lines for one LXC container, via `pct exec <vmid> -- journalctl`. VM-only
    hosts have no equivalent here -- a VM has its own separate kernel, so the Proxmox host cannot
    read its journal without a guest agent, unlike an LXC container, which shares the host kernel
    and can be entered directly. See proxmox_probe.guest_task_log for the REST-only alternative
    that works for both VMs and LXC (Proxmox's own task history, not application/system output)."""
    import asyncssh

    try:
        connect_args = _connect_args(host, account, port)
    except (ValueError, KeyError) as exc:
        return {"ok": False, "error": f"Der hinterlegte Zugang ließ sich nicht lesen: {exc}", "text": ""}

    command = f"pct exec {shlex.quote(str(vmid))} -- journalctl -n {int(lines)} --no-pager"
    try:
        async with asyncssh.connect(**connect_args) as connection:
            result = await connection.run(command, check=False)
    except Exception as exc:  # noqa: BLE001 -- connection errors are an expected, reportable outcome
        return {"ok": False, "error": f"Verbindung zu {host} fehlgeschlagen: {exc}", "text": ""}

    if result.exit_status != 0:
        return {"ok": False, "error": (result.stderr or "journalctl fehlgeschlagen -- läuft der Container?").strip(),
                "text": ""}
    return {"ok": True, "error": "", "text": result.stdout or "(keine Ausgabe)"}


async def run_remote_docker_command(host: str, account: dict, action: str, container_id: str, port: int = 0) -> dict:
    """`action` must be one of `_DOCKER_ACTIONS` -- hardcoded, never taken from free text, same
    allowlist discipline as probe_auth's `_SSH_COMMANDS`. `container_id` is always shell-quoted."""
    import asyncssh

    if action not in _DOCKER_ACTIONS:
        return {"ok": False, "error": f"Unbekannte Aktion '{action}'."}
    try:
        connect_args = _connect_args(host, account, port)
    except (ValueError, KeyError) as exc:
        return {"ok": False, "error": f"Der hinterlegte Zugang ließ sich nicht lesen: {exc}"}

    command = f"docker {action} {shlex.quote(container_id)}"
    try:
        async with asyncssh.connect(**connect_args) as connection:
            result = await connection.run(command, check=False)
    except Exception as exc:  # noqa: BLE001 -- connection errors are an expected, reportable outcome
        return {"ok": False, "error": f"Verbindung zu {host} fehlgeschlagen: {exc}"}

    if result.exit_status != 0:
        return {"ok": False, "error": _docker_error(result.stderr or "", connect_args["username"])}
    return {"ok": True, "error": ""}


async def open_remote_docker_exec(host: str, account: dict, container_id: str, cmd: str = "/bin/sh",
                                   port: int = 0, cols: int = 80, rows: int = 24):
    """Interactive console for a container on a *remote* host, reached over SSH. Rides the exact
    same SSH-PTY machinery as `open_ssh_pty` -- notably lower risk than the local docker_admin
    exec hijack, since it never needs raw HTTP/1.1 framing over a Unix socket, just an ordinary
    interactive SSH command. Raises on failure, same as `open_ssh_pty`; caller owns closing both
    returned objects."""
    import asyncssh

    connect_args = _connect_args(host, account, port)
    connection = await asyncssh.connect(**connect_args)
    command = f"docker exec -it {shlex.quote(container_id)} {shlex.quote(cmd)}"
    try:
        process = await connection.create_process(
            command, term_type="xterm-256color", term_size=(cols, rows), encoding=None,
        )
    except Exception:
        connection.close()
        raise
    return connection, process


async def reboot_host(host: str, account: dict, port: int = 0) -> dict:
    """Generic Linux reboot over SSH -- for any device kind that isn't a router/FRITZ!Box (see
    `reboot_fritzbox` for that path) and isn't itself modeled as a Docker container or Proxmox
    guest (those have their own, more specific restart actions above). Tries passwordless sudo
    first (the common case for a non-root admin login), falling back to a bare `reboot` (works
    when the account already IS root, the common case for a home-lab NAS/Pi login). `sudo -n`
    fails immediately rather than waiting on a password prompt it can never receive over a
    non-interactive SSH command, so this never hangs until the connection's own timeout."""
    import asyncssh

    try:
        connect_args = _connect_args(host, account, port)
    except (ValueError, KeyError) as exc:
        return {"ok": False, "error": f"Der hinterlegte Zugang ließ sich nicht lesen: {exc}"}

    command = "sudo -n reboot 2>/dev/null || reboot"
    try:
        async with asyncssh.connect(**connect_args) as connection:
            result = await connection.run(command, check=False)
    except Exception as exc:  # noqa: BLE001 -- connection errors are an expected, reportable outcome
        return {"ok": False, "error": f"Verbindung zu {host} fehlgeschlagen: {exc}"}

    if result.exit_status != 0:
        return {"ok": False, "error": (result.stderr or "reboot fehlgeschlagen.").strip()}
    return {"ok": True, "error": ""}


async def reboot_fritzbox(host: str, account: dict, port: int = 0) -> dict:
    """Reboots an AVM FRITZ!Box (or another TR-064-capable router) via the DeviceConfig:1#Reboot
    SOAP action -- the one write call this module makes over HTTP rather than SSH, since a router
    in a home network is essentially never reachable over SSH. Same credential shape and Digest
    auth as probe_auth.probe_fritzbox's read-only GetInfo call, duplicated rather than imported
    for the same reason as the SSH connection setup above: this module never imports probe_auth.
    `port` is accepted for signature symmetry with every other function here but ignored -- TR-064
    is always on 49000, never the account's own `port` field (that's the login's SSH/HTTP port,
    a different, unrelated setting)."""
    secret, _ = _decode_secret(account)
    username = (account.get("username") or "").strip()
    envelope = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
        '<u:Reboot xmlns:u="urn:dslforum-org:service:DeviceConfig:1" />'
        "</s:Body></s:Envelope>"
    )
    base = f"http://{host}:{_TR064_PORT}"
    try:
        async with httpx.AsyncClient(timeout=_SSH_TIMEOUT, auth=httpx.DigestAuth(username, secret)) as client:
            response = await client.post(
                f"{base}/upnp/control/deviceconfig",
                content=envelope.encode(),
                headers={
                    "Content-Type": 'text/xml; charset="utf-8"',
                    "SoapAction": "urn:dslforum-org:service:DeviceConfig:1#Reboot",
                },
            )
        if response.status_code >= 400:
            return {"ok": False, "error": f"TR-064-Neustart fehlgeschlagen (HTTP {response.status_code})."}
        return {"ok": True, "error": ""}
    except httpx.HTTPError as exc:
        return {"ok": False, "error": f"Verbindung zu {host} fehlgeschlagen: {exc}"}
