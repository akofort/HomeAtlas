"""Write-capable SSH administration -- the counterpart `probe_auth.py` explicitly is not.

Everything here changes something on a remote device (installs a key, opens an interactive shell,
starts/stops a container over SSH) or is meant only to feed such an action. `probe_auth.py`'s
entire reason to exist is to be provably read-only; mixing write paths into it would make that
claim false. So this module stands apart, and never imports from `probe_auth.py` (nor is it
imported by it) even though the SSH connection setup below is near-identical -- the duplication is
deliberate, not an oversight: `probe_auth.py`'s import graph must never touch a module that can
write to a device.

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

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from . import crypto

_SSH_TIMEOUT = 15.0
_AUTHORIZED_KEYS_PATH = ".ssh/authorized_keys"
_SSH_DIR_PATH = ".ssh"

# Same allowlist discipline as probe_auth._SSH_COMMANDS, just for a write action: this is the
# only place the three literals below are ever chosen from, never free text.
_DOCKER_ACTIONS = ("start", "stop", "restart")


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
