"""Write-capable Docker control -- the counterpart `docker_probe.py` explicitly is not.

The `:ro` flag on the socket bind mount (`docker-compose.yml`) does not block writes over an
already-`connect()`-ed Unix socket -- it only restricts filesystem-level opens on the special file
itself (open-for-write, delete, rename). A connected socket's read()/write() is a separate I/O
path this flag never gated. "Read-only" in `docker_probe.py` has always been application-code
discipline, not an OS-enforced boundary, exactly like `probe_auth.py`'s SSH command allowlist.
This module is that discipline's write-capable counterpart.

Reachable only from `main.py`'s admin-gated routes -- never imported by `tools.py` (the LLM's
tool-calling surface), `pipeline.py`, or `docker_probe.py`. A human clicking a button in the
browser is the only caller these functions may ever have.
"""
from __future__ import annotations

import asyncio
import json
import os
import struct
from dataclasses import dataclass, field

import httpx

_SOCKET = os.environ.get("DOCKER_SOCKET", "/var/run/docker.sock")
_TIMEOUT = httpx.Timeout(15.0, connect=5.0)


async def _get(path: str) -> object:
    transport = httpx.AsyncHTTPTransport(uds=_SOCKET)
    async with httpx.AsyncClient(transport=transport, base_url="http://docker", timeout=_TIMEOUT) as client:
        resp = await client.get(path)
    resp.raise_for_status()
    return resp.json() if resp.content else None


async def _post(path: str, json_body: dict | None = None) -> dict:
    """Returns {"ok", "error"}. Docker's start/stop/restart return 204 (already in the target
    state or now transitioning) or 304 (already there) on success; anything else is reported back
    verbatim rather than raised, since a failed container action is an expected, actionable
    outcome for the admin who clicked the button, not a bug."""
    transport = httpx.AsyncHTTPTransport(uds=_SOCKET)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://docker", timeout=_TIMEOUT) as client:
            resp = await client.post(path, json=json_body)
    except httpx.HTTPError as exc:
        return {"ok": False, "error": f"Docker-API nicht erreichbar: {exc}"}
    if resp.status_code in (200, 204, 304):
        return {"ok": True, "error": ""}
    try:
        detail = resp.json().get("message", resp.text)
    except ValueError:
        detail = resp.text
    return {"ok": False, "error": detail or f"HTTP {resp.status_code}"}


async def start_container(container_id: str) -> dict:
    return await _post(f"/containers/{container_id}/start")


async def stop_container(container_id: str) -> dict:
    return await _post(f"/containers/{container_id}/stop")


async def restart_container(container_id: str) -> dict:
    return await _post(f"/containers/{container_id}/restart")


async def _container_tty(container_id: str) -> bool:
    """GET /containers/{id}/json -> Config.Tty. Determines whether log/attach output needs
    demultiplexing below -- deterministic, not a heuristic sniff of the byte stream."""
    info = await _get(f"/containers/{container_id}/json")
    return bool((info or {}).get("Config", {}).get("Tty"))


class _Demuxer:
    """Docker's non-tty log/attach framing: an 8-byte header (1 byte stream type, 3 bytes
    padding, 4-byte big-endian payload length) followed by that many payload bytes, repeated.
    Stateful because a chunk from `httpx`'s `aiter_bytes()` can split a frame at any byte
    boundary -- a header can arrive split across two reads, and so can a payload."""

    def __init__(self) -> None:
        self._buf = b""

    def feed(self, chunk: bytes) -> bytes:
        self._buf += chunk
        out = bytearray()
        while True:
            if len(self._buf) < 8:
                break
            length = struct.unpack(">I", self._buf[4:8])[0]
            if len(self._buf) < 8 + length:
                break
            out += self._buf[8:8 + length]
            self._buf = self._buf[8 + length:]
        return bytes(out)


async def stream_logs(container_id: str, tail: int = 200):
    """Async generator of decoded text chunks. Unidirectional (server -> client only), so plain
    `httpx.AsyncClient.stream()` is sufficient -- no raw-socket hijacking needed here, unlike
    `open_exec_session` below."""
    is_tty = await _container_tty(container_id)
    demuxer = _Demuxer()
    transport = httpx.AsyncHTTPTransport(uds=_SOCKET)
    params = {"follow": "1", "stdout": "1", "stderr": "1", "tail": str(tail)}
    async with httpx.AsyncClient(transport=transport, base_url="http://docker", timeout=None) as client:
        async with client.stream("GET", f"/containers/{container_id}/logs", params=params) as resp:
            if resp.status_code >= 400:
                yield f"[Log-Abruf fehlgeschlagen: HTTP {resp.status_code}]\n".encode()
                return
            async for chunk in resp.aiter_bytes():
                yield chunk if is_tty else demuxer.feed(chunk)


@dataclass
class ExecSession:
    """Bidirectional handle to a `docker exec` session, backed by the raw hijacked socket
    `open_exec_session` opens. `_pending` holds bytes already read past the HTTP response header
    terminator while parsing the handshake -- often the first prompt bytes -- delivered on the
    first `read()` call so nothing is silently dropped."""

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    exec_id: str
    _pending: bytes = field(default=b"")

    async def read(self, n: int = 4096) -> bytes:
        if self._pending:
            data, self._pending = self._pending[:n], self._pending[n:]
            return data
        return await self.reader.read(n)

    def write(self, data: bytes) -> None:
        self.writer.write(data)

    async def drain(self) -> None:
        await self.writer.drain()

    async def resize(self, cols: int, rows: int) -> None:
        """Docker's exec resize is an ordinary POST, not part of the hijacked stream -- a fresh
        short-lived connection, same as start/stop/restart above."""
        await _post(f"/exec/{self.exec_id}/resize?h={rows}&w={cols}")

    def close(self) -> None:
        self.writer.close()


async def _read_http_response_headers(reader: asyncio.StreamReader) -> tuple[int, dict, bytes]:
    """Reads until the header terminator, parses the status line and headers, and returns
    whatever was already read past the terminator alongside them -- that tail is the first bytes
    of the hijacked stream itself, not part of the headers."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = await reader.read(4096)
        if not chunk:
            raise ConnectionError("Docker hat die Verbindung während der Antwort geschlossen.")
        buf += chunk
    head, _, leftover = buf.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = int(lines[0].split(b" ")[1])
    headers = {}
    for line in lines[1:]:
        if b":" in line:
            key, _, value = line.partition(b":")
            headers[key.strip().lower().decode()] = value.strip().decode()
    return status, headers, leftover


async def open_exec_session(container_id: str, cmd: list[str] | None = None) -> ExecSession:
    """The one piece of this module with no precedent elsewhere in the codebase -- see the module
    docstring and the project plan's Risks section. Two-step Docker Engine API dance:

    1. `POST /containers/{id}/exec` with `{"AttachStdin":true,"AttachStdout":true,
       "AttachStderr":true,"Tty":true,"Cmd":cmd}` -- an ordinary request/response, done through
       `_post()`. Returns `{"Id": exec_id}`.
    2. `POST /exec/{exec_id}/start` with `{"Detach":false,"Tty":true}` -- this is the hijack.
       `httpx`'s request/response model cannot represent "read the response headers, then treat
       the same socket as a raw duplex pipe", so this step bypasses it and talks to the Unix
       socket directly.

    Session end: `ExecSession.read()` returning `b""` (EOF) means Docker closed the connection
    because the exec'd process exited -- there is no separate exit-code frame in Tty mode.
    """
    # Step 1 is an ordinary request/response -- httpx is fine here, no hijacking yet. Not routed
    # through `_post()` above since that helper discards the response body, and the `Id` it
    # returns is exactly what step 2 needs.
    transport = httpx.AsyncHTTPTransport(uds=_SOCKET)
    async with httpx.AsyncClient(transport=transport, base_url="http://docker", timeout=_TIMEOUT) as client:
        resp = await client.post(f"/containers/{container_id}/exec", json={
            "AttachStdin": True, "AttachStdout": True, "AttachStderr": True,
            "Tty": True, "Cmd": cmd or ["/bin/sh"],
        })
    resp.raise_for_status()
    exec_id = resp.json()["Id"]

    body = json.dumps({"Detach": False, "Tty": True}).encode()
    reader, writer = await asyncio.open_unix_connection(_SOCKET)
    try:
        writer.write(
            f"POST /exec/{exec_id}/start HTTP/1.1\r\n"
            f"Host: docker\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: Upgrade\r\n"
            f"Upgrade: tcp\r\n\r\n".encode() + body
        )
        await writer.drain()
        status, _headers, leftover = await _read_http_response_headers(reader)
        if status not in (200, 101):
            writer.close()
            raise RuntimeError(f"Docker-Exec-Start fehlgeschlagen: HTTP {status}")
        return ExecSession(reader=reader, writer=writer, exec_id=exec_id, _pending=leftover)
    except Exception:
        writer.close()
        raise
