"""SQLite persistence. One connection per call (short-lived, WAL enabled) rather than a shared
module-level handle -- discovery scans run in worker threads via `asyncio.to_thread` and would
otherwise share a connection across threads.

Column naming is camelCase throughout so rows can be handed to the frontend as-is without a
translation layer; the JSON-typed columns listed in `_JSON_COLUMNS` are transparently
encoded/decoded here so callers only ever see Python dicts/lists.
"""
from __future__ import annotations

import json
import os
import secrets
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

DB_PATH = os.environ.get("HOMEATLAS_DB_PATH", "/data/homeatlas.db")

# Columns stored as JSON text. Kept in one place so `_row` and the writers can't drift apart.
_JSON_COLUMNS = {"openPorts", "services", "extra", "summary", "toolCalls", "tags", "answers",
                 "providerRaw", "monitorPorts"}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_id() -> str:
    return uuid.uuid4().hex


@contextmanager
def _conn() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(DB_PATH, timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def _row(row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    out: dict[str, Any] = {}
    for key in row.keys():
        value = row[key]
        if key in _JSON_COLUMNS:
            try:
                value = json.loads(value) if value else None
            except (json.JSONDecodeError, TypeError):
                value = None
        out[key] = value
    return out


def _rows(rows) -> list[dict]:
    return [r for r in (_row(row) for row in rows) if r is not None]


def _dump(value: Any) -> str | None:
    return None if value is None else json.dumps(value, ensure_ascii=False)


# --------------------------------------------------------------------------------------------
# Schema
# --------------------------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    passwordHash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL,
    displayName TEXT NOT NULL DEFAULT '',
    -- Second factor: the shared TOTP secret, encrypted like every other secret. `totpEnabled`
    -- only flips to 1 after the user has proved a working code, so a half-finished setup can
    -- never lock anyone out.
    totpSecretEnc TEXT NOT NULL DEFAULT '',
    totpEnabled INTEGER NOT NULL DEFAULT 0,
    createdAt TEXT NOT NULL
);

-- Who did what, when. Deliberately includes reads of stored passwords: for a credential store,
-- "someone looked at the router password at 03:12" is exactly the event worth having later.
CREATE TABLE IF NOT EXISTS accessLog (
    id TEXT PRIMARY KEY,
    at TEXT NOT NULL,
    userId TEXT,
    username TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    userAgent TEXT NOT NULL DEFAULT '',
    ok INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_accesslog_at ON accessLog(at DESC);

-- Only status *changes* from the live monitor. Writing every poll would add ~8600 rows per device
-- per day and say nothing; an up/down transition is the thing anyone ever looks for.
CREATE TABLE IF NOT EXISTS monitorEvents (
    id TEXT PRIMARY KEY,
    systemId TEXT NOT NULL,
    at TEXT NOT NULL,
    status TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_monitorevents_system ON monitorEvents(systemId, at DESC);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    userId TEXT NOT NULL,
    expiresAt TEXT NOT NULL
);

-- Long-lived credentials for the MCP server (see mcp_server.py) -- external LLM clients have no
-- browser session to present, so they authenticate with one of these instead. Stored raw, same as
-- session tokens above: server-generated, high-entropy, and a database compromise already means
-- every session and password is exposed too, so hashing here buys nothing sessions don't already
-- forgo.
CREATE TABLE IF NOT EXISTS apiTokens (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    createdAt TEXT NOT NULL,
    lastUsedAt TEXT
);
CREATE INDEX IF NOT EXISTS idx_apitokens_token ON apiTokens(token);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Every documented thing: router, switch, access point, server, container, VM, PC, phone,
-- thermostat, heat pump, ... `kind` drives which documentation chapter it lands in (see docs.py).
CREATE TABLE IF NOT EXISTS systems (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL DEFAULT 'other',
    name TEXT NOT NULL,
    hostname TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    mac TEXT NOT NULL DEFAULT '',
    vendor TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    os TEXT NOT NULL DEFAULT '',
    location TEXT NOT NULL DEFAULT '',
    purpose TEXT NOT NULL DEFAULT '',
    descriptionMd TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL DEFAULT '',
    -- Link to the manufacturer's manual/support page for this exact model. Separate from `url`,
    -- which is the device's own web interface -- when something is broken you often need both.
    docUrl TEXT NOT NULL DEFAULT '',
    -- The household's *own* documentation for this specific instance (a wiki page, runbook,
    -- compose-repo README, ...) -- distinct from docUrl's manufacturer manual, which is the same
    -- for every unit of a model and says nothing about what this particular one is actually for.
    -- Populated automatically from a `Doc:`/`URL:` line in a Proxmox guest's Notes field (see
    -- proxmox_probe.parse_notes) but editable by hand for anything else.
    docLink TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    importance TEXT NOT NULL DEFAULT 'normal',
    parentId TEXT,
    status TEXT NOT NULL DEFAULT 'unknown',
    discovered INTEGER NOT NULL DEFAULT 0,
    confirmed INTEGER NOT NULL DEFAULT 0,
    discoverySource TEXT NOT NULL DEFAULT '',
    -- Stable re-discovery identity, assigned by discovery.py: 'mac:<mac>' where we have one,
    -- 'ip:<addr>' for hosts off the local L2 segment, 'docker:<container-id>'. Empty for
    -- hand-created entries, which fall back to their row id below so they never collide.
    discoveryKey TEXT NOT NULL DEFAULT '',
    -- Live monitoring: polled every few seconds rather than once per scan.
    monitored INTEGER NOT NULL DEFAULT 0,
    monitorPorts TEXT,
    identityKey TEXT GENERATED ALWAYS AS
        (CASE WHEN discoveryKey != '' THEN discoveryKey ELSE 'id:' || id END) VIRTUAL,
    openPorts TEXT,
    services TEXT,
    tags TEXT,
    extra TEXT,
    firstSeen TEXT NOT NULL,
    lastSeen TEXT NOT NULL,
    updatedAt TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_systems_kind ON systems(kind);
CREATE UNIQUE INDEX IF NOT EXISTS idx_systems_identity ON systems(identityKey);

CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    systemId TEXT,
    label TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'login',
    username TEXT NOT NULL DEFAULT '',
    secretEnc TEXT NOT NULL DEFAULT '',
    -- Passphrase for an SSH private key held in secretEnc, encrypted the same way.
    passphraseEnc TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    -- Opt-in, default off: may HomeAtlas use this credential to log in and read? Nothing is ever
    -- used for authenticated probing unless a human explicitly ticks this per credential.
    allowProbe INTEGER NOT NULL DEFAULT 0,
    -- SSH port / target overrides for credentials whose device isn't on the default port.
    port INTEGER NOT NULL DEFAULT 0,
    updatedAt TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_accounts_system ON accounts(systemId);

-- Every version of every documentation page, so a regenerate is never destructive and older
-- states stay reachable. Written before each change, not after -- a snapshot taken afterwards
-- would already be the new text.
CREATE TABLE IF NOT EXISTS docPageVersions (
    id TEXT PRIMARY KEY,
    slug TEXT NOT NULL,
    title TEXT NOT NULL,
    bodyMd TEXT NOT NULL,
    manualMd TEXT NOT NULL DEFAULT '',
    generated INTEGER NOT NULL DEFAULT 1,
    reason TEXT NOT NULL DEFAULT '',
    createdAt TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_docversions_slug ON docPageVersions(slug, createdAt DESC);

-- Backups of a device's own textual configuration (Mikrotik `/export`, Aruba `show
-- running-config`, ...), view-only history modeled on docPageVersions. `content` is encrypted at
-- rest (see probe_auth.persist_config_backups) -- unlike documentation text, a device export can
-- contain secrets (SNMP community strings, RADIUS shared secrets, WiFi keys). Never written back
-- to the device: see the read-only invariant in probe_auth.py's module docstring.
CREATE TABLE IF NOT EXISTS deviceConfigVersions (
    id TEXT PRIMARY KEY,
    systemId TEXT NOT NULL,
    label TEXT NOT NULL,
    content TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    createdAt TEXT NOT NULL
);

-- One row per scan-time failure a device was the subject of -- an SSH timeout, a Proxmox auth
-- error, a monitored device going down, and so on (see pipeline.py/monitor.py's
-- db.add_device_error_event calls). Kept as its own history table, not a field on `systems`,
-- for the same reason deviceConfigVersions is: it is something that accumulates over many scans,
-- not a single current value an upsert would just overwrite. Never contains a secret -- callers
-- pass through whatever error message probe_auth/proxmox_probe/monitor.py already produced for a
-- human to read, none of which include credentials (see those modules' own invariants).
CREATE TABLE IF NOT EXISTS deviceErrorEvents (
    id TEXT PRIMARY KEY,
    systemId TEXT NOT NULL,
    level TEXT NOT NULL DEFAULT 'error',
    message TEXT NOT NULL,
    createdAt TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_errorevents_system ON deviceErrorEvents(systemId, createdAt DESC);
CREATE INDEX IF NOT EXISTS idx_configversions_system ON deviceConfigVersions(systemId, createdAt DESC);

CREATE TABLE IF NOT EXISTS docPages (
    id TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    topic TEXT NOT NULL,
    title TEXT NOT NULL,
    bodyMd TEXT NOT NULL DEFAULT '',
    -- The household's own notes for this chapter. Held in its own column rather than as a marked
    -- region inside bodyMd: generation then cannot damage it by construction, instead of relying
    -- on a parser to find and re-splice a block every time the layout changes.
    manualMd TEXT NOT NULL DEFAULT '',
    intro TEXT NOT NULL DEFAULT '',
    generated INTEGER NOT NULL DEFAULT 1,
    sortOrder INTEGER NOT NULL DEFAULT 0,
    updatedAt TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    startedAt TEXT NOT NULL,
    finishedAt TEXT,
    status TEXT NOT NULL DEFAULT 'running',
    subnets TEXT NOT NULL DEFAULT '',
    progress INTEGER NOT NULL DEFAULT 0,
    phase TEXT NOT NULL DEFAULT '',
    summary TEXT,
    log TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS chats (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL DEFAULT 'Neue Unterhaltung',
    createdAt TEXT NOT NULL,
    updatedAt TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS chatMessages (
    id TEXT PRIMARY KEY,
    chatId TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL DEFAULT '',
    toolCalls TEXT,
    -- Verbatim provider payload for an assistant turn (see llm_providers.ChatResult.provider_raw).
    -- Anthropic validates a signature on the thinking blocks it emits alongside tool calls, so the
    -- next turn has to replay them exactly -- they cannot be rebuilt from `toolCalls`.
    providerRaw TEXT,
    toolCallId TEXT,
    name TEXT,
    createdAt TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chatmsg_chat ON chatMessages(chatId);
"""

# Columns added after the first release. `CREATE TABLE IF NOT EXISTS` does nothing to a table that
# already exists, so an installation that predates a column would keep the old shape and every
# query naming it would fail -- these are applied explicitly on startup.
_ADDED_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("systems", "docUrl", "TEXT NOT NULL DEFAULT ''"),
    ("accounts", "passphraseEnc", "TEXT NOT NULL DEFAULT ''"),
    ("accounts", "allowProbe", "INTEGER NOT NULL DEFAULT 0"),
    ("accounts", "port", "INTEGER NOT NULL DEFAULT 0"),
    ("docPages", "manualMd", "TEXT NOT NULL DEFAULT ''"),
    ("docPageVersions", "manualMd", "TEXT NOT NULL DEFAULT ''"),
    ("users", "totpSecretEnc", "TEXT NOT NULL DEFAULT ''"),
    ("users", "totpEnabled", "INTEGER NOT NULL DEFAULT 0"),
    ("systems", "monitored", "INTEGER NOT NULL DEFAULT 0"),
    ("systems", "monitorPorts", "TEXT"),
    ("systems", "docLink", "TEXT NOT NULL DEFAULT ''"),
)


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    with _conn() as conn:
        conn.executescript(_SCHEMA)
        for table, column, ddl in _ADDED_COLUMNS:
            existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
            if column not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


# --------------------------------------------------------------------------------------------
# Settings -- one JSON blob under a single key, patched wholesale.
# --------------------------------------------------------------------------------------------

DEFAULT_SETTINGS: dict[str, Any] = {
    "homeName": "Mein Zuhause",
    "setupCompleted": False,
    # LLM -- same provider ids/fields as GlucoSphere-Web so the config UI is familiar.
    "llmProvider": "DEEPSEEK",
    "geminiApiKey": "", "geminiModel": "auto",
    "claudeApiKey": "", "claudeModel": "auto", "claudeBaseUrl": "",
    "openAiApiKey": "", "openAiModel": "auto", "openAiBaseUrl": "",
    "deepseekApiKey": "", "deepseekModel": "auto",
    "providerModelCache": {},
    "systemPromptOverride": "",
    # Discovery
    "scanSubnets": [],          # empty -> auto-detected from the host's own interfaces
    "scanTimeoutMs": 700,
    "scanConcurrency": 128,
    "scanEnableMdns": True,
    "scanEnableSsdp": True,
    "scanEnableDocker": True,
    "scanEnableOmada": True,
    "scanEnableProxmox": True,
    "scanEnableAdguard": True,
    "scanEnableHttpBanner": True,
    "scanUseLlm": True,
    "scanExcludeIps": [],
    # Individual hosts outside the scanned subnets -- a router on another segment, a VM behind a
    # bridge. Addresses of hand-created devices are added automatically (see pipeline).
    "scanExtraTargets": [],
    "scanUseCredentials": True,
    "scanAutoEnabled": False,
    "scanAutoIntervalHours": 24,
    "configVersionKeep": 50,
    # Live monitoring
    "monitorEnabled": True,
    "monitorIntervalSeconds": 10,
    "monitorTimeoutMs": 1500,
    # Fallback credential for authenticated probing, used only where a device has no credential of
    # its own. Stored encrypted inside this blob, same as the API keys, and masked by the API.
    "defaultCredentialEnabled": False,
    "defaultCredentialUsername": "",
    "defaultCredentialIsKey": False,
    "defaultCredentialSecretEnc": "",
    "defaultCredentialPassphraseEnc": "",
    "defaultCredentialPort": 0,
    # Names resolved by the DNS self-test. External by design -- resolving only local names would
    # pass even when the forwarder to the internet is broken, which is the common failure.
    "dnsTestNames": ["www.google.com", "heise.de", "github.com"],
}

_SETTINGS_KEY = "app"


def get_settings() -> dict:
    with _conn() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (_SETTINGS_KEY,)).fetchone()
    stored = {}
    if row:
        try:
            stored = json.loads(row["value"])
        except json.JSONDecodeError:
            stored = {}
    return {**DEFAULT_SETTINGS, **stored}


def update_settings(patch: dict) -> dict:
    merged = {**get_settings(), **patch}
    with _conn() as conn:
        conn.execute(
            "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (_SETTINGS_KEY, json.dumps(merged, ensure_ascii=False)),
        )
    return merged


# --------------------------------------------------------------------------------------------
# Users / sessions
# --------------------------------------------------------------------------------------------

_PUBLIC_USER_COLUMNS = "id, username, role, displayName, totpEnabled, createdAt"


def update_user(user_id: str, patch: dict) -> dict | None:
    allowed = ("displayName", "role", "totpSecretEnc", "totpEnabled")
    fields = [f for f in allowed if f in patch]
    if not fields:
        return get_user(user_id)
    assignments = ", ".join(f"{f} = ?" for f in fields)
    values = [(1 if patch[f] else 0) if f == "totpEnabled" else patch[f] for f in fields]
    with _conn() as conn:
        conn.execute(f"UPDATE users SET {assignments} WHERE id = ?", (*values, user_id))
    return get_user(user_id)


def invalidate_user_sessions(user_id: str) -> None:
    """Forces re-login. Used after an admin resets someone's password -- otherwise an already-open
    session keeps working with the old credential, which is not what "reset" is expected to mean."""
    with _conn() as conn:
        conn.execute("DELETE FROM sessions WHERE userId = ?", (user_id,))


def count_users() -> int:
    with _conn() as conn:
        return conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]


def create_user(username: str, password_hash: str, salt: str, role: str, display_name: str = "") -> str:
    user_id = _new_id()
    with _conn() as conn:
        conn.execute(
            "INSERT INTO users(id, username, passwordHash, salt, role, displayName, createdAt) VALUES(?,?,?,?,?,?,?)",
            (user_id, username, password_hash, salt, role, display_name or username, _now()),
        )
    return user_id


def list_users() -> list[dict]:
    with _conn() as conn:
        return _rows(conn.execute(f"SELECT {_PUBLIC_USER_COLUMNS} FROM users ORDER BY createdAt"))


def get_user(user_id: str) -> dict | None:
    with _conn() as conn:
        return _row(conn.execute(f"SELECT {_PUBLIC_USER_COLUMNS} FROM users WHERE id = ?", (user_id,)).fetchone())


def get_user_raw(user_id: str) -> dict | None:
    with _conn() as conn:
        return _row(conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone())


def get_user_by_username_raw(username: str) -> dict | None:
    with _conn() as conn:
        return _row(conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone())


def set_user_password(user_id: str, password_hash: str, salt: str) -> None:
    with _conn() as conn:
        conn.execute("UPDATE users SET passwordHash = ?, salt = ? WHERE id = ?", (password_hash, salt, user_id))


def delete_user(user_id: str) -> None:
    with _conn() as conn:
        conn.execute("DELETE FROM sessions WHERE userId = ?", (user_id,))
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))


def create_db_session(token: str, user_id: str, ttl_seconds: int) -> None:
    expires = (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with _conn() as conn:
        conn.execute("DELETE FROM sessions WHERE expiresAt < ?", (_now(),))
        conn.execute("INSERT INTO sessions(token, userId, expiresAt) VALUES(?,?,?)", (token, user_id, expires))


def get_db_session(token: str) -> dict | None:
    with _conn() as conn:
        return _row(conn.execute(
            "SELECT * FROM sessions WHERE token = ? AND expiresAt > ?", (token, _now())
        ).fetchone())


def delete_db_session(token: str) -> None:
    with _conn() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))


def create_api_token(label: str) -> dict:
    """The raw token is returned here and only here -- the same one-time-reveal shape as the admin
    bootstrap password in auth.py. `list_api_tokens` never selects the `token` column."""
    token_id = _new_id()
    token = secrets.token_urlsafe(32)
    now = _now()
    with _conn() as conn:
        conn.execute(
            "INSERT INTO apiTokens(id, label, token, createdAt, lastUsedAt) VALUES(?,?,?,?,?)",
            (token_id, label, token, now, None),
        )
    return {"id": token_id, "label": label, "token": token, "createdAt": now, "lastUsedAt": None}


def list_api_tokens() -> list[dict]:
    with _conn() as conn:
        return _rows(conn.execute(
            "SELECT id, label, createdAt, lastUsedAt FROM apiTokens ORDER BY createdAt DESC"
        ))


def delete_api_token(token_id: str) -> None:
    with _conn() as conn:
        conn.execute("DELETE FROM apiTokens WHERE id = ?", (token_id,))


def touch_api_token(token: str) -> dict | None:
    """Looked up on every MCP request (see mcp_server.py). Updates `lastUsedAt` on a hit so the
    settings UI can show which tokens are actually in use versus long-forgotten."""
    with _conn() as conn:
        row = _row(conn.execute("SELECT * FROM apiTokens WHERE token = ?", (token,)).fetchone())
        if row is None:
            return None
        now = _now()
        conn.execute("UPDATE apiTokens SET lastUsedAt = ? WHERE id = ?", (now, row["id"]))
        row["lastUsedAt"] = now
        return row


# --------------------------------------------------------------------------------------------
# Systems (the inventory)
# --------------------------------------------------------------------------------------------

_SYSTEM_FIELDS = (
    "kind", "name", "hostname", "ip", "mac", "vendor", "model", "os", "location", "purpose",
    "descriptionMd", "url", "docUrl", "docLink", "notes", "importance", "parentId", "status", "discovered",
    "confirmed", "discoverySource", "discoveryKey", "monitored", "monitorPorts",
    "openPorts", "services", "tags", "extra",
)


def list_systems(kind: str | None = None) -> list[dict]:
    sql = "SELECT * FROM systems"
    params: tuple = ()
    if kind:
        sql += " WHERE kind = ?"
        params = (kind,)
    sql += " ORDER BY CASE importance WHEN 'critical' THEN 0 WHEN 'normal' THEN 1 ELSE 2 END, name COLLATE NOCASE"
    with _conn() as conn:
        return _rows(conn.execute(sql, params))


def get_system(system_id: str) -> dict | None:
    with _conn() as conn:
        return _row(conn.execute("SELECT * FROM systems WHERE id = ?", (system_id,)).fetchone())


def create_system(data: dict) -> dict:
    system_id = data.get("id") or _new_id()
    now = _now()
    values = {f: data.get(f) for f in _SYSTEM_FIELDS}
    with _conn() as conn:
        conn.execute(
            f"INSERT INTO systems(id, {', '.join(_SYSTEM_FIELDS)}, firstSeen, lastSeen, updatedAt) "
            f"VALUES(?, {', '.join('?' * len(_SYSTEM_FIELDS))}, ?, ?, ?)",
            (system_id, *_system_params(values), data.get("firstSeen") or now, data.get("lastSeen") or now, now),
        )
    return get_system(system_id)  # type: ignore[return-value]


def _system_params(values: dict) -> list:
    defaults = {"kind": "other", "name": "Unbenannt", "importance": "normal", "status": "unknown"}
    out = []
    for field in _SYSTEM_FIELDS:
        value = values.get(field)
        if field in _JSON_COLUMNS:
            out.append(_dump(value))
        elif field == "parentId":
            out.append(value or None)
        elif field in ("discovered", "confirmed", "monitored"):
            out.append(1 if value else 0)
        else:
            out.append(defaults.get(field, "") if value in (None, "") else value)
    return out


def update_system(system_id: str, patch: dict) -> dict | None:
    current = get_system(system_id)
    if current is None:
        return None
    fields = [f for f in _SYSTEM_FIELDS if f in patch]
    if fields:
        merged = {**current, **patch}
        params = _system_params({f: merged.get(f) for f in _SYSTEM_FIELDS})
        by_field = dict(zip(_SYSTEM_FIELDS, params))
        assignments = ", ".join(f"{f} = ?" for f in fields)
        with _conn() as conn:
            conn.execute(
                f"UPDATE systems SET {assignments}, updatedAt = ? WHERE id = ?",
                (*[by_field[f] for f in fields], _now(), system_id),
            )
    if patch.get("lastSeen"):
        with _conn() as conn:
            conn.execute("UPDATE systems SET lastSeen = ? WHERE id = ?", (patch["lastSeen"], system_id))
    return get_system(system_id)


def delete_system(system_id: str) -> None:
    with _conn() as conn:
        conn.execute("UPDATE systems SET parentId = NULL WHERE parentId = ?", (system_id,))
        conn.execute("DELETE FROM accounts WHERE systemId = ?", (system_id,))
        conn.execute("DELETE FROM systems WHERE id = ?", (system_id,))


def find_system_by_key(discovery_key: str) -> dict | None:
    if not discovery_key:
        return None
    with _conn() as conn:
        return _row(conn.execute("SELECT * FROM systems WHERE discoveryKey = ?", (discovery_key,)).fetchone())


def find_system_by_mac(mac: str) -> dict | None:
    """The strongest fallback identity there is: a MAC address is stable regardless of which
    source found the device (network sweep, Omada, Proxmox, ...) and regardless of what
    discoveryKey scheme that source happens to use. Needed because a device's *own* discoveryKey
    can legitimately change between scans for reasons that have nothing to do with the device
    changing -- see find_system_by_proxmox below for the concrete case this exists for."""
    mac = (mac or "").strip().lower()
    if not mac:
        return None
    with _conn() as conn:
        return _row(conn.execute(
            "SELECT * FROM systems WHERE mac = ? AND mac != '' LIMIT 1", (mac,)
        ).fetchone())


def find_system_by_proxmox(node: str, vmid: object) -> dict | None:
    """A guest's (node, vmid) pair, read from `extra.proxmox` -- Python-side, like pipeline.py's
    own `_assign_proxmox_parents`/`_link_omada_topology`, since `extra` is opaque JSON to SQLite.

    This exists because proxmox_probe.probe's own discoveryKey is `mac:<mac>` when net0 parses a
    MAC and `proxmox:<node>:<kind>:<vmid>` when it doesn't (see its docstring) -- the *same* guest
    can flip between those two keys across scans (a NIC hot-added, a guest agent detail changes,
    net0's format varies) with nothing about the guest itself having changed. Without this, that
    flip reads as "new device" and duplicates the row instead of updating it.
    """
    if not node or vmid is None:
        return None
    for system in list_systems():
        proxmox = (system.get("extra") or {}).get("proxmox") or {}
        if proxmox.get("node") == node and proxmox.get("vmid") == vmid:
            return system
    return None


def find_system_by_ip_and_hostname(ip: str, hostname: str) -> dict | None:
    """Weak on their own (a DHCP lease can move an IP, a hostname can be reused), but together a
    reasonable fallback identity for a device recorded under one discoveryKey scheme by a human
    (a hand-created row with just an address and a hostname typed in) and found again under a
    different one by a later scan -- a phone rotating its privacy MAC being the common case."""
    ip, hostname = (ip or "").strip(), (hostname or "").strip()
    if not ip or not hostname:
        return None
    with _conn() as conn:
        return _row(conn.execute(
            "SELECT * FROM systems WHERE ip = ? AND hostname = ? AND ip != '' AND hostname != '' LIMIT 1",
            (ip, hostname),
        ).fetchone())


def find_system_for_merge(found: dict) -> dict | None:
    """Beyond `found`'s own exact discoveryKey (and its legacy keys, tried by the caller first),
    look for the same physical device under a different identity scheme entirely -- the case this
    exists for is a device one source only ever saw by IP (no ARP-resolved MAC, e.g. off the local
    L2 segment) that another source -- an API integration -- already knows by MAC, or a Proxmox
    guest whose discoveryKey scheme flipped (see find_system_by_proxmox). Priority order matches
    how trustworthy each identity is on its own: MAC first, then a Proxmox guest's own (node,
    vmid), then IP+hostname together as the weakest-but-still-useful fallback.
    """
    existing = find_system_by_mac(found.get("mac", ""))
    if existing is not None:
        return existing
    proxmox = (found.get("extra") or {}).get("proxmox") or {}
    existing = find_system_by_proxmox(proxmox.get("node", ""), proxmox.get("vmid"))
    if existing is not None:
        return existing
    return find_system_by_ip_and_hostname(found.get("ip", ""), found.get("hostname", ""))


def link_containers_to_host(host_ip: str) -> int:
    """Docker containers are discovered with the scanning host's own IP (see docker_probe.py) but
    no link to the system row that represents that host. Called once per scan to fill that in, so
    the network plan can nest a host's containers under it instead of showing a flat count with no
    owner. Never touches a parentId a human already set by hand."""
    if not host_ip:
        return 0
    with _conn() as conn:
        host = conn.execute(
            "SELECT id FROM systems WHERE ip = ? AND kind NOT IN ('container', 'vm') "
            "ORDER BY CASE kind WHEN 'server' THEN 0 WHEN 'nas' THEN 1 WHEN 'pc' THEN 2 ELSE 3 END LIMIT 1",
            (host_ip,),
        ).fetchone()
        if host is None:
            return 0
        cursor = conn.execute(
            "UPDATE systems SET parentId = ?, updatedAt = ? "
            "WHERE ip = ? AND discoverySource = 'docker' AND (parentId IS NULL OR parentId = '') AND id != ?",
            (host["id"], _now(), host_ip, host["id"]),
        )
        return cursor.rowcount


def upsert_discovered_system(found: dict) -> tuple[dict, bool]:
    """Merges one discovery result into the inventory, keyed on `discoveryKey`. Returns
    (system, created).

    Fields the user has edited by hand are never overwritten: once a row is `confirmed`, discovery
    may only refresh the volatile facts (ip, status, ports, evidence) -- otherwise every rescan
    would wipe the human-written `name`, `location` and `descriptionMd`, which is the actual value
    the app accumulates over time.

    `legacyDiscoveryKeys`, if present, is a list of discoveryKey values a prober used to emit for
    this same device before its key scheme changed (see docker_probe.py's compose-based key). It
    is only ever a lookup fallback -- never written to the row -- so that an installation upgrading
    across the scheme change merges into its existing row instead of duplicating it.

    `importance` gets one narrow exception to "never overwritten once confirmed": a finding that
    says "critical" (currently only proxmox_probe.py, from a guest's own `critical` tag) promotes
    an existing row straight to critical regardless of confirmed state, but never the reverse --
    a rescan where the tag is gone (or was never there) leaves a human-set "critical" alone. Both
    halves matter: promotion has to survive re-confirmation or tagging a VM critical in Proxmox
    would only ever affect brand-new rows, and it has to be one-directional or the *absence* of a
    tag this scan cycle would silently downgrade a device someone deliberately marked by hand.

    Beyond the exact-key (and legacy-key) lookups below, `find_system_for_merge` tries the same
    device under a different identity scheme entirely -- MAC, then Proxmox (node, vmid), then
    IP+hostname, in that priority order -- so a device found this scan via one source (say, an ARP
    sweep, with no resolved MAC) merges into the row an earlier scan already created via another
    (say, Proxmox, keyed by MAC) instead of duplicating it. See its own docstring for why each
    fallback exists.
    """
    existing = find_system_by_key(found.get("discoveryKey", ""))
    if existing is None:
        for legacy_key in found.get("legacyDiscoveryKeys") or ():
            existing = find_system_by_key(legacy_key)
            if existing is not None:
                break
    if existing is None:
        existing = find_system_for_merge(found)
    now = _now()
    if existing is None:
        created = create_system({**found, "discovered": 1, "firstSeen": now, "lastSeen": now})
        return created, True

    volatile = {
        "ip": found.get("ip") or existing["ip"],
        "status": found.get("status") or "online",
        "openPorts": found.get("openPorts"),
        "services": found.get("services"),
        "extra": {**(existing.get("extra") or {}), **(found.get("extra") or {})},
        "lastSeen": now,
        "discoveryKey": found.get("discoveryKey") or existing["discoveryKey"],
    }
    if found.get("importance") == "critical" and existing.get("importance") != "critical":
        volatile["importance"] = "critical"
    if not existing["confirmed"]:
        for field in ("kind", "name", "hostname", "mac", "vendor", "model", "os", "location",
                      "purpose", "descriptionMd", "url", "docUrl", "docLink"):
            value = found.get(field)
            if value:
                volatile[field] = value
    else:
        # Even for confirmed rows, fill fields that are still empty -- adding a MAC, a vendor or a
        # manufacturer manual to a hand-created entry is strictly new information, not an
        # overwrite. `purpose` and `location` are included because a hand-created row usually has
        # only a name, and filling the blanks is the whole point of a rescan.
        for field in ("hostname", "mac", "vendor", "model", "os", "docUrl", "docLink", "purpose", "location"):
            if found.get(field) and not existing.get(field):
                volatile[field] = found[field]
    return update_system(existing["id"], volatile), False  # type: ignore[return-value]


def mark_systems_offline(seen_ids: set[str]) -> None:
    """Everything previously discovered but absent from this scan goes to `offline` -- manually
    created (non-discovered) entries are left alone, since "I documented my heat pump" says
    nothing about whether it answers pings."""
    with _conn() as conn:
        placeholders = ",".join("?" * len(seen_ids)) if seen_ids else "''"
        conn.execute(
            f"UPDATE systems SET status = 'offline' WHERE discovered = 1 AND id NOT IN ({placeholders})",
            tuple(seen_ids),
        )


# --------------------------------------------------------------------------------------------
# Accounts (credentials). `secretEnc` is written/read encrypted -- see crypto.py.
# --------------------------------------------------------------------------------------------

def list_accounts(system_id: str | None = None) -> list[dict]:
    sql = "SELECT * FROM accounts"
    params: tuple = ()
    if system_id:
        sql += " WHERE systemId = ?"
        params = (system_id,)
    sql += " ORDER BY label COLLATE NOCASE"
    with _conn() as conn:
        return _rows(conn.execute(sql, params))


def get_account(account_id: str) -> dict | None:
    with _conn() as conn:
        return _row(conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone())


def create_account(data: dict) -> dict:
    account_id = _new_id()
    with _conn() as conn:
        conn.execute(
            "INSERT INTO accounts(id, systemId, label, category, username, secretEnc, passphraseEnc, "
            "url, notes, allowProbe, port, updatedAt) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                account_id, data.get("systemId") or None, data.get("label") or "Zugang",
                data.get("category") or "login", data.get("username") or "", data.get("secretEnc") or "",
                data.get("passphraseEnc") or "", data.get("url") or "", data.get("notes") or "",
                1 if data.get("allowProbe") else 0, int(data.get("port") or 0), _now(),
            ),
        )
    return get_account(account_id)  # type: ignore[return-value]


def update_account(account_id: str, patch: dict) -> dict | None:
    allowed = ("systemId", "label", "category", "username", "secretEnc", "passphraseEnc",
               "url", "notes", "allowProbe", "port")
    fields = [f for f in allowed if f in patch]
    if not fields:
        return get_account(account_id)
    assignments = ", ".join(f"{f} = ?" for f in fields)

    def coerce(field: str):
        if field == "systemId":
            return patch[field] or None
        if field == "allowProbe":
            return 1 if patch[field] else 0
        if field == "port":
            return int(patch[field] or 0)
        return patch[field]

    values = [coerce(f) for f in fields]
    with _conn() as conn:
        conn.execute(f"UPDATE accounts SET {assignments}, updatedAt = ? WHERE id = ?", (*values, _now(), account_id))
    return get_account(account_id)


def list_probe_accounts(system_id: str) -> list[dict]:
    """Credentials a human explicitly cleared for authenticated read-only probing of this device."""
    with _conn() as conn:
        return _rows(conn.execute(
            "SELECT * FROM accounts WHERE systemId = ? AND allowProbe = 1 ORDER BY category, label",
            (system_id,),
        ))


def delete_account(account_id: str) -> None:
    with _conn() as conn:
        conn.execute("DELETE FROM accounts WHERE id = ?", (account_id,))


# --------------------------------------------------------------------------------------------
# Documentation pages
# --------------------------------------------------------------------------------------------

def list_doc_pages() -> list[dict]:
    with _conn() as conn:
        return _rows(conn.execute("SELECT * FROM docPages ORDER BY sortOrder, title COLLATE NOCASE"))


def get_doc_page(slug: str) -> dict | None:
    with _conn() as conn:
        return _row(conn.execute("SELECT * FROM docPages WHERE slug = ?", (slug,)).fetchone())


_DOC_VERSION_KEEP = 50


def snapshot_doc_page(slug: str, reason: str) -> None:
    """Records the CURRENT content before it is replaced. Called by every writer -- a snapshot
    taken after the write would store the new text and lose exactly what it was meant to keep."""
    page = get_doc_page(slug)
    if page is None or not (page["bodyMd"].strip() or (page["manualMd"] or "").strip()):
        return
    with _conn() as conn:
        conn.execute(
            "INSERT INTO docPageVersions(id, slug, title, bodyMd, manualMd, generated, reason, createdAt) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (_new_id(), slug, page["title"], page["bodyMd"], page["manualMd"] or "",
             page["generated"], reason, _now()),
        )
        # Unbounded history would grow by a full copy of every chapter on every scan.
        conn.execute(
            "DELETE FROM docPageVersions WHERE slug = ? AND id NOT IN "
            "(SELECT id FROM docPageVersions WHERE slug = ? ORDER BY createdAt DESC, rowid DESC LIMIT ?)",
            (slug, slug, _DOC_VERSION_KEEP),
        )


def list_doc_versions(slug: str) -> list[dict]:
    with _conn() as conn:
        return _rows(conn.execute(
            "SELECT id, slug, title, generated, reason, createdAt, length(bodyMd) AS size "
            "FROM docPageVersions WHERE slug = ? ORDER BY createdAt DESC, rowid DESC",
            (slug,),
        ))


def get_doc_version(version_id: str) -> dict | None:
    with _conn() as conn:
        return _row(conn.execute("SELECT * FROM docPageVersions WHERE id = ?", (version_id,)).fetchone())


def restore_doc_version(version_id: str) -> dict | None:
    """Restoring is itself a change, so the state being replaced is snapshotted first -- an
    accidental restore stays undoable. The page becomes `generated = 0`: a deliberately chosen old
    text must not be overwritten by the next automatic run."""
    version = get_doc_version(version_id)
    if version is None:
        return None
    snapshot_doc_page(version["slug"], "vor Wiederherstellung")
    with _conn() as conn:
        conn.execute(
            "UPDATE docPages SET bodyMd = ?, manualMd = ?, generated = 0, updatedAt = ? WHERE slug = ?",
            (version["bodyMd"], version["manualMd"] or "", _now(), version["slug"]),
        )
    return get_doc_page(version["slug"])


def set_doc_page_manual(slug: str, manual_md: str) -> dict | None:
    """Writes the household's own notes for a chapter.

    Deliberately does NOT touch `generated`: the notes and the auto-written body are independent.
    Someone should be able to add a permanent note to a chapter and still receive updated device
    tables on the next scan -- pinning the whole page for that would defeat the point.
    """
    snapshot_doc_page(slug, "vor Änderung der eigenen Notizen")
    with _conn() as conn:
        conn.execute("UPDATE docPages SET manualMd = ?, updatedAt = ? WHERE slug = ?",
                     (manual_md, _now(), slug))
    return get_doc_page(slug)


def upsert_doc_page(slug: str, topic: str, title: str, body_md: str, intro: str, sort_order: int, generated: bool = True) -> dict:
    """Regenerating documentation must not silently discard a page the user has rewritten -- a page
    with `generated = 0` keeps its body and only refreshes its title/intro metadata."""
    existing = get_doc_page(slug)
    now = _now()
    if existing is not None and existing["generated"] and existing["bodyMd"] != body_md:
        snapshot_doc_page(slug, "automatisch neu erzeugt")
    with _conn() as conn:
        if existing is None:
            conn.execute(
                "INSERT INTO docPages(id, slug, topic, title, bodyMd, intro, generated, sortOrder, updatedAt) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (_new_id(), slug, topic, title, body_md, intro, 1 if generated else 0, sort_order, now),
            )
        elif existing["generated"]:
            conn.execute(
                "UPDATE docPages SET topic = ?, title = ?, bodyMd = ?, intro = ?, sortOrder = ?, updatedAt = ? WHERE slug = ?",
                (topic, title, body_md, intro, sort_order, now, slug),
            )
        else:
            conn.execute(
                "UPDATE docPages SET topic = ?, title = ?, sortOrder = ? WHERE slug = ?",
                (topic, title, sort_order, slug),
            )
    return get_doc_page(slug)  # type: ignore[return-value]


def set_doc_page_body(slug: str, body_md: str) -> dict | None:
    """A manual edit pins the page (`generated = 0`) so the next auto-generation leaves it alone."""
    snapshot_doc_page(slug, "vor manueller Bearbeitung")
    with _conn() as conn:
        conn.execute("UPDATE docPages SET bodyMd = ?, generated = 0, updatedAt = ? WHERE slug = ?", (body_md, _now(), slug))
    return get_doc_page(slug)


def reset_doc_page(slug: str) -> None:
    with _conn() as conn:
        conn.execute("UPDATE docPages SET generated = 1 WHERE slug = ?", (slug,))


def delete_doc_page(slug: str) -> None:
    with _conn() as conn:
        conn.execute("DELETE FROM docPages WHERE slug = ?", (slug,))


# --------------------------------------------------------------------------------------------
# Device configuration backups
# --------------------------------------------------------------------------------------------

# Fallback only -- the effective value is "configVersionKeep" in settings (see SettingsPage.tsx),
# read fresh on every call below so a changed setting applies to the very next backup.
_CONFIG_VERSION_KEEP_DEFAULT = 50


def save_device_config_version(system_id: str, label: str, content_enc: str, source: str) -> dict | None:
    """`content_enc` must already be encrypted by the caller (see probe_auth.persist_config_backups)
    -- this module stays as crypto-agnostic for device configs as it already is for account
    secrets. The caller is also responsible for deciding whether the content actually changed
    (comparing ciphertexts here would be meaningless: encryption is never deterministic)."""
    keep = max(1, min(1000, int(get_settings().get("configVersionKeep") or _CONFIG_VERSION_KEEP_DEFAULT)))
    with _conn() as conn:
        version_id = _new_id()
        conn.execute(
            "INSERT INTO deviceConfigVersions(id, systemId, label, content, source, createdAt) "
            "VALUES(?,?,?,?,?,?)",
            (version_id, system_id, label, content_enc, source, _now()),
        )
        # Unbounded history would grow by a full device export every scan that changes anything.
        conn.execute(
            "DELETE FROM deviceConfigVersions WHERE systemId = ? AND label = ? AND id NOT IN "
            "(SELECT id FROM deviceConfigVersions WHERE systemId = ? AND label = ? "
            "ORDER BY createdAt DESC, rowid DESC LIMIT ?)",
            (system_id, label, system_id, label, keep),
        )
        return _row(conn.execute("SELECT * FROM deviceConfigVersions WHERE id = ?", (version_id,)).fetchone())


def list_device_config_versions(system_id: str) -> list[dict]:
    """Without `content` -- callers that only need the list (to render a table, or to find the
    latest version for a change check) should not have to decrypt every row to get it."""
    with _conn() as conn:
        return _rows(conn.execute(
            "SELECT id, systemId, label, source, createdAt, length(content) AS size "
            "FROM deviceConfigVersions WHERE systemId = ? ORDER BY createdAt DESC, rowid DESC",
            (system_id,),
        ))


def get_device_config_version(version_id: str) -> dict | None:
    with _conn() as conn:
        return _row(conn.execute("SELECT * FROM deviceConfigVersions WHERE id = ?", (version_id,)).fetchone())


# --------------------------------------------------------------------------------------------
# Device error events -- see deviceErrorEvents' own schema comment for what these are.
# --------------------------------------------------------------------------------------------

# Per-device cap, same reasoning and same shape as deviceConfigVersions' "keep" trim: a device with
# a persistently broken credential would otherwise grow one row every single scan forever. Not
# user-configurable like the config-backup limit is -- these are diagnostic breadcrumbs, not
# something anyone restores from, so there is no equivalent tradeoff to expose a setting for.
_ERROR_EVENT_KEEP = 100


def add_device_error_event(system_id: str, level: str, message: str) -> dict | None:
    """Records one scan-time failure against the specific device it happened to, so it shows up
    right where someone looking at *that* device would check first, rather than only in the
    scan-wide log line that scrolls out of view after the next scan. A blank `system_id` is a
    no-op, not an error -- some failures (e.g. a Proxmox host that never resolved to any inventory
    row at all) have nowhere to attach to, and that is a normal, expected case, not a bug."""
    if not system_id:
        return None
    with _conn() as conn:
        event_id = _new_id()
        conn.execute(
            "INSERT INTO deviceErrorEvents(id, systemId, level, message, createdAt) VALUES(?,?,?,?,?)",
            (event_id, system_id, level or "error", (message or "")[:2000], _now()),
        )
        conn.execute(
            "DELETE FROM deviceErrorEvents WHERE systemId = ? AND id NOT IN "
            "(SELECT id FROM deviceErrorEvents WHERE systemId = ? ORDER BY createdAt DESC, rowid DESC LIMIT ?)",
            (system_id, system_id, _ERROR_EVENT_KEEP),
        )
        return _row(conn.execute("SELECT * FROM deviceErrorEvents WHERE id = ?", (event_id,)).fetchone())


def list_device_error_events(system_id: str, limit: int = 50) -> list[dict]:
    with _conn() as conn:
        return _rows(conn.execute(
            "SELECT * FROM deviceErrorEvents WHERE systemId = ? ORDER BY createdAt DESC, rowid DESC LIMIT ?",
            (system_id, limit),
        ))


def count_error_events_by_system() -> dict[str, int]:
    """Every device's error-event count in one query, so the systems list can show a warning
    badge without an extra round trip per device -- same pattern `/api/systems` already uses for
    `accountCount`."""
    with _conn() as conn:
        rows = conn.execute("SELECT systemId, COUNT(*) AS c FROM deviceErrorEvents GROUP BY systemId").fetchall()
    return {row["systemId"]: row["c"] for row in rows}


# --------------------------------------------------------------------------------------------
# Scans
# --------------------------------------------------------------------------------------------

def create_scan(subnets: str) -> str:
    scan_id = _new_id()
    with _conn() as conn:
        conn.execute("INSERT INTO scans(id, startedAt, status, subnets) VALUES(?,?,?,?)", (scan_id, _now(), "running", subnets))
    return scan_id


def update_scan(scan_id: str, *, phase: str | None = None, progress: int | None = None, log_line: str | None = None) -> None:
    with _conn() as conn:
        if phase is not None:
            conn.execute("UPDATE scans SET phase = ? WHERE id = ?", (phase, scan_id))
        if progress is not None:
            conn.execute("UPDATE scans SET progress = ? WHERE id = ?", (max(0, min(100, progress)), scan_id))
        if log_line:
            conn.execute("UPDATE scans SET log = log || ? WHERE id = ?", (f"{_now()}  {log_line}\n", scan_id))


def finish_scan(scan_id: str, status: str, summary: dict) -> None:
    with _conn() as conn:
        conn.execute(
            "UPDATE scans SET status = ?, finishedAt = ?, progress = 100, summary = ? WHERE id = ?",
            (status, _now(), _dump(summary), scan_id),
        )


def get_scan(scan_id: str) -> dict | None:
    with _conn() as conn:
        return _row(conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone())


def latest_scan() -> dict | None:
    with _conn() as conn:
        return _row(conn.execute("SELECT * FROM scans ORDER BY startedAt DESC LIMIT 1").fetchone())


def list_scans(limit: int = 20) -> list[dict]:
    with _conn() as conn:
        return _rows(conn.execute("SELECT id, startedAt, finishedAt, status, subnets, summary FROM scans ORDER BY startedAt DESC LIMIT ?", (limit,)))


def running_scan() -> dict | None:
    with _conn() as conn:
        return _row(conn.execute("SELECT * FROM scans WHERE status = 'running' ORDER BY startedAt DESC LIMIT 1").fetchone())


def abandon_stale_scans() -> None:
    """A container restart mid-scan would otherwise leave a `running` row forever, and the API
    refuses to start a second scan while one is running."""
    with _conn() as conn:
        conn.execute(
            "UPDATE scans SET status = 'failed', finishedAt = ?, phase = 'abgebrochen (Neustart)' WHERE status = 'running'",
            (_now(),),
        )


# --------------------------------------------------------------------------------------------
# Access log
# --------------------------------------------------------------------------------------------

_ACCESS_LOG_KEEP = 5000


def log_access(action: str, *, user: dict | None = None, username: str = "", detail: str = "",
               ip: str = "", user_agent: str = "", ok: bool = True) -> None:
    with _conn() as conn:
        conn.execute(
            "INSERT INTO accessLog(id, at, userId, username, action, detail, ip, userAgent, ok) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (_new_id(), _now(), (user or {}).get("id"), username or (user or {}).get("username", ""),
             action, detail[:500], ip[:60], user_agent[:200], 1 if ok else 0),
        )
        conn.execute(
            "DELETE FROM accessLog WHERE id NOT IN "
            "(SELECT id FROM accessLog ORDER BY at DESC, rowid DESC LIMIT ?)",
            (_ACCESS_LOG_KEEP,),
        )


def list_access_log(limit: int = 200, action: str | None = None, only_failures: bool = False) -> list[dict]:
    sql = "SELECT * FROM accessLog"
    clauses, params = [], []
    if action:
        clauses.append("action = ?")
        params.append(action)
    if only_failures:
        clauses.append("ok = 0")
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY at DESC, rowid DESC LIMIT ?"
    params.append(max(1, min(1000, limit)))
    with _conn() as conn:
        return _rows(conn.execute(sql, tuple(params)))


def access_log_actions() -> list[str]:
    with _conn() as conn:
        return [r["action"] for r in conn.execute("SELECT DISTINCT action FROM accessLog ORDER BY action")]


# --------------------------------------------------------------------------------------------
# Live monitoring
# --------------------------------------------------------------------------------------------

def ensure_monitoring_for_critical() -> int:
    """Enrols every critical device that has an address into the live monitor.

    Runs on startup and before each monitor round, not just at scan time. Otherwise a device that
    a human marks as critical in the UI is never polled and sits at status "unknown" forever --
    which is exactly what the dashboard's "most important devices" list was showing.
    """
    with _conn() as conn:
        cursor = conn.execute(
            "UPDATE systems SET monitored = 1 "
            "WHERE importance = 'critical' AND monitored = 0 AND (ip != '' OR hostname != '')"
        )
        return cursor.rowcount or 0


def list_monitored_systems() -> list[dict]:
    with _conn() as conn:
        return _rows(conn.execute(
            "SELECT * FROM systems WHERE monitored = 1 AND (ip != '' OR hostname != '') "
            "ORDER BY CASE importance WHEN 'critical' THEN 0 WHEN 'normal' THEN 1 ELSE 2 END, name"
        ))


def record_monitor_state(system_id: str, status: str, detail: str) -> bool:
    """Writes the status and, only on a change, an event. Returns True if the status changed."""
    with _conn() as conn:
        row = conn.execute("SELECT status FROM systems WHERE id = ?", (system_id,)).fetchone()
        if row is None:
            return False
        changed = row["status"] != status
        conn.execute("UPDATE systems SET status = ?, lastSeen = CASE WHEN ? = 'online' THEN ? ELSE lastSeen END "
                     "WHERE id = ?", (status, status, _now(), system_id))
        if changed:
            conn.execute(
                "INSERT INTO monitorEvents(id, systemId, at, status, detail) VALUES(?,?,?,?,?)",
                (_new_id(), system_id, _now(), status, detail[:300]),
            )
    return changed


def list_monitor_events(system_id: str | None = None, limit: int = 100) -> list[dict]:
    sql = "SELECT e.*, s.name AS systemName FROM monitorEvents e LEFT JOIN systems s ON s.id = e.systemId"
    params: list = []
    if system_id:
        sql += " WHERE e.systemId = ?"
        params.append(system_id)
    sql += " ORDER BY e.at DESC, e.rowid DESC LIMIT ?"
    params.append(max(1, min(500, limit)))
    with _conn() as conn:
        return _rows(conn.execute(sql, tuple(params)))


# --------------------------------------------------------------------------------------------
# Chat
# --------------------------------------------------------------------------------------------

def create_chat(title: str = "Neue Unterhaltung") -> dict:
    chat_id = _new_id()
    now = _now()
    with _conn() as conn:
        conn.execute("INSERT INTO chats(id, title, createdAt, updatedAt) VALUES(?,?,?,?)", (chat_id, title, now, now))
    return {"id": chat_id, "title": title, "createdAt": now, "updatedAt": now}


def list_chats() -> list[dict]:
    with _conn() as conn:
        return _rows(conn.execute("SELECT * FROM chats ORDER BY updatedAt DESC"))


def get_chat(chat_id: str) -> dict | None:
    with _conn() as conn:
        return _row(conn.execute("SELECT * FROM chats WHERE id = ?", (chat_id,)).fetchone())


def rename_chat(chat_id: str, title: str) -> None:
    with _conn() as conn:
        conn.execute("UPDATE chats SET title = ? WHERE id = ?", (title, chat_id))


def delete_chat(chat_id: str) -> None:
    with _conn() as conn:
        conn.execute("DELETE FROM chatMessages WHERE chatId = ?", (chat_id,))
        conn.execute("DELETE FROM chats WHERE id = ?", (chat_id,))


def add_chat_message(chat_id: str, role: str, content: str = "", tool_calls: list | None = None,
                     tool_call_id: str | None = None, name: str | None = None,
                     provider_raw: dict | None = None) -> dict:
    message_id = _new_id()
    now = _now()
    with _conn() as conn:
        conn.execute(
            "INSERT INTO chatMessages(id, chatId, role, content, toolCalls, providerRaw, toolCallId, name, createdAt) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (message_id, chat_id, role, content, _dump(tool_calls), _dump(provider_raw or None),
             tool_call_id, name, now),
        )
        conn.execute("UPDATE chats SET updatedAt = ? WHERE id = ?", (now, chat_id))
    with _conn() as conn:
        return _row(conn.execute("SELECT * FROM chatMessages WHERE id = ?", (message_id,)).fetchone())  # type: ignore[return-value]


def list_chat_messages(chat_id: str) -> list[dict]:
    with _conn() as conn:
        return _rows(conn.execute("SELECT * FROM chatMessages WHERE chatId = ? ORDER BY createdAt, rowid", (chat_id,)))
