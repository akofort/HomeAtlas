# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

HomeAtlas is a self-hosted home-network documentation tool (German UI/docstrings mixed with
English code comments). It scans the home LAN, identifies devices via multiple independent
sources, generates plain-language Markdown documentation, and provides an LLM-backed
troubleshooting assistant. Two containers, both on `network_mode: host` (required — discovery
reads the host's ARP table and sends mDNS/SSDP multicast, neither of which crosses a Docker
bridge network):

```
Browser ── nginx (frontend, React/TS, :8280) ── /api/* ──▶ 127.0.0.1:8281 ──▶ FastAPI backend
```

The backend binds only to `127.0.0.1`; nginx is the only thing that can reach it, since the host
network means the API port is otherwise exposed on every interface of the Docker host.

Read the README.md "Sicherheit" section before touching auth, credential storage, or the
probe/remote-admin modules — it states the threat model and trade-offs this code is built around.

## Development commands

Backend (from `backend/`):
```bash
pip install -r requirements.txt
HOMEATLAS_DB_PATH=./dev.db HOMEATLAS_KEY_PATH=./dev.key ADMIN_PASSWORD=devpass123 \
  uvicorn app.main:app --reload --port 8000
```

Frontend (from `frontend/`), proxies `/api` to `:8000` automatically:
```bash
npm install
npm run dev        # dev server
npm run build       # tsc -b && vite build — this IS the typecheck; there is no separate lint/typecheck script
npm run preview
```

There is no test suite and no linter configured in this repo (no pytest, no eslint config) —
don't assume either exists.

Full stack via Docker: `docker compose up -d --build`, then http://localhost:8280. First-run
admin credentials are printed once to `docker compose logs backend`. `ADMIN_USERNAME`/
`ADMIN_PASSWORD` in `docker-compose.yml` only take effect when no user exists yet.

`./deploy.sh` deploys to a specific remote host over SSH (default `192.168.1.110`) — it's this
project's real deployment target, not a generic template. Don't run it without confirming with
the user first.

Windows containers lack `ip`/`ping`/`traceroute`, so discovery and diagnostics are degraded there;
this only matters when reasoning about cross-platform behavior, not for normal development.

## Backend architecture (`backend/app/`)

Every module has a docstring explaining its own design rationale and constraints — read the
module docstring before editing it, it usually answers "why is this written this way" before you
have to ask. Key structural rules that span multiple files:

**Read vs. write is a hard architectural split, not just a convention.** Modules that read from
devices/Docker and modules that change them are deliberately separate and never import each
other:
- `docker_probe.py` (read-only, GET-only Docker API calls) vs. `docker_admin.py` (write-capable
  container control) — the latter is reachable only from `main.py`'s admin-gated routes, never
  from `tools.py` or `pipeline.py`.
- `probe_auth.py` (read-only SSH/HTTP/TR-064 device probing, hardcoded command allowlist in
  `_SSH_COMMANDS` with no setting/parameter/tool able to extend it) vs. `remote_admin.py`
  (write-capable SSH admin: install keys, interactive shell, remote container control) — same
  "never imported by/into `tools.py`" rule. A future import from `tools.py` into either write
  module would be a bug, not a refactor.

**`tools.py` is the LLM's entire capability surface** (used by both the in-app chat and
`mcp_server.py`'s external MCP endpoint). It is read-only plus bounded live diagnostics; nothing
reachable from here mutates inventory, docs, or devices, and `list_accounts` always strips
passwords before they reach a model — secrets never enter a prompt, provider log, or chat
history. When adding a new assistant capability, this boundary is the thing to preserve.

**Discovery (`discovery.py`) is intentionally multi-source**: ping/ARP, port scan, reverse-DNS,
mDNS/SSDP, Docker API, each contributing because none alone sees everything. Naming precedence is
fixed: self-reported name (UPnP `friendlyName`, then mDNS) > DNS hostname > page title > vendor +
IP octet. `classify.py` (LLM-assisted identification) runs only over devices the rule-based guess
in `discovery._guess` couldn't confidently place, and a low-confidence LLM answer is discarded
rather than stored.

**`pipeline.py`** orchestrates a full scan (discovery → Docker → credentialed probing →
classification → doc regeneration) and owns the scan `Scheduler`. **`docs.py`** renders the
12-chapter Markdown documentation from the inventory; each doc page has a separate
never-auto-touched "manual notes" field (`db.set_doc_page_manual`) plus an independent
whole-page-manual-override mode — know which one an edit is supposed to affect.

**`monitor.py`** is a background poller for devices flagged "important" — only status
*transitions* are persisted (not every poll), and a down state requires multiple consecutive
failures (`_FAILURES_BEFORE_DOWN`) before it's recorded, to avoid flagging normal Wi-Fi packet
loss as an outage.

**`db.py`** is the only place that touches SQLite — a flat module of functions over a single
connection helper, no ORM. **`crypto.py`** (Fernet, key stored alongside the DB in the same
volume — protects against a leaked DB copy, not a host-root attacker) encrypts credentials in
`accounts.secretEnc`; `main.py` only ever returns a stored secret one-at-a-time from
`GET /api/accounts/{id}/secret`, admin-only, never in bulk.

**`llm_providers.py`** is a provider-neutral HTTP client (Claude/OpenAI/Gemini/DeepSeek/Ollama) —
deliberately not using any vendor SDK. Two correctness details specific to current Claude models:
no sampling parameters (`temperature`/`top_p`/`top_k`) are ever sent to Anthropic (removed on
Opus 5/Sonnet 5/4.8/4.7 — sending them is an HTTP 400), and `thinking` is never explicitly
configured (every explicit setting 400s on some model in the supported range). Mirrors the
sibling project GlucoSphere-Web's `llm_providers.py` structure by design — keep them recognizably
similar if you touch this.

**`auth.py`** implements two roles: ADMIN (full access including secrets) and MEMBER (docs +
chat, read-only, never a plaintext secret). `main.py`'s `require_admin`/`current_user`
dependencies are the enforcement point — `current_user` also hard-requires TOTP enrollment
(`security.py`) on every route except the small allowlist needed to complete enrollment itself.

**`topology.py`** renders the network plan as server-side SVG (fixed layered layout: Internet →
Router → Verteilung → Server → Endgeräte) rather than a client-side graph library, so it stays a
picture a non-technical reader can actually parse.

## Frontend architecture (`frontend/src/`)

Plain React + react-router, no state library — `App.tsx` holds auth state (session user, MFA/setup
gating) in context and is the source of truth for the login → MFA-enroll → setup-wizard → app
gating sequence; the same order is enforced independently on the backend (see `current_user` in
`main.py`), so a UI-only change here doesn't change what the API actually allows.

`lib/api.ts` is a single typed fetch wrapper — every backend call goes through `request()`, which
is where session-cookie handling, FastAPI validation-error flattening, and the "MFA re-enrolled
elsewhere, force reload" behavior all live. Add new endpoints here rather than calling `fetch`
directly from a page.

Pages under `pages/` map roughly 1:1 to the nav items in `App.tsx`'s `NAV` array; several are
admin-only both in the route guard (`isAdmin &&` around the `<Route>`) and on the corresponding
backend routes — when adding an admin-only page, gate both sides.
