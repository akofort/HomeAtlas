"""FastAPI application: auth, inventory, accounts, documentation, scans, and the assistant.

Two cross-cutting rules the routes below implement consistently:

* **Secrets leave the server only on explicit, per-item request.** API keys come back from
  `GET /api/settings` masked, and a stored password is returned only by
  `GET /api/accounts/{id}/secret` -- an admin-only route that fetches exactly one secret. Nothing
  bulk-returns plaintext, so an over-broad frontend fetch can't leak the credential store.
* **MEMBER is a real read-only role.** It exists so the household can look things up and use the
  troubleshooting chat without also getting the router password; `require_admin` guards every
  mutating and every secret-revealing route.
"""
from __future__ import annotations

import asyncio
import logging
import os
import secrets as _secrets
from contextlib import asynccontextmanager

from fastapi import Body, Cookie, Depends, FastAPI, HTTPException, Response, status
from pydantic import BaseModel, Field

from . import auth, crypto, db, diagnostics, docker_probe, docs, llm_providers, model_catalog, oui, pipeline, tools

logger = logging.getLogger("homeatlas")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# Keeps background scan tasks referenced; without this the event loop may garbage-collect a
# running task and the scan silently stops mid-sweep.
_background_tasks: set[asyncio.Task] = set()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    db.init_db()
    db.abandon_stale_scans()
    generated = auth.ensure_admin_bootstrapped()
    if generated:
        logger.warning(
            "=" * 72 + "\nHomeAtlas: Erster Start. Anmeldedaten:\n"
            "  Benutzer:  %s\n  Passwort:  %s\n"
            "Dieses Passwort wird nur EINMAL angezeigt. Bitte notieren und nach dem Login\n"
            "unter Einstellungen -> Konto aendern.\n" + "=" * 72,
            os.environ.get("ADMIN_USERNAME", "admin"), generated,
        )
    yield


app = FastAPI(title="HomeAtlas", version="1.0.0", lifespan=lifespan)


# ---------------------------------------------------------------------------------------------
# Auth plumbing
# ---------------------------------------------------------------------------------------------

def current_user(homeatlas_session: str | None = Cookie(default=None)) -> dict:
    user = auth.get_session_user(homeatlas_session)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Nicht angemeldet.")
    return user


def require_admin(user: dict = Depends(current_user)) -> dict:
    if user["role"] != auth.ROLE_ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Dafür werden Administratorrechte benötigt.")
    return user


class LoginBody(BaseModel):
    username: str
    password: str


@app.get("/api/health")
async def health() -> dict:
    return {"status": "ok", "setupCompleted": db.get_settings().get("setupCompleted", False),
            "userCount": db.count_users()}


@app.post("/api/auth/login")
async def login(body: LoginBody, response: Response) -> dict:
    user = auth.verify_login(body.username, body.password)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Benutzername oder Passwort stimmt nicht.")
    token = auth.create_session(user["id"])
    response.set_cookie(
        auth.SESSION_COOKIE_NAME, token, max_age=auth.SESSION_TTL_SECONDS,
        httponly=True, samesite="lax", path="/",
    )
    return {"user": db.get_user(user["id"])}


@app.post("/api/auth/logout")
async def logout(response: Response, homeatlas_session: str | None = Cookie(default=None)) -> dict:
    if homeatlas_session:
        auth.destroy_session(homeatlas_session)
    response.delete_cookie(auth.SESSION_COOKIE_NAME, path="/")
    return {"ok": True}


@app.get("/api/auth/me")
async def me(user: dict = Depends(current_user)) -> dict:
    return {"user": user}


class PasswordBody(BaseModel):
    currentPassword: str
    newPassword: str = Field(min_length=8)


@app.post("/api/auth/password")
async def change_password(body: PasswordBody, user: dict = Depends(current_user)) -> dict:
    if not auth.change_password(user["id"], body.currentPassword, body.newPassword):
        raise HTTPException(status_code=400, detail="Das aktuelle Passwort stimmt nicht.")
    return {"ok": True}


@app.get("/api/users")
async def list_users(_: dict = Depends(require_admin)) -> dict:
    return {"users": db.list_users()}


class UserBody(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=8)
    role: str = auth.ROLE_MEMBER
    displayName: str = ""


@app.post("/api/users")
async def create_user(body: UserBody, _: dict = Depends(require_admin)) -> dict:
    if db.get_user_by_username_raw(body.username) is not None:
        raise HTTPException(status_code=409, detail="Diesen Benutzernamen gibt es schon.")
    role = body.role if body.role in (auth.ROLE_ADMIN, auth.ROLE_MEMBER) else auth.ROLE_MEMBER
    salt = _secrets.token_hex(16)
    user_id = db.create_user(body.username, auth.hash_password(body.password, salt), salt, role, body.displayName)
    return {"user": db.get_user(user_id)}


@app.delete("/api/users/{user_id}")
async def delete_user(user_id: str, user: dict = Depends(require_admin)) -> dict:
    if user_id == user["id"]:
        raise HTTPException(status_code=400, detail="Das eigene Konto lässt sich nicht löschen.")
    admins = [u for u in db.list_users() if u["role"] == auth.ROLE_ADMIN]
    if len(admins) <= 1 and any(u["id"] == user_id for u in admins):
        # Otherwise the instance ends up with no one who can change settings or read secrets, and
        # there is no recovery path short of editing the database by hand.
        raise HTTPException(status_code=400, detail="Der letzte Administrator lässt sich nicht löschen.")
    db.delete_user(user_id)
    return {"ok": True}


# ---------------------------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------------------------

_SECRET_SETTING_FIELDS = ("claudeApiKey", "openAiApiKey", "geminiApiKey", "deepseekApiKey", "ollamaApiKey")
_MASK = "********"


def _mask_settings(settings: dict) -> dict:
    masked = dict(settings)
    for field in _SECRET_SETTING_FIELDS:
        masked[field] = _MASK if settings.get(field) else ""
    return masked


def _unmask_patch(patch: dict, current: dict) -> dict:
    """The UI round-trips the masked value when the user edits an unrelated field; writing it back
    verbatim would replace the real key with asterisks."""
    cleaned = dict(patch)
    for field in _SECRET_SETTING_FIELDS:
        if cleaned.get(field) == _MASK:
            cleaned[field] = current.get(field, "")
    return cleaned


@app.get("/api/settings")
async def get_settings(user: dict = Depends(current_user)) -> dict:
    settings = _mask_settings(db.get_settings())
    if user["role"] != auth.ROLE_ADMIN:
        # A member has no business seeing which endpoints/models are configured.
        settings = {k: v for k, v in settings.items() if k in ("homeName", "setupCompleted")}
    return {"settings": settings, "providers": model_catalog.PROVIDER_LABELS,
            "catalog": {p: [vars(m) for m in model_catalog.options_for(p)] for p in model_catalog.PROVIDER_LABELS},
            "ouiLoaded": oui.is_downloaded(), "ouiEntries": oui.entry_count(),
            "dockerAvailable": docker_probe.socket_available()}


@app.patch("/api/settings")
async def update_settings(patch: dict = Body(...), _: dict = Depends(require_admin)) -> dict:
    current = db.get_settings()
    merged = db.update_settings(_unmask_patch(patch, current))
    return {"settings": _mask_settings(merged)}


class ProviderBody(BaseModel):
    provider: str
    settings: dict = Field(default_factory=dict)


def _settings_for_provider_test(body: ProviderBody) -> tuple[str, dict]:
    """Test against the *unsaved* form state so an admin can verify a key before storing it, while
    still allowing the masked placeholder to mean "keep what's saved"."""
    stored = db.get_settings()
    return body.provider, {**stored, **_unmask_patch(body.settings, stored)}


@app.post("/api/settings/llm/test")
async def test_llm(body: ProviderBody, _: dict = Depends(require_admin)) -> dict:
    provider, settings = _settings_for_provider_test(body)
    ok, message, model = await llm_providers.test_connection(provider, settings)
    return {"ok": ok, "message": message, "model": model}


@app.post("/api/settings/llm/models")
async def refresh_llm_models(body: ProviderBody, _: dict = Depends(require_admin)) -> dict:
    provider, settings = _settings_for_provider_test(body)
    ok, message, models = await llm_providers.refresh_models(provider, settings)
    if ok:
        cache = dict(db.get_settings().get("providerModelCache") or {})
        cache[provider] = {"models": models}
        db.update_settings({"providerModelCache": cache})
    return {"ok": ok, "message": message, "models": models}


@app.post("/api/settings/oui/refresh")
async def refresh_oui(_: dict = Depends(require_admin)) -> dict:
    ok, message = await oui.refresh_from_ieee()
    return {"ok": ok, "message": message, "entries": oui.entry_count()}


# ---------------------------------------------------------------------------------------------
# Systems
# ---------------------------------------------------------------------------------------------

@app.get("/api/systems")
async def list_systems(kind: str | None = None, _: dict = Depends(current_user)) -> dict:
    systems = db.list_systems(kind)
    accounts_by_system: dict[str, int] = {}
    for account in db.list_accounts():
        if account["systemId"]:
            accounts_by_system[account["systemId"]] = accounts_by_system.get(account["systemId"], 0) + 1
    return {"systems": [{**s, "accountCount": accounts_by_system.get(s["id"], 0)} for s in systems],
            "kindLabels": docs.KIND_LABELS}


@app.get("/api/systems/{system_id}")
async def get_system(system_id: str, _: dict = Depends(current_user)) -> dict:
    system = db.get_system(system_id)
    if system is None:
        raise HTTPException(status_code=404, detail="Gerät nicht gefunden.")
    accounts = [{k: v for k, v in a.items() if k != "secretEnc"} | {"hasSecret": bool(a["secretEnc"])}
                for a in db.list_accounts(system_id)]
    return {"system": system, "accounts": accounts}


@app.post("/api/systems")
async def create_system(body: dict = Body(...), _: dict = Depends(require_admin)) -> dict:
    # confirmed=1: anything a human typed is protected from being overwritten by the next scan.
    return {"system": db.create_system({**body, "confirmed": 1, "discovered": 0})}


@app.patch("/api/systems/{system_id}")
async def update_system(system_id: str, patch: dict = Body(...), _: dict = Depends(require_admin)) -> dict:
    system = db.update_system(system_id, {**patch, "confirmed": 1})
    if system is None:
        raise HTTPException(status_code=404, detail="Gerät nicht gefunden.")
    return {"system": system}


@app.delete("/api/systems/{system_id}")
async def delete_system(system_id: str, _: dict = Depends(require_admin)) -> dict:
    db.delete_system(system_id)
    return {"ok": True}


# ---------------------------------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------------------------------

class AccountBody(BaseModel):
    systemId: str | None = None
    label: str = "Zugang"
    category: str = "login"
    username: str = ""
    secret: str = ""
    url: str = ""
    notes: str = ""


def _public_account(account: dict) -> dict:
    return {k: v for k, v in account.items() if k != "secretEnc"} | {"hasSecret": bool(account.get("secretEnc"))}


@app.get("/api/accounts")
async def list_accounts(_: dict = Depends(require_admin)) -> dict:
    return {"accounts": [_public_account(a) for a in db.list_accounts()]}


@app.post("/api/accounts")
async def create_account(body: AccountBody, _: dict = Depends(require_admin)) -> dict:
    account = db.create_account({**body.model_dump(exclude={"secret"}),
                                 "secretEnc": crypto.encrypt(body.secret)})
    return {"account": _public_account(account)}


@app.patch("/api/accounts/{account_id}")
async def update_account(account_id: str, body: AccountBody, _: dict = Depends(require_admin)) -> dict:
    patch = body.model_dump(exclude={"secret"})
    # An empty secret means "leave it alone" -- the edit form never receives the stored value, so
    # treating blank as "clear it" would silently delete the password on every unrelated edit.
    if body.secret:
        patch["secretEnc"] = crypto.encrypt(body.secret)
    account = db.update_account(account_id, patch)
    if account is None:
        raise HTTPException(status_code=404, detail="Zugang nicht gefunden.")
    return {"account": _public_account(account)}


@app.get("/api/accounts/{account_id}/secret")
async def reveal_secret(account_id: str, _: dict = Depends(require_admin)) -> dict:
    account = db.get_account(account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="Zugang nicht gefunden.")
    return {"secret": crypto.decrypt(account["secretEnc"])}


@app.delete("/api/accounts/{account_id}")
async def delete_account(account_id: str, _: dict = Depends(require_admin)) -> dict:
    db.delete_account(account_id)
    return {"ok": True}


# ---------------------------------------------------------------------------------------------
# Documentation
# ---------------------------------------------------------------------------------------------

@app.get("/api/docs")
async def list_docs(_: dict = Depends(current_user)) -> dict:
    return {"pages": [{k: v for k, v in p.items() if k != "bodyMd"} for p in db.list_doc_pages()]}


@app.get("/api/docs/{slug}")
async def get_doc(slug: str, _: dict = Depends(current_user)) -> dict:
    page = db.get_doc_page(slug)
    if page is None:
        raise HTTPException(status_code=404, detail="Kapitel nicht gefunden.")
    return {"page": page}


@app.put("/api/docs/{slug}")
async def edit_doc(slug: str, body: dict = Body(...), _: dict = Depends(require_admin)) -> dict:
    page = db.set_doc_page_body(slug, body.get("bodyMd", ""))
    if page is None:
        raise HTTPException(status_code=404, detail="Kapitel nicht gefunden.")
    return {"page": page}


@app.post("/api/docs/{slug}/reset")
async def reset_doc(slug: str, _: dict = Depends(require_admin)) -> dict:
    db.reset_doc_page(slug)
    settings = db.get_settings()
    await docs.generate(settings, use_llm=settings.get("scanUseLlm", True))
    return {"page": db.get_doc_page(slug)}


@app.post("/api/docs/generate")
async def generate_docs(body: dict = Body(default={}), _: dict = Depends(require_admin)) -> dict:
    settings = db.get_settings()
    use_llm = body.get("useLlm", settings.get("scanUseLlm", True))
    slugs = await docs.generate(settings, use_llm=use_llm)
    return {"generated": slugs}


# ---------------------------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------------------------

@app.post("/api/scans")
async def start_scan(_: dict = Depends(require_admin)) -> dict:
    if db.running_scan() is not None:
        raise HTTPException(status_code=409, detail="Es läuft bereits ein Scan.")
    settings = db.get_settings()
    scan_id = db.create_scan(", ".join(settings.get("scanSubnets") or []) or "automatisch")
    task = asyncio.create_task(pipeline.run_full_scan(scan_id))
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return {"scanId": scan_id}


@app.get("/api/scans")
async def list_scans(_: dict = Depends(current_user)) -> dict:
    return {"scans": db.list_scans(), "running": db.running_scan()}


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str, _: dict = Depends(current_user)) -> dict:
    scan = db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan nicht gefunden.")
    return {"scan": scan}


# ---------------------------------------------------------------------------------------------
# Diagnostics (same functions the assistant calls, exposed for the UI's manual checks)
# ---------------------------------------------------------------------------------------------

class DiagnosticBody(BaseModel):
    tool: str
    args: dict = Field(default_factory=dict)


@app.post("/api/diagnostics")
async def run_diagnostic(body: DiagnosticBody, _: dict = Depends(current_user)) -> dict:
    handlers = {
        "internet_check": lambda a: diagnostics.internet_check(),
        "ping": lambda a: diagnostics.ping(a.get("host", ""), a.get("count", 3)),
        "check_port": lambda a: diagnostics.check_port(a.get("host", ""), a.get("port", 0)),
        "dns_lookup": lambda a: diagnostics.dns_lookup(a.get("name", "")),
        "http_check": lambda a: diagnostics.http_check(a.get("url", "")),
        "traceroute": lambda a: diagnostics.traceroute(a.get("host", ""), a.get("maxHops", 15)),
    }
    handler = handlers.get(body.tool)
    if handler is None:
        raise HTTPException(status_code=400, detail=f"Unbekannte Prüfung '{body.tool}'.")
    try:
        return {"result": await handler(body.args)}
    except diagnostics.DiagnosticError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------------------------
# Chat
# ---------------------------------------------------------------------------------------------

@app.get("/api/chats")
async def list_chats(_: dict = Depends(current_user)) -> dict:
    return {"chats": db.list_chats()}


@app.post("/api/chats")
async def create_chat(_: dict = Depends(current_user)) -> dict:
    return {"chat": db.create_chat()}


@app.get("/api/chats/{chat_id}/messages")
async def list_messages(chat_id: str, _: dict = Depends(current_user)) -> dict:
    if db.get_chat(chat_id) is None:
        raise HTTPException(status_code=404, detail="Unterhaltung nicht gefunden.")
    # Tool traffic is machine chatter; the UI shows which checks ran via `toolsUsed`.
    messages = [m for m in db.list_chat_messages(chat_id) if m["role"] in ("user", "assistant") and m["content"]]
    return {"messages": messages}


class ChatBody(BaseModel):
    message: str = Field(min_length=1)


@app.post("/api/chats/{chat_id}/messages")
async def send_message(chat_id: str, body: ChatBody, _: dict = Depends(current_user)) -> dict:
    chat = db.get_chat(chat_id)
    if chat is None:
        raise HTTPException(status_code=404, detail="Unterhaltung nicht gefunden.")
    settings = db.get_settings()
    provider = settings.get("llmProvider", "")
    # Ollama runs without a key; every cloud provider needs one, and failing here gives a usable
    # message instead of a raw 401 from the provider.
    if provider != "OLLAMA" and not llm_providers.api_key_for(provider, settings):
        raise HTTPException(status_code=400, detail=(
            "Es ist noch kein KI-Zugang eingerichtet. Bitte unter Einstellungen -> KI-Assistent "
            "einen Anbieter und einen Schlüssel hinterlegen."
        ))
    if chat["title"] == "Neue Unterhaltung":
        db.rename_chat(chat_id, body.message.strip()[:60])
    try:
        return await tools.run_chat_turn(chat_id, body.message, settings)
    except llm_providers.ProviderError as exc:
        raise HTTPException(status_code=502, detail=f"Der KI-Anbieter meldet: {exc}") from exc


@app.delete("/api/chats/{chat_id}")
async def delete_chat(chat_id: str, _: dict = Depends(current_user)) -> dict:
    db.delete_chat(chat_id)
    return {"ok": True}


# ---------------------------------------------------------------------------------------------
# Dashboard + first-run setup
# ---------------------------------------------------------------------------------------------

@app.get("/api/dashboard")
async def dashboard(_: dict = Depends(current_user)) -> dict:
    systems = db.list_systems()
    settings = db.get_settings()
    scan = db.latest_scan()
    provider = settings.get("llmProvider", "")
    return {
        "homeName": settings.get("homeName"),
        "setupCompleted": settings.get("setupCompleted", False),
        "counts": {
            "total": len(systems),
            "online": sum(1 for s in systems if s["status"] == "online"),
            "offline": sum(1 for s in systems if s["status"] == "offline"),
            "critical": sum(1 for s in systems if s["importance"] == "critical"),
            "accounts": len(db.list_accounts()),
            "documented": sum(1 for s in systems if s["descriptionMd"]),
        },
        "byKind": {k: sum(1 for s in systems if s["kind"] == k) for k in sorted({s["kind"] for s in systems})},
        "kindLabels": docs.KIND_LABELS,
        "criticalSystems": [s for s in systems if s["importance"] == "critical"][:8],
        "recentlyChanged": sorted(systems, key=lambda s: s["updatedAt"], reverse=True)[:8],
        "lastScan": scan,
        "llmConfigured": provider == "OLLAMA" or bool(llm_providers.api_key_for(provider, settings)),
    }


class SetupSystem(BaseModel):
    name: str
    kind: str = "other"
    ip: str = ""
    location: str = ""
    purpose: str = ""
    url: str = ""
    username: str = ""
    password: str = ""


class SetupAccount(BaseModel):
    label: str
    category: str = "login"
    username: str = ""
    secret: str = ""
    url: str = ""
    notes: str = ""


class SetupBody(BaseModel):
    homeName: str = "Mein Zuhause"
    systems: list[SetupSystem] = Field(default_factory=list)
    accounts: list[SetupAccount] = Field(default_factory=list)
    scanSubnets: list[str] = Field(default_factory=list)


@app.post("/api/setup")
async def run_setup(body: SetupBody, _: dict = Depends(require_admin)) -> dict:
    """Stores what the first-run wizard collected. Each system with a password gets a matching
    account row, so the credential lands encrypted rather than in a free-text note."""
    created_systems = 0
    for entry in body.systems:
        if not entry.name.strip():
            continue
        system = db.create_system({
            "name": entry.name, "kind": entry.kind, "ip": entry.ip, "location": entry.location,
            "purpose": entry.purpose, "url": entry.url, "confirmed": 1, "discovered": 0,
            "importance": "critical" if entry.kind in ("router", "server", "nas", "heating") else "normal",
        })
        created_systems += 1
        if entry.username or entry.password:
            db.create_account({
                "systemId": system["id"], "label": f"Zugang {entry.name}", "category": "login",
                "username": entry.username, "secretEnc": crypto.encrypt(entry.password), "url": entry.url,
            })
    created_accounts = 0
    for account in body.accounts:
        if not account.label.strip():
            continue
        db.create_account({**account.model_dump(exclude={"secret"}),
                           "secretEnc": crypto.encrypt(account.secret)})
        created_accounts += 1

    db.update_settings({"homeName": body.homeName, "setupCompleted": True,
                        "scanSubnets": [s.strip() for s in body.scanSubnets if s.strip()]})
    return {"ok": True, "systems": created_systems, "accounts": created_accounts}
