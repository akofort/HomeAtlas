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

from fastapi import Body, Cookie, Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from . import (auth, crypto, db, diagnostics, docker_probe, docs, llm_providers, model_catalog,
               monitor as monitor_module, oui, pipeline, probe_auth, security, topology, tools)

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
    db.ensure_monitoring_for_critical()
    monitor_module.monitor.start()
    try:
        yield
    finally:
        await monitor_module.monitor.stop()


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


def _client(request: Request) -> tuple[str, str]:
    """Best-effort client identity for the access log. `X-Real-IP` comes from the nginx in front;
    without it every entry would read 127.0.0.1 and the log would be useless."""
    ip = request.headers.get("x-real-ip") or (request.client.host if request.client else "")
    return ip, request.headers.get("user-agent", "")


class LoginBody(BaseModel):
    username: str
    password: str
    totpCode: str = ""


@app.get("/api/health")
async def health() -> dict:
    return {"status": "ok", "setupCompleted": db.get_settings().get("setupCompleted", False),
            "userCount": db.count_users()}


@app.post("/api/auth/login")
async def login(body: LoginBody, response: Response, request: Request) -> dict:
    ip, agent = _client(request)
    try:
        user = auth.verify_login(body.username, body.password, body.totpCode)
    except auth.MfaRequired as exc:
        db.log_access("login.mfa", username=body.username, ip=ip, user_agent=agent, ok=False,
                      detail="falscher Code" if exc.wrong_code else "Code angefordert")
        # 401 + a flag rather than 200: the credentials alone did not authenticate anything yet.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=("Der Code stimmt nicht oder ist abgelaufen. Bitte den aktuellen aus der App eingeben."
                    if exc.wrong_code else "Bitte zusätzlich den 6-stelligen Code aus deiner Authenticator-App eingeben."),
            headers={"X-HomeAtlas-MFA": "required"},
        ) from exc
    if user is None:
        db.log_access("login", username=body.username, ip=ip, user_agent=agent, ok=False,
                      detail="Benutzername oder Passwort falsch")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Benutzername oder Passwort stimmt nicht.")
    db.log_access("login", user=user, ip=ip, user_agent=agent,
                  detail="mit zweitem Faktor" if user.get("totpEnabled") else "")
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
    # No length constraint here on purpose: `security.check_password` owns the policy and returns a
    # sentence the user can act on. A pydantic `min_length` would short-circuit that with a raw 422.
    newPassword: str


@app.post("/api/auth/password")
async def change_password(body: PasswordBody, request: Request, user: dict = Depends(current_user)) -> dict:
    ip, agent = _client(request)
    try:
        changed = auth.change_password(user["id"], body.currentPassword, body.newPassword)
    except security.PasswordError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not changed:
        db.log_access("password.change", user=user, ip=ip, user_agent=agent, ok=False,
                      detail="aktuelles Passwort falsch")
        raise HTTPException(status_code=400, detail="Das aktuelle Passwort stimmt nicht.")
    db.log_access("password.change", user=user, ip=ip, user_agent=agent)
    return {"ok": True}


@app.get("/api/auth/password-policy")
async def password_policy(_: dict = Depends(current_user)) -> dict:
    return security.describe_policy()


# ---------------------------------------------------------------------------------------------
# Second factor (TOTP)
# ---------------------------------------------------------------------------------------------

class TotpBody(BaseModel):
    code: str = ""
    password: str = ""


@app.post("/api/auth/mfa/setup")
async def mfa_setup(user: dict = Depends(current_user)) -> dict:
    """Creates a fresh secret and hands back the QR. Not yet active -- `totpEnabled` only flips
    after `/confirm` proves a working code, so a half-finished setup can't lock anyone out."""
    if user.get("totpEnabled"):
        raise HTTPException(status_code=400, detail="Die Zwei-Faktor-Anmeldung ist bereits aktiv.")
    secret = security.generate_totp_secret()
    db.update_user(user["id"], {"totpSecretEnc": crypto.encrypt(secret), "totpEnabled": False})
    uri = security.provisioning_uri(secret, user["username"])
    return {"secret": secret, "uri": uri, "qrSvg": security.qr_svg(uri)}


@app.post("/api/auth/mfa/confirm")
async def mfa_confirm(body: TotpBody, request: Request, user: dict = Depends(current_user)) -> dict:
    raw = db.get_user_raw(user["id"]) or {}
    secret = crypto.decrypt(raw.get("totpSecretEnc") or "")
    if not secret:
        raise HTTPException(status_code=400, detail="Bitte zuerst die Einrichtung starten.")
    if not security.verify_totp(secret, body.code):
        raise HTTPException(status_code=400, detail="Der Code stimmt nicht. Bitte den aktuellen aus der App eingeben.")
    db.update_user(user["id"], {"totpEnabled": True})
    ip, agent = _client(request)
    db.log_access("mfa.enable", user=user, ip=ip, user_agent=agent)
    return {"ok": True}


@app.post("/api/auth/mfa/disable")
async def mfa_disable(body: TotpBody, request: Request, user: dict = Depends(current_user)) -> dict:
    """Requires the account password again -- otherwise anyone at an unlocked browser could strip
    the second factor off, which defeats the point of having one."""
    if not auth.verify_password(user["id"], body.password):
        raise HTTPException(status_code=400, detail="Das Passwort stimmt nicht.")
    db.update_user(user["id"], {"totpSecretEnc": "", "totpEnabled": False})
    ip, agent = _client(request)
    db.log_access("mfa.disable", user=user, ip=ip, user_agent=agent)
    return {"ok": True}


@app.get("/api/users")
async def list_users(_: dict = Depends(require_admin)) -> dict:
    return {"users": db.list_users()}


class UserBody(BaseModel):
    username: str = Field(min_length=1)
    password: str  # policy enforced in the route, see PasswordBody
    role: str = auth.ROLE_MEMBER
    displayName: str = ""


@app.post("/api/users")
async def create_user(body: UserBody, request: Request, admin: dict = Depends(require_admin)) -> dict:
    if db.get_user_by_username_raw(body.username) is not None:
        raise HTTPException(status_code=409, detail="Diesen Benutzernamen gibt es schon.")
    try:
        security.check_password(body.password, body.username)
    except security.PasswordError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    role = body.role if body.role in (auth.ROLE_ADMIN, auth.ROLE_MEMBER) else auth.ROLE_MEMBER
    salt = _secrets.token_hex(16)
    user_id = db.create_user(body.username, auth.hash_password(body.password, salt), salt, role, body.displayName)
    ip, agent = _client(request)
    db.log_access("user.create", user=admin, ip=ip, user_agent=agent,
                  detail=f"{body.username} als {role}")
    return {"user": db.get_user(user_id)}


class UserPatchBody(BaseModel):
    displayName: str | None = None
    role: str | None = None
    newPassword: str | None = None


@app.patch("/api/users/{user_id}")
async def update_user(user_id: str, body: UserPatchBody, request: Request,
                      admin: dict = Depends(require_admin)) -> dict:
    target = db.get_user(user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Benutzer nicht gefunden.")

    patch: dict = {}
    changes: list[str] = []
    if body.displayName is not None and body.displayName != target["displayName"]:
        patch["displayName"] = body.displayName
        changes.append("Anzeigename")
    if body.role is not None and body.role != target["role"]:
        if body.role not in (auth.ROLE_ADMIN, auth.ROLE_MEMBER):
            raise HTTPException(status_code=400, detail="Unbekannte Rolle.")
        # Demoting the last admin would leave nobody able to reach settings or secrets, with no
        # recovery path short of editing the database by hand.
        admins = [u for u in db.list_users() if u["role"] == auth.ROLE_ADMIN]
        if target["role"] == auth.ROLE_ADMIN and body.role != auth.ROLE_ADMIN and len(admins) <= 1:
            raise HTTPException(status_code=400,
                                detail="Der letzte Administrator kann die Rolle nicht abgeben.")
        patch["role"] = body.role
        changes.append(f"Rolle → {body.role}")
    if patch:
        db.update_user(user_id, patch)

    if body.newPassword:
        try:
            security.check_password(body.newPassword, target["username"])
        except security.PasswordError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        auth.set_password(user_id, body.newPassword)
        # An open session would otherwise keep working with the replaced credential, which is not
        # what anyone means by "reset the password".
        db.invalidate_user_sessions(user_id)
        changes.append("Passwort zurückgesetzt, offene Sitzungen beendet")

    if changes:
        ip, agent = _client(request)
        db.log_access("user.update", user=admin, ip=ip, user_agent=agent,
                      detail=f"{target['username']}: {', '.join(changes)}")
    return {"user": db.get_user(user_id), "changes": changes}


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
# Written encrypted, never returned. The client sends plaintext under the name without the `Enc`
# suffix; an empty value means "keep what is stored", same rule as the account edit form.
_ENCRYPTED_SETTING_FIELDS = {
    "defaultCredentialSecret": "defaultCredentialSecretEnc",
    "defaultCredentialPassphrase": "defaultCredentialPassphraseEnc",
}
_MASK = "********"


def _mask_settings(settings: dict) -> dict:
    masked = dict(settings)
    for field in _SECRET_SETTING_FIELDS:
        masked[field] = _MASK if settings.get(field) else ""
    for plain, encrypted in _ENCRYPTED_SETTING_FIELDS.items():
        # The ciphertext never leaves the server; the UI only learns whether something is stored.
        masked.pop(encrypted, None)
        masked[f"has{plain[0].upper()}{plain[1:]}"] = bool(settings.get(encrypted))
    return masked


def _unmask_patch(patch: dict, current: dict) -> dict:
    """The UI round-trips the masked value when the user edits an unrelated field; writing it back
    verbatim would replace the real key with asterisks."""
    cleaned = dict(patch)
    for field in _SECRET_SETTING_FIELDS:
        if cleaned.get(field) == _MASK:
            cleaned[field] = current.get(field, "")
    for plain, encrypted in _ENCRYPTED_SETTING_FIELDS.items():
        if plain in cleaned:
            value = cleaned.pop(plain)
            # Blank means "leave it alone" -- the form never receives the stored value, so treating
            # it as "clear" would wipe the credential on every unrelated settings save.
            if value:
                cleaned[encrypted] = crypto.encrypt(value)
        cleaned.pop(f"has{plain[0].upper()}{plain[1:]}", None)
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
    return {"systems": [{**s, "accountCount": accounts_by_system.get(s["id"], 0),
                         "description": docs.describe_device(s)} for s in systems],
            "kindLabels": docs.KIND_LABELS}


@app.get("/api/systems/{system_id}")
async def get_system(system_id: str, _: dict = Depends(current_user)) -> dict:
    system = db.get_system(system_id)
    if system is None:
        raise HTTPException(status_code=404, detail="Gerät nicht gefunden.")
    accounts = [_public_account(a) for a in db.list_accounts(system_id)]
    return {"system": system, "accounts": accounts,
            # Derived rather than stored, so it stays correct as the device's data fills in.
            "description": docs.describe_device(system),
            "monitorPortsEffective": monitor_module.effective_ports(system)[0]}


@app.post("/api/systems")
async def create_system(body: dict = Body(...), _: dict = Depends(require_admin)) -> dict:
    # confirmed=1: anything a human typed is protected from being overwritten by the next scan.
    system = db.create_system({**body, "confirmed": 1, "discovered": 0})
    db.ensure_monitoring_for_critical()
    return {"system": db.get_system(system["id"])}


@app.patch("/api/systems/{system_id}")
async def update_system(system_id: str, patch: dict = Body(...), _: dict = Depends(require_admin)) -> dict:
    system = db.update_system(system_id, {**patch, "confirmed": 1})
    if system is None:
        raise HTTPException(status_code=404, detail="Gerät nicht gefunden.")
    # Marking something critical in the UI has to start the monitoring right away, not at the next
    # scan -- that gap is why the dashboard used to show "unbekannt" for the important devices.
    db.ensure_monitoring_for_critical()
    return {"system": db.get_system(system_id)}


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
    passphrase: str = ""
    url: str = ""
    notes: str = ""
    allowProbe: bool = False
    port: int = 0


def _public_account(account: dict) -> dict:
    """Strips both encrypted blobs. `hasSecret`/`hasPassphrase` tell the UI whether something is
    stored without ever shipping it."""
    return {k: v for k, v in account.items() if k not in ("secretEnc", "passphraseEnc")} | {
        "hasSecret": bool(account.get("secretEnc")),
        "hasPassphrase": bool(account.get("passphraseEnc")),
    }


@app.get("/api/accounts")
async def list_accounts(_: dict = Depends(require_admin)) -> dict:
    return {"accounts": [_public_account(a) for a in db.list_accounts()]}


@app.post("/api/accounts")
async def create_account(body: AccountBody, _: dict = Depends(require_admin)) -> dict:
    account = db.create_account({**body.model_dump(exclude={"secret", "passphrase"}),
                                 "secretEnc": crypto.encrypt(body.secret),
                                 "passphraseEnc": crypto.encrypt(body.passphrase)})
    return {"account": _public_account(account)}


@app.patch("/api/accounts/{account_id}")
async def update_account(account_id: str, body: AccountBody, _: dict = Depends(require_admin)) -> dict:
    patch = body.model_dump(exclude={"secret", "passphrase"})
    # An empty secret means "leave it alone" -- the edit form never receives the stored value, so
    # treating blank as "clear it" would silently delete the password on every unrelated edit.
    if body.secret:
        patch["secretEnc"] = crypto.encrypt(body.secret)
    if body.passphrase:
        patch["passphraseEnc"] = crypto.encrypt(body.passphrase)
    account = db.update_account(account_id, patch)
    if account is None:
        raise HTTPException(status_code=404, detail="Zugang nicht gefunden.")
    return {"account": _public_account(account)}


@app.get("/api/accounts/{account_id}/secret")
async def reveal_secret(account_id: str, request: Request, user: dict = Depends(require_admin)) -> dict:
    account = db.get_account(account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="Zugang nicht gefunden.")
    ip, agent = _client(request)
    # Logged deliberately: for a credential store, "who looked at the router password, and when"
    # is the single most useful entry the log can hold.
    db.log_access("secret.reveal", user=user, ip=ip, user_agent=agent, detail=account["label"])
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


@app.put("/api/docs/{slug}/manual")
async def edit_doc_manual(slug: str, body: dict = Body(...), _: dict = Depends(require_admin)) -> dict:
    """The household's own notes for a chapter. Kept apart from the generated body so a scan can
    keep refreshing the device tables while this text stays exactly as written."""
    if db.get_doc_page(slug) is None:
        raise HTTPException(status_code=404, detail="Kapitel nicht gefunden.")
    return {"page": db.set_doc_page_manual(slug, body.get("manualMd", ""))}


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


@app.get("/api/docs/{slug}/versions")
async def list_doc_versions(slug: str, _: dict = Depends(current_user)) -> dict:
    return {"versions": db.list_doc_versions(slug)}


@app.get("/api/docs/{slug}/versions/{version_id}")
async def get_doc_version(slug: str, version_id: str, _: dict = Depends(current_user)) -> dict:
    version = db.get_doc_version(version_id)
    if version is None or version["slug"] != slug:
        raise HTTPException(status_code=404, detail="Version nicht gefunden.")
    return {"version": version}


@app.post("/api/docs/{slug}/versions/{version_id}/restore")
async def restore_doc_version(slug: str, version_id: str, _: dict = Depends(require_admin)) -> dict:
    version = db.get_doc_version(version_id)
    if version is None or version["slug"] != slug:
        raise HTTPException(status_code=404, detail="Version nicht gefunden.")
    page = db.restore_doc_version(version_id)
    return {"page": page}


# ---------------------------------------------------------------------------------------------
# Authenticated probing (read-only -- see probe_auth)
# ---------------------------------------------------------------------------------------------

@app.post("/api/systems/{system_id}/probe")
async def probe_system(system_id: str, _: dict = Depends(require_admin)) -> dict:
    """Runs the read-only login probe for one device on demand, so the result is visible
    immediately instead of only after the next full scan."""
    system = db.get_system(system_id)
    if system is None:
        raise HTTPException(status_code=404, detail="Gerät nicht gefunden.")
    accounts = db.list_probe_accounts(system_id)
    if not accounts:
        raise HTTPException(status_code=400, detail=(
            "Für dieses Gerät ist kein Zugang freigegeben. Unter Zugänge beim gewünschten Eintrag "
            "„Zum Auslesen verwenden“ aktivieren."
        ))
    outcome = await probe_auth.probe_system(system, accounts)
    if outcome["ran"]:
        db.update_system(system_id, {"extra": {**(system.get("extra") or {}), "probe": outcome["results"]}})
        if outcome.get("purpose") and not system.get("purpose"):
            db.update_system(system_id, {"purpose": outcome["purpose"]})
    return {"outcome": outcome, "system": db.get_system(system_id)}


# ---------------------------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------------------------

@app.post("/api/scans")
async def start_scan(request: Request, user: dict = Depends(require_admin)) -> dict:
    if db.running_scan() is not None:
        raise HTTPException(status_code=409, detail="Es läuft bereits ein Scan.")
    ip, agent = _client(request)
    db.log_access("scan.start", user=user, ip=ip, user_agent=agent)
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

# ---------------------------------------------------------------------------------------------
# Access log, monitoring, overview plan
# ---------------------------------------------------------------------------------------------

@app.get("/api/access-log")
async def access_log(limit: int = 200, action: str | None = None, onlyFailures: bool = False,
                     _: dict = Depends(require_admin)) -> dict:
    return {"entries": db.list_access_log(limit, action, onlyFailures),
            "actions": db.access_log_actions()}


@app.get("/api/monitor")
async def monitor_status(_: dict = Depends(current_user)) -> dict:
    settings = db.get_settings()
    systems = db.list_monitored_systems()
    return {
        "enabled": settings.get("monitorEnabled", True),
        "intervalSeconds": settings.get("monitorIntervalSeconds", 10),
        "status": monitor_module.monitor.status(),
        "systems": [
            {"id": s["id"], "name": s["name"], "ip": s["ip"], "kind": s["kind"],
             "status": s["status"], "importance": s["importance"], "lastSeen": s["lastSeen"],
             "ports": monitor_module.effective_ports(s)[0],
             "portsExplicit": monitor_module.effective_ports(s)[1]}
            for s in systems
        ],
        "events": db.list_monitor_events(limit=50),
    }


@app.post("/api/monitor/run")
async def monitor_run_now(_: dict = Depends(require_admin)) -> dict:
    """Forces one round immediately instead of waiting for the next tick."""
    changes = await monitor_module.monitor.run_once()
    return {"changes": changes}


@app.get("/api/topology.svg", response_class=PlainTextResponse)
async def topology_svg(_: dict = Depends(current_user)) -> Response:
    return Response(content=topology.render(), media_type="image/svg+xml",
                    headers={"Cache-Control": "no-store"})


@app.post("/api/diagnostics/dns")
async def dns_diagnostic(body: dict = Body(default={}), _: dict = Depends(current_user)) -> dict:
    settings = db.get_settings()
    names = body.get("names") or settings.get("dnsTestNames") or []
    return {"result": await diagnostics.dns_check(names)}


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
        "criticalSystems": [
            {**s, "monitorPortsEffective": monitor_module.effective_ports(s)[0]}
            for s in systems if s["importance"] == "critical"
        ][:8],
        "monitorIntervalSeconds": settings.get("monitorIntervalSeconds", 10),
        "monitorEnabled": settings.get("monitorEnabled", True),
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
