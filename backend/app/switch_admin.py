"""Write-capable switching of Shelly relays and Home Assistant `switch`/`light` entities -- the
counterpart `discovery.shelly_identity`/`probe_auth.probe_homeassistant` explicitly are not.

Same split as `remote_admin.py` vs. `probe_auth.py` (see that module's docstring): this file only
ever sends a state-changing request, never imports a read-only module, and duplicates the small
amount of connection setup it needs (Shelly generation detection, HA's Bearer header) rather than
sharing it.

Unlike every other write module in this codebase, this one *is* reachable from `tools.py` --
that's a deliberate, explicit product decision (switching a light or plug is judged safe enough
for the assistant to do directly, unlike editing inventory/docs or touching containers/hosts) and
is documented at the point of exposure in `tools.py`, not a loophole.

Scope is deliberately narrow: on/off only, and for Home Assistant only the `switch` and `light`
domains (`_HA_ALLOWED_DOMAINS`) -- never `lock`, `cover`, `climate`, `alarm_control_panel` or
anything else HA might expose, even though the REST call shape would happily accept them.
"""
from __future__ import annotations

import httpx

_TIMEOUT = httpx.Timeout(8.0, connect=3.0)

_HA_ALLOWED_DOMAINS = ("switch", "light")


async def shelly_set_switch(host: str, on: bool, channel: int = 0) -> dict:
    """Turns one relay channel of a Shelly device on or off. Gen1 devices (`/shelly` -> no "gen"
    key, or `gen` == 1) use the classic `GET /relay/{ch}?turn=on|off` REST call; Gen2+ (Plus/Pro
    line) use the RPC endpoint `GET /rpc/Switch.Set?id={ch}&on=true|false`. Both generations answer
    `/shelly` without credentials (see `discovery.shelly_identity`), so generation is detected
    fresh here rather than trusting a possibly-stale value from the last scan."""
    turn = "on" if on else "off"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            try:
                identity = (await client.get(f"http://{host}/shelly")).json()
            except (httpx.HTTPError, ValueError) as exc:
                return {"ok": False, "error": f"„{host}“ antwortet nicht wie ein Shelly-Gerät: {exc}"}
            gen = int(identity.get("gen") or 1)
            if gen >= 2:
                response = await client.get(
                    f"http://{host}/rpc/Switch.Set", params={"id": channel, "on": str(on).lower()})
            else:
                response = await client.get(f"http://{host}/relay/{channel}", params={"turn": turn})
        if response.status_code >= 400:
            return {"ok": False, "error": f"Shelly-Gerät „{host}“ hat mit HTTP {response.status_code} abgelehnt."}
        return {"ok": True, "error": ""}
    except httpx.HTTPError as exc:
        return {"ok": False, "error": f"Verbindung zu „{host}“ fehlgeschlagen: {exc}"}


async def ha_set_switch(base_url: str, token: str, entity_id: str, on: bool) -> dict:
    """Flips one Home Assistant entity via `POST /api/services/{domain}/turn_on|turn_off`.
    `entity_id`'s domain (the part before the dot, e.g. "switch" in "switch.wohnzimmer_stecker")
    picks the service to call, and is checked against `_HA_ALLOWED_DOMAINS` before any request is
    made -- see module docstring for why the scope stops at switches and lights."""
    base_url = (base_url or "").rstrip("/")
    if not base_url:
        return {"ok": False, "error": "Keine Adresse für Home Assistant hinterlegt."}
    if not token:
        return {"ok": False, "error": "Kein Zugriffstoken hinterlegt."}
    domain = (entity_id or "").split(".", 1)[0]
    if domain not in _HA_ALLOWED_DOMAINS:
        return {"ok": False, "error": (
            f"„{entity_id}“ gehört zur Domäne „{domain}“ -- geschaltet werden dürfen hier nur "
            f"switch/light-Entities ({', '.join(_HA_ALLOWED_DOMAINS)}).")}
    service = "turn_on" if on else "turn_off"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, headers=headers) as client:
            response = await client.post(
                f"{base_url}/api/services/{domain}/{service}", json={"entity_id": entity_id})
        if response.status_code in (401, 403):
            return {"ok": False, "error": f"Home Assistant hat das Zugriffstoken abgelehnt (HTTP {response.status_code})."}
        if response.status_code >= 400:
            return {"ok": False, "error": f"Home Assistant hat mit HTTP {response.status_code} abgelehnt."}
        return {"ok": True, "error": ""}
    except httpx.HTTPError as exc:
        return {"ok": False, "error": f"Home Assistant unter {base_url} nicht erreichbar: {exc}"}
