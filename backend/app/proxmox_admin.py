"""Write-capable Proxmox VE control -- the counterpart `proxmox_probe.py` explicitly is not, same
split as `docker_probe.py`/`docker_admin.py`.

One call: `POST /nodes/{node}/{qemu|lxc}/{vmid}/status/{start|shutdown|reboot}` against the same
REST API `proxmox_probe.py` reads from, with the same `PVEAPIToken` auth header.

Reachable only from `main.py`'s admin-gated routes -- never imported by `tools.py` (the LLM's
tool-calling surface), `pipeline.py`, or `proxmox_probe.py`. A human clicking a button in the
browser is the only caller this function may ever have.
"""
from __future__ import annotations

import httpx

_TIMEOUT = httpx.Timeout(15.0, connect=5.0)

# Proxmox's own status verbs. "stop" maps to its graceful `shutdown` (ACPI/systemd shutdown inside
# the guest), not its hard `stop` (power-cut) -- the same choice Docker's own "stop" action makes
# elsewhere in this app. A genuine power-cut is one click away in the Proxmox web UI itself if
# ever needed; deliberately not exposed here.
_ACTIONS = {"start": "start", "stop": "shutdown", "restart": "reboot"}


async def guest_action(base_url: str, token_id: str, token_secret: str,
                       node: str, kind: str, vmid: str, action: str) -> dict:
    """Starts/stops/restarts one VM or LXC guest. Returns {"ok", "error"}, never raises -- same
    posture as docker_admin's `_post`, since a failed guest action is an expected, reportable
    outcome for the admin who clicked the button, not a bug."""
    proxmox_action = _ACTIONS.get(action)
    if proxmox_action is None:
        return {"ok": False, "error": f"Unbekannte Aktion '{action}'."}
    base_url = (base_url or "").rstrip("/")
    if not base_url:
        return {"ok": False, "error": "Keine Adresse für den Proxmox-Host hinterlegt."}
    if not token_id or not token_secret:
        return {"ok": False, "error": "API-Token-ID oder -Secret fehlt."}

    headers = {"Authorization": f"PVEAPIToken={token_id}={token_secret}"}
    path = f"/nodes/{node}/{'qemu' if kind == 'vm' else 'lxc'}/{vmid}/status/{proxmox_action}"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, headers=headers) as client:
            response = await client.post(f"{base_url}/api2/json{path}")
        if response.status_code >= 400:
            try:
                detail = response.json().get("errors") or response.text
            except ValueError:
                detail = response.text
            return {"ok": False, "error": f"Proxmox-Aktion fehlgeschlagen: {detail or response.status_code}"}
        return {"ok": True, "error": ""}
    except httpx.HTTPError as exc:
        return {"ok": False, "error": f"Proxmox-Host nicht erreichbar: {exc}"}
