"""Reads a TP-Link Omada SDN Controller's Open API to discover the access points, switches and
gateways it manages -- a Wi-Fi/mDNS scan alone can only say "something answers on 192.168.1.5",
never that it is the living-room access point this specific controller has adopted.

Read-only: every call below is a GET, except the token exchange -- that POST is the client-
credentials login step Omada's own Open API defines, not a configuration change, and no endpoint
capable of changing a device (reboot, port config, SSID) is ever called from here.

Opt-in per credential, same invariant as probe_auth.py: nothing here runs unless a human created
an account with category "omada" and ticked allowProbe on it. The account's `username`/`secretEnc`
hold the Open API client ID/secret (an OAuth client-credentials pair, not a personal login), and
its `url` the controller's own base address -- see AccountsPage.tsx.
"""
from __future__ import annotations

import httpx

from . import oui

_TIMEOUT = httpx.Timeout(15.0, connect=5.0)

# Omada's own device "type" values -- see TP-Link's Open API docs (Platform Integration -> Open
# API -> Online API Document in the controller itself).
_KIND_BY_TYPE = {"ap": "network", "switch": "network", "gateway": "router"}
_PURPOSE_BY_TYPE = {
    "ap": "WLAN-Access-Point (TP-Link Omada)",
    "switch": "Netzwerk-Switch (TP-Link Omada)",
    "gateway": "Internet-Router/Gateway (TP-Link Omada)",
}


async def _json(client: httpx.AsyncClient, method: str, url: str, **kwargs) -> dict:
    response = await client.request(method, url, **kwargs)
    response.raise_for_status()
    result = response.json()
    if not isinstance(result, dict):
        raise ValueError("Unerwartete Antwort (kein JSON-Objekt).")
    return result


async def probe(base_url: str, client_id: str, client_secret: str) -> dict:
    """Returns {"ok", "error", "systems": [...]}. `systems` entries are ready for
    `db.upsert_discovered_system`, same shape as docker_probe.probe()'s."""
    base_url = (base_url or "").rstrip("/")
    if not base_url:
        return {"ok": False, "error": "Keine Adresse für den Omada Controller hinterlegt.", "systems": []}
    if not client_id or not client_secret:
        return {"ok": False, "error": "Client-ID oder Client-Secret der Open API fehlt.", "systems": []}

    try:
        # verify=False: a local Omada Controller almost always runs on a self-signed certificate --
        # same posture probe_auth.probe_http already takes for router/switch web UIs on the LAN.
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False) as client:
            info = await _json(client, "GET", f"{base_url}/api/info")
            omada_id = (info.get("result") or {}).get("omadacId", "")
            if not omada_id:
                return {"ok": False, "systems": [], "error": (
                    "Die Omada-Controller-ID (omadacId) konnte nicht ermittelt werden -- "
                    "ist die hinterlegte Adresse die des Controllers?"
                )}

            token_response = await _json(
                client, "POST", f"{base_url}/openapi/authorize/token",
                params={"grant_type": "client_credentials"},
                json={"omadacId": omada_id, "client_id": client_id, "client_secret": client_secret},
            )
            if token_response.get("errorCode"):
                return {"ok": False, "systems": [], "error": (
                    f"Anmeldung an der Open API fehlgeschlagen: "
                    f"{token_response.get('msg') or 'unbekannter Fehler'} "
                    f"(Code {token_response.get('errorCode')})."
                )}
            access_token = (token_response.get("result") or {}).get("accessToken", "")
            if not access_token:
                return {"ok": False, "error": "Open API lieferte keinen Zugriffstoken.", "systems": []}

            # Omada's own header shape -- not a standard OAuth "Bearer" token.
            headers = {"Authorization": f"AccessToken={access_token}"}
            sites_response = await _json(
                client, "GET", f"{base_url}/openapi/v1/{omada_id}/sites",
                params={"pageSize": 100, "page": 1}, headers=headers,
            )
            if sites_response.get("errorCode"):
                return {"ok": False, "systems": [], "error": (
                    f"Sites konnten nicht abgerufen werden: "
                    f"{sites_response.get('msg') or 'unbekannter Fehler'}."
                )}
            sites = (sites_response.get("result") or {}).get("data") or []

            systems = []
            for site in sites:
                site_id, site_name = site.get("siteId", ""), site.get("name", "")
                if not site_id:
                    continue
                devices_response = await _json(
                    client, "GET", f"{base_url}/openapi/v1/{omada_id}/sites/{site_id}/devices",
                    params={"pageSize": 100, "page": 1}, headers=headers,
                )
                if devices_response.get("errorCode"):
                    continue
                for device in (devices_response.get("result") or {}).get("data") or []:
                    device_type = (device.get("type") or "").lower()
                    if device_type not in _KIND_BY_TYPE:
                        continue
                    # Same normalization discovery.py's own ARP/mDNS findings use for their
                    # "mac:..." discoveryKey -- without it, a device found by both sources would
                    # merge only by luck of matching case/delimiter and usually create a duplicate.
                    mac = oui.normalize_mac(device.get("mac", ""))
                    systems.append({
                        "discoveryKey": f"mac:{mac}" if mac else f"omada:{site_id}:{device.get('name', '')}",
                        "kind": _KIND_BY_TYPE[device_type],
                        "name": device.get("name") or "Omada-Gerät",
                        "ip": device.get("ip", ""),
                        "mac": mac,
                        "location": site_name,
                        "vendor": "TP-Link",
                        "model": device.get("model", ""),
                        "purpose": _PURPOSE_BY_TYPE[device_type],
                        # Omada's own enum for this field: 1 == connected/online, confirmed against
                        # TP-Link's reference Home Assistant integration (device.status == 1).
                        "status": "online" if device.get("status") == 1 else "offline",
                        "discovered": 1,
                        "discoverySource": "omada",
                        "extra": {
                            "omada": {
                                "siteId": site_id,
                                "siteName": site_name,
                                "type": device_type,
                                "firmwareVersion": device.get("firmwareVersion", ""),
                                "serial": device.get("sn", ""),
                            }
                        },
                    })
            return {"ok": True, "error": "", "systems": systems}
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        return {"ok": False, "error": f"Omada Controller nicht erreichbar: {exc}", "systems": []}
