"""Reads an AdGuard Home instance's own REST API (HTTP Basic Auth) for DNS-filtering status,
block statistics and known clients/DHCP leases -- the same reasoning as omada_probe.py/
proxmox_probe.py: a port scan can only say "something answers on 192.168.1.2", never whether DNS
filtering is actually protecting the network or which of AdGuard's own DHCP leases the network
sweep never saw itself.

Read-only: every call below is a GET against AdGuard's `/control/*` API. No endpoint that changes
a setting, client or lease is ever called from here.

Opt-in per credential, same invariant as probe_auth.py: nothing here runs unless a human created
an account with category "adguard" and ticked allowProbe on it. AdGuard Home accepts a plain HTTP
Basic Auth header on every `/control/*` route (no separate `/control/login` session dance needed)
for whichever admin user/password is configured on the instance itself -- the account's
`username`/`secretEnc` hold exactly that, and its `url` the instance's own base address.

Two different things flow out of `probe()`:
- `stats`: DNS protection status and block-rate numbers, meant for the credential's own system row
  (the AdGuard host itself) -- there is exactly one AdGuard instance per credential, unlike
  Proxmox/Omada's per-guest/per-device fan-out, so pipeline.py attaches this directly rather than
  through `db.upsert_discovered_system`.
- `systems`: DHCP-lease and known-client entries ready for `db.upsert_discovered_system`, purely
  to fill IP<->hostname/MAC gaps elsewhere in the inventory -- see `upsert_discovered_system`'s own
  merge rules for why this can never clobber a device's existing name/hostname, only fill it in
  where still empty. Entries with no hostname are skipped: a MAC/IP pair alone tells the inventory
  nothing an ARP-based scan wouldn't already have found itself.
"""
from __future__ import annotations

import httpx

from . import oui

_TIMEOUT = httpx.Timeout(10.0, connect=5.0)


async def _get(client: httpx.AsyncClient, base_url: str, path: str) -> dict:
    response = await client.get(f"{base_url}{path}")
    if response.status_code in (401, 403):
        raise PermissionError(f"HTTP {response.status_code}")
    response.raise_for_status()
    result = response.json()
    if not isinstance(result, dict):
        raise ValueError("Unerwartete Antwort (kein JSON-Objekt).")
    return result


def _dhcp_lease_systems(dhcp_status: dict) -> list[dict]:
    systems = []
    leases = (dhcp_status.get("leases") or []) + (dhcp_status.get("static_leases") or [])
    for lease in leases:
        if not isinstance(lease, dict):
            continue
        mac = oui.normalize_mac(lease.get("mac", ""))
        hostname = (lease.get("hostname") or "").strip()
        # A lease with no hostname (still a raw DHCP allocation, not yet resolved to a name) adds
        # nothing an ARP sweep wouldn't already know -- skipped rather than creating a nameless row.
        if not mac or not hostname:
            continue
        systems.append({
            "discoveryKey": f"mac:{mac}",
            "name": hostname,
            "hostname": hostname,
            "ip": lease.get("ip", ""),
            "mac": mac,
            "vendor": oui.lookup(mac),
            "discovered": 1,
            "discoverySource": "adguard",
        })
    return systems


def _known_client_systems(clients: dict) -> list[dict]:
    systems = []
    for entry in clients.get("clients") or []:
        if not isinstance(entry, dict):
            continue
        name = (entry.get("name") or "").strip()
        if not name:
            continue
        # AdGuard's own `ids` field mixes IPs, MACs and CIDR ranges for one client depending on how
        # it was configured -- only a MAC identifies one specific device unambiguously enough to
        # upsert against.
        mac = next((oui.normalize_mac(i) for i in entry.get("ids") or [] if oui.normalize_mac(i)), "")
        if not mac:
            continue
        ip = next((i for i in entry.get("ids") or [] if i.count(".") == 3 and not oui.normalize_mac(i)), "")
        systems.append({
            "discoveryKey": f"mac:{mac}",
            "name": name,
            "hostname": name,
            "ip": ip,
            "mac": mac,
            "vendor": oui.lookup(mac),
            "discovered": 1,
            "discoverySource": "adguard",
        })
    return systems


async def probe(base_url: str, username: str, password: str) -> dict:
    """Returns {"ok", "error", "systems": [...], "stats": {...}}."""
    base_url = (base_url or "").rstrip("/")
    if not base_url:
        return {"ok": False, "error": "Keine Adresse für AdGuard Home hinterlegt.", "systems": [], "stats": {}}
    if not username or not password:
        return {"ok": False, "error": "Benutzername oder Passwort fehlt.", "systems": [], "stats": {}}

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False,
                                     auth=httpx.BasicAuth(username, password)) as client:
            try:
                dns_info = await _get(client, base_url, "/control/dns_info")
            except PermissionError:
                return {"ok": False, "systems": [], "stats": {}, "error": (
                    "AdGuard Home hat die hinterlegten Zugangsdaten abgelehnt -- Benutzername/"
                    "Passwort des AdGuard-Administrators prüfen."
                )}

            stats: dict = {
                "protectionEnabled": bool(dns_info.get("protection_enabled")),
                "upstreamCount": len(dns_info.get("upstream_dns") or []),
            }
            try:
                stats_data = await _get(client, base_url, "/control/stats")
                num_queries = stats_data.get("num_dns_queries") or 0
                num_blocked = stats_data.get("num_blocked_filtering") or 0
                stats["queries"] = num_queries
                stats["blocked"] = num_blocked
                stats["blockedPercent"] = round(100 * num_blocked / num_queries, 1) if num_queries else 0.0
            except (httpx.HTTPError, ValueError, PermissionError):
                pass  # stats missing must not fail the whole probe -- dns_info alone is still useful

            systems: list[dict] = []
            seen_macs: set[str] = set()

            try:
                dhcp_status = await _get(client, base_url, "/control/dhcp/status")
            except (httpx.HTTPError, ValueError, PermissionError):
                dhcp_status = {}
            for system in _dhcp_lease_systems(dhcp_status):
                if system["mac"] not in seen_macs:
                    seen_macs.add(system["mac"])
                    systems.append(system)

            try:
                clients = await _get(client, base_url, "/control/clients")
            except (httpx.HTTPError, ValueError, PermissionError):
                clients = {}
            for system in _known_client_systems(clients):
                if system["mac"] not in seen_macs:
                    seen_macs.add(system["mac"])
                    systems.append(system)

            return {"ok": True, "error": "", "systems": systems, "stats": stats}
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        return {"ok": False, "error": f"AdGuard Home nicht erreichbar: {exc}", "systems": [], "stats": {}}
