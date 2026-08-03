"""Reads a Proxmox VE host's own REST API (API token) to discover the virtual machines and LXC
containers it runs -- the same reasoning as docker_probe.py: a port scan can only say "something
answers on 192.168.1.40", never that it is a specific VM this hypervisor knows about, on which
node, and whether it is set to run.

Read-only: every call below is a GET. No endpoint that starts/stops/reconfigures a guest is ever
called from here.

Opt-in per credential, same invariant as probe_auth.py: nothing here runs unless a human created an
account with category "proxmox" and ticked allowProbe on it. The account's `username`/`secretEnc`
hold a Proxmox API token ID (e.g. "root@pam!homeatlas") and its secret (a UUID) -- not a personal
login -- and its `url` the Proxmox host's own base address. See AccountsPage.tsx.
"""
from __future__ import annotations

import re

import httpx

from . import oui

_TIMEOUT = httpx.Timeout(15.0, connect=5.0)

# qemu (VM) net config lines look like "virtio=AA:BB:...,bridge=vmbr0,...", LXC's like
# "name=eth0,bridge=vmbr0,hwaddr=AA:BB:...,ip=192.168.1.50/24,...". One regex covers both NIC-model
# keys and LXC's "hwaddr" by matching whichever key precedes the MAC.
_NET_MAC_RE = re.compile(
    r"(?:virtio|e1000e?|rtl8139|vmxnet3|hwaddr)=([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", re.IGNORECASE,
)
_NET_IP_RE = re.compile(r"\bip=(\d{1,3}(?:\.\d{1,3}){3})(?:/\d+)?")


async def _get(client: httpx.AsyncClient, base_url: str, path: str) -> dict:
    response = await client.get(f"{base_url}/api2/json{path}")
    response.raise_for_status()
    result = response.json()
    if not isinstance(result, dict):
        raise ValueError("Unerwartete Antwort (kein JSON-Objekt).")
    return result


async def _guest_net_info(client: httpx.AsyncClient, base_url: str, node: str, kind: str, vmid: int) -> tuple[str, str]:
    """(mac, ip) parsed from the guest's own net0 config line -- no QEMU guest agent required
    (which many VMs never have installed), unlike asking the guest itself for its address, so this
    works even for a guest that has never booted since its last config change."""
    path = f"/nodes/{node}/{'qemu' if kind == 'vm' else 'lxc'}/{vmid}/config"
    try:
        response = await _get(client, base_url, path)
    except (httpx.HTTPError, ValueError):
        return "", ""
    net0 = (response.get("data") or {}).get("net0", "") or ""
    mac_match = _NET_MAC_RE.search(net0)
    ip_match = _NET_IP_RE.search(net0)
    return (oui.normalize_mac(mac_match.group(1)) if mac_match else "", ip_match.group(1) if ip_match else "")


async def probe(base_url: str, token_id: str, token_secret: str) -> dict:
    """Returns {"ok", "error", "systems": [...]}. `systems` entries are ready for
    `db.upsert_discovered_system`, same shape as docker_probe.probe()'s -- except `parentId`,
    which this module deliberately leaves unset: the caller (pipeline.py) knows which HomeAtlas
    system row the credential it used is attached to and sets it there, so a guest ends up nested
    under the right Proxmox host even in a cluster with several nodes at several addresses.
    """
    base_url = (base_url or "").rstrip("/")
    if not base_url:
        return {"ok": False, "error": "Keine Adresse für den Proxmox-Host hinterlegt.", "systems": []}
    if not token_id or not token_secret:
        return {"ok": False, "error": "API-Token-ID oder -Secret fehlt.", "systems": []}

    # Proxmox's own auth scheme, not a standard OAuth Bearer token.
    headers = {"Authorization": f"PVEAPIToken={token_id}={token_secret}"}
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, headers=headers) as client:
            nodes = (await _get(client, base_url, "/nodes")).get("data") or []

            systems = []
            for node_entry in nodes:
                node = node_entry.get("node", "")
                if not node:
                    continue
                for kind, path in (("vm", "qemu"), ("container", "lxc")):
                    try:
                        guests = (await _get(client, base_url, f"/nodes/{node}/{path}")).get("data") or []
                    except (httpx.HTTPError, ValueError):
                        continue  # one node/guest-type failing must not drop the rest
                    for guest in guests:
                        vmid = guest.get("vmid")
                        if vmid is None:
                            continue
                        mac, ip = await _guest_net_info(client, base_url, node, kind, int(vmid))
                        memory_mb = round((guest.get("maxmem") or 0) / 1048576) or None
                        systems.append({
                            "discoveryKey": f"mac:{mac}" if mac else f"proxmox:{node}:{kind}:{vmid}",
                            "kind": kind,
                            "name": guest.get("name") or f"{'VM' if kind == 'vm' else 'LXC'} {vmid}",
                            "ip": ip,
                            "mac": mac,
                            "location": f"Proxmox-Node {node}",
                            "vendor": "Proxmox",
                            "model": "VM (QEMU/KVM)" if kind == "vm" else "LXC-Container",
                            "purpose": (f"Virtuelle Maschine auf Proxmox-Node {node}" if kind == "vm"
                                       else f"LXC-Container auf Proxmox-Node {node}"),
                            "status": "online" if guest.get("status") == "running" else "offline",
                            "discovered": 1,
                            "discoverySource": "proxmox",
                            "extra": {"proxmox": {
                                "node": node, "vmid": vmid,
                                "cpuCores": guest.get("cpus"), "memoryMb": memory_mb,
                            }},
                        })
            return {"ok": True, "error": "", "systems": systems}
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        return {"ok": False, "error": f"Proxmox-Host nicht erreichbar: {exc}", "systems": []}
