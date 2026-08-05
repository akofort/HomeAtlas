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

Each guest's own Notes field (`description` in the API) is read too, via `parse_notes`: a
`Doc:`/`URL:` line becomes `docLink`, and whatever text is left becomes `purpose`/`descriptionMd`.
A `critical` Proxmox tag (`is_critical_tag`) promotes the guest to HomeAtlas's own `importance`
field -- see db.upsert_discovered_system for why that promotion is one-directional.
"""
from __future__ import annotations

import asyncio
import re

import httpx

from . import oui

_TIMEOUT = httpx.Timeout(15.0, connect=5.0)

# qemu (VM) net config lines look like "virtio=AA:BB:...,bridge=vmbr0,...", LXC's like
# "name=eth0,bridge=vmbr0,hwaddr=AA:BB:...,ip=192.168.1.50/24,...". Rather than enumerate every
# NIC-model key Proxmox accepts (virtio, e1000/e1000e, rtl8139, vmxnet3/vmxnet, pcnet, ne2k_pci,
# i82551, e1000-82545em, ...) or LXC's "hwaddr", this matches the MAC itself -- net0 has exactly
# one, regardless of which key precedes it.
_NET_MAC_RE = re.compile(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")
_NET_IP_RE = re.compile(r"\bip=(\d{1,3}(?:\.\d{1,3}){3})(?:/\d+)?")

# A household documenting its own homelab in Proxmox's free-text Notes field is the common case
# this exists for: a line like "Doc: https://wiki.local/nextcloud" or "URL: https://..." names
# where the *real* documentation for this guest lives, separate from the prose describing what it
# is. Matched per-line rather than searched for anywhere in the text so a URL mentioned in passing
# elsewhere in the notes (e.g. "migrated from https://old-host/vm3") is never mistaken for this.
_DOC_LINK_RE = re.compile(r"^\s*(?:Doc|URL)\s*:\s*(https?://\S+)", re.IGNORECASE)

# Proxmox's own tag field is semicolon-separated when set via the web UI, comma-separated when set
# via `qm set --tags`/`pct set --tags` -- both are real, in-the-wild separators, so both are
# accepted here rather than picking one.
_TAG_SPLIT_RE = re.compile(r"[;,]")


def parse_notes(notes: str) -> tuple[str, str]:
    """(purpose, doc_link) from a guest's Notes/Description field. A `Doc:`/`URL:` line is pulled
    out as its own field rather than left sitting in the descriptive text -- it is a *link*, not a
    description, and conflating the two would mean it only ever surfaces as buried prose instead
    of someplace the UI can render as an actual link. Whatever text remains after removing that
    line becomes `purpose`: its first non-empty line, since `purpose` is meant to be one short
    line (see docs.py), while the notes' full text -- unmodified -- is kept separately as
    `descriptionMd`, which is meant for exactly this longer free-form content."""
    doc_link = ""
    kept_lines = []
    for line in (notes or "").splitlines():
        match = _DOC_LINK_RE.match(line)
        if match and not doc_link:  # first match wins -- later ones are left as plain prose
            doc_link = match.group(1)
            continue
        kept_lines.append(line)
    purpose = next((line.strip() for line in kept_lines if line.strip()), "")
    return purpose[:200], doc_link


def is_critical_tag(tags: str) -> bool:
    """Whether a guest's Proxmox tags mark it critical -- a plain `critical` tag (case-insensitive,
    alongside whatever other tags exist), set the same way any other Proxmox tag is set (web UI or
    `qm`/`pct set --tags`). Deliberately not tied to any other config flag: Proxmox has no built-in
    "importance" concept, and tags are the one mechanism meant for exactly this kind of
    user-assigned label."""
    return any(tag.strip().lower() == "critical" for tag in _TAG_SPLIT_RE.split(tags or ""))


async def _get(client: httpx.AsyncClient, base_url: str, path: str) -> dict:
    response = await client.get(f"{base_url}/api2/json{path}")
    response.raise_for_status()
    result = response.json()
    if not isinstance(result, dict):
        raise ValueError("Unerwartete Antwort (kein JSON-Objekt).")
    return result


async def _guest_details(client: httpx.AsyncClient, base_url: str, node: str, kind: str, vmid: int) -> dict:
    """mac/ip (parsed from the guest's own net0 config line -- no QEMU guest agent required, which
    many VMs never have installed, unlike asking the guest itself for its address, so this works
    even for a guest that has never booted since its last config change), plus its free-text
    `description` (qemu/lxc's own name for the Notes field shown in the web UI) and `tags`, all
    from the one `/config` call -- a second round trip per guest just for notes/tags would double
    this module's request count for data the config response already carries."""
    path = f"/nodes/{node}/{'qemu' if kind == 'vm' else 'lxc'}/{vmid}/config"
    try:
        response = await _get(client, base_url, path)
    except (httpx.HTTPError, ValueError):
        return {"mac": "", "ip": "", "notes": "", "tags": ""}
    data = response.get("data") or {}
    net0 = data.get("net0", "") or ""
    mac_match = _NET_MAC_RE.search(net0)
    ip_match = _NET_IP_RE.search(net0)
    return {
        "mac": oui.normalize_mac(mac_match.group(1)) if mac_match else "",
        "ip": ip_match.group(1) if ip_match else "",
        "notes": data.get("description") or "",
        "tags": data.get("tags") or "",
    }


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
            errors = []
            for node_entry in nodes:
                node = node_entry.get("node", "")
                if not node:
                    continue
                for kind, path in (("vm", "qemu"), ("container", "lxc")):
                    try:
                        guests = (await _get(client, base_url, f"/nodes/{node}/{path}")).get("data") or []
                    except (httpx.HTTPError, ValueError) as exc:
                        # See list_guests()'s matching comment: swallowing every failure here would
                        # make a token without its own permission grant look identical to a host
                        # with genuinely zero guests.
                        errors.append(f"{node}/{path}: {exc}")
                        continue
                    valid_guests = [g for g in guests if g.get("vmid") is not None]
                    details = await asyncio.gather(*(
                        _guest_details(client, base_url, node, kind, int(g["vmid"])) for g in valid_guests
                    ))
                    for guest, detail in zip(valid_guests, details):
                        vmid = guest["vmid"]
                        mac, ip = detail["mac"], detail["ip"]
                        memory_mb = round((guest.get("maxmem") or 0) / 1048576) or None
                        default_purpose = (f"Virtuelle Maschine auf Proxmox-Node {node}" if kind == "vm"
                                          else f"LXC-Container auf Proxmox-Node {node}")
                        purpose, doc_link = parse_notes(detail["notes"])
                        # The guest-list endpoint carries its own "tags" on some Proxmox versions
                        # too -- merged in rather than relied on exclusively, since /config is the
                        # one call guaranteed to have it across versions.
                        tags = f'{guest.get("tags") or ""};{detail["tags"]}'
                        system: dict = {
                            "discoveryKey": f"mac:{mac}" if mac else f"proxmox:{node}:{kind}:{vmid}",
                            "kind": kind,
                            "name": guest.get("name") or f"{'VM' if kind == 'vm' else 'LXC'} {vmid}",
                            "ip": ip,
                            "mac": mac,
                            "location": f"Proxmox-Node {node}",
                            "vendor": "Proxmox",
                            "model": "VM (QEMU/KVM)" if kind == "vm" else "LXC-Container",
                            "purpose": purpose or default_purpose,
                            "descriptionMd": detail["notes"].strip()[:800],
                            "docLink": doc_link,
                            "status": "online" if guest.get("status") == "running" else "offline",
                            "discovered": 1,
                            "discoverySource": "proxmox",
                            "extra": {"proxmox": {
                                "node": node, "vmid": vmid,
                                "cpuCores": guest.get("cpus"), "memoryMb": memory_mb,
                            }},
                        }
                        if is_critical_tag(tags):
                            # One-directional: this only ever promotes a guest to critical when
                            # its Proxmox tag says so. db.upsert_discovered_system applies the
                            # actual promote-not-demote rule -- see its docstring -- so removing
                            # the tag later never silently un-marks a device a human relied on.
                            system["importance"] = "critical"
                        systems.append(system)
            if not systems and errors:
                return {"ok": False, "systems": [], "error": (
                    "Gäste-Liste konnte nicht gelesen werden (Berechtigung des API-Tokens prüfen -- "
                    "bei aktivierter Privilege Separation braucht der Token eine eigene Berechtigung, "
                    "z. B. PVEAuditor auf „/“): " + "; ".join(errors)
                )}
            return {"ok": True, "error": "", "systems": systems}
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        return {"ok": False, "error": f"Proxmox-Host nicht erreichbar: {exc}", "systems": []}


_KIND_LABEL = {"vm": "VM (QEMU/KVM)", "container": "LXC-Container"}


async def list_guests(base_url: str, token_id: str, token_secret: str) -> dict:
    """Returns {"ok", "error", "containers": [...]}. A lean node/VM/LXC listing for the "VMs &
    LXC-Container laden" button on a Proxmox host's own device page in the UI -- unlike `probe()`
    above, this never touches the inventory and skips the per-guest `/config` round trip (MAC/IP/
    notes/tags), since the button only needs name/kind/status, not everything a full scan collects.

    `containers` entries share their shape (id/name/image/state/status) with remote_admin.
    list_remote_containers' Docker listing so the frontend can render both with one table -- but
    Docker is never involved on the Proxmox path: this is the primary source main.py's
    `list_remote_containers` route uses for a system with a "proxmox"-category account attached,
    with `remote_admin.list_remote_proxmox_guests` (native `pct list`/`qm list` over SSH) only as
    its fallback when this call itself fails. Neither path ever runs a `docker` command against a
    Proxmox host -- it has no Docker CLI at all."""
    base_url = (base_url or "").rstrip("/")
    if not base_url:
        return {"ok": False, "error": "Keine Adresse für den Proxmox-Host hinterlegt.", "containers": []}
    if not token_id or not token_secret:
        return {"ok": False, "error": "API-Token-ID oder -Secret fehlt.", "containers": []}

    headers = {"Authorization": f"PVEAPIToken={token_id}={token_secret}"}
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, headers=headers) as client:
            nodes = (await _get(client, base_url, "/nodes")).get("data") or []

            containers = []
            errors = []
            for node_entry in nodes:
                node = node_entry.get("node", "")
                if not node:
                    continue
                for kind, path in (("vm", "qemu"), ("container", "lxc")):
                    try:
                        guests = (await _get(client, base_url, f"/nodes/{node}/{path}")).get("data") or []
                    except (httpx.HTTPError, ValueError) as exc:
                        # One node/guest-type failing must not drop the rest -- but if every one of
                        # them fails (typically an API token that has no permission of its own: with
                        # Proxmox's "Privilege Separation" a token needs its own ACL entry, separate
                        # from the user it belongs to), an empty `containers` list would look exactly
                        # like "this host genuinely has zero guests" instead of "token can't see
                        # them" -- see the `errors` check below.
                        errors.append(f"{node}/{path}: {exc}")
                        continue
                    for guest in guests:
                        vmid = guest.get("vmid")
                        if vmid is None:
                            continue
                        status = guest.get("status") or "unbekannt"
                        containers.append({
                            "id": f"{node}/{path}/{vmid}",
                            "name": guest.get("name") or f"{'VM' if kind == 'vm' else 'LXC'} {vmid}",
                            "image": f"{_KIND_LABEL[kind]} · Node {node}",
                            "state": "running" if status == "running" else "stopped",
                            "status": status,
                        })
            if not containers and errors:
                return {"ok": False, "containers": [], "error": (
                    "Gäste-Liste konnte nicht gelesen werden (Berechtigung des API-Tokens prüfen -- "
                    "bei aktivierter Privilege Separation braucht der Token eine eigene Berechtigung, "
                    "z. B. PVEAuditor auf „/“): " + "; ".join(errors)
                )}
            return {"ok": True, "error": "", "containers": containers}
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        return {"ok": False, "error": f"Proxmox-Host nicht erreichbar: {exc}", "containers": []}
