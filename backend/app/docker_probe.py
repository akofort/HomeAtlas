"""Reads the Docker host through its socket (mounted read-only, see docker-compose.yml).

This is the single highest-value discovery source in a self-hosted household: a port scan can only
say "something answers on 8180", while the Docker API says which image it is, which compose
project it belongs to, which volumes hold its data and whether it is set to restart on boot --
exactly the facts someone needs six months later when it breaks.

Read-only in the honest sense: only GET endpoints are ever called. The socket mount itself is
root-equivalent on the host, which the README states outright.
"""
from __future__ import annotations

import os

import httpx

_SOCKET = os.environ.get("DOCKER_SOCKET", "/var/run/docker.sock")
_TIMEOUT = httpx.Timeout(15.0, connect=5.0)


def socket_available() -> bool:
    return os.path.exists(_SOCKET)


async def _get(path: str) -> object:
    transport = httpx.AsyncHTTPTransport(uds=_SOCKET)
    async with httpx.AsyncClient(transport=transport, base_url="http://docker", timeout=_TIMEOUT) as client:
        resp = await client.get(path)
    resp.raise_for_status()
    return resp.json()


def _clean_name(names: list[str] | None) -> str:
    if not names:
        return "unbenannter Container"
    return names[0].lstrip("/")


def _published_ports(container: dict) -> list[int]:
    """Only ports actually published to the host -- an internal container port says nothing about
    what is reachable from the network, and listing it would make the documentation misleading."""
    ports = {p["PublicPort"] for p in container.get("Ports") or [] if p.get("PublicPort")}
    return sorted(ports)


def _port_mappings(container: dict) -> list[str]:
    out = []
    for p in container.get("Ports") or []:
        if p.get("PublicPort"):
            out.append(f"{p.get('IP') or '0.0.0.0'}:{p['PublicPort']} -> {p.get('PrivatePort')}/{p.get('Type', 'tcp')}")
    return sorted(set(out))


async def probe(host_ip: str = "") -> dict:
    """Returns {"ok", "error", "version", "systems": [...], "networks": [...], "volumes": [...]}.

    `systems` entries are ready for `db.upsert_discovered_system`.
    """
    if not socket_available():
        return {"ok": False, "error": f"Docker-Socket {_SOCKET} ist nicht eingebunden.", "systems": []}
    try:
        version = await _get("/version")
        info = await _get("/info")
        containers = await _get("/containers/json?all=1")
        networks = await _get("/networks")
        volumes = await _get("/volumes")
    except (httpx.HTTPError, ValueError) as exc:
        return {"ok": False, "error": f"Docker-API nicht erreichbar: {exc}", "systems": []}

    assert isinstance(containers, list)
    volume_list = (volumes or {}).get("Volumes") or [] if isinstance(volumes, dict) else []
    # "Where is this container?" has exactly one useful answer for a household: the machine it
    # runs on. Docker's /info reports that host's own name, which beats a room label nobody would
    # ever fill in for 30 containers.
    host_name = (info or {}).get("Name", "") if isinstance(info, dict) else ""
    location = host_name or host_ip or "Docker-Host"

    systems = []
    for container in containers:
        labels = container.get("Labels") or {}
        project = labels.get("com.docker.compose.project", "")
        service = labels.get("com.docker.compose.service", "")
        name = _clean_name(container.get("Names"))
        mounts = [
            m.get("Name") or m.get("Source") or ""
            for m in container.get("Mounts") or []
            if m.get("Name") or m.get("Source")
        ]
        state = container.get("State", "")
        published = _published_ports(container)
        # The container's own ID changes on every recreate (a rebuild, `docker compose up
        # --build`, even a plain restart-with-new-image) -- keying on it here made every redeploy
        # of a compose-managed container add a brand-new "duplicate" row instead of updating the
        # existing one. Compose project+service survives a recreate; a container's own --name
        # (used for the handful of non-compose containers) is just as stable. Only a bare `docker
        # run` container with no name at all falls back to its ID, and even that keeps the ID
        # constant across rescans since nothing there recreates it.
        stable_key = f"{project}:{service}" if project and service else name or container.get("Id", "")[:12]
        # Before compose project+service became the key, every container was keyed on its own ID
        # (see the note above) -- an installation upgrading across that change would otherwise fail
        # to find its existing row by the new key and duplicate every compose-managed container.
        # This lets db.upsert_discovered_system fall back to the old key and migrate the row in place.
        legacy_key = f"docker:{container.get('Id', '')[:12]}"
        systems.append({
            "discoveryKey": f"docker:{stable_key}",
            "legacyDiscoveryKeys": [legacy_key],
            "kind": "container",
            "name": name,
            "ip": host_ip,
            "location": location,
            "model": container.get("Image", ""),
            "status": "online" if state == "running" else "offline",
            "discovered": 1,
            "discoverySource": "docker",
            "openPorts": published,
            "url": f"http://{host_ip}:{published[0]}" if host_ip and published else "",
            "extra": {
                "docker": {
                    # Full ID, unlike discoveryKey's [:12] -- docker_admin.py's start/stop/restart/
                    # exec actions need the exact ID, and Docker's actions API accepts short IDs
                    # too but there is no reason to rely on that when the full one is right here.
                    "containerId": container.get("Id", ""),
                    "image": container.get("Image", ""),
                    "imageId": (container.get("ImageID") or "")[:19],
                    "state": state,
                    "status": container.get("Status", ""),
                    "composeProject": project,
                    "composeService": service,
                    "restartPolicy": labels.get("restart", ""),
                    "portMappings": _port_mappings(container),
                    "volumes": mounts,
                    "networks": sorted((container.get("NetworkSettings") or {}).get("Networks", {}).keys()),
                    "created": container.get("Created"),
                }
            },
        })

    return {
        "ok": True,
        "error": "",
        "hostName": host_name,
        "version": {
            "version": (version or {}).get("Version", "") if isinstance(version, dict) else "",
            "apiVersion": (version or {}).get("ApiVersion", "") if isinstance(version, dict) else "",
            "os": (version or {}).get("Os", "") if isinstance(version, dict) else "",
            "arch": (version or {}).get("Arch", "") if isinstance(version, dict) else "",
        },
        "systems": systems,
        "networks": [
            {
                "name": n.get("Name", ""),
                "driver": n.get("Driver", ""),
                "subnet": ", ".join(
                    c.get("Subnet", "") for c in ((n.get("IPAM") or {}).get("Config") or []) if c.get("Subnet")
                ),
            }
            for n in (networks if isinstance(networks, list) else [])
        ],
        "volumes": [
            {"name": v.get("Name", ""), "mountpoint": v.get("Mountpoint", ""), "driver": v.get("Driver", "")}
            for v in volume_list
        ],
    }
