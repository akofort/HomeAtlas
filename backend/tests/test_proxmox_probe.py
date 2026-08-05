import asyncio

import httpx

from app import proxmox_probe


def test_parse_notes_extracts_doc_link_and_leaves_purpose():
    notes = "Nextcloud fuer Fotos und Kalender.\nDoc: https://wiki.home.local/nextcloud\nBackup: taeglich 3 Uhr"
    purpose, doc_link = proxmox_probe.parse_notes(notes)
    assert purpose == "Nextcloud fuer Fotos und Kalender."
    assert doc_link == "https://wiki.home.local/nextcloud"


def test_parse_notes_accepts_url_label_case_insensitively():
    purpose, doc_link = proxmox_probe.parse_notes("url: HTTPS://example.com/runbook\nMehr Text")
    assert doc_link == "HTTPS://example.com/runbook"
    assert purpose == "Mehr Text"


def test_parse_notes_only_takes_the_first_doc_link():
    purpose, doc_link = proxmox_probe.parse_notes(
        "Doc: https://first.example\nDoc: https://second.example\nBeschreibung"
    )
    assert doc_link == "https://first.example"
    # The second Doc: line is left as plain prose since it wasn't consumed as *the* link, and
    # `purpose` is just the first remaining non-empty line.
    assert purpose == "Doc: https://second.example"


def test_parse_notes_does_not_match_url_mentioned_mid_sentence():
    purpose, doc_link = proxmox_probe.parse_notes("Migriert von https://old-host/vm3 letzten Monat.")
    assert doc_link == ""
    assert purpose == "Migriert von https://old-host/vm3 letzten Monat."


def test_parse_notes_empty_input():
    assert proxmox_probe.parse_notes("") == ("", "")
    assert proxmox_probe.parse_notes(None) == ("", "")  # type: ignore[arg-type]


def test_is_critical_tag_matches_semicolon_and_comma_separated():
    assert proxmox_probe.is_critical_tag("backup;critical;linux")
    assert proxmox_probe.is_critical_tag("backup,critical,linux")
    assert proxmox_probe.is_critical_tag("Critical")
    assert not proxmox_probe.is_critical_tag("backup;linux")
    assert not proxmox_probe.is_critical_tag("")
    assert not proxmox_probe.is_critical_tag("noncritical")  # substring, not a whole tag


def _handler(routes: dict):
    def handler(request: httpx.Request) -> httpx.Response:
        return routes.get(request.url.path, httpx.Response(404))
    return handler


def test_probe_sets_critical_importance_docs_and_purpose_from_notes(monkeypatch):
    routes = {
        "/api2/json/nodes": httpx.Response(200, json={"data": [{"node": "pve"}]}),
        "/api2/json/nodes/pve/qemu": httpx.Response(200, json={"data": [
            {"vmid": 101, "name": "nextcloud", "status": "running", "cpus": 2, "maxmem": 2147483648},
        ]}),
        "/api2/json/nodes/pve/lxc": httpx.Response(200, json={"data": []}),
        "/api2/json/nodes/pve/qemu/101/config": httpx.Response(200, json={"data": {
            "net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,ip=192.168.1.50/24",
            "description": "Cloud-Speicher fuers Haus.\nDoc: https://wiki.local/nextcloud",
            "tags": "critical;linux",
        }}),
    }
    transport = httpx.MockTransport(_handler(routes))

    class _FakeAsyncClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            kwargs.pop("verify", None)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(proxmox_probe.httpx, "AsyncClient", _FakeAsyncClient)

    result = asyncio.run(proxmox_probe.probe("https://pve.local:8006", "root@pam!token", "secret"))

    assert result["ok"]
    assert len(result["systems"]) == 1
    vm = result["systems"][0]
    assert vm["importance"] == "critical"
    assert vm["purpose"] == "Cloud-Speicher fuers Haus."
    assert vm["docLink"] == "https://wiki.local/nextcloud"
    assert vm["mac"] == "aa:bb:cc:dd:ee:ff"
    assert vm["discoveryKey"] == "mac:aa:bb:cc:dd:ee:ff"


def test_probe_leaves_importance_unset_when_not_tagged_critical(monkeypatch):
    routes = {
        "/api2/json/nodes": httpx.Response(200, json={"data": [{"node": "pve"}]}),
        "/api2/json/nodes/pve/qemu": httpx.Response(200, json={"data": [
            {"vmid": 102, "name": "test-vm", "status": "stopped", "cpus": 1, "maxmem": 1073741824},
        ]}),
        "/api2/json/nodes/pve/lxc": httpx.Response(200, json={"data": []}),
        "/api2/json/nodes/pve/qemu/102/config": httpx.Response(200, json={"data": {}}),
    }
    transport = httpx.MockTransport(_handler(routes))

    class _FakeAsyncClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            kwargs.pop("verify", None)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(proxmox_probe.httpx, "AsyncClient", _FakeAsyncClient)

    result = asyncio.run(proxmox_probe.probe("https://pve.local:8006", "root@pam!token", "secret"))

    vm = result["systems"][0]
    assert "importance" not in vm
    assert vm["status"] == "offline"
    assert vm["discoveryKey"] == "proxmox:pve:vm:102"


def _fake_client(monkeypatch, routes: dict) -> None:
    transport = httpx.MockTransport(_handler(routes))

    class _FakeAsyncClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            kwargs.pop("verify", None)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(proxmox_probe.httpx, "AsyncClient", _FakeAsyncClient)


def test_list_guests_requires_address():
    result = asyncio.run(proxmox_probe.list_guests("", "root@pam!token", "secret"))
    assert not result["ok"]
    assert "Adresse" in result["error"]


def test_list_guests_requires_token():
    result = asyncio.run(proxmox_probe.list_guests("https://pve.local:8006", "", ""))
    assert not result["ok"]
    assert "Token" in result["error"]


def test_list_guests_never_calls_docker_and_returns_vm_and_lxc(monkeypatch):
    routes = {
        "/api2/json/nodes": httpx.Response(200, json={"data": [{"node": "pve"}]}),
        "/api2/json/nodes/pve/qemu": httpx.Response(200, json={"data": [
            {"vmid": 101, "name": "nextcloud-vm", "status": "running"},
        ]}),
        "/api2/json/nodes/pve/lxc": httpx.Response(200, json={"data": [
            {"vmid": 102, "name": "pihole", "status": "stopped"},
        ]}),
    }
    _fake_client(monkeypatch, routes)

    result = asyncio.run(proxmox_probe.list_guests("https://pve.local:8006", "root@pam!token", "secret"))

    assert result["ok"]
    by_name = {c["name"]: c for c in result["containers"]}
    assert by_name["nextcloud-vm"]["state"] == "running"
    assert by_name["nextcloud-vm"]["image"] == "VM (QEMU/KVM) · Node pve"
    assert by_name["pihole"]["state"] == "stopped"
    assert by_name["pihole"]["image"] == "LXC-Container · Node pve"
    # No fact/field here is ever a Docker command or image name -- this is the REST path meant to
    # replace "docker ps" over SSH on a host that has no Docker CLI at all.
    assert all("docker" not in str(v).lower() for c in result["containers"] for v in c.values())


def test_list_guests_includes_ip_node_vmid_kind_and_colon_separated_id(monkeypatch):
    """The "id" field must use ":" not "/" as its separator -- it becomes a single FastAPI path
    segment (main.py's `{container_id}` in the remote-containers routes), and a literal slash
    inside it would split into extra path segments and break routing entirely."""
    routes = {
        "/api2/json/nodes": httpx.Response(200, json={"data": [{"node": "pve"}]}),
        "/api2/json/nodes/pve/qemu": httpx.Response(200, json={"data": [
            {"vmid": 101, "name": "nextcloud-vm", "status": "running"},
        ]}),
        "/api2/json/nodes/pve/lxc": httpx.Response(200, json={"data": []}),
        "/api2/json/nodes/pve/qemu/101/config": httpx.Response(200, json={"data": {
            "net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,ip=192.168.1.50/24",
        }}),
    }
    _fake_client(monkeypatch, routes)

    result = asyncio.run(proxmox_probe.list_guests("https://pve.local:8006", "root@pam!token", "secret"))

    assert result["ok"]
    vm = result["containers"][0]
    assert vm["id"] == "pve:qemu:101"
    assert "/" not in vm["id"]
    assert vm["ip"] == "192.168.1.50"
    assert vm["node"] == "pve"
    assert vm["vmid"] == "101"
    assert vm["kind"] == "vm"


def test_list_guests_reports_unreachable_host(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    transport = httpx.MockTransport(handler)

    class _FakeAsyncClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            kwargs.pop("verify", None)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(proxmox_probe.httpx, "AsyncClient", _FakeAsyncClient)

    result = asyncio.run(proxmox_probe.list_guests("https://pve.local:8006", "root@pam!token", "secret"))

    assert not result["ok"]
    assert "nicht erreichbar" in result["error"]


def test_guest_task_log_renders_history_newest_first(monkeypatch):
    routes = {
        # _handler keys on request.url.path, which never includes the query string -- the
        # "?vmid=...&limit=..." part of guest_task_log's own GET is irrelevant here.
        "/api2/json/nodes/pve/tasks": httpx.Response(200, json={"data": [
            {"upid": "UPID:pve:0001", "type": "vzstart", "status": "OK", "starttime": 1000},
            {"upid": "UPID:pve:0002", "type": "vzshutdown", "status": "OK", "starttime": 2000},
        ]}),
        "/api2/json/nodes/pve/tasks/UPID:pve:0001/log": httpx.Response(200, json={"data": [
            {"t": "starting container"}, {"t": "started"},
        ]}),
        "/api2/json/nodes/pve/tasks/UPID:pve:0002/log": httpx.Response(200, json={"data": [
            {"t": "shutting down"},
        ]}),
    }
    _fake_client(monkeypatch, routes)

    result = asyncio.run(proxmox_probe.guest_task_log("https://pve.local:8006", "root@pam!token", "secret",
                                                       "pve", "101"))

    assert result["ok"]
    # Newest (starttime 2000) first, regardless of the API's own return order.
    assert result["text"].index("vzshutdown") < result["text"].index("vzstart")
    assert "shutting down" in result["text"]
    assert "started" in result["text"]


def test_guest_task_log_reports_no_history(monkeypatch):
    routes = {"/api2/json/nodes/pve/tasks": httpx.Response(200, json={"data": []})}
    _fake_client(monkeypatch, routes)

    result = asyncio.run(proxmox_probe.guest_task_log("https://pve.local:8006", "root@pam!token", "secret",
                                                       "pve", "101"))

    assert result["ok"]
    assert "Kein Aufgabenprotokoll" in result["text"]


def test_guest_task_log_requires_address():
    result = asyncio.run(proxmox_probe.guest_task_log("", "root@pam!token", "secret", "pve", "101"))
    assert not result["ok"]
    assert "Adresse" in result["error"]
