"""HTTP-level smoke tests for the two new device-control surfaces: POST /systems/{id}/reboot
(generic device restart, routed to either TR-064 or SSH depending on what the device is) and
GET /systems/{id}/remote-containers/{id}/logs (Proxmox task log / LXC journalctl / remote Docker
logs). The underlying logic already has its own focused unit tests (test_remote_admin_proxmox.py,
test_remote_admin_reboot_and_logs.py, test_proxmox_probe.py) -- these exist to catch wiring
mistakes in main.py itself."""
import pytest
from fastapi.testclient import TestClient

from app import auth, crypto, db, main, proxmox_probe, remote_admin


@pytest.fixture()
def client(temp_db, tmp_path, monkeypatch):
    monkeypatch.setattr(crypto, "_KEY_PATH", tmp_path / "secret.key")
    monkeypatch.setattr(crypto, "_cached", None)
    main.app.dependency_overrides[main.require_admin] = lambda: {"role": auth.ROLE_ADMIN, "username": "admin"}
    try:
        yield TestClient(main.app)
    finally:
        main.app.dependency_overrides.clear()


# --------------------------------------------------------------------------------------- reboot

def test_reboot_uses_ssh_for_a_generic_host(client, monkeypatch):
    system = db.create_system({"kind": "server", "name": "NAS", "ip": "10.0.0.70"})
    account = db.create_account({"systemId": system["id"], "label": "SSH", "category": "sshkey"})

    seen = {}

    async def fake_reboot_host(host, account_arg, port=0):
        seen["host"] = host
        return {"ok": True, "error": ""}

    async def fail_if_called(*args, **kwargs):
        raise AssertionError("a non-router host must never use the TR-064 path")

    monkeypatch.setattr(remote_admin, "reboot_host", fake_reboot_host)
    monkeypatch.setattr(remote_admin, "reboot_fritzbox", fail_if_called)

    response = client.post(f"/api/systems/{system['id']}/reboot?accountId={account['id']}")

    assert response.status_code == 200
    assert seen["host"] == "10.0.0.70"


def test_reboot_uses_tr064_for_a_router(client, monkeypatch):
    system = db.create_system({"kind": "router", "name": "FritzBox", "ip": "10.0.0.1", "vendor": "AVM"})
    account = db.create_account({"systemId": system["id"], "label": "Login", "category": "login"})

    seen = {}

    async def fake_reboot_fritzbox(host, account_arg, port=0):
        seen["host"] = host
        return {"ok": True, "error": ""}

    async def fail_if_called(*args, **kwargs):
        raise AssertionError("a router must never use the generic SSH reboot path")

    monkeypatch.setattr(remote_admin, "reboot_fritzbox", fake_reboot_fritzbox)
    monkeypatch.setattr(remote_admin, "reboot_host", fail_if_called)

    response = client.post(f"/api/systems/{system['id']}/reboot?accountId={account['id']}")

    assert response.status_code == 200
    assert seen["host"] == "10.0.0.1"


def test_reboot_rejects_ssh_account_for_a_router(client):
    system = db.create_system({"kind": "router", "name": "FritzBox", "ip": "10.0.0.1"})
    account = db.create_account({"systemId": system["id"], "label": "SSH", "category": "sshkey"})

    response = client.post(f"/api/systems/{system['id']}/reboot?accountId={account['id']}")

    assert response.status_code == 400
    assert "TR-064" in response.json()["detail"]


def test_reboot_rejects_non_ssh_account_for_a_generic_host(client):
    system = db.create_system({"kind": "server", "name": "NAS", "ip": "10.0.0.70"})
    account = db.create_account({"systemId": system["id"], "label": "SNMP", "category": "snmp"})

    response = client.post(f"/api/systems/{system['id']}/reboot?accountId={account['id']}")

    assert response.status_code == 400
    assert "SSH" in response.json()["detail"]


def test_reboot_404s_for_unknown_account(client):
    system = db.create_system({"kind": "server", "name": "NAS", "ip": "10.0.0.70"})

    response = client.post(f"/api/systems/{system['id']}/reboot?accountId=does-not-exist")

    assert response.status_code == 404


# ---------------------------------------------------------------------------------------- logs

def test_logs_reads_proxmox_task_log_when_node_is_known(client, monkeypatch):
    system = db.create_system({"kind": "server", "name": "PVE-Host", "ip": "10.0.0.51"})
    db.create_account({
        "systemId": system["id"], "label": "Proxmox API", "category": "proxmox",
        "username": "root@pam!homeatlas", "secretEnc": crypto.encrypt("token-secret"),
        "url": "https://10.0.0.51:8006",
    })

    async def fake_guest_task_log(base_url, token_id, token_secret, node, vmid):
        assert node == "pve" and vmid == "100"
        return {"ok": True, "error": "", "text": "=== vzstart (OK) ==="}

    monkeypatch.setattr(proxmox_probe, "guest_task_log", fake_guest_task_log)

    response = client.get(f"/api/systems/{system['id']}/remote-containers/pve:lxc:100/logs?accountId=")

    assert response.status_code == 200
    assert "vzstart" in response.json()["text"]


def test_logs_journal_mode_requires_lxc_kind(client):
    system = db.create_system({"kind": "server", "name": "PVE-Host", "ip": "10.0.0.51"})
    db.create_account({
        "systemId": system["id"], "label": "Proxmox API", "category": "proxmox",
        "username": "root@pam!homeatlas", "url": "https://10.0.0.51:8006",
    })

    response = client.get(f"/api/systems/{system['id']}/remote-containers/pve:qemu:200/logs?accountId=&mode=journal")

    assert response.status_code == 400
    assert "LXC" in response.json()["detail"]


def test_logs_journal_mode_uses_ssh_journalctl(client, monkeypatch):
    system = db.create_system({"kind": "server", "name": "PVE-Host", "ip": "10.0.0.51"})
    db.create_account({
        "systemId": system["id"], "label": "Proxmox API", "category": "proxmox",
        "username": "root@pam!homeatlas", "url": "https://10.0.0.51:8006",
    })
    ssh_account = db.create_account({"systemId": system["id"], "label": "SSH", "category": "sshkey"})

    async def fake_journalctl(host, account_arg, vmid, port=0, lines=200):
        assert vmid == "100"
        return {"ok": True, "error": "", "text": "journal output"}

    monkeypatch.setattr(remote_admin, "run_remote_lxc_journalctl", fake_journalctl)

    response = client.get(
        f"/api/systems/{system['id']}/remote-containers/pve:lxc:100/logs?accountId={ssh_account['id']}&mode=journal"
    )

    assert response.status_code == 200
    assert response.json()["text"] == "journal output"


def test_logs_uses_remote_docker_path_for_a_non_proxmox_host(client, monkeypatch):
    system = db.create_system({"kind": "server", "name": "NAS", "ip": "10.0.0.52"})
    account = db.create_account({"systemId": system["id"], "label": "SSH", "category": "sshkey"})

    async def fake_logs(host, account_arg, container_id, port=0, tail=200):
        assert container_id == "abc123"
        return {"ok": True, "error": "", "text": "docker log output"}

    monkeypatch.setattr(remote_admin, "remote_container_logs", fake_logs)

    response = client.get(f"/api/systems/{system['id']}/remote-containers/abc123/logs?accountId={account['id']}")

    assert response.status_code == 200
    assert response.json()["text"] == "docker log output"
