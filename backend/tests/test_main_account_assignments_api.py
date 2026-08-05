"""Light HTTP-level smoke tests for the new routes -- the underlying logic (db.list_probe_accounts'
merge, proxmox_probe.list_guests, remote_admin.list_remote_proxmox_guests) already has its own
focused unit tests; these exist to catch wiring mistakes in main.py itself (route path, request/
response shape, the "proxmox host never gets a docker command" guard) that only show up when the
whole request/response cycle runs."""
import pytest
from fastapi.testclient import TestClient

from app import auth, crypto, db, main, proxmox_probe


@pytest.fixture()
def client(temp_db, tmp_path, monkeypatch):
    # crypto._fernet() lazily creates/reads a key file next to the (real, non-test) DB by default
    # -- redirected into the same throwaway tmp_path temp_db already isolates everything else into.
    monkeypatch.setattr(crypto, "_KEY_PATH", tmp_path / "secret.key")
    monkeypatch.setattr(crypto, "_cached", None)
    main.app.dependency_overrides[main.require_admin] = lambda: {"role": auth.ROLE_ADMIN, "username": "admin"}
    try:
        yield TestClient(main.app)
    finally:
        main.app.dependency_overrides.clear()


def test_assignment_round_trip(client):
    account = db.create_account({"label": "Aruba Switch Admin", "category": "login", "allowProbe": 1})

    put_response = client.put(
        f"/api/accounts/{account['id']}/assignments",
        json=[{"targetType": "kind", "targetValue": "network"}],
    )
    assert put_response.status_code == 200
    assert put_response.json()["assignments"][0]["targetValue"] == "network"

    get_response = client.get(f"/api/accounts/{account['id']}/assignments")
    assert get_response.status_code == 200
    assert len(get_response.json()["assignments"]) == 1

    listing = client.get("/api/accounts").json()["accounts"]
    assert next(a for a in listing if a["id"] == account["id"])["assignmentCount"] == 1
    # Never a plaintext secret anywhere in the list response.
    assert all("secretEnc" not in a and "passphraseEnc" not in a for a in listing)


def test_assignments_404_for_unknown_account(client):
    assert client.get("/api/accounts/does-not-exist/assignments").status_code == 404
    assert client.put("/api/accounts/does-not-exist/assignments", json=[]).status_code == 404


def test_remote_containers_uses_proxmox_rest_path_without_needing_an_ssh_account(client, monkeypatch):
    system = db.create_system({"kind": "server", "name": "PVE-Host", "ip": "10.0.0.50"})
    db.create_account({
        "systemId": system["id"], "label": "Proxmox API", "category": "proxmox",
        "username": "root@pam!homeatlas", "secretEnc": crypto.encrypt("token-secret"),
        "url": "https://10.0.0.50:8006",
    })

    async def fake_list_guests(base_url, token_id, token_secret):
        return {"ok": True, "error": "", "containers": [
            {"id": "pve:lxc:100", "name": "pihole", "image": "LXC-Container · Node pve",
             "state": "running", "status": "running", "ip": "10.0.0.60", "node": "pve",
             "vmid": "100", "kind": "container"},
        ]}

    monkeypatch.setattr(proxmox_probe, "list_guests", fake_list_guests)

    response = client.get(f"/api/systems/{system['id']}/remote-containers")

    assert response.status_code == 200
    body = response.json()
    assert body["proxmoxUrl"] == "https://10.0.0.50:8006"
    assert body["containers"][0]["id"] == "pve:lxc:100"
    assert "/" not in body["containers"][0]["id"]


def test_remote_container_action_routes_to_proxmox_and_never_docker(client, monkeypatch):
    system = db.create_system({"kind": "server", "name": "PVE-Host", "ip": "10.0.0.51"})
    db.create_account({
        "systemId": system["id"], "label": "Proxmox API", "category": "proxmox",
        "username": "root@pam!homeatlas", "secretEnc": crypto.encrypt("token-secret"),
        "url": "https://10.0.0.51:8006",
    })

    from app import proxmox_admin, remote_admin

    seen = {}

    async def fake_guest_action(base_url, token_id, token_secret, node, kind, vmid, action):
        seen.update(node=node, kind=kind, vmid=vmid, action=action)
        return {"ok": True, "error": ""}

    async def fail_if_called(*args, **kwargs):
        raise AssertionError("a Proxmox host must never run a Docker command")

    monkeypatch.setattr(proxmox_admin, "guest_action", fake_guest_action)
    monkeypatch.setattr(remote_admin, "run_remote_docker_command", fail_if_called)

    response = client.post(f"/api/systems/{system['id']}/remote-containers/pve:lxc:100/start?accountId=")

    assert response.status_code == 200
    assert seen == {"node": "pve", "kind": "container", "vmid": "100", "action": "start"}


def test_remote_container_action_rejects_a_malformed_guest_id_for_proxmox_host(client):
    system = db.create_system({"kind": "server", "name": "PVE-Host", "ip": "10.0.0.51"})
    db.create_account({
        "systemId": system["id"], "label": "Proxmox API", "category": "proxmox",
        "username": "root@pam!homeatlas", "url": "https://10.0.0.51:8006",
    })

    response = client.post(f"/api/systems/{system['id']}/remote-containers/100/start?accountId=")

    assert response.status_code == 400
    assert "Ungültige" in response.json()["detail"]


def test_remote_containers_still_uses_docker_path_for_a_non_proxmox_host(client, monkeypatch):
    system = db.create_system({"kind": "server", "name": "NAS", "ip": "10.0.0.52"})
    account = db.create_account({
        "systemId": system["id"], "label": "SSH", "category": "sshkey", "allowProbe": 1,
    })

    async def fake_list_remote_containers(host, account_arg, port=0):
        assert host == "10.0.0.52"
        return {"ok": True, "error": "", "containers": [
            {"id": "abc123", "name": "app", "image": "myapp:latest", "state": "running", "status": "Up 2 hours"},
        ]}

    from app import remote_admin
    monkeypatch.setattr(remote_admin, "list_remote_containers", fake_list_remote_containers)

    response = client.get(f"/api/systems/{system['id']}/remote-containers?accountId={account['id']}")

    assert response.status_code == 200
    body = response.json()
    assert body["containers"][0]["name"] == "app"
    assert body["proxmoxUrl"] == ""
