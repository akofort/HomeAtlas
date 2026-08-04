"""main._proxmox_account is the single signal that routes list_remote_containers (and its action/
console counterparts) away from the Docker path for a Proxmox host -- see remote_admin.py's
list_remote_proxmox_guests and proxmox_probe.list_guests for what that routing avoids
("bash: line 1: docker: command not found")."""
from app import main


def test_proxmox_account_found_when_attached_to_system(temp_db):
    system = temp_db.create_system({"kind": "server", "name": "PVE-Host", "ip": "10.0.0.30"})
    temp_db.create_account({
        "systemId": system["id"], "label": "Proxmox API", "category": "proxmox",
        "username": "root@pam!homeatlas", "url": "https://10.0.0.30:8006",
    })

    account = main._proxmox_account(system["id"])

    assert account is not None
    assert account["category"] == "proxmox"


def test_proxmox_account_none_for_a_plain_docker_host(temp_db):
    system = temp_db.create_system({"kind": "server", "name": "NAS", "ip": "10.0.0.31"})
    temp_db.create_account({
        "systemId": system["id"], "label": "SSH", "category": "sshkey",
    })

    assert main._proxmox_account(system["id"]) is None


def test_proxmox_account_ignores_accounts_on_other_systems(temp_db):
    proxmox_host = temp_db.create_system({"kind": "server", "name": "PVE-Host", "ip": "10.0.0.32"})
    other_host = temp_db.create_system({"kind": "server", "name": "NAS", "ip": "10.0.0.33"})
    temp_db.create_account({
        "systemId": proxmox_host["id"], "label": "Proxmox API", "category": "proxmox",
        "username": "root@pam!homeatlas", "url": "https://10.0.0.32:8006",
    })

    assert main._proxmox_account(other_host["id"]) is None
