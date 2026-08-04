"""Credential-profile assignments: one `accounts` row (an SSH key, SNMP community, API token, ...)
can apply to more than the single device its own `systemId` points at -- a whole device kind or a
subnet, in addition to specific further systems. list_probe_accounts is where a scan resolves that
back to "which credentials apply to this device" -- these tests cover both ends: writing/validating
assignments, and the resolution used at scan time."""
from app import db


def test_set_and_list_account_assignments(temp_db):
    system = temp_db.create_system({"kind": "server", "name": "Host-A", "ip": "10.0.0.5"})
    account = temp_db.create_account({"label": "Standard SSH-Key", "category": "sshkey", "allowProbe": 1})

    assignments = temp_db.set_account_assignments(account["id"], [
        {"targetType": "kind", "targetValue": "router"},
        {"targetType": "subnet", "targetValue": "192.168.1.0/24"},
        {"targetType": "system", "targetValue": system["id"]},
    ])

    assert len(assignments) == 3
    listed = temp_db.list_account_assignments(account["id"])
    assert {(a["targetType"], a["targetValue"]) for a in listed} == {
        ("kind", "router"), ("subnet", "192.168.1.0/24"), ("system", system["id"]),
    }


def test_set_account_assignments_replaces_the_whole_list(temp_db):
    account = temp_db.create_account({"label": "SNMP", "category": "snmp", "allowProbe": 1})
    temp_db.set_account_assignments(account["id"], [{"targetType": "kind", "targetValue": "network"}])

    temp_db.set_account_assignments(account["id"], [{"targetType": "kind", "targetValue": "printer"}])

    listed = temp_db.list_account_assignments(account["id"])
    assert [a["targetValue"] for a in listed] == ["printer"]


def test_set_account_assignments_drops_unparseable_subnet_and_unknown_type(temp_db):
    account = temp_db.create_account({"label": "SNMP", "category": "snmp", "allowProbe": 1})

    assignments = temp_db.set_account_assignments(account["id"], [
        {"targetType": "subnet", "targetValue": "not-a-cidr"},
        {"targetType": "bogus", "targetValue": "whatever"},
        {"targetType": "kind", "targetValue": ""},
        {"targetType": "kind", "targetValue": "router"},  # the only valid one
    ])

    assert len(assignments) == 1
    assert assignments[0]["targetType"] == "kind"
    assert assignments[0]["targetValue"] == "router"


def test_list_probe_accounts_includes_directly_attached_credential(temp_db):
    system = temp_db.create_system({"kind": "server", "name": "NAS", "ip": "10.0.0.10"})
    temp_db.create_account({"systemId": system["id"], "label": "Direkt", "category": "sshkey", "allowProbe": 1})

    accounts = temp_db.list_probe_accounts(system["id"])

    assert [a["label"] for a in accounts] == ["Direkt"]


def test_list_probe_accounts_includes_kind_assigned_credential(temp_db):
    switch = temp_db.create_system({"kind": "network", "name": "Switch-1", "ip": "10.0.0.20"})
    router = temp_db.create_system({"kind": "router", "name": "Router-1", "ip": "10.0.0.1"})
    account = temp_db.create_account({"label": "Aruba Switch Admin", "category": "login", "allowProbe": 1})
    temp_db.set_account_assignments(account["id"], [{"targetType": "kind", "targetValue": "network"}])

    assert [a["label"] for a in temp_db.list_probe_accounts(switch["id"])] == ["Aruba Switch Admin"]
    assert temp_db.list_probe_accounts(router["id"]) == []  # different kind, not assigned


def test_list_probe_accounts_includes_subnet_assigned_credential(temp_db):
    in_subnet = temp_db.create_system({"kind": "server", "name": "In-Subnet", "ip": "192.168.2.50"})
    outside = temp_db.create_system({"kind": "server", "name": "Outside", "ip": "192.168.3.50"})
    account = temp_db.create_account({"label": "Home-Lab-Netz", "category": "snmp", "allowProbe": 1})
    temp_db.set_account_assignments(account["id"], [{"targetType": "subnet", "targetValue": "192.168.2.0/24"}])

    assert [a["label"] for a in temp_db.list_probe_accounts(in_subnet["id"])] == ["Home-Lab-Netz"]
    assert temp_db.list_probe_accounts(outside["id"]) == []


def test_list_probe_accounts_includes_directly_assigned_additional_system(temp_db):
    system = temp_db.create_system({"kind": "printer", "name": "Drucker", "ip": "10.0.0.40"})
    account = temp_db.create_account({"label": "Proxmox API Token", "category": "proxmox", "allowProbe": 1})
    temp_db.set_account_assignments(account["id"], [{"targetType": "system", "targetValue": system["id"]}])

    assert [a["label"] for a in temp_db.list_probe_accounts(system["id"])] == ["Proxmox API Token"]


def test_list_probe_accounts_deduplicates_direct_and_assigned_and_ignores_allowprobe_off(temp_db):
    system = temp_db.create_system({"kind": "router", "name": "Router", "ip": "10.0.0.1"})
    same_credential = temp_db.create_account({
        "systemId": system["id"], "label": "Beides", "category": "login", "allowProbe": 1,
    })
    temp_db.set_account_assignments(same_credential["id"], [{"targetType": "kind", "targetValue": "router"}])
    not_cleared = temp_db.create_account({"label": "Nicht freigegeben", "category": "login", "allowProbe": 0})
    temp_db.set_account_assignments(not_cleared["id"], [{"targetType": "kind", "targetValue": "router"}])

    accounts = temp_db.list_probe_accounts(system["id"])

    assert [a["label"] for a in accounts] == ["Beides"]  # not duplicated, and the un-cleared one excluded


def test_list_probe_accounts_returns_empty_for_unknown_system(temp_db):
    assert temp_db.list_probe_accounts("does-not-exist") == []


def test_delete_account_removes_its_assignments(temp_db):
    system = temp_db.create_system({"kind": "router", "name": "Router", "ip": "10.0.0.1"})
    account = temp_db.create_account({"label": "Wird gelöscht", "category": "login", "allowProbe": 1})
    temp_db.set_account_assignments(account["id"], [{"targetType": "kind", "targetValue": "router"}])

    temp_db.delete_account(account["id"])

    assert temp_db.list_account_assignments(account["id"]) == []
    assert temp_db.list_probe_accounts(system["id"]) == []


def test_delete_system_removes_assignments_targeting_it_and_owned_by_its_accounts(temp_db):
    system_a = temp_db.create_system({"kind": "server", "name": "A", "ip": "10.0.0.5"})
    system_b = temp_db.create_system({"kind": "server", "name": "B", "ip": "10.0.0.6"})
    owned_account = temp_db.create_account({
        "systemId": system_a["id"], "label": "Von A", "category": "login", "allowProbe": 1,
    })
    temp_db.set_account_assignments(owned_account["id"], [{"targetType": "system", "targetValue": system_b["id"]}])
    other_account = temp_db.create_account({"label": "Fremd", "category": "login", "allowProbe": 1})
    temp_db.set_account_assignments(other_account["id"], [{"targetType": "system", "targetValue": system_a["id"]}])

    temp_db.delete_system(system_a["id"])

    # The deleted system's own account (and its assignments) is gone entirely.
    assert temp_db.get_account(owned_account["id"]) is None
    # An assignment on a *surviving* account that targeted the now-deleted system is cleaned up too.
    assert temp_db.list_account_assignments(other_account["id"]) == []


def test_count_assignments_by_account(temp_db):
    a = temp_db.create_account({"label": "A", "category": "login", "allowProbe": 1})
    b = temp_db.create_account({"label": "B", "category": "login", "allowProbe": 1})
    temp_db.set_account_assignments(a["id"], [
        {"targetType": "kind", "targetValue": "router"},
        {"targetType": "kind", "targetValue": "network"},
    ])

    counts = temp_db.count_assignments_by_account()

    assert counts[a["id"]] == 2
    assert b["id"] not in counts
