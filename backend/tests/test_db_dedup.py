"""Tests for db.py's cross-scheme dedup fallbacks (find_system_by_mac / find_system_by_proxmox /
find_system_by_ip_and_hostname / find_system_for_merge) and their integration into
upsert_discovered_system. Without these, a device found under one discoveryKey scheme by one
source (e.g. a network sweep that never resolved a MAC) and under a different scheme by another
(e.g. Proxmox, keyed by MAC) would silently duplicate instead of merging into the existing row."""
from app import db


def test_find_system_by_mac_matches_and_ignores_empty(temp_db):
    system = temp_db.create_system({"kind": "server", "name": "Host", "mac": "aa:bb:cc:dd:ee:ff"})
    assert temp_db.find_system_by_mac("aa:bb:cc:dd:ee:ff")["id"] == system["id"]
    assert temp_db.find_system_by_mac("AA:BB:CC:DD:EE:FF")["id"] == system["id"]  # case-insensitive
    assert temp_db.find_system_by_mac("") is None
    assert temp_db.find_system_by_mac("11:22:33:44:55:66") is None


def test_find_system_by_proxmox_matches_node_and_vmid_exactly(temp_db):
    vm = temp_db.create_system({
        "kind": "vm", "name": "VM101", "extra": {"proxmox": {"node": "pve", "vmid": 101}},
    })
    temp_db.create_system({
        "kind": "vm", "name": "VM102", "extra": {"proxmox": {"node": "pve", "vmid": 102}},
    })
    assert temp_db.find_system_by_proxmox("pve", 101)["id"] == vm["id"]
    assert temp_db.find_system_by_proxmox("pve", 999) is None
    assert temp_db.find_system_by_proxmox("other-node", 101) is None
    assert temp_db.find_system_by_proxmox("", 101) is None
    assert temp_db.find_system_by_proxmox("pve", None) is None


def test_find_system_by_ip_and_hostname_requires_both(temp_db):
    system = temp_db.create_system({
        "kind": "pc", "name": "Laptop", "ip": "10.0.0.20", "hostname": "laptop.local",
    })
    assert temp_db.find_system_by_ip_and_hostname("10.0.0.20", "laptop.local")["id"] == system["id"]
    assert temp_db.find_system_by_ip_and_hostname("10.0.0.20", "other.local") is None
    assert temp_db.find_system_by_ip_and_hostname("10.0.0.99", "laptop.local") is None
    assert temp_db.find_system_by_ip_and_hostname("", "laptop.local") is None


def test_find_system_for_merge_prefers_mac_over_proxmox_over_ip_hostname(temp_db):
    by_mac = temp_db.create_system({"kind": "vm", "name": "ByMac", "mac": "aa:aa:aa:aa:aa:aa"})
    temp_db.create_system({
        "kind": "vm", "name": "ByProxmox", "extra": {"proxmox": {"node": "pve", "vmid": 1}},
    })
    # A finding that could match either the MAC row or the Proxmox row must resolve to MAC, since
    # that is the strongest/most trustworthy identity of the three.
    found = {"mac": "aa:aa:aa:aa:aa:aa", "extra": {"proxmox": {"node": "pve", "vmid": 1}}}
    assert temp_db.find_system_for_merge(found)["id"] == by_mac["id"]


def test_upsert_merges_proxmox_guest_whose_key_scheme_flipped_to_mac(temp_db):
    """The concrete bug: proxmox_probe.probe's discoveryKey is `proxmox:<node>:<kind>:<vmid>` when
    net0 has no parseable MAC, and `mac:<mac>` once it does -- the same guest, same vmid, flips
    between the two across scans. Without find_system_for_merge, the second scan's exact-key
    lookup misses and the guest duplicates instead of updating."""
    first_scan = {
        "discoveryKey": "proxmox:pve:vm:101", "kind": "vm", "name": "nextcloud",
        "mac": "", "ip": "", "extra": {"proxmox": {"node": "pve", "vmid": 101}},
    }
    system, created = db.upsert_discovered_system(first_scan)
    assert created

    second_scan = {
        "discoveryKey": "mac:aa:bb:cc:dd:ee:ff", "kind": "vm", "name": "nextcloud",
        "mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.50",
        "extra": {"proxmox": {"node": "pve", "vmid": 101}},
    }
    merged, created_again = db.upsert_discovered_system(second_scan)

    assert not created_again
    assert merged["id"] == system["id"]
    assert merged["mac"] == "aa:bb:cc:dd:ee:ff"
    assert merged["discoveryKey"] == "mac:aa:bb:cc:dd:ee:ff"
    assert len(db.list_systems()) == 1  # no duplicate row


def test_upsert_merges_device_found_by_ip_only_then_by_mac_via_ip_hostname_match(temp_db):
    """A hand-created (confirmed) entry with just an address and hostname, later re-discovered by
    a network scan that resolves a MAC (e.g. a phone's privacy MAC rotated, so it's a "new" MAC
    the discoveryKey scheme has never seen for this device) -- ip+hostname is the only identity
    that still lines up."""
    hand_created = db.create_system({
        "kind": "mobile", "name": "Handy", "ip": "10.0.0.40", "hostname": "handy.local",
        "confirmed": 1, "discoveryKey": "",
    })

    rediscovered = {
        "discoveryKey": "mac:11:22:33:44:55:66", "kind": "mobile", "name": "Handy",
        "mac": "11:22:33:44:55:66", "ip": "10.0.0.40", "hostname": "handy.local",
    }
    merged, created = db.upsert_discovered_system(rediscovered)

    assert not created
    assert merged["id"] == hand_created["id"]
    assert merged["mac"] == "11:22:33:44:55:66"
    assert len(db.list_systems()) == 1


def test_upsert_does_not_merge_unrelated_devices(temp_db):
    db.create_system({"kind": "pc", "name": "PC1", "ip": "10.0.0.1", "hostname": "pc1"})
    finding = {
        "discoveryKey": "mac:99:99:99:99:99:99", "kind": "pc", "name": "PC2",
        "mac": "99:99:99:99:99:99", "ip": "10.0.0.2", "hostname": "pc2",
    }
    _, created = db.upsert_discovered_system(finding)
    assert created
    assert len(db.list_systems()) == 2
