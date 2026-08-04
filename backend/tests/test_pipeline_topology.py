from app import pipeline


def test_tokens_lowercases_and_drops_short_words():
    assert pipeline._tokens("HP OfficeJet Pro 9010") == {"officejet", "pro", "9010"}


def test_match_printer_supplies_single_printer_gets_everything_unconditionally():
    # A single-printer household is the common case, and token matching has the most room to fail
    # when HA's own device name shares no words with the inventory entry at all.
    supplies = [{"name": "Unrelated HA Sensor Name", "percent": 50.0}]
    printers = [{"id": "p1", "name": "Buerodrucker", "vendor": "", "model": ""}]
    assert pipeline._match_printer_supplies(supplies, printers) == {"p1": supplies}


def test_match_printer_supplies_multiple_printers_uses_token_overlap():
    supplies = [
        {"name": "HP OfficeJet Pro 9010 Schwarz", "percent": 40.0},
        {"name": "Brother HL-L2350DW Toner", "percent": 10.0},
    ]
    printers = [
        {"id": "hp", "name": "HP OfficeJet Pro 9010", "vendor": "HP", "model": ""},
        {"id": "brother", "name": "Brother HL-L2350DW", "vendor": "Brother", "model": ""},
    ]
    result = pipeline._match_printer_supplies(supplies, printers)
    assert result["hp"] == [supplies[0]]
    assert result["brother"] == [supplies[1]]


def test_match_printer_supplies_unmatched_supply_is_dropped_not_misassigned():
    supplies = [{"name": "Completely Unrelated Name", "percent": 5.0}]
    printers = [
        {"id": "a", "name": "Canon Pixma", "vendor": "Canon", "model": ""},
        {"id": "b", "name": "Epson EcoTank", "vendor": "Epson", "model": ""},
    ]
    assert pipeline._match_printer_supplies(supplies, printers) == {}


def test_match_printer_supplies_no_printers_or_no_supplies_returns_empty():
    assert pipeline._match_printer_supplies([], [{"id": "a", "name": "x", "vendor": "", "model": ""}]) == {}
    assert pipeline._match_printer_supplies([{"name": "x", "percent": 1.0}], []) == {}


def test_link_omada_topology_resolves_uplink_mac_to_parent_id(temp_db):
    switch = temp_db.create_system({
        "kind": "network", "name": "Switch", "mac": "aa:aa:aa:aa:aa:01",
        "discoveryKey": "mac:aa:aa:aa:aa:aa:01",
    })
    ap = temp_db.create_system({
        "kind": "network", "name": "AP", "mac": "aa:aa:aa:aa:aa:02",
        "discoveryKey": "mac:aa:aa:aa:aa:aa:02",
        "extra": {"omada": {"uplinkMac": "aa:aa:aa:aa:aa:01"}},
    })
    unrelated = temp_db.create_system({
        "kind": "server", "name": "NAS", "mac": "aa:aa:aa:aa:aa:03",
        "discoveryKey": "mac:aa:aa:aa:aa:aa:03",
    })

    linked = pipeline._link_omada_topology()

    assert linked == 1
    assert temp_db.get_system(ap["id"])["parentId"] == switch["id"]
    assert temp_db.get_system(unrelated["id"])["parentId"] is None
    # Idempotent: running it again on an already-linked device must not count it a second time.
    assert pipeline._link_omada_topology() == 0


def test_assign_proxmox_parents_matches_guest_to_its_own_node(temp_db):
    pve1 = temp_db.create_system({"kind": "server", "name": "pve1", "hostname": "pve1"})
    pve2 = temp_db.create_system({"kind": "server", "name": "pve2", "hostname": "pve2"})
    guests = [
        {"name": "vm-on-1", "extra": {"proxmox": {"node": "pve1", "vmid": 100}}},
        {"name": "vm-on-2", "extra": {"proxmox": {"node": "pve2", "vmid": 200}}},
    ]

    pipeline._assign_proxmox_parents(guests, fallback_host_id="__fallback__")

    assert guests[0]["parentId"] == pve1["id"]
    assert guests[1]["parentId"] == pve2["id"]


def test_assign_proxmox_parents_falls_back_when_node_has_no_own_row(temp_db):
    # Single-node setup: the only row is whatever the credential is attached to, and every guest's
    # `node` is that same node -- there's nothing else in the inventory to match against.
    guests = [{"name": "vm", "extra": {"proxmox": {"node": "pve", "vmid": 100}}}]

    pipeline._assign_proxmox_parents(guests, fallback_host_id="host-1")

    assert guests[0]["parentId"] == "host-1"


def test_link_omada_topology_ignores_unresolvable_uplink(temp_db):
    orphan = temp_db.create_system({
        "kind": "network", "name": "Orphan AP", "mac": "bb:bb:bb:bb:bb:01",
        "discoveryKey": "mac:bb:bb:bb:bb:bb:01",
        "extra": {"omada": {"uplinkMac": "cc:cc:cc:cc:cc:99"}},  # no such device in the inventory
    })
    assert pipeline._link_omada_topology() == 0
    assert temp_db.get_system(orphan["id"])["parentId"] is None
