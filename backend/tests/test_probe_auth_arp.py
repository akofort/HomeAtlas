from app import probe_auth


def test_parse_arp_pairs_linux_ip_neigh():
    text = (
        "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
        "192.168.1.2 dev eth0 lladdr 11:22:33:44:55:66 STALE\n"
        "192.168.1.3 dev eth0  FAILED\n"
    )
    assert probe_auth.parse_arp_pairs(text) == {
        "192.168.1.1": "aa:bb:cc:dd:ee:ff",
        "192.168.1.2": "11:22:33:44:55:66",
    }


def test_parse_arp_pairs_arp_an_fallback():
    text = "? (192.168.1.5) at aa:bb:cc:dd:ee:ff [ether] on eth0\n"
    assert probe_auth.parse_arp_pairs(text) == {"192.168.1.5": "aa:bb:cc:dd:ee:ff"}


def test_parse_arp_pairs_mikrotik_print_detail():
    text = " 0   address=192.168.1.10 mac-address=AA:BB:CC:DD:EE:01 interface=bridge status=reachable\n"
    assert probe_auth.parse_arp_pairs(text) == {"192.168.1.10": "aa:bb:cc:dd:ee:01"}


def test_parse_arp_pairs_cisco_dotted_mac():
    text = "Internet  192.168.1.20          5   aabb.ccdd.eeff  ARPA   Vlan1\n"
    assert probe_auth.parse_arp_pairs(text) == {"192.168.1.20": "aa:bb:cc:dd:ee:ff"}


def test_parse_arp_pairs_aruba_dashed_hex_sextets():
    text = "192.168.1.30     aabbcc-ddeeff     dynamic  A1      1\n"
    assert probe_auth.parse_arp_pairs(text) == {"192.168.1.30": "aa:bb:cc:dd:ee:ff"}


def test_parse_arp_pairs_snmp_walk_space_separated_octets():
    text = "IP-MIB::ipNetToMediaPhysAddress.6.192.168.1.40 = STRING: aa bb cc dd ee ff\n"
    assert probe_auth.parse_arp_pairs(text) == {"192.168.1.40": "aa:bb:cc:dd:ee:ff"}


def test_parse_arp_pairs_ignores_broadcast_and_unspecified():
    text = (
        "0.0.0.0 dev eth0 lladdr aa:bb:cc:dd:ee:ff\n"
        "255.255.255.255 dev eth0 lladdr aa:bb:cc:dd:ee:ff\n"
    )
    assert probe_auth.parse_arp_pairs(text) == {}


def test_parse_arp_pairs_skips_header_and_separator_lines():
    text = (
        "IP Address      MAC Address       Type    Port    VLAN\n"
        "--------------- ----------------- ------- ------- ----\n"
        "192.168.1.30     aabbcc-ddeeff     dynamic  A1      1\n"
    )
    assert probe_auth.parse_arp_pairs(text) == {"192.168.1.30": "aa:bb:cc:dd:ee:ff"}


def test_extract_arp_entries_merges_across_facts_and_skips_failed_results():
    outcome = {
        "results": {
            "ssh:router": {"ok": True, "facts": {
                "arp_table": {"label": "ARP", "value": "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff\n"},
            }},
            "snmp:switch": {"ok": True, "facts": {
                "arpTable": {"label": "ARP", "value": "192.168.1.2 dev eth0 lladdr 11:22:33:44:55:66\n"},
            }},
            "ha:hub": {"ok": False, "facts": {}},
        }
    }
    assert probe_auth.extract_arp_entries(outcome) == {
        "192.168.1.1": "aa:bb:cc:dd:ee:ff",
        "192.168.1.2": "11:22:33:44:55:66",
    }


def test_extract_arp_entries_empty_outcome():
    assert probe_auth.extract_arp_entries({"results": {}}) == {}
