from app import omada_probe


def test_extract_uplink_nested_dict_field():
    assert omada_probe._extract_uplink({"uplink": {"mac": "AA:BB:CC:DD:EE:FF"}}) == "aa:bb:cc:dd:ee:ff"


def test_extract_uplink_flat_field_dashed():
    assert omada_probe._extract_uplink({"switchMac": "11-22-33-44-55-66"}) == "11:22:33:44:55:66"


def test_extract_uplink_prefers_nested_over_flat():
    device = {"uplink": {"deviceMac": "AA:BB:CC:DD:EE:01"}, "gatewayMac": "AA:BB:CC:DD:EE:02"}
    assert omada_probe._extract_uplink(device) == "aa:bb:cc:dd:ee:01"


def test_extract_uplink_missing_returns_empty():
    assert omada_probe._extract_uplink({"name": "AP", "mac": "AA:BB:CC:DD:EE:FF"}) == ""


def test_extract_uplink_ignores_malformed_mac():
    assert omada_probe._extract_uplink({"uplinkMac": "not-a-mac"}) == ""
