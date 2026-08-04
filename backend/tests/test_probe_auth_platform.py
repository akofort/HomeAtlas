from app import probe_auth


def _system(vendor="", model="", name="", os_="") -> dict:
    return {"vendor": vendor, "model": model, "name": name, "os": os_}


def test_detect_platform_mikrotik():
    assert probe_auth._detect_platform(_system(vendor="MikroTik")) == "mikrotik"


def test_detect_platform_aruba():
    assert probe_auth._detect_platform(_system(vendor="Aruba Networks")) == "aruba"


def test_detect_platform_hp_procurve_maps_to_aruba():
    # ArubaOS-Switch is the renamed HP ProCurve CLI -- older/relabelled hardware still reports
    # "HP"/"Hewlett Packard"/"ProCurve" rather than "Aruba".
    assert probe_auth._detect_platform(_system(vendor="Hewlett Packard", model="ProCurve 2810")) == "aruba"
    assert probe_auth._detect_platform(_system(vendor="HP", model="J9019A")) == "aruba"


def test_detect_platform_cisco():
    assert probe_auth._detect_platform(_system(vendor="Cisco", model="Catalyst 2960")) == "cisco"


def test_detect_platform_tplink_jetstream():
    assert probe_auth._detect_platform(_system(vendor="TP-Link", model="T1600G-28TS JetStream")) == "tplink"
    assert probe_auth._detect_platform(_system(name="Omada JetStream switch")) == "tplink"


def test_detect_platform_unknown_vendor_falls_back_to_generic():
    assert probe_auth._detect_platform(_system(vendor="Synology", model="DS920+")) == ""


def test_detect_platform_hp_word_boundary_does_not_match_substring():
    # "hp" must match as a whole word, not as a substring of an unrelated vendor string.
    assert probe_auth._detect_platform(_system(vendor="Shpock GmbH")) == ""
