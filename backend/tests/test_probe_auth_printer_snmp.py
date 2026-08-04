import asyncio

from app import probe_auth


def _walk_line(base_oid: str, index: str, type_: str, value: str) -> str:
    return f".{base_oid}.{index} = {type_}: {value}"


def test_parse_printer_mib_supplies_computes_percent_and_matches_by_index():
    descr = "\n".join([
        _walk_line(probe_auth._PRINTER_MIB_DESCR_OID, "1.1", "STRING", '"Black Toner Cartridge"'),
        _walk_line(probe_auth._PRINTER_MIB_DESCR_OID, "1.2", "STRING", '"Cyan Toner Cartridge"'),
    ])
    level = "\n".join([
        _walk_line(probe_auth._PRINTER_MIB_LEVEL_OID, "1.1", "INTEGER", "33"),
        _walk_line(probe_auth._PRINTER_MIB_LEVEL_OID, "1.2", "INTEGER", "-3"),  # RFC 3805 "not used"
    ])
    maxcap = "\n".join([
        _walk_line(probe_auth._PRINTER_MIB_MAX_OID, "1.1", "INTEGER", "70"),
        _walk_line(probe_auth._PRINTER_MIB_MAX_OID, "1.2", "INTEGER", "-2"),  # RFC 3805 "unrestricted"
    ])

    supplies = probe_auth.parse_printer_mib_supplies(descr, level, maxcap)

    assert supplies == [{"name": "Black Toner Cartridge", "percent": 47.1}]


def test_parse_printer_mib_supplies_falls_back_to_index_when_description_missing():
    level = _walk_line(probe_auth._PRINTER_MIB_LEVEL_OID, "1.1", "INTEGER", "50")
    maxcap = _walk_line(probe_auth._PRINTER_MIB_MAX_OID, "1.1", "INTEGER", "100")

    supplies = probe_auth.parse_printer_mib_supplies("", level, maxcap)

    assert supplies == [{"name": "Verbrauchsmaterial 1.1", "percent": 50.0}]


def test_parse_printer_mib_supplies_returns_nothing_for_all_sentinel_values():
    level = _walk_line(probe_auth._PRINTER_MIB_LEVEL_OID, "1.1", "INTEGER", "-3")
    maxcap = _walk_line(probe_auth._PRINTER_MIB_MAX_OID, "1.1", "INTEGER", "-2")

    assert probe_auth.parse_printer_mib_supplies("", level, maxcap) == []


def _brother_hex(*records: tuple[int, int], trailing_padding: bool = True) -> str:
    """Builds a synthetic brInfoMaintenance blob: each (record_id, percent_hundredths) becomes one
    7-byte record (id, 01 04 marker, 4-byte big-endian value), separated by 3 bytes of 0xFF
    padding, per `parse_brother_maintenance`'s documented layout."""
    parts: list[str] = []
    for record_id, value in records:
        value_bytes = " ".join(f"{b:02x}" for b in value.to_bytes(4, "big"))
        parts.append(f"{record_id:02x} 01 04 {value_bytes}")
    body = " ff ff ff ".join(parts)
    if trailing_padding:
        body += " ff ff ff ff"
    return f"Hex-STRING: {body}"


def test_parse_brother_maintenance_decodes_percent_records():
    hex_text = _brother_hex((1, 9700), (2, 4500))

    supplies = probe_auth.parse_brother_maintenance(hex_text)

    assert supplies == [
        {"name": "Verbrauchsmaterial 1", "percent": 97.0},
        {"name": "Verbrauchsmaterial 2", "percent": 45.0},
    ]


def test_parse_brother_maintenance_drops_records_with_wrong_marker():
    # Second record's marker bytes are "02 09" instead of the expected "01 04" -- unrecognised
    # layout, dropped rather than misread as a percentage.
    hex_text = "Hex-STRING: 01 01 04 00 00 25 e4 ff ff ff 02 02 09 00 00 11 94 ff ff ff ff"

    supplies = probe_auth.parse_brother_maintenance(hex_text)

    assert supplies == [{"name": "Verbrauchsmaterial 1", "percent": 97.0}]


def test_parse_brother_maintenance_drops_out_of_range_percent():
    # 999900 hundredths would decode to 9999.0%, well outside a sane 0-100% reading.
    hex_text = _brother_hex((1, 999900))

    assert probe_auth.parse_brother_maintenance(hex_text) == []


def test_parse_brother_maintenance_returns_nothing_for_non_hex_reply():
    assert probe_auth.parse_brother_maintenance('STRING: "No Such Object"') == []
    assert probe_auth.parse_brother_maintenance("") == []


def test_probe_snmp_adds_printer_supplies_fact_for_printer_kind(monkeypatch):
    calls: list[tuple] = []

    async def fake_snmp_run(*args):
        calls.append(args)
        binary, oid = args[0], args[-1]
        if oid == probe_auth._PRINTER_MIB_DESCR_OID:
            return _walk_line(oid, "1.1", "STRING", '"Black Toner"')
        if oid == probe_auth._PRINTER_MIB_LEVEL_OID:
            return _walk_line(oid, "1.1", "INTEGER", "80")
        if oid == probe_auth._PRINTER_MIB_MAX_OID:
            return _walk_line(oid, "1.1", "INTEGER", "100")
        if oid == "1.3.6.1.2.1.1.5.0":
            return "sysName.0 = STRING: \"printer1\""
        return ""

    monkeypatch.setattr(probe_auth, "_snmp_run", fake_snmp_run)
    account = {"secretEnc": "", "port": 161}
    monkeypatch.setattr(probe_auth, "_decode_secret", lambda a: ("public", ""))

    result = asyncio.run(probe_auth.probe_snmp("10.0.0.5", account, kind="printer"))

    assert result["ok"]
    assert result["facts"]["printerSupplies"]["value"] == "- Black Toner: 80.0%"
    # extract_printer_supplies (used by pipeline.py) must be able to read this fact back out.
    outcome = {"results": {"snmp:printer": result}}
    assert probe_auth.extract_printer_supplies(outcome) == [{"name": "Black Toner", "percent": 80.0}]


def test_probe_snmp_skips_printer_supplies_for_non_printer_kind(monkeypatch):
    async def fake_snmp_run(*args):
        oid = args[-1]
        if oid == "1.3.6.1.2.1.1.5.0":
            return "sysName.0 = STRING: \"switch1\""
        return ""

    monkeypatch.setattr(probe_auth, "_snmp_run", fake_snmp_run)
    monkeypatch.setattr(probe_auth, "_decode_secret", lambda a: ("public", ""))

    result = asyncio.run(probe_auth.probe_snmp("10.0.0.6", {"secretEnc": "", "port": 161}, kind="switch"))

    assert result["ok"]
    assert "printerSupplies" not in result["facts"]
