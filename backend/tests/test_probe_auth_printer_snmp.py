import asyncio

from app import probe_auth


def _walk_line(base_oid: str, index: str, type_: str, value: str) -> str:
    return f".{base_oid}.{index} = {type_}: {value}"


def _type_walk(*entries: tuple[str, str]) -> str:
    """Builds a synthetic prtMarkerSuppliesType walk -- `entries` are (index, type) pairs, type
    given as the RFC 3805 integer string (e.g. "3" for toner, "9" for an OPC/drum unit)."""
    return "\n".join(_walk_line(probe_auth._PRINTER_MIB_TYPE_OID, index, "INTEGER", t) for index, t in entries)


def test_parse_printer_mib_maintenance_supplies_computes_percent_and_matches_by_index():
    descr = "\n".join([
        _walk_line(probe_auth._PRINTER_MIB_DESCR_OID, "1.1", "STRING", '"Drum Unit"'),
        _walk_line(probe_auth._PRINTER_MIB_DESCR_OID, "1.2", "STRING", '"Waste Toner Box"'),
    ])
    level = "\n".join([
        _walk_line(probe_auth._PRINTER_MIB_LEVEL_OID, "1.1", "INTEGER", "33"),
        _walk_line(probe_auth._PRINTER_MIB_LEVEL_OID, "1.2", "INTEGER", "-3"),  # RFC 3805 sentinel
    ])
    maxcap = "\n".join([
        _walk_line(probe_auth._PRINTER_MIB_MAX_OID, "1.1", "INTEGER", "70"),
        _walk_line(probe_auth._PRINTER_MIB_MAX_OID, "1.2", "INTEGER", "-2"),  # RFC 3805 sentinel
    ])
    type_ = _type_walk(("1.1", "9"), ("1.2", "4"))  # OPC/drum, wasteToner

    supplies = probe_auth.parse_printer_mib_maintenance_supplies(descr, level, maxcap, type_)

    assert supplies == [{"name": "Drum Unit", "percent": 47.1}]


def test_parse_printer_mib_maintenance_supplies_falls_back_to_index_when_description_missing():
    level = _walk_line(probe_auth._PRINTER_MIB_LEVEL_OID, "1.1", "INTEGER", "50")
    maxcap = _walk_line(probe_auth._PRINTER_MIB_MAX_OID, "1.1", "INTEGER", "100")
    type_ = _type_walk(("1.1", "9"))

    supplies = probe_auth.parse_printer_mib_maintenance_supplies("", level, maxcap, type_)

    assert supplies == [{"name": "Verbrauchsmaterial 1.1", "percent": 50.0}]


def test_parse_printer_mib_maintenance_supplies_excludes_toner_rows():
    descr = "\n".join([
        _walk_line(probe_auth._PRINTER_MIB_DESCR_OID, "1.1", "STRING", '"Black Toner"'),
        _walk_line(probe_auth._PRINTER_MIB_DESCR_OID, "1.2", "STRING", '"Drum Unit"'),
    ])
    level = "\n".join([
        _walk_line(probe_auth._PRINTER_MIB_LEVEL_OID, "1.1", "INTEGER", "80"),
        _walk_line(probe_auth._PRINTER_MIB_LEVEL_OID, "1.2", "INTEGER", "62"),
    ])
    maxcap = "\n".join([
        _walk_line(probe_auth._PRINTER_MIB_MAX_OID, "1.1", "INTEGER", "100"),
        _walk_line(probe_auth._PRINTER_MIB_MAX_OID, "1.2", "INTEGER", "100"),
    ])
    type_ = _type_walk(("1.1", "3"), ("1.2", "9"))

    assert probe_auth.parse_printer_mib_maintenance_supplies(descr, level, maxcap, type_) == [
        {"name": "Drum Unit", "percent": 62.0},
    ]


def test_parse_printer_mib_maintenance_supplies_keeps_rows_with_unknown_type():
    # Unlike toner (see merge_brother_toner_levels), maintenance has no gauge riding on type
    # certainty, so a row the Type walk never mentioned is still surfaced rather than dropped.
    level = _walk_line(probe_auth._PRINTER_MIB_LEVEL_OID, "1.1", "INTEGER", "50")
    maxcap = _walk_line(probe_auth._PRINTER_MIB_MAX_OID, "1.1", "INTEGER", "100")

    assert probe_auth.parse_printer_mib_maintenance_supplies("", level, maxcap, "") == [
        {"name": "Verbrauchsmaterial 1.1", "percent": 50.0},
    ]


def test_percent_from_level_capacity_rejects_negative_level_and_nonpositive_capacity():
    # -3 ("Toner niedrig") and -2 ("Normal/OK") are status codes, never a literal reading -- must
    # never be divided into a percentage no matter how "valid" the capacity looks.
    assert probe_auth._percent_from_level_capacity("-3", "100") is None
    assert probe_auth._percent_from_level_capacity("-2", "100") is None
    assert probe_auth._percent_from_level_capacity("50", "0") is None
    assert probe_auth._percent_from_level_capacity("50", "-2") is None
    assert probe_auth._percent_from_level_capacity(None, "100") is None
    assert probe_auth._percent_from_level_capacity("33", "70") == 47.1


def test_parse_brother_toner_reply_accepts_zero_as_syntactically_valid():
    # _parse_brother_toner_reply only checks "is this a real 0-100 integer" -- whether a 0 should
    # actually be trusted is merge_brother_toner_levels' decision, not this parser's.
    assert probe_auth._parse_brother_toner_reply("INTEGER: 0") == 0.0
    assert probe_auth._parse_brother_toner_reply("INTEGER: 74") == 74.0
    assert probe_auth._parse_brother_toner_reply("INTEGER: 200") is None
    assert probe_auth._parse_brother_toner_reply("INTEGER: -3") is None
    assert probe_auth._parse_brother_toner_reply("No Such Object available") is None
    assert probe_auth._parse_brother_toner_reply("") is None


def test_merge_brother_toner_levels_uses_direct_oid_when_nonzero():
    readings = {"Toner Schwarz": "INTEGER: 74"}
    supplies = probe_auth.merge_brother_toner_levels(readings, "", "", "")
    assert supplies == [{"name": "Toner Schwarz", "percent": 74.0}]


def test_merge_brother_toner_levels_falls_back_when_direct_oid_is_zero():
    """The reported bug: Magenta's direct Brother OID reads 0 even though the printer isn't
    actually out of magenta toner. A 0 (like a missing/unparseable reply) must trigger the
    Printer-MIB fallback for that colour, matched by "magenta" in the row's own description."""
    readings = {"Toner Magenta": "INTEGER: 0"}
    descr = _walk_line(probe_auth._PRINTER_MIB_DESCR_OID, "1.2", "STRING", '"Magenta Toner Cartridge"')
    level = _walk_line(probe_auth._PRINTER_MIB_LEVEL_OID, "1.2", "INTEGER", "63")
    maxcap = _walk_line(probe_auth._PRINTER_MIB_MAX_OID, "1.2", "INTEGER", "100")

    supplies = probe_auth.merge_brother_toner_levels(readings, descr, level, maxcap)

    assert supplies == [{"name": "Toner Magenta", "percent": 63.0}]


def test_merge_brother_toner_levels_falls_back_when_direct_oid_is_missing():
    readings = {"Toner Cyan": "No Such Object available"}
    descr = _walk_line(probe_auth._PRINTER_MIB_DESCR_OID, "2.1", "STRING", '"Cyan Toner Cartridge"')
    level = _walk_line(probe_auth._PRINTER_MIB_LEVEL_OID, "2.1", "INTEGER", "41")
    maxcap = _walk_line(probe_auth._PRINTER_MIB_MAX_OID, "2.1", "INTEGER", "100")

    supplies = probe_auth.merge_brother_toner_levels(readings, descr, level, maxcap)

    assert supplies == [{"name": "Toner Cyan", "percent": 41.0}]


def test_merge_brother_toner_levels_drops_colour_when_neither_source_has_data():
    readings = {"Toner Gelb": "INTEGER: 0"}
    supplies = probe_auth.merge_brother_toner_levels(readings, "", "", "")
    assert supplies == []


def test_merge_brother_toner_levels_one_bad_colour_does_not_hide_the_others():
    """Regression test for the exact bug report: Magenta misreads as 0 while Schwarz/Cyan/Gelb read
    correctly through their own direct OIDs -- all four colours must still come back."""
    readings = {
        "Toner Schwarz": "INTEGER: 74",
        "Toner Magenta": "INTEGER: 0",
        "Toner Cyan": "INTEGER: 88",
        "Toner Gelb": "INTEGER: 45",
    }
    descr = _walk_line(probe_auth._PRINTER_MIB_DESCR_OID, "1.2", "STRING", '"Magenta Toner Cartridge"')
    level = _walk_line(probe_auth._PRINTER_MIB_LEVEL_OID, "1.2", "INTEGER", "63")
    maxcap = _walk_line(probe_auth._PRINTER_MIB_MAX_OID, "1.2", "INTEGER", "100")

    supplies = probe_auth.merge_brother_toner_levels(readings, descr, level, maxcap)

    assert {s["name"]: s["percent"] for s in supplies} == {
        "Toner Schwarz": 74.0, "Toner Magenta": 63.0, "Toner Cyan": 88.0, "Toner Gelb": 45.0,
    }


def test_merge_brother_toner_levels_logs_the_raw_fallback_reading(caplog):
    readings = {"Toner Magenta": "INTEGER: 0"}
    descr = _walk_line(probe_auth._PRINTER_MIB_DESCR_OID, "1.2", "STRING", '"Magenta Toner Cartridge"')
    level = _walk_line(probe_auth._PRINTER_MIB_LEVEL_OID, "1.2", "INTEGER", "63")
    maxcap = _walk_line(probe_auth._PRINTER_MIB_MAX_OID, "1.2", "INTEGER", "100")

    with caplog.at_level("INFO", logger="homeatlas.probe_auth"):
        probe_auth.merge_brother_toner_levels(readings, descr, level, maxcap)

    assert len(caplog.records) == 1
    message = caplog.records[0].getMessage()
    assert "Toner Magenta" in message
    assert "Index=1.2" in message
    assert "Level=63" in message
    assert "MaxCapacity=100" in message
    assert "63.0%" in message


def test_merge_brother_toner_levels_logs_status_code_meaning():
    descr = _walk_line(probe_auth._PRINTER_MIB_DESCR_OID, "1.1", "STRING", '"Black Toner"')
    level = _walk_line(probe_auth._PRINTER_MIB_LEVEL_OID, "1.1", "INTEGER", "-3")
    maxcap = _walk_line(probe_auth._PRINTER_MIB_MAX_OID, "1.1", "INTEGER", "-2")

    assert probe_auth._describe_level("-3") == "-3 (Toner niedrig (Low))"
    assert probe_auth._describe_level("-2") == "-2 (Normal/OK)"
    assert probe_auth._describe_level("50") == "50"
    assert probe_auth._describe_level(None) == "kein Wert"

    # And end to end: a sentinel-only standard-MIB row still yields no percent, not a bogus one.
    supplies = probe_auth.merge_brother_toner_levels({"Toner Schwarz": "INTEGER: 0"}, descr, level, maxcap)
    assert supplies == []


def test_probe_snmp_prefers_direct_brother_oid_when_nonzero(monkeypatch):
    calls: list[tuple] = []

    async def fake_snmp_run(*args):
        calls.append(args)
        binary, oid = args[0], args[-1]
        if oid == "1.3.6.1.4.1.2435.2.3.9.4.2.1.5.5.8.0":  # Toner Schwarz
            return "INTEGER: 80"
        if oid == "1.3.6.1.2.1.1.5.0":
            return "sysName.0 = STRING: \"printer1\""
        return ""

    monkeypatch.setattr(probe_auth, "_snmp_run", fake_snmp_run)
    account = {"secretEnc": "", "port": 161}
    monkeypatch.setattr(probe_auth, "_decode_secret", lambda a: ("public", ""))

    result = asyncio.run(probe_auth.probe_snmp("10.0.0.5", account, kind="printer"))

    assert result["ok"]
    assert result["facts"]["printerSupplies"]["value"] == "- Toner Schwarz: 80.0%"
    # extract_printer_supplies (used by pipeline.py) must be able to read this fact back out.
    outcome = {"results": {"snmp:printer": result}}
    assert probe_auth.extract_printer_supplies(outcome) == [{"name": "Toner Schwarz", "percent": 80.0}]


def test_probe_snmp_falls_back_to_printer_mib_when_brother_oid_reads_zero(monkeypatch):
    """End-to-end regression test for the reported bug via the real probe_snmp entry point, not
    just the pure merge function."""
    async def fake_snmp_run(*args):
        oid = args[-1]
        if oid == probe_auth._PRINTER_MIB_DESCR_OID:
            return _walk_line(oid, "1.2", "STRING", '"Magenta Toner Cartridge"')
        if oid == probe_auth._PRINTER_MIB_LEVEL_OID:
            return _walk_line(oid, "1.2", "INTEGER", "63")
        if oid == probe_auth._PRINTER_MIB_MAX_OID:
            return _walk_line(oid, "1.2", "INTEGER", "100")
        if oid == "1.3.6.1.4.1.2435.2.3.9.4.2.1.5.5.9.0":  # Toner Magenta direct OID
            return "INTEGER: 0"
        if oid == "1.3.6.1.2.1.1.5.0":
            return "sysName.0 = STRING: \"printer1\""
        return ""

    monkeypatch.setattr(probe_auth, "_snmp_run", fake_snmp_run)
    monkeypatch.setattr(probe_auth, "_decode_secret", lambda a: ("public", ""))

    result = asyncio.run(probe_auth.probe_snmp("10.0.0.5", {"secretEnc": "", "port": 161}, kind="printer"))

    assert result["ok"]
    assert result["facts"]["printerSupplies"]["value"] == "- Toner Magenta: 63.0%"


def test_probe_snmp_reports_drum_and_belt_under_consumables_maintenance(monkeypatch):
    async def fake_snmp_run(*args):
        oid = args[-1]
        if oid == probe_auth._PRINTER_MIB_DESCR_OID:
            return "\n".join([
                _walk_line(oid, "1.1", "STRING", '"Drum Unit"'),
                _walk_line(oid, "1.2", "STRING", '"Belt Unit"'),
            ])
        if oid == probe_auth._PRINTER_MIB_LEVEL_OID:
            return "\n".join([_walk_line(oid, "1.1", "INTEGER", "70"), _walk_line(oid, "1.2", "INTEGER", "90")])
        if oid == probe_auth._PRINTER_MIB_MAX_OID:
            return "\n".join([_walk_line(oid, "1.1", "INTEGER", "100"), _walk_line(oid, "1.2", "INTEGER", "100")])
        if oid == probe_auth._PRINTER_MIB_TYPE_OID:
            return "\n".join([_walk_line(oid, "1.1", "INTEGER", "9"), _walk_line(oid, "1.2", "INTEGER", "20")])
        if oid == "1.3.6.1.2.1.1.5.0":
            return "sysName.0 = STRING: \"printer1\""
        return ""

    monkeypatch.setattr(probe_auth, "_snmp_run", fake_snmp_run)
    monkeypatch.setattr(probe_auth, "_decode_secret", lambda a: ("public", ""))

    result = asyncio.run(probe_auth.probe_snmp("10.0.0.5", {"secretEnc": "", "port": 161}, kind="printer"))

    assert result["ok"]
    assert "printerSupplies" not in result["facts"]  # no toner data anywhere for this device
    value = result["facts"]["consumablesMaintenance"]["value"]
    assert "- Drum Unit: 70.0%" in value
    assert "- Belt Unit: 90.0%" in value


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
    assert "consumablesMaintenance" not in result["facts"]
