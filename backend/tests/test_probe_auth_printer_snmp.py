import asyncio

from app import probe_auth


def _walk_line(base_oid: str, index: str, type_: str, value: str) -> str:
    return f".{base_oid}.{index} = {type_}: {value}"


def _type_walk(*entries: tuple[str, str]) -> str:
    """Builds a synthetic prtMarkerSuppliesType walk -- `entries` are (index, type) pairs, type
    given as the RFC 3805 integer string (e.g. "3" for toner, "9" for an OPC/drum unit)."""
    return "\n".join(_walk_line(probe_auth._PRINTER_MIB_TYPE_OID, index, "INTEGER", t) for index, t in entries)


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
    type_ = _type_walk(("1.1", "3"), ("1.2", "3"))

    supplies = probe_auth.parse_printer_mib_supplies(descr, level, maxcap, type_)

    assert supplies == [{"name": "Black Toner Cartridge", "percent": 47.1}]


def test_parse_printer_mib_supplies_falls_back_to_index_when_description_missing():
    level = _walk_line(probe_auth._PRINTER_MIB_LEVEL_OID, "1.1", "INTEGER", "50")
    maxcap = _walk_line(probe_auth._PRINTER_MIB_MAX_OID, "1.1", "INTEGER", "100")
    type_ = _type_walk(("1.1", "3"))

    supplies = probe_auth.parse_printer_mib_supplies("", level, maxcap, type_)

    assert supplies == [{"name": "Verbrauchsmaterial 1.1", "percent": 50.0}]


def test_parse_printer_mib_supplies_returns_nothing_for_all_sentinel_values():
    level = _walk_line(probe_auth._PRINTER_MIB_LEVEL_OID, "1.1", "INTEGER", "-3")
    maxcap = _walk_line(probe_auth._PRINTER_MIB_MAX_OID, "1.1", "INTEGER", "-2")
    type_ = _type_walk(("1.1", "3"))

    assert probe_auth.parse_printer_mib_supplies("", level, maxcap, type_) == []


def test_parse_printer_mib_supplies_excludes_drum_and_belt_rows():
    """Regression test: a printer that reports real percentages for its drum unit and transfer
    belt through the standard table -- while its actual toner rows sit at RFC 3805 sentinels, as
    real Brother firmware does -- must not have those non-toner rows show up as "toner"."""
    descr = "\n".join([
        _walk_line(probe_auth._PRINTER_MIB_DESCR_OID, "1.1", "STRING", '"Black Toner"'),
        _walk_line(probe_auth._PRINTER_MIB_DESCR_OID, "1.2", "STRING", '"Drum Unit"'),
        _walk_line(probe_auth._PRINTER_MIB_DESCR_OID, "1.3", "STRING", '"Belt Unit"'),
    ])
    level = "\n".join([
        _walk_line(probe_auth._PRINTER_MIB_LEVEL_OID, "1.1", "INTEGER", "-3"),  # sentinel
        _walk_line(probe_auth._PRINTER_MIB_LEVEL_OID, "1.2", "INTEGER", "62"),
        _walk_line(probe_auth._PRINTER_MIB_LEVEL_OID, "1.3", "INTEGER", "81"),
    ])
    maxcap = "\n".join([
        _walk_line(probe_auth._PRINTER_MIB_MAX_OID, "1.1", "INTEGER", "-2"),  # sentinel
        _walk_line(probe_auth._PRINTER_MIB_MAX_OID, "1.2", "INTEGER", "100"),
        _walk_line(probe_auth._PRINTER_MIB_MAX_OID, "1.3", "INTEGER", "100"),
    ])
    type_ = _type_walk(("1.1", "3"), ("1.2", "9"), ("1.3", "20"))  # toner, OPC/drum, transferUnit

    assert probe_auth.parse_printer_mib_supplies(descr, level, maxcap, type_) == []

    maintenance = probe_auth.parse_printer_mib_maintenance_supplies(descr, level, maxcap, type_)
    assert maintenance == [
        {"name": "Drum Unit", "percent": 62.0},
        {"name": "Belt Unit", "percent": 81.0},
    ]


def test_parse_printer_mib_supplies_excludes_rows_with_unknown_type():
    """A row this device's Type walk never mentioned at all must not be assumed to be toner --
    "strictly" filtered means excluded by default, not included by default."""
    level = _walk_line(probe_auth._PRINTER_MIB_LEVEL_OID, "1.1", "INTEGER", "50")
    maxcap = _walk_line(probe_auth._PRINTER_MIB_MAX_OID, "1.1", "INTEGER", "100")

    assert probe_auth.parse_printer_mib_supplies("", level, maxcap, "") == []
    # ...but maintenance (which never claims to be a toner reading) still surfaces it.
    assert probe_auth.parse_printer_mib_maintenance_supplies("", level, maxcap, "") == [
        {"name": "Verbrauchsmaterial 1.1", "percent": 50.0},
    ]


def test_parse_brother_toner_levels_reads_each_colour_by_label():
    readings = {
        "Toner Schwarz": "SNMPv2-SMI::enterprises.2435.2.3.9.4.2.1.5.5.8.0 = INTEGER: 74",
        "Toner Magenta": "SNMPv2-SMI::enterprises.2435.2.3.9.4.2.1.5.5.9.0 = INTEGER: 61",
        "Toner Cyan": "SNMPv2-SMI::enterprises.2435.2.3.9.4.2.1.5.5.10.0 = INTEGER: 88",
        "Toner Gelb": "SNMPv2-SMI::enterprises.2435.2.3.9.4.2.1.5.5.11.0 = INTEGER: 45",
    }

    supplies = probe_auth.parse_brother_toner_levels(readings)

    assert supplies == [
        {"name": "Toner Schwarz", "percent": 74.0},
        {"name": "Toner Magenta", "percent": 61.0},
        {"name": "Toner Cyan", "percent": 88.0},
        {"name": "Toner Gelb", "percent": 45.0},
    ]


def test_parse_brother_toner_levels_skips_missing_or_out_of_range_readings():
    readings = {
        "Toner Schwarz": "SNMPv2-SMI::enterprises.2435.2.3.9.4.2.1.5.5.8.0 = No Such Object available",
        "Toner Magenta": "SNMPv2-SMI::enterprises.2435.2.3.9.4.2.1.5.5.9.0 = INTEGER: 200",
        "Toner Cyan": "",
        "Toner Gelb": "SNMPv2-SMI::enterprises.2435.2.3.9.4.2.1.5.5.11.0 = INTEGER: 12",
    }

    assert probe_auth.parse_brother_toner_levels(readings) == [{"name": "Toner Gelb", "percent": 12.0}]


def test_probe_snmp_prefers_standard_mib_toner_when_usable(monkeypatch):
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
        if oid == probe_auth._PRINTER_MIB_TYPE_OID:
            return _walk_line(oid, "1.1", "INTEGER", "3")
        if oid == "1.3.6.1.2.1.1.5.0":
            return "sysName.0 = STRING: \"printer1\""
        return ""

    monkeypatch.setattr(probe_auth, "_snmp_run", fake_snmp_run)
    account = {"secretEnc": "", "port": 161}
    monkeypatch.setattr(probe_auth, "_decode_secret", lambda a: ("public", ""))

    result = asyncio.run(probe_auth.probe_snmp("10.0.0.5", account, kind="printer"))

    assert result["ok"]
    assert result["facts"]["printerSupplies"]["value"] == "- Black Toner: 80.0%"
    # No Brother OID was ever queried since the standard table already had usable toner data.
    assert not any(str(call[-1]).startswith("1.3.6.1.4.1.2435") for call in calls)
    # extract_printer_supplies (used by pipeline.py) must be able to read this fact back out.
    outcome = {"results": {"snmp:printer": result}}
    assert probe_auth.extract_printer_supplies(outcome) == [{"name": "Black Toner", "percent": 80.0}]


def test_probe_snmp_falls_back_to_brother_oids_when_standard_toner_rows_are_sentinels(monkeypatch):
    """The real-world bug this guards against: a printer whose standard Printer-MIB table reports
    genuine drum/belt percentages (so the table isn't empty) but leaves toner at RFC 3805
    sentinels -- the old code treated "the table returned *something*" as "toner is covered" and
    never tried the Brother fallback at all."""
    async def fake_snmp_run(*args):
        binary, oid = args[0], args[-1]
        if oid == probe_auth._PRINTER_MIB_DESCR_OID:
            return "\n".join([
                _walk_line(oid, "1.1", "STRING", '"Black Toner"'),
                _walk_line(oid, "1.2", "STRING", '"Drum Unit"'),
            ])
        if oid == probe_auth._PRINTER_MIB_LEVEL_OID:
            return "\n".join([
                _walk_line(oid, "1.1", "INTEGER", "-3"),
                _walk_line(oid, "1.2", "INTEGER", "70"),
            ])
        if oid == probe_auth._PRINTER_MIB_MAX_OID:
            return "\n".join([
                _walk_line(oid, "1.1", "INTEGER", "-2"),
                _walk_line(oid, "1.2", "INTEGER", "100"),
            ])
        if oid == probe_auth._PRINTER_MIB_TYPE_OID:
            return "\n".join([_walk_line(oid, "1.1", "INTEGER", "3"), _walk_line(oid, "1.2", "INTEGER", "9")])
        if oid == "1.3.6.1.4.1.2435.2.3.9.4.2.1.5.5.8.0":
            return f"{oid} = INTEGER: 55"
        if oid == "1.3.6.1.2.1.1.5.0":
            return "sysName.0 = STRING: \"printer1\""
        return ""

    monkeypatch.setattr(probe_auth, "_snmp_run", fake_snmp_run)
    monkeypatch.setattr(probe_auth, "_decode_secret", lambda a: ("public", ""))

    result = asyncio.run(probe_auth.probe_snmp("10.0.0.5", {"secretEnc": "", "port": 161}, kind="printer"))

    assert result["ok"]
    assert result["facts"]["printerSupplies"]["value"] == "- Toner Schwarz: 55.0%"
    assert result["facts"]["consumablesMaintenance"]["value"] == "- Drum Unit: 70.0%"


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
