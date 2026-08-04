import asyncio

import httpx

from app import probe_auth


def test_ha_printer_supplies_extracts_matching_sensors():
    states = [
        {"entity_id": "sensor.officejet_black_ink", "state": "42",
         "attributes": {"friendly_name": "OfficeJet Schwarz-Patrone", "unit_of_measurement": "%"}},
        {"entity_id": "sensor.brother_toner", "state": "7",
         "attributes": {"friendly_name": "Brother Toner", "unit_of_measurement": "%"}},
        {"entity_id": "sensor.living_room_temperature", "state": "21.5",
         "attributes": {"friendly_name": "Wohnzimmer Temperatur", "unit_of_measurement": "°C"}},
        {"entity_id": "sensor.printer_drum_unit", "state": "unavailable",
         "attributes": {"friendly_name": "Trommel"}},
    ]
    supplies = probe_auth._ha_printer_supplies(states)
    names = {s["name"] for s in supplies}
    assert names == {"OfficeJet Schwarz-Patrone", "Brother Toner"}
    # "unavailable" readings are dropped -- a bar showing a stale/missing value is worse than none.
    assert "Trommel" not in names


def test_extract_printer_supplies_parses_percentage_lines_only():
    outcome = {
        "results": {
            "ha:hub": {"ok": True, "facts": {
                "printerSupplies": {
                    "label": "Drucker-Verbrauchsmaterial (2)",
                    "value": "- OfficeJet Schwarz-Patrone: 42%\n- Brother Toner: 7%",
                },
            }},
        }
    }
    supplies = probe_auth.extract_printer_supplies(outcome)
    assert supplies == [
        {"name": "OfficeJet Schwarz-Patrone", "percent": 42.0},
        {"name": "Brother Toner", "percent": 7.0},
    ]


def test_extract_printer_supplies_ignores_non_percentage_and_failed_results():
    outcome = {
        "results": {
            "ha:hub": {"ok": True, "facts": {
                "printerSupplies": {"label": "x", "value": "- Sonstiger Sensor: 123 code"},
            }},
            "ha:other": {"ok": False, "facts": {
                "printerSupplies": {"label": "x", "value": "- Sollte nicht zaehlen: 5%"},
            }},
        }
    }
    assert probe_auth.extract_printer_supplies(outcome) == []


def test_probe_homeassistant_includes_disabled_automations_with_explicit_status(monkeypatch):
    """Regression test for the fix itself: `probe_homeassistant` used to filter to `state == "on"`
    only, silently dropping every disabled automation -- exactly the thing someone debugging "why
    doesn't X run anymore" needs to see. Exercises the real function end-to-end over a mocked
    transport, not a reimplementation of its filtering logic."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/":
            return httpx.Response(200, json={"message": "API running"})
        if request.url.path.endswith("/api/states"):
            return httpx.Response(200, json=[
                {"entity_id": "automation.enabled_one", "state": "on",
                 "attributes": {"friendly_name": "Laeuft", "id": "1"}},
                {"entity_id": "automation.disabled_one", "state": "off",
                 "attributes": {"friendly_name": "Deaktiviert", "id": "2"}},
            ])
        return httpx.Response(404)  # automation config lookups -- absence just means no description

    transport = httpx.MockTransport(handler)

    class _FakeAsyncClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            kwargs.pop("verify", None)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(probe_auth.httpx, "AsyncClient", _FakeAsyncClient)
    monkeypatch.setattr(probe_auth, "_decode_secret", lambda account: ("fake-token", ""))

    result = asyncio.run(probe_auth.probe_homeassistant("http://ha.local:8123", {}))

    assert result["ok"]
    value = result["facts"]["automations"]["value"]
    assert "Laeuft (ein)" in value
    assert "Deaktiviert (aus)" in value
