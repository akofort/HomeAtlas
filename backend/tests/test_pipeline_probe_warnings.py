"""Regression test: a system with two credentials -- one that succeeds (e.g. SSH) and one that
fails (e.g. an expired Home Assistant token) -- used to have the failing credential's error
swallowed entirely, because pipeline.py only ever collected per-result warnings inside the
`if not outcome["ran"]` branch. Since *some* credential succeeded, `ran` was True, and the specific,
informative error probe_homeassistant now produces (see test_probe_auth_homeassistant.py) never
reached the scan log at all."""
import asyncio

from app import db, pipeline, probe_auth


def test_probe_with_credentials_logs_failure_even_when_another_credential_on_same_system_succeeds(
    temp_db, monkeypatch,
):
    system = temp_db.create_system({"kind": "server", "name": "Smart-Home-Hub", "ip": "10.0.0.9"})
    temp_db.create_account({
        "systemId": system["id"], "label": "SSH", "category": "sshkey", "allowProbe": 1,
    })
    temp_db.create_account({
        "systemId": system["id"], "label": "Home Assistant", "category": "homeassistant", "allowProbe": 1,
    })

    async def fake_probe_system(sys_arg, accounts):
        return {
            "ran": True,
            "purpose": "",
            "reason": "",
            "results": {
                "ssh:SSH": {"ok": True, "error": "", "facts": {"hostname": {"label": "Hostname", "value": "hub"}}},
                "ha:Home Assistant": {
                    "ok": False, "facts": {},
                    "error": "Home Assistant hat das Zugriffstoken abgelehnt (HTTP 401) beim Abruf der Zustände.",
                },
            },
        }

    monkeypatch.setattr(probe_auth, "probe_system", fake_probe_system)
    logs: list[str] = []
    probed, warnings, learned_arp, printer_supplies = asyncio.run(
        pipeline._probe_with_credentials(logs.append)
    )

    assert probed == 1
    assert any("Zugriffstoken abgelehnt" in w for w in warnings)
    assert any("Smart-Home-Hub" in w for w in warnings)

    # The same failure is also recorded against the specific device (see db.add_device_error_event
    # calls in pipeline.py) -- not just the scan-wide warnings list, which is gone after the next scan.
    events = db.list_device_error_events(system["id"])
    assert len(events) == 1
    assert "Zugriffstoken abgelehnt" in events[0]["message"]
