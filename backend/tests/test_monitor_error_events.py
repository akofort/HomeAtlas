import asyncio

from app import db, monitor as monitor_module


def test_confirmed_down_transition_logs_a_device_error_event(temp_db, monkeypatch):
    system = temp_db.create_system({
        "kind": "server", "name": "NAS", "ip": "10.0.0.30", "monitored": 1, "status": "online",
    })

    async def fake_check_system(sys_arg, timeout_s):
        return "offline", "Weder Ping noch Port 445 erreichbar"

    monkeypatch.setattr(monitor_module, "check_system", fake_check_system)

    mon = monitor_module.Monitor()
    settings = {"monitorTimeoutMs": 1500}
    # First poll only counts a failure (_FAILURES_BEFORE_DOWN = 2) -- not yet a confirmed change.
    asyncio.run(mon.run_once(settings))
    assert db.list_device_error_events(system["id"]) == []

    asyncio.run(mon.run_once(settings))

    events = db.list_device_error_events(system["id"])
    assert len(events) == 1
    assert events[0]["level"] == "warning"
    assert "Weder Ping noch Port 445" in events[0]["message"]
    assert db.get_system(system["id"])["status"] == "offline"


def test_flapping_back_online_does_not_log_an_error_event(temp_db, monkeypatch):
    system = temp_db.create_system({
        "kind": "server", "name": "NAS", "ip": "10.0.0.31", "monitored": 1, "status": "unknown",
    })

    async def fake_check_system(sys_arg, timeout_s):
        return "online", "Antwortet auf Ping"

    monkeypatch.setattr(monitor_module, "check_system", fake_check_system)

    mon = monitor_module.Monitor()
    asyncio.run(mon.run_once({"monitorTimeoutMs": 1500}))

    assert db.list_device_error_events(system["id"]) == []
    assert db.get_system(system["id"])["status"] == "online"
