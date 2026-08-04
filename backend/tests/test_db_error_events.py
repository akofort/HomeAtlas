from app import db


def test_add_and_list_device_error_events(temp_db):
    system = temp_db.create_system({"kind": "network", "name": "Switch"})
    temp_db.add_device_error_event(system["id"], "error", "SSH-Verbindung zu 10.0.0.5:22 fehlgeschlagen: timeout")
    temp_db.add_device_error_event(system["id"], "warning", "Nicht mehr erreichbar: Weder Ping noch Port erreichbar")

    events = temp_db.list_device_error_events(system["id"])

    assert len(events) == 2
    # Most recent first.
    assert events[0]["level"] == "warning"
    assert events[1]["level"] == "error"
    assert "timeout" in events[1]["message"]


def test_add_device_error_event_is_a_noop_without_a_system_id(temp_db):
    assert temp_db.add_device_error_event("", "error", "irrelevant") is None
    assert temp_db.add_device_error_event(None, "error", "irrelevant") is None  # type: ignore[arg-type]


def test_error_events_are_capped_per_device(temp_db, monkeypatch):
    monkeypatch.setattr(db, "_ERROR_EVENT_KEEP", 3)
    system = temp_db.create_system({"kind": "server", "name": "Host"})
    for i in range(10):
        temp_db.add_device_error_event(system["id"], "error", f"Fehler {i}")

    events = temp_db.list_device_error_events(system["id"], limit=100)

    assert len(events) == 3
    assert events[0]["message"] == "Fehler 9"  # newest kept, oldest trimmed


def test_count_error_events_by_system_is_one_query_for_all_devices(temp_db):
    a = temp_db.create_system({"kind": "server", "name": "A"})
    b = temp_db.create_system({"kind": "server", "name": "B"})
    c = temp_db.create_system({"kind": "server", "name": "C"})  # no errors at all

    temp_db.add_device_error_event(a["id"], "error", "x")
    temp_db.add_device_error_event(a["id"], "error", "y")
    temp_db.add_device_error_event(b["id"], "warning", "z")

    counts = temp_db.count_error_events_by_system()

    assert counts[a["id"]] == 2
    assert counts[b["id"]] == 1
    assert c["id"] not in counts  # untouched dict.get(..., 0) on the caller side handles the absence
