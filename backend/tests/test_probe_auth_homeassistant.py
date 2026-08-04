"""Tests for probe_homeassistant's connection self-check: it used to go straight to /api/states
and report every failure (wrong URL, some other web server answering, an invalid/expired token) as
the same generic "nicht erreichbar" message. It now checks /api/ first (Home Assistant's own
health/identity endpoint, which always answers {"message": "API running"} once the token is
accepted) so an invalid token and an unreachable/wrong endpoint produce distinct, actionable
errors."""
import asyncio

import httpx

from app import probe_auth


def _fake_client(monkeypatch, handler) -> None:
    transport = httpx.MockTransport(handler)

    class _FakeAsyncClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            kwargs.pop("verify", None)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(probe_auth.httpx, "AsyncClient", _FakeAsyncClient)
    monkeypatch.setattr(probe_auth, "_decode_secret", lambda account: ("fake-token", ""))


def test_self_check_passes_and_probe_proceeds_to_states(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/":
            assert request.headers["authorization"] == "Bearer fake-token"
            return httpx.Response(200, json={"message": "API running"})
        if request.url.path.endswith("/api/states"):
            return httpx.Response(200, json=[
                {"entity_id": "automation.a", "state": "on", "attributes": {"friendly_name": "A", "id": "1"}},
            ])
        return httpx.Response(404)

    _fake_client(monkeypatch, handler)
    result = asyncio.run(probe_auth.probe_homeassistant("http://ha.local:8123", {}))
    assert result["ok"]
    assert "A (ein)" in result["facts"]["automations"]["value"]


def test_self_check_reports_invalid_token_distinctly(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/":
            return httpx.Response(401, json={"message": "401: Unauthorized"})
        return httpx.Response(200, json=[])

    _fake_client(monkeypatch, handler)
    result = asyncio.run(probe_auth.probe_homeassistant("http://ha.local:8123", {}))
    assert not result["ok"]
    assert "Zugriffstoken abgelehnt" in result["error"]
    assert "401" in result["error"]


def test_self_check_reports_wrong_endpoint_distinctly_from_auth_failure(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/":
            # Reachable, 200, but not Home Assistant's own API shape -- e.g. the URL points at
            # nginx's default page or the wrong service entirely.
            return httpx.Response(200, text="<html>Willkommen</html>")
        return httpx.Response(200, json=[])

    _fake_client(monkeypatch, handler)
    result = asyncio.run(probe_auth.probe_homeassistant("http://not-ha.local", {}))
    assert not result["ok"]
    assert "nicht wie die Home-Assistant-API" in result["error"]
    assert "Zugriffstoken" not in result["error"]  # must not be confused with an auth failure


def test_self_check_reports_unreachable_host(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused")

    _fake_client(monkeypatch, handler)
    result = asyncio.run(probe_auth.probe_homeassistant("http://ha.local:8123", {}))
    assert not result["ok"]
    assert "nicht erreichbar" in result["error"]
    assert "ha.local:8123" in result["error"]


def test_states_call_rejected_after_self_check_passed_still_reports_auth_error(monkeypatch):
    # Edge case: token valid at self-check time but rejected moments later (e.g. revoked between
    # the two calls) -- /api/states' own 401 must still produce a clear message, not a raw
    # exception string from raise_for_status().
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/":
            return httpx.Response(200, json={"message": "API running"})
        return httpx.Response(401, json={"message": "401: Unauthorized"})

    _fake_client(monkeypatch, handler)
    result = asyncio.run(probe_auth.probe_homeassistant("http://ha.local:8123", {}))
    assert not result["ok"]
    assert "Zugriffstoken abgelehnt" in result["error"]
