import asyncio

import httpx

from app import adguard_probe


def _handler(routes: dict):
    def handler(request: httpx.Request) -> httpx.Response:
        return routes.get(request.url.path, httpx.Response(404))
    return handler


def _fake_client(monkeypatch, routes: dict) -> None:
    transport = httpx.MockTransport(_handler(routes))

    class _FakeAsyncClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            kwargs.pop("verify", None)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(adguard_probe.httpx, "AsyncClient", _FakeAsyncClient)


def test_probe_requires_address():
    result = asyncio.run(adguard_probe.probe("", "admin", "hunter2"))
    assert not result["ok"]
    assert "Adresse" in result["error"]


def test_probe_requires_credentials():
    result = asyncio.run(adguard_probe.probe("http://adguard.local", "", ""))
    assert not result["ok"]
    assert "fehlt" in result["error"]


def test_probe_reports_rejected_credentials(monkeypatch):
    _fake_client(monkeypatch, {"/control/dns_info": httpx.Response(403)})
    result = asyncio.run(adguard_probe.probe("http://adguard.local", "admin", "wrong"))
    assert not result["ok"]
    assert "abgelehnt" in result["error"]


def test_probe_reads_protection_status_and_block_stats(monkeypatch):
    routes = {
        "/control/dns_info": httpx.Response(200, json={
            "protection_enabled": True, "upstream_dns": ["1.1.1.1", "8.8.8.8"],
        }),
        "/control/stats": httpx.Response(200, json={
            "num_dns_queries": 1000, "num_blocked_filtering": 250,
        }),
        "/control/dhcp/status": httpx.Response(200, json={"leases": [], "static_leases": []}),
        "/control/clients": httpx.Response(200, json={"clients": []}),
    }
    _fake_client(monkeypatch, routes)

    result = asyncio.run(adguard_probe.probe("http://adguard.local", "admin", "hunter2"))

    assert result["ok"]
    assert result["stats"]["protectionEnabled"] is True
    assert result["stats"]["upstreamCount"] == 2
    assert result["stats"]["queries"] == 1000
    assert result["stats"]["blocked"] == 250
    assert result["stats"]["blockedPercent"] == 25.0


def test_probe_survives_missing_stats_endpoint(monkeypatch):
    routes = {
        "/control/dns_info": httpx.Response(200, json={"protection_enabled": False, "upstream_dns": []}),
        "/control/dhcp/status": httpx.Response(200, json={"leases": [], "static_leases": []}),
        "/control/clients": httpx.Response(200, json={"clients": []}),
    }
    _fake_client(monkeypatch, routes)

    result = asyncio.run(adguard_probe.probe("http://adguard.local", "admin", "hunter2"))

    assert result["ok"]
    assert result["stats"]["protectionEnabled"] is False
    assert "queries" not in result["stats"]


def test_probe_turns_dhcp_leases_into_upsertable_systems(monkeypatch):
    routes = {
        "/control/dns_info": httpx.Response(200, json={"protection_enabled": True, "upstream_dns": []}),
        "/control/stats": httpx.Response(200, json={"num_dns_queries": 0, "num_blocked_filtering": 0}),
        "/control/dhcp/status": httpx.Response(200, json={
            "leases": [{"mac": "AA:BB:CC:DD:EE:01", "ip": "192.168.1.50", "hostname": "nas"}],
            "static_leases": [{"mac": "aa-bb-cc-dd-ee-02", "ip": "192.168.1.51", "hostname": "printer"}],
        }),
        "/control/clients": httpx.Response(200, json={"clients": []}),
    }
    _fake_client(monkeypatch, routes)

    result = asyncio.run(adguard_probe.probe("http://adguard.local", "admin", "hunter2"))

    assert result["ok"]
    keys = {s["discoveryKey"] for s in result["systems"]}
    assert keys == {"mac:aa:bb:cc:dd:ee:01", "mac:aa:bb:cc:dd:ee:02"}
    nas = next(s for s in result["systems"] if s["hostname"] == "nas")
    assert nas["ip"] == "192.168.1.50"
    assert nas["discoverySource"] == "adguard"


def test_probe_skips_dhcp_leases_without_a_hostname(monkeypatch):
    routes = {
        "/control/dns_info": httpx.Response(200, json={"protection_enabled": True, "upstream_dns": []}),
        "/control/stats": httpx.Response(200, json={"num_dns_queries": 0, "num_blocked_filtering": 0}),
        "/control/dhcp/status": httpx.Response(200, json={
            "leases": [{"mac": "AA:BB:CC:DD:EE:03", "ip": "192.168.1.52", "hostname": ""}],
            "static_leases": [],
        }),
        "/control/clients": httpx.Response(200, json={"clients": []}),
    }
    _fake_client(monkeypatch, routes)

    result = asyncio.run(adguard_probe.probe("http://adguard.local", "admin", "hunter2"))

    assert result["systems"] == []


def test_probe_reads_known_clients_by_mac_id_and_ignores_cidr_ids(monkeypatch):
    routes = {
        "/control/dns_info": httpx.Response(200, json={"protection_enabled": True, "upstream_dns": []}),
        "/control/stats": httpx.Response(200, json={"num_dns_queries": 0, "num_blocked_filtering": 0}),
        "/control/dhcp/status": httpx.Response(200, json={"leases": [], "static_leases": []}),
        "/control/clients": httpx.Response(200, json={"clients": [
            {"name": "Laptop", "ids": ["AA:BB:CC:DD:EE:04", "192.168.1.60"]},
            {"name": "Guest-Subnet", "ids": ["192.168.2.0/24"]},
            {"name": "", "ids": ["AA:BB:CC:DD:EE:05"]},
        ]}),
    }
    _fake_client(monkeypatch, routes)

    result = asyncio.run(adguard_probe.probe("http://adguard.local", "admin", "hunter2"))

    assert result["ok"]
    assert len(result["systems"]) == 1
    laptop = result["systems"][0]
    assert laptop["mac"] == "aa:bb:cc:dd:ee:04"
    assert laptop["ip"] == "192.168.1.60"
    assert laptop["name"] == "Laptop"


def test_probe_deduplicates_a_mac_seen_in_both_dhcp_and_clients(monkeypatch):
    routes = {
        "/control/dns_info": httpx.Response(200, json={"protection_enabled": True, "upstream_dns": []}),
        "/control/stats": httpx.Response(200, json={"num_dns_queries": 0, "num_blocked_filtering": 0}),
        "/control/dhcp/status": httpx.Response(200, json={
            "leases": [{"mac": "AA:BB:CC:DD:EE:06", "ip": "192.168.1.70", "hostname": "phone"}],
            "static_leases": [],
        }),
        "/control/clients": httpx.Response(200, json={"clients": [
            {"name": "phone", "ids": ["AA:BB:CC:DD:EE:06"]},
        ]}),
    }
    _fake_client(monkeypatch, routes)

    result = asyncio.run(adguard_probe.probe("http://adguard.local", "admin", "hunter2"))

    assert len(result["systems"]) == 1


def test_probe_unreachable_host_reports_error(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    transport = httpx.MockTransport(handler)

    class _FakeAsyncClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            kwargs.pop("verify", None)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(adguard_probe.httpx, "AsyncClient", _FakeAsyncClient)

    result = asyncio.run(adguard_probe.probe("http://adguard.local", "admin", "hunter2"))

    assert not result["ok"]
    assert "nicht erreichbar" in result["error"]
