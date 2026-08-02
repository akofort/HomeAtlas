"""Dauerüberwachung der wichtigen Geräte.

A background loop polls every monitored device on a short interval (default 10s) and keeps
`systems.status` current, so the dashboard reflects reality rather than the last scan.

Three design points worth stating:

* **A port beats a ping.** If a device has monitor ports configured, reachability is decided by
  those, because that is what the household actually cares about -- a NAS that answers ICMP while
  its file service is dead is *not* "online" in any useful sense. ICMP is the fallback for devices
  with no port worth checking.
* **Only transitions are persisted.** Writing a row per poll would add ~8600 rows per device per
  day and answer no question anyone asks; an up/down change is the event people look for.
* **A failure is confirmed before it counts.** A single missed poll flips nothing -- Wi-Fi devices
  drop a packet routinely, and an alert that cries wolf gets ignored. `_FAILURES_BEFORE_DOWN`
  consecutive misses are required, while a single success restores immediately.
"""
from __future__ import annotations

import asyncio
import contextlib
import time

from . import db, diagnostics, ports as port_catalog

_FAILURES_BEFORE_DOWN = 2
# Ports that mean "this device is doing its job", tried when none were configured by hand.
_DEFAULT_PORTS_BY_KIND: dict[str, tuple[int, ...]] = {
    "router": (80, 443),
    "nas": (445, 5001, 5000),
    "server": (22, 80, 443),
    "container": (),
    "printer": (9100, 631),
    "smarthome": (8123, 1883),
    "camera": (554, 80),
    "network": (80, 443),
}


def effective_ports(system: dict) -> list[int]:
    configured = [int(p) for p in (system.get("monitorPorts") or []) if str(p).isdigit()]
    if configured:
        return configured[:3]
    open_ports = system.get("openPorts") or []
    preferred = _DEFAULT_PORTS_BY_KIND.get(system.get("kind", ""), ())
    # Prefer a port the device is actually known to serve; a default that was never open would
    # report a permanent outage.
    chosen = [p for p in preferred if p in open_ports][:3]
    if chosen:
        return chosen
    return list(open_ports)[:1]


async def check_system(system: dict, timeout_s: float) -> tuple[str, str]:
    """Returns (status, human-readable detail)."""
    host = (system.get("ip") or system.get("hostname") or "").strip()
    if not host:
        return "unknown", "Keine Adresse hinterlegt"

    targets = effective_ports(system)
    if targets:
        results = await asyncio.gather(
            *(diagnostics.check_port(host, port, timeout_s) for port in targets),
            return_exceptions=True,
        )
        reachable = [
            (targets[i], r) for i, r in enumerate(results) if isinstance(r, dict) and r.get("open")
        ]
        if reachable:
            names = ", ".join(f"{p} ({port_catalog.label_for(p)[0]})" for p, _ in reachable)
            return "online", f"Dienst erreichbar auf Port {names}"
        closed = ", ".join(str(p) for p in targets)
        return "offline", f"Kein Dienst erreichbar (geprüft: Port {closed})"

    try:
        result = await diagnostics.ping(host, count=1)
    except Exception:  # noqa: BLE001 -- a monitor must never raise into its own loop
        return "unknown", "Prüfung fehlgeschlagen"
    return ("online", "Antwortet auf Ping") if result.get("reachable") else ("offline", "Antwortet nicht auf Ping")


class Monitor:
    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._failures: dict[str, int] = {}
        self.last_run: float = 0.0
        self.last_error: str = ""

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    async def _loop(self) -> None:
        while True:
            settings = db.get_settings()
            interval = max(5, min(600, int(settings.get("monitorIntervalSeconds", 10))))
            if not settings.get("monitorEnabled", True):
                await asyncio.sleep(interval)
                continue
            try:
                await self.run_once(settings)
                self.last_error = ""
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 -- the loop has to outlive any single failure
                self.last_error = str(exc)
            await asyncio.sleep(interval)

    async def run_once(self, settings: dict | None = None) -> list[dict]:
        settings = settings or db.get_settings()
        timeout_s = max(0.2, int(settings.get("monitorTimeoutMs", 1500)) / 1000)
        systems = db.list_monitored_systems()
        if not systems:
            self.last_run = time.time()
            return []

        outcomes = await asyncio.gather(
            *(check_system(s, timeout_s) for s in systems), return_exceptions=True
        )
        changes: list[dict] = []
        for system, outcome in zip(systems, outcomes):
            if isinstance(outcome, BaseException):
                continue
            status, detail = outcome
            if status == "offline":
                self._failures[system["id"]] = self._failures.get(system["id"], 0) + 1
                if self._failures[system["id"]] < _FAILURES_BEFORE_DOWN:
                    # Not yet confirmed -- leave the previous status alone.
                    continue
            else:
                self._failures.pop(system["id"], None)
            if db.record_monitor_state(system["id"], status, detail):
                changes.append({"systemId": system["id"], "name": system["name"],
                                "status": status, "detail": detail})
        self.last_run = time.time()
        return changes

    def status(self) -> dict:
        return {
            "running": self._task is not None and not self._task.done(),
            "lastRun": self.last_run,
            "lastError": self.last_error,
            "pendingFailures": {k: v for k, v in self._failures.items() if v},
        }


monitor = Monitor()
