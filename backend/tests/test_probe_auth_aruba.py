"""Regression tests for the Aruba switch-config-backup fix: ArubaOS-Switch's "-- MORE --" pager
was never disabled before `show running-config`, so any config longer than one screen either hung
the one-shot exec channel until _SSH_TIMEOUT killed it (losing the backup entirely) or came back
truncated. See the `_ARUBA_DISABLE_PAGING`/`_ARUBA_CX_DISABLE_PAGING` comments in probe_auth.py for
why the fix folds the pager-disable command into the same exec channel rather than sending it as
its own earlier command."""
import asyncio

import asyncssh

from app import probe_auth


def _command_for(commands, key: str) -> str:
    return next(command for k, _label, command in commands if k == key)


def test_aruba_config_export_disables_paging_before_running_config():
    command = _command_for(probe_auth._SSH_COMMANDS_ARUBA, "config_export")
    assert command == "no page\nshow running-config"


def test_every_aruba_command_disables_paging_first():
    for key, _label, command in probe_auth._SSH_COMMANDS_ARUBA:
        assert command.startswith("no page\n"), f"{key!r} does not disable paging first: {command!r}"


def test_arubacx_uses_no_paging_not_no_page():
    command = _command_for(probe_auth._SSH_COMMANDS_ARUBA_CX, "config_export")
    assert command == "no paging\nshow running-config"


def test_arubacx_uses_its_own_command_grammar_not_procurve_derived_one():
    system_cmd = _command_for(probe_auth._SSH_COMMANDS_ARUBA_CX, "system")
    neighbors_cmd = _command_for(probe_auth._SSH_COMMANDS_ARUBA_CX, "neighbors")
    assert system_cmd.endswith("show system")  # not "show system-information" (classic ArubaOS-Switch)
    assert neighbors_cmd.endswith("show lldp neighbor-info")  # not "show lldp info remote-device"


def test_detect_platform_arubaos_cx_by_explicit_string():
    system = {"vendor": "Aruba", "model": "Aruba CX 6300", "name": "", "os": ""}
    assert probe_auth._detect_platform(system) == "arubacx"


def test_detect_platform_classic_arubaos_switch_unaffected():
    system = {"vendor": "Aruba Networks", "model": "2930F", "name": "", "os": ""}
    assert probe_auth._detect_platform(system) == "aruba"


def test_detect_platform_hp_procurve_still_maps_to_classic_aruba_not_cx():
    system = {"vendor": "Hewlett Packard", "model": "ProCurve 2810", "name": "", "os": ""}
    assert probe_auth._detect_platform(system) == "aruba"


# --- Mocked SSH session: exercises probe_ssh end-to-end rather than just the command tables -----

class _FakeRunResult:
    def __init__(self, stdout: str):
        self.stdout = stdout


class _FakeConnection:
    """Records every command sent to `run()` and answers with canned output keyed by whatever
    substring of the (possibly multi-line, paging-disable-prefixed) command it contains."""

    def __init__(self, responses: dict[str, str]):
        self.responses = responses
        self.commands: list[str] = []
        self.term_types: list[str | None] = []

    async def run(self, command: str, check: bool = False, term_type: str | None = None):
        self.commands.append(command)
        self.term_types.append(term_type)
        for needle, output in self.responses.items():
            if needle in command:
                return _FakeRunResult(output)
        return _FakeRunResult("")


class _FakeConnectContextManager:
    def __init__(self, connection: _FakeConnection):
        self._connection = connection

    async def __aenter__(self):
        return self._connection

    async def __aexit__(self, *exc_info):
        return False


def _account() -> dict:
    return {"category": "login", "username": "admin", "secretEnc": "", "port": 22}


def test_probe_ssh_sends_no_page_before_running_config_over_a_mocked_session(monkeypatch):
    connection = _FakeConnection({
        "show running-config": "hostname SW1\ninterface 1\n   name Uplink\n",
        "show system-information": "System Name: SW1",
    })
    monkeypatch.setattr(asyncssh, "connect", lambda **kwargs: _FakeConnectContextManager(connection))
    monkeypatch.setattr(probe_auth, "_decode_secret", lambda account: ("hunter2", ""))

    result = asyncio.run(probe_auth.probe_ssh("10.0.0.20", _account(), platform="aruba"))

    assert result["ok"]
    assert result["facts"]["config_export"]["value"] == "hostname SW1\ninterface 1\n   name Uplink"
    # Every command sent to the switch had paging disabled first, in the same exec call.
    config_commands = [c for c in connection.commands if "show running-config" in c]
    assert config_commands == ["no page\nshow running-config"]


def test_probe_ssh_arubacx_uses_no_paging_over_a_mocked_session(monkeypatch):
    connection = _FakeConnection({"show running-config": "hostname CX1\n"})
    monkeypatch.setattr(asyncssh, "connect", lambda **kwargs: _FakeConnectContextManager(connection))
    monkeypatch.setattr(probe_auth, "_decode_secret", lambda account: ("hunter2", ""))

    result = asyncio.run(probe_auth.probe_ssh("10.0.0.21", _account(), platform="arubacx"))

    assert result["ok"]
    assert result["facts"]["config_export"]["value"] == "hostname CX1"
    config_commands = [c for c in connection.commands if "show running-config" in c]
    assert config_commands == ["no paging\nshow running-config"]


def test_probe_ssh_aruba_config_backup_survives_a_slow_paged_reply(monkeypatch):
    """Without the fix, a switch that actually enforces its pager over a non-interactive exec
    channel would never return -- this stands in for that by simulating what disabling paging
    achieves: the full multi-screen output comes back in one shot rather than one page's worth."""
    long_config = "\n".join(f"interface {i}" for i in range(100))
    connection = _FakeConnection({"show running-config": long_config})
    monkeypatch.setattr(asyncssh, "connect", lambda **kwargs: _FakeConnectContextManager(connection))
    monkeypatch.setattr(probe_auth, "_decode_secret", lambda account: ("hunter2", ""))

    result = asyncio.run(probe_auth.probe_ssh("10.0.0.22", _account(), platform="aruba"))

    assert result["facts"]["config_export"]["value"] == long_config
    assert "interface 99" in result["facts"]["config_export"]["value"]


def test_probe_ssh_requests_a_pty_for_aruba_platform(monkeypatch):
    connection = _FakeConnection({"show running-config": "hostname SW1\n"})
    monkeypatch.setattr(asyncssh, "connect", lambda **kwargs: _FakeConnectContextManager(connection))
    monkeypatch.setattr(probe_auth, "_decode_secret", lambda account: ("hunter2", ""))

    asyncio.run(probe_auth.probe_ssh("10.0.0.20", _account(), platform="aruba"))

    assert connection.term_types
    assert all(t == "vt100" for t in connection.term_types)


def test_probe_ssh_does_not_request_a_pty_for_plain_linux_hosts(monkeypatch):
    connection = _FakeConnection({"hostname": "server1\n"})
    monkeypatch.setattr(asyncssh, "connect", lambda **kwargs: _FakeConnectContextManager(connection))
    monkeypatch.setattr(probe_auth, "_decode_secret", lambda account: ("hunter2", ""))

    asyncio.run(probe_auth.probe_ssh("10.0.0.30", _account(), platform=""))

    assert connection.term_types
    assert all(t is None for t in connection.term_types)


def test_probe_ssh_logs_a_clear_warning_when_a_command_times_out(monkeypatch):
    class _TimeoutConnection(_FakeConnection):
        async def run(self, command, check=False, term_type=None):
            self.commands.append(command)
            self.term_types.append(term_type)
            if "show running-config" in command:
                raise asyncio.TimeoutError()
            return await super().run(command, check=check, term_type=term_type)

    connection = _TimeoutConnection({"show system-information": "System Name: SW1"})
    monkeypatch.setattr(asyncssh, "connect", lambda **kwargs: _FakeConnectContextManager(connection))
    monkeypatch.setattr(probe_auth, "_decode_secret", lambda account: ("hunter2", ""))

    result = asyncio.run(probe_auth.probe_ssh("10.0.0.23", _account(), platform="aruba"))

    assert result["ok"]  # other commands still succeeded
    assert "config_export" not in result["facts"]
    assert any("nicht geantwortet" in w for w in result["warnings"])
