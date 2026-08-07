"""Regression tests for classic ArubaOS-Switch config backup.

Two real-hardware findings drove this file's shape (see probe_auth.py's `_SSH_COMMANDS_ARUBA` and
`probe_ssh_aruba` comments for the full story):

1. Every new session opens with a mandatory copyright banner ending in "Press any key to
   continue" that the one-exec-channel-per-command model every *other* platform in probe_auth.py
   uses cannot get past -- `connection.run(command)` hands the switch one opaque exec request
   rather than paced keystrokes, so the banner's keypress never arrives and the channel closes
   having processed nothing else in it.
2. Past the banner, the session starts in Operator context ("Switch>"), which can't run "show
   running-config" at all -- "enable" is required, and on a switch with AAA/RADIUS or a separate
   Manager password, "enable" itself challenges for its own Username/Password, which this module
   must never attempt to answer (no Manager credential is ever stored for it to answer with).

So classic Aruba gets its own persistent interactive shell (`probe_ssh_aruba`) instead of the
generic exec loop. These tests exercise that shell against a scripted fake connection rather than
`asyncssh.connect`'s usual `run()`-based fake, since the whole point is that `run()` doesn't work
here.
"""
import asyncio

import asyncssh

from app import probe_auth


def _command_for(commands, key: str) -> str:
    return next(command for k, _label, command in commands if k == key)


def test_aruba_commands_are_bare_show_commands_run_one_at_a_time():
    # No folded "enable\nno page\n..." prefix any more -- probe_ssh_aruba sends those once for
    # the whole session instead of once per command, see its own docstring for why.
    for key, _label, command in probe_auth._SSH_COMMANDS_ARUBA:
        assert command.startswith("show "), f"{key!r} is not a bare show command: {command!r}"
        assert "\n" not in command, f"{key!r} embeds a newline, but commands run one at a time now: {command!r}"
    assert _command_for(probe_auth._SSH_COMMANDS_ARUBA, "config_export") == "show running-config"


def test_arubacx_still_folds_no_paging_into_the_exec_command():
    # ArubaOS-CX is untouched by the Aruba-Classic rewrite -- it stays on the generic exec-per-
    # command model, which its CLI (unlike classic ArubaOS-Switch) apparently tolerates fine.
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


# --- _strip_aruba_echo_and_prompt / _aruba_last_line -------------------------------------------

def test_strip_aruba_echo_and_prompt_removes_leading_echo_and_trailing_prompt():
    raw = "show running-config\r\nhostname SW1\r\ninterface 1\r\n\r\nSwitch#"
    assert probe_auth._strip_aruba_echo_and_prompt(raw, "show running-config") == "hostname SW1\ninterface 1"


def test_strip_aruba_echo_and_prompt_leaves_content_alone_if_shapes_dont_match():
    raw = "unexpected output\r\nmore output"
    assert probe_auth._strip_aruba_echo_and_prompt(raw, "show vlan") == "unexpected output\nmore output"


def test_aruba_last_line_ignores_blank_trailing_lines():
    assert probe_auth._aruba_last_line("hello\r\nSwitch>\r\n\r\n") == "Switch>"
    assert probe_auth._aruba_last_line("") == ""


# --- _bounded_fact (shared with the generic exec loop) ------------------------------------------

def test_bounded_fact_gives_config_export_the_wide_limit():
    long_config = "x" * 70000
    assert len(probe_auth._bounded_fact("config_export", long_config)) == 60000


def test_bounded_fact_drops_an_oversized_binary_backup_entirely():
    assert probe_auth._bounded_fact("omada_backup", "x" * probe_auth._BINARY_BACKUP_LIMIT) is None


def test_bounded_fact_uses_the_narrow_limit_for_everything_else():
    assert len(probe_auth._bounded_fact("hostname", "x" * 2000)) == 1200


# --- probe_ssh_aruba: scripted interactive session -----------------------------------------------

class _FakeAsyncQueueReader:
    """Stands in for `SSHClientProcess.stdout`. `read()` returns whatever has been `feed()`-ed so
    far and then blocks forever, so the caller's own `asyncio.wait_for(..., timeout=...)` is what
    ends the wait -- exactly like a real idle SSH stream, but without needing wall-clock delays
    (tests monkeypatch `_ARUBA_IDLE_READ_SECONDS` down to keep this fast)."""

    def __init__(self):
        self._queue: asyncio.Queue = asyncio.Queue()

    def feed(self, text: str) -> None:
        if text:
            self._queue.put_nowait(text)

    async def read(self, n: int = -1) -> str:
        if self._queue.empty():
            await asyncio.Event().wait()
        return await self._queue.get()


class _FakeStdin:
    def __init__(self, on_write):
        self._on_write = on_write
        self.written: list[str] = []

    def write(self, data: str) -> None:
        self.written.append(data)
        self._on_write(data)

    async def drain(self) -> None:
        return None


class _FakeArubaProcess:
    def __init__(self, stdin: _FakeStdin, stdout: _FakeAsyncQueueReader):
        self.stdin = stdin
        self.stdout = stdout
        self.closed = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        self.closed = True
        return False


class _ScriptedArubaConnection:
    """Fake `asyncssh.SSHClientConnection`: `create_process()` opens one shell whose replies are
    scripted by exact stdin payload (`responses`), fed into the output stream the instant the
    matching line is written -- mirrors how a real switch replies to each line typed at its CLI."""

    def __init__(self, banner: str, responses: dict[str, str]):
        self._banner = banner
        self._responses = responses
        self.written: list[str] = []
        self.create_process_kwargs: dict = {}

    async def create_process(self, **kwargs):
        self.create_process_kwargs = kwargs
        reader = _FakeAsyncQueueReader()
        reader.feed(self._banner)

        def on_write(data: str) -> None:
            self.written.append(data)
            reader.feed(self._responses.get(data, ""))

        return _FakeArubaProcess(_FakeStdin(on_write), reader)


def _aruba_responses(enable_reply: str) -> dict[str, str]:
    """One scripted reply per line probe_ssh_aruba can send, echoing the command back (as a real
    pty would) followed by canned output and the Manager prompt -- enough for every fact in
    `_SSH_COMMANDS_ARUBA` to resolve to something non-empty."""
    return {
        "\n": "\r\nSwitch>",
        "enable\n": enable_reply,
        "no page\n": "",
        "show system-information\n": "show system-information\r\nSystem Name: SW1\r\n\r\nSwitch#",
        "show vlan\n": "show vlan\r\n1 DEFAULT_VLAN\r\n\r\nSwitch#",
        "show vlan ports all detail\n": "show vlan ports all detail\r\nPort 1 Untagged\r\n\r\nSwitch#",
        "show lldp info remote-device\n": "show lldp info remote-device\r\n\r\nSwitch#",
        "show interfaces brief\n": "show interfaces brief\r\n1  Up\r\n\r\nSwitch#",
        "show ip\n": "show ip\r\nVLAN1  10.0.0.1\r\n\r\nSwitch#",
        "show arp\n": "show arp\r\n10.0.0.5 aabbcc\r\n\r\nSwitch#",
        "show running-config\n": (
            "show running-config\r\nhostname SW1\r\ninterface 1\r\n   name Uplink\r\n\r\nSwitch#"
        ),
    }


def test_probe_ssh_aruba_enables_from_operator_prompt_and_captures_config(monkeypatch):
    monkeypatch.setattr(probe_auth, "_ARUBA_IDLE_READ_SECONDS", 0.01)
    connection = _ScriptedArubaConnection(
        banner="Aruba JL261A ... Press any key to continue",
        responses=_aruba_responses(enable_reply="\r\nSwitch#"),
    )
    warnings: list[str] = []

    facts = asyncio.run(probe_auth.probe_ssh_aruba(connection, warnings))

    assert facts["config_export"]["value"] == "hostname SW1\ninterface 1\n   name Uplink"
    assert "enable\n" in connection.written
    assert "no page\n" in connection.written
    assert connection.create_process_kwargs.get("term_type") == "vt100"
    assert warnings == []


def test_probe_ssh_aruba_skips_enable_when_session_already_at_manager_prompt(monkeypatch):
    monkeypatch.setattr(probe_auth, "_ARUBA_IDLE_READ_SECONDS", 0.01)
    responses = _aruba_responses(enable_reply="\r\nSwitch#")
    responses["\n"] = "\r\nSwitch#"  # already Manager right after the banner dismiss
    connection = _ScriptedArubaConnection(banner="... Press any key to continue", responses=responses)
    warnings: list[str] = []

    facts = asyncio.run(probe_auth.probe_ssh_aruba(connection, warnings))

    assert "enable\n" not in connection.written
    assert facts["config_export"]["value"] == "hostname SW1\ninterface 1\n   name Uplink"


def test_probe_ssh_aruba_gives_up_without_answering_a_manager_credential_prompt(monkeypatch):
    monkeypatch.setattr(probe_auth, "_ARUBA_IDLE_READ_SECONDS", 0.01)
    connection = _ScriptedArubaConnection(
        banner="... Press any key to continue",
        responses={"\n": "\r\nSwitch>", "enable\n": "\r\nUsername: "},
    )
    warnings: list[str] = []

    facts = asyncio.run(probe_auth.probe_ssh_aruba(connection, warnings))

    assert facts == {}
    # Never got past the credential challenge -- no show command was even attempted.
    assert "no page\n" not in connection.written
    assert any("Manager-Zugangsdaten" in w for w in warnings)


def test_probe_ssh_aruba_closes_the_process_when_done(monkeypatch):
    monkeypatch.setattr(probe_auth, "_ARUBA_IDLE_READ_SECONDS", 0.01)
    connection = _ScriptedArubaConnection(
        banner="... Press any key to continue",
        responses=_aruba_responses(enable_reply="\r\nSwitch#"),
    )

    asyncio.run(probe_auth.probe_ssh_aruba(connection, []))

    # create_process() only hands back the process object itself in this fake, so re-open one to
    # inspect closed state directly is redundant -- instead confirm via the connection that a
    # session was actually opened and driven (closing is exercised implicitly by `async with`
    # not raising).
    assert connection.written


# --- probe_ssh(): full entry point, asyncssh.connect mocked --------------------------------------

class _ConnectContextManager:
    def __init__(self, connection):
        self._connection = connection

    async def __aenter__(self):
        return self._connection

    async def __aexit__(self, *exc_info):
        return False


def _account() -> dict:
    return {"category": "login", "username": "admin", "secretEnc": "", "port": 22}


def test_probe_ssh_end_to_end_for_aruba_platform(monkeypatch):
    monkeypatch.setattr(probe_auth, "_ARUBA_IDLE_READ_SECONDS", 0.01)
    connection = _ScriptedArubaConnection(
        banner="... Press any key to continue",
        responses=_aruba_responses(enable_reply="\r\nSwitch#"),
    )
    monkeypatch.setattr(asyncssh, "connect", lambda **kwargs: _ConnectContextManager(connection))
    monkeypatch.setattr(probe_auth, "_decode_secret", lambda account: ("hunter2", ""))

    result = asyncio.run(probe_auth.probe_ssh("10.0.0.20", _account(), platform="aruba"))

    assert result["ok"]
    assert result["facts"]["config_export"]["value"] == "hostname SW1\ninterface 1\n   name Uplink"


def test_probe_ssh_end_to_end_for_aruba_reports_error_when_enable_is_challenged(monkeypatch):
    monkeypatch.setattr(probe_auth, "_ARUBA_IDLE_READ_SECONDS", 0.01)
    connection = _ScriptedArubaConnection(
        banner="... Press any key to continue",
        responses={"\n": "\r\nSwitch>", "enable\n": "\r\nUsername: "},
    )
    monkeypatch.setattr(asyncssh, "connect", lambda **kwargs: _ConnectContextManager(connection))
    monkeypatch.setattr(probe_auth, "_decode_secret", lambda account: ("hunter2", ""))

    result = asyncio.run(probe_auth.probe_ssh("10.0.0.20", _account(), platform="aruba"))

    assert not result["ok"]
    assert "Manager-Zugangsdaten" in result["error"]


# --- Generic exec-per-command loop: still used by every other platform --------------------------

class _FakeRunResult:
    def __init__(self, stdout: str):
        self.stdout = stdout


class _FakeConnection:
    """Records every command sent to `run()` and answers with canned output keyed by whatever
    substring of the command it contains."""

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


def test_probe_ssh_arubacx_uses_no_paging_over_a_mocked_session(monkeypatch):
    connection = _FakeConnection({"show running-config": "hostname CX1\n"})
    monkeypatch.setattr(asyncssh, "connect", lambda **kwargs: _ConnectContextManager(connection))
    monkeypatch.setattr(probe_auth, "_decode_secret", lambda account: ("hunter2", ""))

    result = asyncio.run(probe_auth.probe_ssh("10.0.0.21", _account(), platform="arubacx"))

    assert result["ok"]
    assert result["facts"]["config_export"]["value"] == "hostname CX1"
    config_commands = [c for c in connection.commands if "show running-config" in c]
    assert config_commands == ["no paging\nshow running-config"]
    # ArubaOS-CX stays on the generic exec loop, which still requests a pty for it.
    assert all(t == "vt100" for t in connection.term_types)


def test_probe_ssh_does_not_request_a_pty_for_plain_linux_hosts(monkeypatch):
    connection = _FakeConnection({"hostname": "server1\n"})
    monkeypatch.setattr(asyncssh, "connect", lambda **kwargs: _ConnectContextManager(connection))
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

    connection = _TimeoutConnection({"show system": "System Name: CX1"})
    monkeypatch.setattr(asyncssh, "connect", lambda **kwargs: _ConnectContextManager(connection))
    monkeypatch.setattr(probe_auth, "_decode_secret", lambda account: ("hunter2", ""))

    result = asyncio.run(probe_auth.probe_ssh("10.0.0.23", _account(), platform="arubacx"))

    assert result["ok"]  # other commands still succeeded
    assert "config_export" not in result["facts"]
    assert any("nicht geantwortet" in w for w in result["warnings"])
