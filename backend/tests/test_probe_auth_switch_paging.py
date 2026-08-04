"""Regression tests for the TP-Link switch-config-backup fix: `show running-config` (and every
other TP-Link command) used to run with the switch's own "--More--" pager still on, which either
truncated the captured fact at the first screen or hung the one-shot exec channel until
_SSH_TIMEOUT killed it -- either way the config backup was empty or incomplete. See the
`_TPLINK_DISABLE_PAGING` comment in probe_auth.py for why the fix is a same-channel, multi-line
command rather than a separate "no clipaging" command sent first."""
from app import probe_auth


def _command_for(key: str) -> str:
    return next(command for k, _label, command in probe_auth._SSH_COMMANDS_TPLINK if k == key)


def test_tplink_config_export_disables_paging_before_running_config():
    command = _command_for("config_export")
    assert "no clipaging" in command
    assert command.index("no clipaging") < command.index("show running-config")
    assert command.endswith("show running-config")


def test_tplink_disable_paging_enters_and_leaves_config_mode():
    lines = probe_auth._TPLINK_DISABLE_PAGING.strip("\n").splitlines()
    assert lines == ["configure", "no clipaging", "exit"]


def test_every_tplink_command_disables_paging_first():
    for key, _label, command in probe_auth._SSH_COMMANDS_TPLINK:
        assert command.startswith(probe_auth._TPLINK_DISABLE_PAGING), (
            f"{key!r} command does not disable paging first: {command!r}"
        )


def test_cisco_running_config_already_suppresses_paging_with_no_more():
    # Not a regression -- Cisco's IOS/IOS-XE CLI has a per-command pager modifier ("| no-more"),
    # so it never needed the same same-channel "configure/no .../exit" workaround TP-Link does.
    command = next(c for k, _l, c in probe_auth._SSH_COMMANDS_CISCO if k == "config_export")
    assert command == "show running-config | no-more"
