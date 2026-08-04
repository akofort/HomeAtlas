"""Regression tests for the Proxmox "Container laden" bug: a Proxmox host has no Docker CLI at
all, so `docker ps` over SSH failed with "bash: line 1: docker: command not found". These cover
the native `pct list`/`qm list` SSH fallback (remote_admin.list_remote_proxmox_guests) -- see
proxmox_probe.list_guests / test_proxmox_probe.py for the REST-API path that is tried first."""
import asyncio

import asyncssh

from app import remote_admin


def test_parse_pct_list_reads_vmid_status_and_name():
    text = (
        "VMID       Status     Lock         Name\n"
        "100        running                 nextcloud\n"
        "101        stopped                 pihole\n"
    )
    containers = remote_admin._parse_pct_list(text)
    assert containers == [
        {"id": "lxc/100", "name": "nextcloud", "image": "LXC-Container", "state": "running", "status": "running"},
        {"id": "lxc/101", "name": "pihole", "image": "LXC-Container", "state": "stopped", "status": "stopped"},
    ]


def test_parse_pct_list_handles_a_locked_row_with_extra_column():
    text = (
        "VMID       Status     Lock         Name\n"
        "100        running    backup       nextcloud\n"
    )
    containers = remote_admin._parse_pct_list(text)
    assert containers == [
        {"id": "lxc/100", "name": "nextcloud", "image": "LXC-Container", "state": "running", "status": "running"},
    ]


def test_parse_pct_list_ignores_empty_output():
    assert remote_admin._parse_pct_list("") == []
    assert remote_admin._parse_pct_list("VMID       Status     Lock         Name\n") == []


def test_parse_qm_list_reads_vmid_name_and_status():
    text = (
        "      VMID NAME                 STATUS     MEM(MB)    BOOTDISK(GB) PID\n"
        "       100 nextcloud-vm         running    2048              32.00 12345\n"
        "       101 test-vm              stopped    1024              20.00 0\n"
    )
    containers = remote_admin._parse_qm_list(text)
    assert containers == [
        {"id": "qemu/100", "name": "nextcloud-vm", "image": "VM (QEMU/KVM)", "state": "running", "status": "running"},
        {"id": "qemu/101", "name": "test-vm", "image": "VM (QEMU/KVM)", "state": "stopped", "status": "stopped"},
    ]


def test_parse_qm_list_ignores_empty_output():
    assert remote_admin._parse_qm_list("") == []


class _FakeRunResult:
    def __init__(self, stdout: str, exit_status: int = 0, stderr: str = ""):
        self.stdout = stdout
        self.stderr = stderr
        self.exit_status = exit_status


class _FakeConnection:
    def __init__(self, responses: dict[str, _FakeRunResult]):
        self.responses = responses
        self.commands: list[str] = []

    async def run(self, command: str, check: bool = False):
        self.commands.append(command)
        return self.responses.get(command, _FakeRunResult("", 127, "command not found"))


class _FakeConnectContextManager:
    def __init__(self, connection: _FakeConnection):
        self._connection = connection

    async def __aenter__(self):
        return self._connection

    async def __aexit__(self, *exc_info):
        return False


def _account() -> dict:
    return {"category": "login", "username": "root", "secretEnc": "", "port": 22}


def test_list_remote_proxmox_guests_never_runs_docker(monkeypatch):
    connection = _FakeConnection({
        "pct list": _FakeRunResult("VMID       Status     Lock         Name\n100        running                 pihole\n"),
        "qm list": _FakeRunResult(
            "      VMID NAME                 STATUS     MEM(MB)    BOOTDISK(GB) PID\n"
            "       200 nextcloud-vm         running    2048              32.00 12345\n"
        ),
    })
    monkeypatch.setattr(asyncssh, "connect", lambda **kwargs: _FakeConnectContextManager(connection))
    monkeypatch.setattr(remote_admin, "_decode_secret", lambda account: ("hunter2", ""))

    result = asyncio.run(remote_admin.list_remote_proxmox_guests("10.0.0.20", _account()))

    assert result["ok"]
    names = {c["name"] for c in result["containers"]}
    assert names == {"pihole", "nextcloud-vm"}
    assert connection.commands == ["pct list", "qm list"]
    assert not any("docker" in c for c in connection.commands)


def test_list_remote_proxmox_guests_reports_a_clear_error_when_both_commands_fail(monkeypatch):
    connection = _FakeConnection({})  # every command falls through to the "not found" default
    monkeypatch.setattr(asyncssh, "connect", lambda **kwargs: _FakeConnectContextManager(connection))
    monkeypatch.setattr(remote_admin, "_decode_secret", lambda account: ("hunter2", ""))

    result = asyncio.run(remote_admin.list_remote_proxmox_guests("10.0.0.21", _account()))

    assert not result["ok"]
    assert "command not found" in result["error"]
    assert result["containers"] == []


def test_list_remote_proxmox_guests_survives_qm_missing_when_pct_works(monkeypatch):
    """A container-only Proxmox node (no VMs configured) is a normal case, not a failure -- one
    command's clean success must not be discarded because the other returned nothing useful."""
    connection = _FakeConnection({
        "pct list": _FakeRunResult("VMID       Status     Lock         Name\n100        running                 pihole\n"),
    })
    monkeypatch.setattr(asyncssh, "connect", lambda **kwargs: _FakeConnectContextManager(connection))
    monkeypatch.setattr(remote_admin, "_decode_secret", lambda account: ("hunter2", ""))

    result = asyncio.run(remote_admin.list_remote_proxmox_guests("10.0.0.22", _account()))

    assert result["ok"]
    assert [c["name"] for c in result["containers"]] == ["pihole"]
