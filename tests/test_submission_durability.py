"""Local persistence fault injection; no network or actual sample submission."""

import hashlib
import json
import os
from pathlib import Path

import pytest
from analysis_helpers import BODY, SHA, TOKEN, submission_response

from vt_mcp import submission_cli as cli
from vt_mcp.vtai_client import Settings


@pytest.fixture
def recovery(tmp_path, monkeypatch):
    settings = Settings(TOKEN, "http://127.0.0.1:12345/api/v3")
    source = tmp_path / "input.txt"
    source.write_bytes(BODY)
    state = tmp_path / "state"
    service = state / hashlib.sha256(settings.base_url.encode()).hexdigest()
    actor = (
        service
        / hashlib.sha256(
            b"vt-mcp-submission-identity-v1\0"
            + settings.base_url.encode()
            + b"\0"
            + settings.token.encode()
        ).hexdigest()
    )
    monkeypatch.setattr(cli.Settings, "from_env", lambda: settings)
    args = [
        "submit",
        str(source),
        "--mode",
        "standard",
        "--accept-standard",
        "--expected-sha256",
        SHA,
        "--state-dir",
        str(state),
    ]
    return args, state, service, actor


def _path(fd):
    return Path(os.readlink(f"/proc/self/fd/{fd}"))


@pytest.mark.parametrize("level", ["state", "service", "actor"])
def test_failed_new_entry_is_reconfirmed_on_later_attempt(recovery, monkeypatch, capsys, level):
    args, state, service, actor = recovery
    child = {"state": state, "service": service, "actor": actor}[level]
    real_fsync = os.fsync
    failed = False
    confirmed = set()
    dispatch = []

    def fsync(fd):
        nonlocal failed
        path = _path(fd)
        if not failed and path == child.parent and child.exists():
            failed = True
            raise OSError("synthetic directory acknowledgement failure")
        real_fsync(fd)
        confirmed.add(path)

    async def submit(settings, snapshot, created):
        # Each directory inode, every parent entry and the receipt have completed
        # a real fsync during THIS attempt before a new POST can become eligible.
        required = set(actor.parents) | {actor, actor / (SHA + ".json")}
        if created:
            assert required <= confirmed
        dispatch.append(created)
        return submission_response()

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(cli, "_submit", submit)
    before = set(os.listdir("/proc/self/fd"))
    assert cli.main(args) == 2
    assert json.loads(capsys.readouterr().out)["error"]["code"] == "local_state_unavailable"
    assert failed and child.is_dir() and not list(state.rglob("*.json"))
    assert dispatch == []
    confirmed.clear()
    assert cli.main(args) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "submitted"
    assert dispatch == [True]
    assert cli.main(args) == 0
    capsys.readouterr()
    assert dispatch == [True, False]
    assert set(os.listdir("/proc/self/fd")) == before


@pytest.mark.parametrize("level", ["ancestor", "state", "service", "actor"])
def test_preexisting_directories_cannot_skip_a_persistent_fsync_failure(
    recovery, monkeypatch, capsys, level
):
    args, state, service, actor = recovery
    for directory in (state, service, actor):
        directory.mkdir(mode=0o700)
    target = {"ancestor": state.parent, "state": state, "service": service, "actor": actor}[level]
    real_fsync = os.fsync
    enabled = True
    synced = set()
    dispatch = []

    def fsync(fd):
        path = _path(fd)
        if enabled and path == target:
            raise OSError("synthetic persistent storage failure")
        real_fsync(fd)
        synced.add(path)

    async def submit(settings, snapshot, created):
        assert set(actor.parents) | {actor, actor / (SHA + ".json")} <= synced
        dispatch.append(created)
        return submission_response()

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(cli, "_submit", submit)
    for _ in range(2):
        assert cli.main(args) == 2
        output = capsys.readouterr()
        assert json.loads(output.out)["error"]["code"] == "local_state_unavailable"
        assert "synthetic" not in output.out + output.err
        assert dispatch == [] and not list(state.rglob("*.json"))
    enabled = False
    synced.clear()
    assert cli.main(args) == 0
    capsys.readouterr()
    assert dispatch == [True]


def test_existing_receipt_survives_failed_directory_reconfirmation(recovery, monkeypatch, capsys):
    args, state, _, actor = recovery
    dispatch = []

    async def submit(settings, snapshot, created):
        dispatch.append(created)
        return submission_response()

    monkeypatch.setattr(cli, "_submit", submit)
    assert cli.main(args) == 0
    capsys.readouterr()
    receipt = actor / (SHA + ".json")
    original_bytes, original_inode = receipt.read_bytes(), receipt.stat().st_ino
    real_fsync = os.fsync

    def fsync(fd):
        if _path(fd) == state:
            raise OSError("synthetic revalidation failure")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fsync)
    assert cli.main(args) == 2
    assert json.loads(capsys.readouterr().out)["error"]["code"] == "local_state_unavailable"
    assert dispatch == [True]
    monkeypatch.setattr(os, "fsync", real_fsync)
    assert cli.main(args) == 0
    capsys.readouterr()
    assert dispatch == [True, False]
    assert receipt.read_bytes() == original_bytes and receipt.stat().st_ino == original_inode
