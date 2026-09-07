"""Deadline and bounded evidence regressions using inert, local fixtures."""

import hashlib
import json
import os
from datetime import UTC, datetime

import pytest

from vt_mcp import guard
from vt_mcp.reports import VTAIError


@pytest.mark.parametrize("mode", ["control", "observe"])
@pytest.mark.parametrize("phase", ["memfd", "write", "seal", "hash_read", "hash_rewind"])
def test_expired_preparation_never_queries_or_executes(tmp_path, monkeypatch, mode, phase):
    script = tmp_path / "inert.py"
    script.write_bytes(b"pass\n")
    policy = guard.Policy(mode, str(tmp_path / "token"), "http://localhost/api/v3", 1, 30)
    clock = [0.0]
    state = {"fd": None, "sealed": False, "seeks": 0}
    monkeypatch.setattr(guard.time, "monotonic", lambda: clock[0])
    original_memfd, original_seal = guard._new_memfd, guard._seal
    original_write, original_read, original_seek = os.write, os.read, os.lseek

    def expire(when):
        if phase == when:
            clock[0] = guard.PREPARATION_SECONDS + 1

    def new_memfd():
        state["fd"] = original_memfd()
        expire("memfd")
        return state["fd"]

    def write(fd, data):
        result = original_write(fd, data[:1])
        expire("write")
        return result

    def seal(fd):
        original_seal(fd)
        state["sealed"] = True
        expire("seal")

    def read(fd, length):
        result = original_read(fd, length)
        if state["sealed"] and fd == state["fd"]:
            expire("hash_read")
        return result

    def seek(fd, offset, whence):
        result = original_seek(fd, offset, whence)
        state["seeks"] += 1
        if state["seeks"] == 2:
            expire("hash_rewind")
        return result

    monkeypatch.setattr(guard, "_new_memfd", new_memfd)
    monkeypatch.setattr(guard, "_seal", seal)
    monkeypatch.setattr(os, "write", write)
    monkeypatch.setattr(os, "read", read)
    monkeypatch.setattr(os, "lseek", seek)
    monkeypatch.setattr(guard, "VTAIClient", lambda *_: pytest.fail("Queried after expiry"))
    monkeypatch.setattr(guard, "_execute", lambda *_: pytest.fail("Executed after expiry"))
    before = set(os.listdir("/proc/self/fd"))
    with pytest.raises(guard.GuardError, match="preparation_timeout"):
        guard.run(policy, str(script))
    assert set(os.listdir("/proc/self/fd")) == before


@pytest.mark.parametrize("phase", ["open", "eof"])
def test_regular_read_budget_includes_open_and_final_eof(tmp_path, monkeypatch, phase):
    path = tmp_path / "data"
    path.write_bytes(b"fixture")
    clock = [0.0]
    monkeypatch.setattr(guard.time, "monotonic", lambda: clock[0])
    original_open, original_read = os.open, os.read

    def open_file(*args):
        fd = original_open(*args)
        if phase == "open":
            clock[0] = guard.PREPARATION_SECONDS + 1
        return fd

    def read_file(*args):
        result = original_read(*args)
        if phase == "eof" and not result:
            clock[0] = guard.PREPARATION_SECONDS + 1
        return result

    monkeypatch.setattr(os, "open", open_file)
    monkeypatch.setattr(os, "read", read_file)
    before = set(os.listdir("/proc/self/fd"))
    with pytest.raises(guard.GuardError, match="preparation_timeout"):
        guard._read_regular(str(path), 100)
    assert set(os.listdir("/proc/self/fd")) == before


@pytest.mark.parametrize(
    "case", ["valid", "long_date", "naive_date", "huge_count", "wrong_hash", "error"]
)
def test_status_evidence_is_faithful_bounded_and_sanitized(tmp_path, monkeypatch, capsys, case):
    script = tmp_path / "inert.py"
    script.write_bytes(b"pass\n")
    digest = hashlib.sha256(script.read_bytes()).hexdigest()
    token = tmp_path / "token"
    token.write_text("synthetic-private-token")
    policy = guard.Policy("control", str(token), "http://localhost/api/v3", 1, 30)
    date = datetime.now(UTC).replace(microsecond=0).isoformat()
    report = {
        "status": "found",
        "source": "synthetic-private-upstream-text\n",
        "analysis_date": date,
        "coverage": {"engines": 2, "categories": ["synthetic-private-upstream-text"]},
        "data": {
            "id": digest,
            "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 1,
                "undetected": 1,
            },
        },
    }
    if case == "long_date":
        report["analysis_date"] = date[:19] + "." + "0" * 10000 + "+00:00"
    elif case == "naive_date":
        report["analysis_date"] = date[:19]
    elif case == "huge_count":
        report["coverage"]["engines"] = 10**3000
    elif case == "wrong_hash":
        report["data"]["id"] = "0" * 64

    class Client:
        def __init__(self, settings):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def get_file_report(self, sha256):
            assert sha256 == digest
            if case == "error":
                raise VTAIError("access_denied", "synthetic-private-upstream-text")
            return report

    monkeypatch.setattr(guard, "VTAIClient", Client)
    monkeypatch.setattr(guard, "_execute", lambda *_: None)
    guard.run(policy, str(script))
    output = capsys.readouterr()
    assert output.out == ""
    assert len(output.err.encode()) <= 2048
    assert "synthetic-private" not in output.err and str(tmp_path) not in output.err
    status = json.loads(output.err)
    assert status["source"] == "VirusTotal via VTAI" and status["sha256"] == digest
    assert status["analysis_date"] == (
        None if case in {"naive_date", "wrong_hash", "error"} else date
    )
    expected_engines = None if case in {"huge_count", "wrong_hash", "error"} else 2
    assert status["coverage"] == {"engines": expected_engines}
    if case == "huge_count":
        assert status["coverage_omitted"] is True
    if case in {"naive_date", "wrong_hash", "error"}:
        assert status["decision"] == "blocked"
