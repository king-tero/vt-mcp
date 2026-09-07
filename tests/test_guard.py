"""Bounded guard behavior using only generated harmless files and synthetic access."""

import asyncio
import fcntl
import hashlib
import json
import os
import shlex
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import anyio
import pytest

from vt_mcp import guard
from vt_mcp.reports import VTAIError
from vt_mcp.vtai_client import ConfigurationError, Settings

NOW = datetime(2026, 9, 6, 12, tzinfo=UTC)
HASH = "a" * 64


@pytest.fixture
def policy_file(tmp_path):
    token = tmp_path / "token"
    token.write_text("synthetic-guard-test-only\n")
    data = {
        "schema_version": 1,
        "mode": "control",
        "token_file": str(token),
        "base_url": "http://127.0.0.1:12345/api/v3",
        "minimum_completed_engines": 2,
        "maximum_analysis_age_days": 30,
    }
    path = tmp_path / "policy.json"

    def write(value=data):
        raw = value if isinstance(value, bytes) else json.dumps(value).encode()
        path.write_bytes(raw)
        return str(path), hashlib.sha256(raw).hexdigest()

    return data, write


def report():
    return {
        "status": "found",
        "analysis_date": (NOW - timedelta(days=1)).isoformat(),
        "coverage": {"engines": 3},
        "data": {
            "id": HASH,
            "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 1,
                "undetected": 2,
            },
        },
    }


@pytest.mark.parametrize(
    "command",
    [
        "/usr/bin/python3 -I /tmp/a.py",
        "/usr/bin/python3 -I /tmp/A-1_b.c.py",
    ],
)
def test_exact_shape(command):
    assert guard.covered_script(command) == command.split(" ")[2]


@pytest.mark.parametrize(
    "command",
    [
        None,
        [],
        "",
        "python3 -I /tmp/a.py",
        "/usr/bin/python3 /tmp/a.py",
        "/usr/bin/python3  -I /tmp/a.py",
        "/usr/bin/python3 -I /tmp/a.py\n",
        "/usr/bin/python3 -I /tmp/a.py; true",
        "/usr/bin/python3 -I /tmp/a.py --help",
        "/usr/bin/python3 -I '/tmp/a.py'",
        "/usr/bin/python3 -I /tmp/a.py > /tmp/output",
        "/usr/bin/python3 -I /tmp/a.py && true",
        "/usr/bin/python3 -I /tmp/../a.py",
        "/usr/bin/python3 -I /tmp/./a.py",
        "/usr/bin/python3 -I /tmp//a.py",
        "/usr/bin/python3 -I /tmp/$NAME.py",
        "/usr/bin/python3 -I /tmp/é.py",
        "/usr/bin/python3 -I relative.py",
        "/usr/bin/python3 -I /tmp/a.py\x00",
    ],
)
def test_uncovered_shapes_never_rewritten(command):
    assert guard.covered_script(command) is None


def test_policy_hash_and_environment_are_authoritative(policy_file, monkeypatch):
    _, write = policy_file
    path, digest = write()
    monkeypatch.setenv("VTAI_TOKEN", "wrong-synthetic-token")
    monkeypatch.setenv("VTAI_TOKEN_FILE", "/unavailable")
    monkeypatch.setenv("VTAI_BASE_URL", "https://example.invalid")
    monkeypatch.setenv("VTAI_TIMEOUT", "60")
    policy = guard.load_policy(path, digest)
    settings = guard._settings(policy)
    assert settings.token == "synthetic-guard-test-only"
    assert settings.base_url == policy.base_url
    assert settings.timeout == 15
    Path(path).write_text(Path(path).read_text() + " ")
    with pytest.raises(guard.GuardError, match="policy_changed"):
        guard.load_policy(path, digest)
    with pytest.raises(ConfigurationError):
        Settings.from_env({})


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", True),
        ("schema_version", 2),
        ("mode", "allow"),
        ("mode", None),
        ("minimum_completed_engines", 0),
        ("minimum_completed_engines", True),
        ("minimum_completed_engines", 10001),
        ("maximum_analysis_age_days", 366),
        ("maximum_analysis_age_days", 1.5),
        ("token_file", "relative"),
        ("base_url", "http://example.invalid"),
        ("base_url", "https://user:secret@example.invalid"),
        ("unknown", "ignored-not-allowed"),
    ],
)
def test_policy_invalid_fields(policy_file, field, value):
    data, write = policy_file
    data[field] = value
    with pytest.raises(guard.GuardError, match="invalid_policy"):
        guard.load_policy(*write(data))


@pytest.mark.parametrize(
    "raw", [b"null", b"[]", b"{}", b"{", b"x" * 16385, b'{"mode":"control","mode":"observe"}']
)
def test_policy_invalid_json(policy_file, raw):
    _, write = policy_file
    with pytest.raises(guard.GuardError, match="invalid_policy"):
        guard.load_policy(*write(raw))


def test_qualified_and_flagged_reports(policy_file):
    _, write = policy_file
    policy = guard.load_policy(*write())
    assert guard.report_reason(report(), HASH, policy, NOW) == "policy_satisfied"
    for kind in ("malicious", "suspicious"):
        flagged = report()
        flagged["data"]["last_analysis_stats"][kind] = 1
        assert guard.report_reason(flagged, HASH, policy, NOW) == "flagged"
        del flagged["data"]["last_analysis_stats"]["harmless"]
        assert guard.report_reason(flagged, HASH, policy, NOW) == "flagged"
    wrong = report()
    wrong["data"]["id"] = "b" * 64
    assert guard.report_reason(wrong, HASH, policy, NOW) == "invalid_response"


@pytest.mark.parametrize(
    "kind,value",
    [
        ("malicious", None),
        ("suspicious", False),
        ("harmless", -1),
        ("undetected", 1.0),
    ],
)
def test_counts_are_explicit_strict_integers(policy_file, kind, value):
    _, write = policy_file
    policy = guard.load_policy(*write())
    raw = report()
    raw["data"]["last_analysis_stats"][kind] = value
    assert guard.report_reason(raw, HASH, policy, NOW) == "insufficient_evidence"
    del raw["data"]["last_analysis_stats"][kind]
    assert guard.report_reason(raw, HASH, policy, NOW) == "insufficient_evidence"


@pytest.mark.parametrize(
    "date",
    [
        None,
        "not-a-date",
        "2026-09-05T12:00:00",
        "2026-09-05T13:00:00+01:00",
        "2026-09-06T12:00:01Z",
        "2026-08-07T11:59:59Z",
        "2026-02-31T12:00:00Z",
    ],
)
def test_missing_stale_future_dates_do_not_allow(policy_file, date):
    _, write = policy_file
    raw = report()
    raw["analysis_date"] = date
    assert (
        guard.report_reason(raw, HASH, guard.load_policy(*write()), NOW) == "insufficient_evidence"
    )


@pytest.mark.parametrize("coverage", [None, {}, {"engines": 0}, {"engines": True}])
def test_missing_or_inadequate_coverage(policy_file, coverage):
    _, write = policy_file
    raw = report()
    raw["coverage"] = coverage
    assert (
        guard.report_reason(raw, HASH, guard.load_policy(*write()), NOW) == "insufficient_evidence"
    )


def test_failed_engines_are_not_completed_evidence(policy_file):
    _, write = policy_file
    raw = report()
    raw["data"]["last_analysis_stats"] = {
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "timeout": 50,
        "failure": 50,
    }
    raw["coverage"]["engines"] = 100
    assert (
        guard.report_reason(raw, HASH, guard.load_policy(*write()), NOW) == "insufficient_evidence"
    )


def test_snapshot_seals_hash_and_original_replacement(tmp_path):
    original = tmp_path / "script.py"
    original.write_bytes(b'print("harmless fixture A")\n')
    expected = original.read_bytes()
    before_fds = set(os.listdir("/proc/self/fd"))
    with guard.snapshot(str(original)) as checked:
        assert checked.sha256 == hashlib.sha256(expected).hexdigest()
        assert os.get_inheritable(checked.fd) is False
        assert not os.fstat(checked.fd).st_mode & 0o111
        required = guard._seals()[1] | guard.F_SEAL_EXEC
        assert fcntl.fcntl(checked.fd, guard.F_GET_SEALS) & required == required
        for operation in (
            lambda: os.pwrite(checked.fd, b"x", 0),
            lambda: os.ftruncate(checked.fd, 0),
            lambda: os.ftruncate(checked.fd, len(expected) + 1),
            lambda: os.fchmod(checked.fd, 0o700),
        ):
            with pytest.raises(PermissionError):
                operation()
        replacement = tmp_path / "replacement.py"
        replacement.write_bytes(b'print("harmless fixture B")\n')
        replacement.replace(original)
        assert os.pread(checked.fd, len(expected) + 1, 0) == expected
    assert set(os.listdir("/proc/self/fd")) == before_fds


@pytest.mark.parametrize("kind", ["empty", "large", "directory", "symlink", "fifo", "missing"])
def test_non_regular_files_rejected_without_leaks(tmp_path, kind):
    path = tmp_path / "invalid.py"
    if kind == "empty":
        path.touch()
    elif kind == "large":
        with path.open("wb") as file:
            file.truncate(guard.MAX_SCRIPT_BYTES + 1)
    elif kind == "directory":
        path.mkdir()
    elif kind == "symlink":
        target = tmp_path / "target.py"
        target.write_text("pass\n")
        path.symlink_to(target)
    elif kind == "fifo":
        os.mkfifo(path)
    before = set(os.listdir("/proc/self/fd"))
    with pytest.raises(guard.GuardError), guard.snapshot(str(path)):
        pytest.fail("Invalid file yielded a snapshot")
    assert set(os.listdir("/proc/self/fd")) == before


def test_mutation_during_copy_is_rejected(tmp_path, monkeypatch):
    path = tmp_path / "changed.py"
    path.write_bytes(b"# harmless fixture\n" * 5000)
    read = os.read
    changed = False

    def mutate(fd, count):
        nonlocal changed
        part = read(fd, count)
        if part and not changed:
            changed = True
            with path.open("ab") as file:
                file.write(b"# changed\n")
        return part

    monkeypatch.setattr(os, "read", mutate)
    with pytest.raises(guard.GuardError, match="source_changed"), guard.snapshot(str(path)):
        pytest.fail("Modified file accepted")


def test_partial_writes_and_copy_deadline(tmp_path, monkeypatch):
    path = tmp_path / "script.py"
    path.write_bytes(b"pass\n" * 100)
    write = os.write
    monkeypatch.setattr(os, "write", lambda fd, part: write(fd, part[:7]))
    with guard.snapshot(str(path)) as checked:
        assert checked.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(guard, "PREPARATION_SECONDS", 0)
    with pytest.raises(guard.GuardError, match="preparation_timeout"), guard.snapshot(str(path)):
        pytest.fail("Expired preparation accepted")


def test_hook_rewrites_only_command_and_pins_policy(policy_file, monkeypatch):
    _, write = policy_file
    path, digest = write()
    tool_input = {
        "command": "/usr/bin/python3 -I /tmp/script.py",
        "workdir": "/tmp",
        "yield_time_ms": 1000,
        "sandbox_permissions": "use_default",
    }
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": tool_input}
    monkeypatch.setenv("VTAI_TOKEN", "synthetic-not-reflected")
    result = guard.hook(json.dumps(event).encode(), path, digest)
    output = result["hookSpecificOutput"]
    assert output["permissionDecision"] == "allow"
    command = shlex.split(output["updatedInput"]["command"])
    assert command == [
        sys.executable,
        "-I",
        "-m",
        "vt_mcp",
        "guard",
        "run",
        "--policy",
        path,
        "--policy-sha256",
        digest,
        "--",
        "/tmp/script.py",
    ]
    updated = {**output["updatedInput"], "command": tool_input["command"]}
    assert updated == tool_input
    assert "synthetic-not-reflected" not in json.dumps(result)
    assert event["tool_input"] == tool_input


@pytest.mark.parametrize(
    "raw", [b"x" * (65536 + 1), b"null", b"[]", b"{", b'{"a":1,"a":2}', b'{"a":NaN}']
)
def test_malformed_hook_input_has_closed_denial(raw):
    assert guard.hook(raw, "/unused", HASH) == guard._deny()


def test_hook_uncovered_and_output_bound(policy_file):
    _, write = policy_file
    args = write()
    assert guard.hook(b'{"tool_name":"Other"}', *args) == {}
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo harmless"},
    }
    assert guard.hook(json.dumps(event).encode(), *args) == {}
    event["tool_input"] = {"command": "/usr/bin/python3 -I /tmp/fixture.py", "extra": "é" * 15000}
    raw = json.dumps(event, ensure_ascii=False).encode()
    assert len(raw) < guard.MAX_HOOK_BYTES
    assert guard.hook(raw, *args) == guard._deny()
    event["tool_input"] = {"command": "/usr/bin/python3 -I /tmp/fixture.py"}
    assert guard.hook(json.dumps(event).encode(), args[0], "f" * 64) == guard._deny()


def test_hook_output_limit_includes_final_newline(policy_file, monkeypatch):
    _, write = policy_file
    args = write()
    raw = json.dumps(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "/usr/bin/python3 -I /tmp/fixture.py"},
        }
    ).encode()
    result = guard.hook(raw, *args)
    length = len(json.dumps(result, ensure_ascii=True).encode("ascii"))
    monkeypatch.setattr(guard, "MAX_HOOK_BYTES", length)
    assert guard.hook(raw, *args) == guard._deny()
    monkeypatch.setattr(guard, "MAX_HOOK_BYTES", length + 1)
    assert guard.hook(raw, *args) == result


@pytest.mark.parametrize("mode", ["observe", "control"])
def test_http_closed_before_exec_and_environment_clean(policy_file, tmp_path, monkeypatch, mode):
    data, write = policy_file
    data["mode"] = mode
    policy = guard.load_policy(*write())
    path = tmp_path / "fixture.py"
    path.write_text("pass\n")
    state = {"closed": False, "queried": False}

    class Client:
        def __init__(self, settings):
            assert settings.timeout == 15

        async def __aenter__(self):
            return self

        async def get_file_report(self, sha256):
            state["queried"] = True
            raw = report()
            raw["data"]["id"] = sha256
            raw["analysis_date"] = datetime.now(UTC).isoformat()
            return raw

        async def __aexit__(self, *args):
            state["closed"] = True

    monkeypatch.setattr(guard, "VTAIClient", Client)
    for name in ("VTAI_TOKEN", "VTAI_TOKEN_FILE", "VTAI_MCP_TOKEN", "VTAI_FUTURE_CREDENTIAL"):
        monkeypatch.setenv(name, "synthetic-never-in-child")
    inherited = os.open(path, os.O_RDONLY)
    os.set_inheritable(inherited, True)

    def execute(executable, argv, env):
        assert state == {"closed": True, "queried": True}
        assert executable == "/usr/bin/python3"
        assert argv[1] == "-I"
        assert not any(name.startswith("VTAI_") for name in env)
        assert not os.get_inheritable(inherited)
        fd = int(argv[2].rsplit("/", 1)[1])
        assert os.get_inheritable(fd)
        assert os.pread(fd, 100, 0) == path.read_bytes()
        raise OSError("synthetic-private-error-never-print")

    monkeypatch.setattr(os, "execve", execute)
    try:
        with pytest.raises(guard.GuardError, match="execution_failed"):
            guard.run(policy, str(path))
    finally:
        os.close(inherited)


@pytest.mark.parametrize("reason", sorted(guard.REPORT_ERRORS) + ["unexpected-private-error"])
def test_error_codes_are_closed(policy_file, monkeypatch, reason):
    _, write = policy_file

    class Client:
        def __init__(self, settings):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def get_file_report(self, sha256):
            raise VTAIError(reason, "synthetic-private-message")

    monkeypatch.setattr(guard, "VTAIClient", Client)
    expected = reason if reason in guard.REPORT_ERRORS else "check_failed"
    assert anyio.run(guard._check, guard.load_policy(*write()), HASH).reason == expected


def test_cancellation_propagates_and_closes_http(policy_file, monkeypatch):
    _, write = policy_file
    state = []

    class Client:
        def __init__(self, settings):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            state.append("closed")

        async def get_file_report(self, sha256):
            raise asyncio.CancelledError

    monkeypatch.setattr(guard, "VTAIClient", Client)
    with pytest.raises(asyncio.CancelledError):
        anyio.run(guard._check, guard.load_policy(*write()), HASH)
    assert state == ["closed"]


def test_doctor_is_local_and_does_not_claim_host_activation(policy_file, monkeypatch, capsys):
    _, write = policy_file
    monkeypatch.setattr(guard, "VTAIClient", lambda *_: pytest.fail("Doctor used HTTP"))
    path, digest = write()
    assert guard.main(["doctor", "--policy", path, "--policy-sha256", digest]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["host_activation"] == "unverified"
    assert result["access"] == result["network"] == "not_checked"
    monkeypatch.setattr(os, "memfd_create", lambda *_: (_ for _ in ()).throw(OSError()))
    with pytest.raises(guard.GuardError, match="unsupported_platform"):
        guard.doctor(guard.load_policy(*write()))


def test_missing_credential_is_not_read_from_ambient_env(policy_file, monkeypatch):
    data, write = policy_file
    Path(data["token_file"]).unlink()
    monkeypatch.setenv("VTAI_TOKEN", "synthetic-ambient-fallback-disallowed")
    assert (
        anyio.run(guard._check, guard.load_policy(*write()), HASH).reason
        == "credential_unavailable"
    )


@pytest.mark.parametrize("kind", ["fifo", "symlink", "oversized", "non_ascii"])
def test_invalid_credentials_are_bounded_without_environment_fallback(policy_file, kind):
    data, write = policy_file
    token_file = Path(data["token_file"])
    token_file.unlink()
    if kind == "fifo":
        os.mkfifo(token_file)
    elif kind == "symlink":
        token_file.symlink_to("missing-credential")
    elif kind == "oversized":
        token_file.write_bytes(b"a" * 515)
    else:
        token_file.write_bytes(b"\xff")
    assert (
        anyio.run(guard._check, guard.load_policy(*write()), HASH).reason
        == "credential_unavailable"
    )


@pytest.mark.parametrize("mode", ["control", "observe"])
def test_seal_failure_never_queries_or_executes(policy_file, tmp_path, monkeypatch, mode, capsys):
    data, write = policy_file
    data["mode"] = mode
    path, digest = write()
    script = tmp_path / "fixture.py"
    script.write_text("pass\n")

    def fail_seal(fd):
        raise OSError("private-fixture-error")

    monkeypatch.setattr(guard, "_seal", fail_seal)
    monkeypatch.setattr(guard, "VTAIClient", lambda *_: pytest.fail("Queried without valid seals"))
    monkeypatch.setattr(guard, "_execute", lambda *_: pytest.fail("Executed without valid seals"))
    before = set(os.listdir("/proc/self/fd"))
    assert guard.main(["run", "--policy", path, "--policy-sha256", digest, "--", str(script)]) == 78
    output = capsys.readouterr()
    assert output.out == "" and "private-fixture-error" not in output.err
    assert json.loads(output.err)["decision"] == "blocked"
    assert set(os.listdir("/proc/self/fd")) == before


def test_cli_errors_never_echo_arguments(capsys):
    assert guard.main(["run", "--unexpected", "synthetic-private-value"]) == 78
    output = capsys.readouterr()
    assert output.out == ""
    assert "synthetic-private-value" not in output.err
    assert json.loads(output.err)["reason"] == "invalid_arguments"
    assert guard.main(["hook", "--unexpected", "synthetic-private-value"]) == 0
    assert json.loads(capsys.readouterr().out) == guard._deny()
