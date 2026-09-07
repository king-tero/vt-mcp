import asyncio
import io
import json
import os
import stat
import time

import anyio
import pytest
from analysis_helpers import ANALYSIS_ID, BODY, SHA, TOKEN, analysis_response, submission_response

from vt_mcp import submission_cli as cli
from vt_mcp.analyses import AnalysisError
from vt_mcp.vtai_client import Settings


class TTY(io.StringIO):
    def isatty(self):
        return True


@pytest.fixture
def local(tmp_path, monkeypatch):
    source = tmp_path / "private-local-name.txt"
    source.write_bytes(BODY)
    state = tmp_path / "private-state"
    monkeypatch.setattr(
        cli.Settings, "from_env", lambda: Settings(TOKEN, "http://127.0.0.1:12345/api/v3")
    )
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO(""))
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
    return source, state, args


@pytest.mark.parametrize("response", ["", "no\n", "yes\n", "SUBMIT\n"])
def test_interactive_consent_is_explicit_and_binds_only_snapshot(
    local, monkeypatch, capsys, response
):
    source, state, args = local
    calls = []

    async def submit(settings, snapshot, created):
        calls.append((created, snapshot.sha256, snapshot.file.read()))
        return submission_response()

    monkeypatch.setattr(cli, "_submit", submit)
    monkeypatch.setattr(cli.sys, "stdin", TTY(response))
    args.remove("--accept-standard")
    code = cli.main(args)
    output = capsys.readouterr()
    assert "not confidential" in output.err and SHA in output.err
    assert str(source) not in output.out + output.err and TOKEN not in output.out + output.err
    if response == "SUBMIT\n":
        assert code == 0 and calls == [(True, SHA, BODY)]
        assert len(list(state.rglob("*.json"))) == 1
    else:
        assert code == 2 and calls == [] and not state.exists()
        assert json.loads(output.out)["error"]["code"] == "confirmation_declined"


@pytest.mark.parametrize("case", ["no_flags", "accept_only", "hash_only", "wrong_hash", "bad_hash"])
def test_noninteractive_requires_both_flags_and_matching_sha(local, monkeypatch, capsys, case):
    _, state, args = local
    monkeypatch.setattr(cli, "_submit", lambda *_: pytest.fail("Unconsented POST"))
    if case in {"no_flags", "hash_only"}:
        args.remove("--accept-standard")
    if case in {"no_flags", "accept_only"}:
        index = args.index("--expected-sha256")
        del args[index : index + 2]
    elif case in {"wrong_hash", "bad_hash"}:
        args[args.index("--expected-sha256") + 1] = "0" * 64 if case == "wrong_hash" else "bad"
    assert cli.main(args) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "error"
    assert not state.exists()


def test_original_changes_after_consent_do_not_change_sent_bytes(local, monkeypatch, capsys):
    source, _, args = local
    original_confirm = cli.confirm

    def confirm(snapshot, **options):
        original_confirm(snapshot, **options)
        source.write_bytes(b"Different harmless bytes after consent.\n")

    async def submit(settings, snapshot, created):
        assert created and snapshot.file.read() == BODY and snapshot.sha256 == SHA
        return submission_response()

    monkeypatch.setattr(cli, "confirm", confirm)
    monkeypatch.setattr(cli, "_submit", submit)
    assert cli.main(args) == 0
    assert json.loads(capsys.readouterr().out)["sha256"] == SHA


@pytest.mark.parametrize("kind", ["fifo", "directory", "symlink", "oversized", "missing"])
def test_non_regular_or_oversized_inputs_fail_without_state(local, monkeypatch, capsys, kind):
    source, state, args = local
    source.unlink()
    if kind == "fifo":
        os.mkfifo(source)
    elif kind == "directory":
        source.mkdir()
    elif kind == "symlink":
        source.symlink_to("missing")
    elif kind == "oversized":
        with source.open("wb") as file:
            file.truncate(32_000_001)
    monkeypatch.setattr(cli, "_submit", lambda *_: pytest.fail("Invalid file POST"))
    assert cli.main(args) == 2
    assert json.loads(capsys.readouterr().out)["error"]["code"] == "invalid_file"
    assert not state.exists()


def test_snapshot_change_and_deadline_close_descriptors(local, monkeypatch):
    source, _, _ = local
    before = set(os.listdir("/proc/self/fd"))
    original = os.read
    changed = False

    def mutate(fd, count):
        nonlocal changed
        part = original(fd, count)
        if not changed:
            changed = True
            source.write_bytes(BODY + b"changed\n")
        return part

    monkeypatch.setattr(os, "read", mutate)
    with pytest.raises(cli.CLIError, match="source changed"), cli.copy_snapshot(str(source)):
        pytest.fail("Changed snapshot accepted")
    monkeypatch.setattr(os, "read", original)
    monkeypatch.setattr(cli, "COPY_SECONDS", 0)
    with pytest.raises(cli.CLIError, match="budget"), cli.copy_snapshot(str(source)):
        pytest.fail("Expired snapshot accepted")
    assert set(os.listdir("/proc/self/fd")) == before


def test_recovery_reference_is_private_minimal_and_not_recreated(local, capsys):
    _, state, _ = local
    settings = Settings(TOKEN, "https://example.invalid/api/v3/")
    assert cli.persist_reference(settings, SHA, state) is True
    assert cli.persist_reference(settings, SHA, state) is False
    files = list(state.rglob("*.json"))
    assert len(files) == 1
    record = json.loads(files[0].read_text())
    assert record == {
        "schema_version": 1,
        "service": "https://example.invalid/api/v3",
        "mode": "standard",
        "sha256": SHA,
    }
    assert not files[0].stat().st_mode & 0o077
    assert all(
        not directory.stat().st_mode & 0o077
        for directory in files[0].parents
        if directory == state or state in directory.parents
    )
    assert TOKEN not in str(files[0]) + files[0].read_text()
    assert capsys.readouterr().out == ""


def test_service_and_credential_namespaces_are_distinct(local):
    _, state, _ = local
    assert cli.persist_reference(Settings(TOKEN, "https://example.invalid/a"), SHA, state)
    assert cli.persist_reference(Settings(TOKEN, "https://example.invalid/b"), SHA, state)
    assert cli.persist_reference(
        Settings("synthetic-rotated", "https://example.invalid/a"), SHA, state
    )
    assert len(list(state.rglob("*.json"))) == 3


@pytest.mark.parametrize(
    "case", ["public_directory", "symlink_directory", "root_directory", "token_in_service"]
)
def test_state_rejects_nonprivate_or_secret_bearing_locations(local, case):
    _, state, _ = local
    settings = Settings(TOKEN, "https://example.invalid/api/v3")
    if case == "public_directory":
        state.mkdir(mode=0o755)
    elif case == "symlink_directory":
        target = state.with_name("other-directory")
        target.mkdir(mode=0o700)
        state.symlink_to(target)
    elif case == "root_directory":
        state = state.__class__("/")
    else:
        settings = Settings(TOKEN, "https://example.invalid/" + TOKEN)
    with pytest.raises(cli.CLIError):
        cli.persist_reference(settings, SHA, state)


@pytest.mark.parametrize("failure", ["file_fsync", "directory_fsync", "write"])
def test_failed_durability_never_starts_post(local, monkeypatch, capsys, failure):
    _, state, args = local
    original_fsync, original_write = os.fsync, os.write
    state.mkdir(mode=0o700)

    def fsync(fd):
        is_file = stat.S_ISREG(os.fstat(fd).st_mode)
        if (failure == "file_fsync" and is_file) or (failure == "directory_fsync" and not is_file):
            raise OSError("private-storage-detail")
        return original_fsync(fd)

    def write(fd, data):
        if failure == "write":
            raise OSError("private-storage-detail")
        return original_write(fd, data)

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "write", write)
    monkeypatch.setattr(cli, "_submit", lambda *_: pytest.fail("POST before durable state"))
    assert cli.main(args) == 2
    output = capsys.readouterr()
    assert json.loads(output.out)["error"]["code"] == "local_state_unavailable"
    assert "private-storage-detail" not in output.out + output.err


def test_durable_state_precedes_post_and_repeat_only_reads(local, monkeypatch, capsys):
    _, state, args = local
    observed = []

    async def submit(settings, snapshot, created):
        assert len(list(state.rglob("*.json"))) == 1
        observed.append(created)
        if created:
            raise AnalysisError(
                "submission_unknown", submission=submission_response(status="submission_unknown")
            )
        return submission_response(status="submission_unknown")

    monkeypatch.setattr(cli, "_submit", submit)
    assert cli.main(args) == 3
    assert json.loads(capsys.readouterr().out)["submission"]["sha256"] == SHA
    assert cli.main(args) == 3
    assert json.loads(capsys.readouterr().out)["status"] == "submission_unknown"
    assert observed == [True, False]


@pytest.mark.parametrize("phase", ["confirmation", "dispatch"])
def test_interruption_keeps_correct_uncertainty_and_closes_snapshot(
    local, monkeypatch, capsys, phase
):
    _, state, args = local
    before = set(os.listdir("/proc/self/fd"))

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "confirm" if phase == "confirmation" else "_submit", interrupt)
    assert cli.main(args) == 130
    result = json.loads(capsys.readouterr().out)
    if phase == "confirmation":
        assert not state.exists() and result["error"]["code"] == "cancelled"
    else:
        assert result["status"] == "submission_unknown" and len(list(state.rglob("*.json"))) == 1
    assert set(os.listdir("/proc/self/fd")) == before


@pytest.mark.anyio
async def test_wait_preserves_pending_and_never_pretends_completion():
    calls = []

    class Client:
        async def get_analysis(self, identifier):
            calls.append(identifier)
            return analysis_response()

    start = time.monotonic()
    result = await cli.wait_analysis(Client(), ANALYSIS_ID, 0.04)
    assert 0.03 <= time.monotonic() - start < 0.5
    assert result["status"] == "pending" and result["wait"]["status"] == "budget_exhausted"
    assert calls == [ANALYSIS_ID]


@pytest.mark.anyio
async def test_wait_honors_retry_after_and_only_retries_reads(monkeypatch):
    calls, delays = [], []

    class Client:
        async def get_analysis(self, identifier):
            calls.append(identifier)
            if len(calls) == 1:
                raise AnalysisError("rate_limited", retry_after_seconds=17)
            return analysis_response(completed=True)

    async def sleep(seconds):
        delays.append(seconds)
        await anyio.lowlevel.checkpoint()

    monkeypatch.setattr(anyio, "sleep", sleep)
    result = await cli.wait_analysis(Client(), ANALYSIS_ID, 1)
    assert result["status"] == "completed" and result["wait"]["status"] == "completed"
    assert delays == [17] and calls == [ANALYSIS_ID, ANALYSIS_ID]


@pytest.mark.anyio
async def test_wait_distinguishes_no_report_auth_failure_and_cancellation():
    class Client:
        async def get_analysis(self, identifier):
            raise AnalysisError("rate_limited", retry_after_seconds=60)

    with pytest.raises(AnalysisError) as error:
        await cli.wait_analysis(Client(), ANALYSIS_ID, 0.02)
    assert error.value.error["code"] == "rate_limited"

    class Denied:
        async def get_analysis(self, identifier):
            raise AnalysisError("access_denied")

    with pytest.raises(AnalysisError, match="credential"):
        await cli.wait_analysis(Denied(), ANALYSIS_ID, 1)

    class Cancelled:
        async def get_analysis(self, identifier):
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await cli.wait_analysis(Cancelled(), ANALYSIS_ID, 1)


@pytest.mark.anyio
async def test_wait_retains_observed_pending_after_transient_error(monkeypatch):
    requests = []
    sleep = anyio.sleep

    class Client:
        async def get_analysis(self, identifier):
            requests.append(identifier)
            if len(requests) == 1:
                return analysis_response()
            raise AnalysisError("unavailable")

    async def short_first_sleep(seconds):
        await sleep(0 if len(requests) == 1 else seconds)

    monkeypatch.setattr(anyio, "sleep", short_first_sleep)
    result = await cli.wait_analysis(Client(), ANALYSIS_ID, 0.03)
    assert result["status"] == "pending"
    assert result["wait"]["last_error"]["code"] == "unavailable"
    assert requests == [ANALYSIS_ID, ANALYSIS_ID]


@pytest.mark.parametrize("value", ["301", "nan", "inf", "-1", "synthetic-private-value"])
def test_bad_wait_or_arguments_are_rejected_without_echo(value, capsys):
    assert cli.main(["analysis", ANALYSIS_ID, "--wait", value]) == 2
    result = capsys.readouterr()
    assert value not in result.out + result.err
    assert json.loads(result.out)["error"]["code"] == "invalid_arguments"
