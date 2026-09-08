"""Inert bytes, private test state and mocked VTAI; no external submissions."""

import base64
import hashlib
import os
import stat
import threading
import time
from contextlib import contextmanager

import anyio
import httpx
import pytest
from analysis_helpers import BODY, SHA, TOKEN, submission_response

from vt_mcp import submissions
from vt_mcp.analyses import (
    MAX_INLINE_SUBMISSION_BYTES,
    AnalysisError,
    decode_submission,
)
from vt_mcp.client import AnalysisClient
from vt_mcp.submissions import LocalSubmissions
from vt_mcp.vtai_client import Settings


def encoded(body=BODY):
    return base64.b64encode(body).decode("ascii")


@pytest.mark.parametrize("body", [b"", b"a", b"ab", BODY, bytes(range(256))])
def test_canonical_base64_binds_exact_bytes(body):
    assert decode_submission(hashlib.sha256(body).hexdigest(), encoded(body)) == body


@pytest.mark.parametrize(
    "value",
    [
        None,
        12,
        b"YQ==",
        "YQ",
        "YQ=",
        "YR==",
        "YWJ=",
        "YQ===",
        "YQ======",
        "AAAA====",
        "YQ==\n",
        " YQ==",
        "YQ==YQ==",
        "====",
        "****",
        "é===",
        "-w==",
        "data:application/octet-stream;base64,YQ==",
        "file:///tmp/fixture",
    ],
)
def test_invalid_encoding_is_closed(value):
    with pytest.raises(AnalysisError) as error:
        decode_submission(hashlib.sha256(b"a").hexdigest(), value)
    assert error.value.error["code"] == "invalid_input"


def test_wrong_sha_and_inline_exact_size_boundary():
    with pytest.raises(AnalysisError) as mismatch:
        decode_submission("0" * 64, encoded())
    assert mismatch.value.error["code"] == "hash_mismatch"
    body = b"x" * MAX_INLINE_SUBMISSION_BYTES
    assert len(decode_submission(hashlib.sha256(body).hexdigest(), encoded(body))) == len(body)
    with pytest.raises(AnalysisError) as oversized:
        decode_submission(SHA, encoded(body + b"x"))
    assert oversized.value.error["code"] == "inline_too_large"


@pytest.fixture
def local(tmp_path):
    path = tmp_path / "private-original-name.txt"
    path.write_bytes(BODY)
    return path, tmp_path / "state"


@pytest.mark.anyio
async def test_original_mutation_after_snapshot_does_not_change_upload(local, monkeypatch):
    path, state = local
    calls = []
    original = submissions.persist_reference

    def persist(*args):
        created = original(*args)
        path.write_bytes(b"Changed innocent original after copying.\n")
        return created

    async def handler(request):
        assert len(list(state.rglob("*.json"))) == 1
        assert request.headers["x-apikey"] == TOKEN
        assert request.headers["x-vtai-consent"] == "standard-v1"
        assert request.headers["content-type"] == "application/octet-stream"
        assert "content-disposition" not in request.headers
        assert str(path) not in str(request.headers)
        calls.append((request.method, await request.aread()))
        return httpx.Response(200, json=submission_response())

    monkeypatch.setattr(submissions, "persist_reference", persist)
    async with AnalysisClient(Settings(TOKEN), transport=httpx.MockTransport(handler)) as client:
        result = await LocalSubmissions(client, directory=state).submit_local_file(str(path))
    assert result == submission_response()
    assert calls == [("POST", BODY)]
    reference = next(state.rglob("*.json"))
    assert not reference.stat().st_mode & 0o077
    assert TOKEN not in reference.read_text() and str(path) not in reference.read_text()


@pytest.mark.anyio
@pytest.mark.parametrize("first", ["inline", "local"])
async def test_inline_and_local_share_no_repeat_state(local, first):
    path, state = local
    calls = []

    def handler(request):
        calls.append(request.method)
        return httpx.Response(200, json=submission_response())

    async with AnalysisClient(Settings(TOKEN), transport=httpx.MockTransport(handler)) as client:
        service = LocalSubmissions(client, directory=state)
        methods = {
            "inline": lambda: service.submit_file(SHA, encoded()),
            "local": lambda: service.submit_local_file(str(path), SHA),
        }
        assert await methods[first]() == submission_response()
        assert await methods["local" if first == "inline" else "inline"]() == submission_response()
    assert calls == ["POST", "GET"]


@pytest.mark.anyio
async def test_concurrent_calls_only_dispatch_once(local):
    path, state = local
    dispatched, finish = anyio.Event(), anyio.Event()
    calls, results = [], []

    async def handler(request):
        calls.append(request.method)
        if request.method == "POST":
            dispatched.set()
            await finish.wait()
        return httpx.Response(200, json=submission_response())

    async with AnalysisClient(Settings(TOKEN), transport=httpx.MockTransport(handler)) as client:
        service = LocalSubmissions(client, directory=state)

        async def first():
            results.append(await service.submit_local_file(str(path)))

        async with anyio.create_task_group() as tasks:
            tasks.start_soon(first)
            await dispatched.wait()
            results.append(await service.submit_file(SHA, encoded()))
            finish.set()
    assert calls == ["POST", "GET"] and results == [submission_response()] * 2


@pytest.mark.anyio
@pytest.mark.parametrize("found", [True, False])
async def test_ambiguous_reply_keeps_recovery_and_missing_receipt_never_reposts(local, found):
    path, state = local
    calls = []

    def handler(request):
        calls.append(request.method)
        if request.method == "POST":
            raise httpx.ReadTimeout("synthetic-private-network-detail")
        return httpx.Response(200, json=submission_response()) if found else httpx.Response(404)

    async with AnalysisClient(Settings(TOKEN), transport=httpx.MockTransport(handler)) as client:
        service = LocalSubmissions(client, directory=state)
        with pytest.raises(AnalysisError) as error:
            await service.submit_local_file(str(path))
        assert error.value.error["code"] == "submission_unknown"
        assert error.value.submission == submission_response(status="submission_unknown")
        if found:
            assert await service.submit_file(SHA, encoded()) == submission_response()
        else:
            with pytest.raises(AnalysisError) as missing:
                await service.submit_file(SHA, encoded())
            assert missing.value.error["code"] == "not_found"
            assert missing.value.submission == error.value.submission
    assert calls == ["POST", "GET"]


@pytest.mark.anyio
@pytest.mark.parametrize("kind", ["fifo", "directory", "symlink", "missing", "oversized"])
async def test_invalid_local_file_never_creates_reference_or_calls_vtai(local, kind):
    path, state = local
    path.unlink()
    if kind == "fifo":
        os.mkfifo(path)
    elif kind == "directory":
        path.mkdir()
    elif kind == "symlink":
        path.symlink_to("missing")
    elif kind == "oversized":
        with path.open("wb") as file:
            file.truncate(32_000_001)
    async with AnalysisClient(
        Settings(TOKEN), transport=httpx.MockTransport(lambda _: pytest.fail("Unexpected HTTP"))
    ) as client:
        with pytest.raises(AnalysisError) as error:
            await LocalSubmissions(client, directory=state).submit_local_file(str(path))
    assert error.value.error["code"] == "invalid_file"
    assert not state.exists()


@pytest.mark.anyio
async def test_local_32million_bytes_remains_supported(local):
    path, state = local
    # An inert sparse zero-filled fixture; only the mock transport sees its bytes.
    with path.open("wb") as file:
        file.truncate(32_000_000)
    observed = []

    async def handler(request):
        body = await request.aread()
        sha = hashlib.sha256(body).hexdigest()
        assert request.url.path.endswith(sha)
        observed.append(len(body))
        return httpx.Response(200, json=submission_response(sha, len(body)))

    async with AnalysisClient(Settings(TOKEN), transport=httpx.MockTransport(handler)) as client:
        result = await LocalSubmissions(client, directory=state).submit_local_file(str(path))
    assert result["size"] == 32_000_000 and observed == [32_000_000]


@pytest.mark.anyio
async def test_expected_digest_mismatch_prevents_state_and_http(local):
    path, state = local
    async with AnalysisClient(
        Settings(TOKEN), transport=httpx.MockTransport(lambda _: pytest.fail("Unexpected HTTP"))
    ) as client:
        with pytest.raises(AnalysisError) as error:
            await LocalSubmissions(client, directory=state).submit_local_file(str(path), "0" * 64)
    assert error.value.error["code"] == "hash_mismatch" and not state.exists()


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["file", "directory"])
async def test_unconfirmed_durability_never_posts(local, monkeypatch, mode):
    _, state = local
    original = os.fsync

    def fail(fd):
        if stat.S_ISREG(os.fstat(fd).st_mode) == (mode == "file"):
            raise OSError("synthetic-private-state-detail")
        original(fd)

    monkeypatch.setattr(os, "fsync", fail)
    async with AnalysisClient(
        Settings(TOKEN), transport=httpx.MockTransport(lambda _: pytest.fail("Unexpected HTTP"))
    ) as client:
        with pytest.raises(AnalysisError) as error:
            await LocalSubmissions(client, directory=state).submit_file(SHA, encoded())
    assert error.value.error["code"] == "local_state_unavailable"
    assert "synthetic-private-state-detail" not in str(error.value)


@pytest.mark.anyio
async def test_cancelled_copy_runs_off_event_loop_and_closes_its_descriptor(local, monkeypatch):
    path, state = local
    started, closed = threading.Event(), threading.Event()
    original = submissions.copy_snapshot

    @contextmanager
    def slow(*args, **kwargs):
        try:
            with original(*args, **kwargs) as snapshot:
                started.set()
                while True:
                    kwargs["checkpoint"]()
                    time.sleep(0.005)
                yield snapshot
        finally:
            closed.set()

    monkeypatch.setattr(submissions, "copy_snapshot", slow)
    async with AnalysisClient(
        Settings(TOKEN), transport=httpx.MockTransport(lambda _: pytest.fail("Unexpected HTTP"))
    ) as client:
        service = LocalSubmissions(client, directory=state)
        with anyio.move_on_after(0.05) as cancellation:
            await service.submit_local_file(str(path))
        assert cancellation.cancelled_caught
    assert started.is_set() and closed.is_set() and not state.exists()


@pytest.mark.anyio
@pytest.mark.parametrize("external", [True, False])
async def test_inline_decode_cancel_or_deadline_stops_before_state_and_http(
    local, monkeypatch, external
):
    _, state = local
    entered, stopped = anyio.Event(), anyio.Event()

    async def blocked_decode(*args):
        entered.set()
        try:
            await anyio.sleep_forever()
        finally:
            stopped.set()

    monkeypatch.setattr(submissions, "decode_submission_async", blocked_decode)
    if not external:
        monkeypatch.setattr(submissions, "LOCAL_SUBMISSION_SECONDS", 0.03)
    async with AnalysisClient(
        Settings(TOKEN), transport=httpx.MockTransport(lambda _: pytest.fail("Unexpected HTTP"))
    ) as client:
        service = LocalSubmissions(client, directory=state)
        with anyio.fail_after(0.2):
            if external:
                with anyio.move_on_after(0.03) as cancellation:
                    await service.submit_file(SHA, encoded())
                assert cancellation.cancelled_caught
            else:
                with pytest.raises(AnalysisError) as error:
                    await service.submit_file(SHA, encoded())
                assert error.value.error["code"] == "timeout"
        assert entered.is_set() and stopped.is_set() and not state.exists()


@pytest.mark.anyio
@pytest.mark.parametrize("external", [True, False])
async def test_cancel_or_deadline_after_dispatch_closes_copy_and_preserves_reference(
    local, monkeypatch, external
):
    path, state = local
    original, copies, calls = submissions.copy_snapshot, [], []

    @contextmanager
    def track(*args, **kwargs):
        with original(*args, **kwargs) as snapshot:
            copies.append(snapshot.file)
            yield snapshot

    async def handler(request):
        calls.append(request.method)
        if request.method == "POST":
            await anyio.sleep_forever()
        return httpx.Response(200, json=submission_response())

    monkeypatch.setattr(submissions, "copy_snapshot", track)
    if not external:
        monkeypatch.setattr(submissions, "LOCAL_SUBMISSION_SECONDS", 0.05)
    async with AnalysisClient(Settings(TOKEN), transport=httpx.MockTransport(handler)) as client:
        service = LocalSubmissions(client, directory=state)
        if external:
            with anyio.move_on_after(0.05) as cancellation:
                await service.submit_local_file(str(path))
            assert cancellation.cancelled_caught
        else:
            with pytest.raises(AnalysisError) as error:
                await service.submit_local_file(str(path))
            assert error.value.error["code"] == "submission_unknown"
            assert error.value.submission["sha256"] == SHA
        assert copies and all(file.closed for file in copies)
        assert len(list(state.rglob("*.json"))) == 1
        assert await service.submit_file(SHA, encoded()) == submission_response()
    assert calls == ["POST", "GET"]
