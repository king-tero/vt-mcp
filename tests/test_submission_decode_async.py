"""Equivalent strict decoding and cancellation, entirely local and without threads."""

import base64
import hashlib

import anyio
import pytest

from vt_mcp import analyses
from vt_mcp.analyses import AnalysisError, decode_submission, decode_submission_async

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize("size", [0, 1, 2, 3, 49_151, 49_152, 49_153, 98_305, 24_000_000])
async def test_sync_async_return_exact_same_bytes_across_block_boundaries(size):
    body = (bytes(range(256)) * (size // 256 + 1))[:size]
    encoded = base64.b64encode(body).decode("ascii")
    sha = hashlib.sha256(body).hexdigest()
    assert decode_submission(sha, encoded) == body
    assert await decode_submission_async(sha, encoded) == body


@pytest.mark.parametrize(
    "sha,encoded,code",
    [
        ("bad", "YQ==", "invalid_input"),
        ("0" * 64, None, "invalid_input"),
        ("0" * 64, 1, "invalid_input"),
        ("0" * 64, b"YQ==", "invalid_input"),
        ("0" * 64, "", "hash_mismatch"),
        ("0" * 64, "YQ==", "hash_mismatch"),
        ("0" * 64, "YQ", "invalid_input"),
        ("0" * 64, "YR==", "invalid_input"),
        ("0" * 64, "YWJ=", "invalid_input"),
        ("0" * 64, "YQ======", "invalid_input"),
        ("0" * 64, "AAAA====", "invalid_input"),
        ("0" * 64, "====", "invalid_input"),
        ("0" * 64, "-w==", "invalid_input"),
        ("0" * 64, "YQ==\n   ", "invalid_input"),
        ("0" * 64, "A" * 65_532 + "YQ==AAAA", "invalid_input"),
        ("0" * 64, "A" * 65_536 + "YR==", "invalid_input"),
        ("0" * 64, "A" * 65_536 + "YWJ=", "invalid_input"),
        ("0" * 64, "A" * 65_536 + "é===", "invalid_input"),
        ("0" * 64, "A" * 65_536 + "\ud800===", "invalid_input"),
        ("0" * 64, "A" * 65_536 + "****", "invalid_input"),
        ("0" * 64, "A" * 32_000_004, "inline_too_large"),
    ],
)
async def test_sync_async_keep_error_code_and_closed_fields(sha, encoded, code):
    with pytest.raises(AnalysisError) as sync_error:
        decode_submission(sha, encoded)
    with pytest.raises(AnalysisError) as async_error:
        await decode_submission_async(sha, encoded)
    assert sync_error.value.error == async_error.value.error
    assert async_error.value.error["code"] == code
    assert async_error.value.submission is None


async def test_async_uses_bounded_steps_without_thread_or_sync_wrapper(monkeypatch):
    body = b"innocent fixture\0" * 50_000
    original = base64.b64decode
    blocks = []

    def decode(block, **kwargs):
        blocks.append(len(block))
        return original(block, **kwargs)

    def forbidden(*args, **kwargs):
        pytest.fail("Async decoding must not use a thread or the synchronous wrapper")

    monkeypatch.setattr(base64, "b64decode", decode)
    monkeypatch.setattr(anyio.to_thread, "run_sync", forbidden)
    monkeypatch.setattr(analyses, "decode_submission", forbidden)
    result = await decode_submission_async(
        hashlib.sha256(body).hexdigest(), base64.b64encode(body).decode("ascii")
    )
    assert result == body and len(blocks) > 3
    assert all(0 < size <= 65_536 and size % 4 == 0 for size in blocks)


async def test_cancellation_mid_decode_never_finishes_hash_or_returns_body(monkeypatch):
    body = b"x" * 1_000_000
    sha = hashlib.sha256(body).hexdigest()
    original_decode, original_hash = base64.b64decode, hashlib.sha256
    decoded, finalized, closed = [], [], []
    original_blocks = analyses._decode_submission_blocks

    class Hash:
        def __init__(self):
            self.inner = original_hash()

        def update(self, block):
            self.inner.update(block)

        def hexdigest(self):
            finalized.append(True)
            return self.inner.hexdigest()

    def decode(block, **kwargs):
        decoded.append(len(block))
        if len(decoded) == 3:
            cancellation.cancel()
        return original_decode(block, **kwargs)

    def blocks(*args):
        try:
            yield from original_blocks(*args)
        finally:
            closed.append(True)

    monkeypatch.setattr(base64, "b64decode", decode)
    monkeypatch.setattr(hashlib, "sha256", Hash)
    monkeypatch.setattr(analyses, "_decode_submission_blocks", blocks)
    with anyio.CancelScope() as cancellation:
        await decode_submission_async(sha, base64.b64encode(body).decode("ascii"))
        pytest.fail("Cancelled decode returned a complete body")
    assert cancellation.cancelled_caught
    assert len(decoded) == 3 and finalized == [] and closed == [True]
    await anyio.lowlevel.checkpoint()
    assert len(decoded) == 3  # No background worker continues after return.


async def test_expired_budget_stops_before_first_decode(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Expired decode budget performed work")

    monkeypatch.setattr(base64, "b64decode", forbidden)
    with pytest.raises(TimeoutError), anyio.fail_after(0):
        await decode_submission_async("0" * 64, "AAAA")


async def test_final_checkpoint_honors_cancellation_at_hash_completion(monkeypatch):
    body = b"innocent fixture"
    original_hash = hashlib.sha256
    sha = original_hash(body).hexdigest()

    class Hash:
        def __init__(self):
            self.inner = original_hash()

        def update(self, block):
            self.inner.update(block)

        def hexdigest(self):
            cancellation.cancel()
            return self.inner.hexdigest()

    monkeypatch.setattr(hashlib, "sha256", Hash)
    with anyio.CancelScope() as cancellation:
        await decode_submission_async(sha, base64.b64encode(body).decode("ascii"))
        pytest.fail("Cancellation at finalization returned a body")
    assert cancellation.cancelled_caught
