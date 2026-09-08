"""Autonomous local submission of one immutable copy, with durable recovery."""

import io
import os
from contextlib import asynccontextmanager
from pathlib import Path

import anyio

from vt_mcp.analyses import (
    AnalysisError,
    decode_submission,
    format_submission_response,
    unknown_submission,
    validate_sha256,
)
from vt_mcp.client import AnalysisClient
from vt_mcp.submission_cli import CLIError, Snapshot, copy_snapshot, persist_reference, state_path

LOCAL_SUBMISSION_SECONDS = 150.0


@asynccontextmanager
async def _local_snapshot(path: str):
    copied = copy_snapshot(path, checkpoint=anyio.from_thread.check_cancelled)
    snapshot = await anyio.to_thread.run_sync(copied.__enter__)
    try:
        await anyio.lowlevel.checkpoint()
        yield snapshot
    finally:
        # Wait for the owner thread and close the copy even after cancellation;
        # never abandon a thread that could return a live descriptor.
        with anyio.CancelScope(shield=True):
            await anyio.to_thread.run_sync(copied.__exit__, None, None, None)


class LocalSubmissions:
    """Uses the existing credential/client. No prompts, registration or POST retries."""

    def __init__(self, client: AnalysisClient, *, directory: Path | None = None):
        self.client = client
        self.directory = state_path(None) if directory is None else directory

    async def get_submission(self, sha256: str) -> dict:
        return await self.client.get_submission(sha256)

    async def _submit(
        self,
        snapshot: Snapshot,
        budget: anyio.CancelScope,
        *,
        forbidden_values: tuple[str, ...] = (),
    ) -> dict:
        try:
            created = await anyio.to_thread.run_sync(
                persist_reference, self.client.settings, snapshot.sha256, self.directory
            )
        except CLIError:
            raise AnalysisError("local_state_unavailable") from None
        recovery = unknown_submission(snapshot.sha256, snapshot.size)
        try:
            await anyio.lowlevel.checkpoint()
            result = (
                await self.client.submit(snapshot.file, snapshot.sha256, snapshot.size)
                if created
                else await self.client.get_submission(snapshot.sha256)
            )
            return format_submission_response(
                result,
                snapshot.sha256,
                size=snapshot.size,
                forbidden_values=(self.client.settings.token, *forbidden_values),
            )
        except anyio.get_cancelled_exc_class():
            if not budget.cancel_called:
                raise
            raise AnalysisError("submission_unknown", submission=recovery) from None
        except AnalysisError as error:
            code = error.error["code"]
            if created and code in {
                "timeout",
                "unavailable",
                "invalid_response",
                "response_too_large",
            }:
                code = "submission_unknown"
            raise AnalysisError(
                code,
                http_status=error.error["http_status"] if code != "submission_unknown" else None,
                retry_after_seconds=error.error["retry_after_seconds"],
                submission=recovery,
            ) from None
        except Exception:
            raise AnalysisError("submission_unknown", submission=recovery) from None

    async def submit_file(self, sha256: str, content_base64: str) -> dict:
        try:
            with anyio.fail_after(LOCAL_SUBMISSION_SECONDS) as budget:
                body = await anyio.to_thread.run_sync(decode_submission, sha256, content_base64)
                await anyio.lowlevel.checkpoint()
                with io.BytesIO(body) as copied:
                    return await self._submit(Snapshot(copied, sha256, len(body)), budget)
        except TimeoutError:
            raise AnalysisError("timeout") from None

    async def submit_local_file(self, path: str, expected_sha256: str | None = None) -> dict:
        if not isinstance(path, str) or not path or "\x00" in path:
            raise AnalysisError("invalid_file")
        if expected_sha256 is not None:
            validate_sha256(expected_sha256)
        try:
            with anyio.fail_after(LOCAL_SUBMISSION_SECONDS) as budget:
                async with _local_snapshot(path) as snapshot:
                    if expected_sha256 is not None and expected_sha256 != snapshot.sha256:
                        raise AnalysisError("hash_mismatch")
                    return await self._submit(
                        snapshot, budget, forbidden_values=(os.path.abspath(path),)
                    )
        except CLIError as error:
            raise AnalysisError(error.code) from None
        except TimeoutError:
            raise AnalysisError("timeout") from None
