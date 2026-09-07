"""Bounded analysis reads and a single explicit raw-byte submission to VTAI."""

import json
from collections.abc import AsyncIterator
from typing import BinaryIO
from urllib.parse import quote

import anyio
import httpx

from vt_mcp.analyses import (
    MAX_SUBMISSION_BYTES,
    AnalysisError,
    analysis_http_error,
    format_analysis_response,
    format_submission_response,
    unknown_submission,
    validate_analysis_id,
    validate_sha256,
)
from vt_mcp.reports import MAX_RESPONSE_BYTES
from vt_mcp.vtai_client import VTAIClient

SUBMIT_TIMEOUT = 130.0
READ_TIMEOUT = 35.0


def _object(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate key")
        result[key] = value
    return result


def _constant(value):
    raise ValueError("Non-finite number")


class AnalysisClient(VTAIClient):
    """Shares the existing credential and HTTP lifecycle; POST never retries."""

    async def _analysis_request(
        self, method, path, *, content=None, size=None, timeout=READ_TIMEOUT
    ):
        headers = {}
        if method == "POST":
            headers = {
                "Content-Type": "application/octet-stream",
                "X-VTAI-Consent": "standard-v1",
                "Content-Length": str(size),
            }
        try:
            with anyio.fail_after(timeout):
                async with self._http.stream(
                    method, path, content=content, headers=headers, timeout=timeout
                ) as response:
                    if response.headers.get("Content-Encoding", "identity").strip().lower() not in {
                        "",
                        "identity",
                    }:
                        raise AnalysisError("invalid_response")
                    payload = bytearray()
                    async for chunk in response.aiter_bytes(chunk_size=65536):
                        payload.extend(chunk)
                        if len(payload) > MAX_RESPONSE_BYTES:
                            raise AnalysisError("response_too_large")
                    try:
                        raw = json.loads(
                            payload, object_pairs_hook=_object, parse_constant=_constant
                        )
                    except (ValueError, UnicodeError, TypeError, RecursionError):
                        raw = None
                    if response.status_code not in ({200, 202} if method == "POST" else {200}):
                        detail = raw.get("detail") if isinstance(raw, dict) else None
                        detail = detail if isinstance(detail, dict) else {}
                        retry = detail.get("retry_after_seconds")
                        raise analysis_http_error(
                            response.status_code, code=detail.get("code"), retry_after_seconds=retry
                        )
                    if raw is None:
                        raise AnalysisError("invalid_response")
                    if response.status_code == 202 and (
                        not isinstance(raw, dict) or raw.get("status") != "submission_unknown"
                    ):
                        raise AnalysisError("invalid_response")
                    return raw
        except (httpx.TimeoutException, TimeoutError):
            raise AnalysisError("timeout") from None
        except httpx.RequestError:
            raise AnalysisError("unavailable") from None

    async def get_analysis(self, analysis_id: str) -> dict:
        validate_analysis_id(analysis_id)
        raw = await self._analysis_request("GET", f"analyses/{quote(analysis_id, safe='')}")
        return format_analysis_response(raw, analysis_id, forbidden_values=(self.settings.token,))

    async def get_submission(self, sha256: str) -> dict:
        validate_sha256(sha256)
        raw = await self._analysis_request("GET", f"submissions/{sha256}")
        result = format_submission_response(raw, sha256, forbidden_values=(self.settings.token,))
        if result["status"] == "exists":
            raise AnalysisError("invalid_response")
        return result

    async def submit(self, snapshot: BinaryIO, sha256: str, size: int) -> dict:
        """Only call after explicit consent and confirmed durable local recovery state."""
        validate_sha256(sha256)
        if type(size) is not int or not 0 <= size <= MAX_SUBMISSION_BYTES:
            raise AnalysisError("invalid_input")

        async def chunks() -> AsyncIterator[bytes]:
            snapshot.seek(0)
            sent = 0
            while part := snapshot.read(65536):
                sent += len(part)
                if sent > size:
                    raise AnalysisError("submission_unknown")
                yield part
                await anyio.lowlevel.checkpoint()
            if sent != size:
                raise AnalysisError("submission_unknown")

        try:
            raw = await self._analysis_request(
                "POST", f"submissions/{sha256}", content=chunks(), size=size, timeout=SUBMIT_TIMEOUT
            )
            return format_submission_response(
                raw, sha256, size=size, forbidden_values=(self.settings.token,)
            )
        except AnalysisError as exc:
            # A lost/malformed reply can follow durable reservation or external acceptance.
            # Even known HTTP failures retain the local reference; no POST is repeated.
            if exc.error["code"] in {
                "timeout",
                "unavailable",
                "invalid_response",
                "response_too_large",
                "submission_unknown",
            }:
                raise AnalysisError(
                    "submission_unknown", submission=unknown_submission(sha256, size)
                ) from None
            raise
