"""Pure, bounded presentation of actor-owned submissions and selected analyses."""

import json
import re
import unicodedata
from datetime import UTC, datetime
from typing import Annotated, Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from vt_mcp.reports import MAX_RESPONSE_BYTES, VTAIError, format_file_report, validate_report_values

MAX_SUBMISSION_BYTES = 32_000_000
MAX_ANALYSIS_ID_BYTES = 1024
SHA256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Count = Annotated[int, Field(ge=0)]
_ERRORS = {
    "invalid_input": (422, "Invalid analysis or submission input", False),
    "consent_required": (422, "Explicit standard submission consent is required", False),
    "body_too_large": (413, "Submission exceeds 32000000 bytes", False),
    "hash_mismatch": (422, "Submission bytes do not match the declared SHA256", False),
    "receipt_conflict": (409, "The existing submission receipt is incompatible", False),
    "not_found": (404, "No registered submission or analysis found", False),
    "rate_limited": (429, "VTAI or VirusTotal query quota exceeded", True),
    "capacity_exceeded": (503, "Submission capacity is temporarily full", True),
    "invalid_response": (502, "Invalid VirusTotal analysis response", True),
    "response_too_large": (502, "Analysis response exceeds the supported size", True),
    "unavailable": (503, "Analysis service is temporarily unavailable", True),
    "timeout": (504, "Analysis operation timed out", True),
    "submission_unknown": (
        503,
        "Submission outcome is unknown; recover its receipt before taking further action",
        False,
    ),
    "access_denied": (403, "VTAI rejected this request. Check the credential and access.", False),
}


class AnalysisReader(Protocol):
    async def get_analysis(self, analysis_id: str) -> dict[str, Any]: ...


class AnalysisError(VTAIError):
    def __init__(
        self,
        code: str,
        *,
        http_status: int | None = None,
        retry_after_seconds: int | None = None,
        submission: dict | None = None,
    ) -> None:
        code = code if code in _ERRORS else "invalid_response"
        status, message, retryable = _ERRORS[code]
        if type(retry_after_seconds) is not int or not 0 <= retry_after_seconds <= 9_999_999_999:
            retry_after_seconds = None
        super().__init__(
            code,
            message,
            retryable=retryable,
            http_status=http_status or status,
            retry_after_seconds=retry_after_seconds,
        )
        self.submission = submission


def analysis_http_error(
    status: int,
    *,
    code: str | None = None,
    retry_after_seconds: int | None = None,
    submission: dict | None = None,
) -> AnalysisError:
    """Use semantic HTTP status and a closed code, never a provider's message."""
    if status in (401, 403):
        code = "access_denied"
    elif not isinstance(code, str) or code not in _ERRORS or _ERRORS[code][0] != status:
        code = {
            404: "not_found",
            409: "receipt_conflict",
            413: "body_too_large",
            422: "invalid_input",
            429: "rate_limited",
            502: "invalid_response",
            503: "unavailable",
            504: "timeout",
        }.get(status, "unavailable")
    if code not in {"rate_limited", "capacity_exceeded"}:
        retry_after_seconds = None
    return AnalysisError(
        code, http_status=status, retry_after_seconds=retry_after_seconds, submission=submission
    )


def validate_sha256(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
        raise AnalysisError("invalid_input")
    return value


def _text(value: str, limit: int) -> None:
    if len(value) > limit or any(unicodedata.category(char).startswith("C") for char in value):
        raise ValueError("Invalid text")


def validate_analysis_id(value: Any) -> str:
    try:
        if not isinstance(value, str) or not value or value in {".", ".."}:
            raise ValueError
        _text(value, MAX_ANALYSIS_ID_BYTES)
        if len(value.encode("utf-8")) > MAX_ANALYSIS_ID_BYTES or any(c.isspace() for c in value):
            raise ValueError
    except (ValueError, UnicodeError):
        raise AnalysisError("invalid_input") from None
    return value


def _bounded(raw: Any, forbidden_values: tuple[str, ...]) -> None:
    try:
        validate_report_values(raw, forbidden_values=forbidden_values)
        encoded = json.dumps(raw, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, UnicodeError, TypeError, RecursionError):
        raise AnalysisError("invalid_response") from None
    if len(encoded) > MAX_RESPONSE_BYTES:
        raise AnalysisError("response_too_large")


def _utc(value: str) -> datetime:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)", value):
        raise ValueError("Invalid UTC date")
    return datetime.fromisoformat(value)


class _Engine(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    engine_name: str | None = Field(None, max_length=512)
    engine_version: str | None = Field(None, max_length=256)
    engine_update: str | None = Field(None, max_length=64)
    category: str | None = Field(None, max_length=128)
    result: str | None = Field(None, max_length=4096)
    method: str | None = Field(None, max_length=128)


class _Coverage(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    engines: Count | None
    categories: list[str]


class _Analysis(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    status: Literal["pending", "completed"]
    analysis_id: str
    analysis_status: Literal["queued", "in-progress", "completed"] | None
    sha256: SHA256
    source: Literal["VirusTotal via VTAI"]
    retrieved_at: str
    analysis_date: str | None
    stats: dict[str, Count] | None
    results: dict[str, _Engine] | None
    detections: list[str]
    coverage: _Coverage
    report_url: str
    next_poll_after_seconds: Literal[5] | None
    pending_reason: Literal["processing", "not_available_yet", "result_not_ready"] | None


def format_analysis_response(
    raw: Any,
    analysis_id: str,
    *,
    forbidden_values: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Validate only the selected analysis. No I/O, current clock or latest report."""
    validate_analysis_id(analysis_id)
    _bounded(raw, forbidden_values)
    try:
        data = _Analysis.model_validate(raw)
        if data.analysis_id != analysis_id:
            raise ValueError
        _utc(data.retrieved_at)
        if data.analysis_date is not None and _utc(data.analysis_date).timestamp() < 0:
            raise ValueError
        if data.report_url != f"https://www.virustotal.com/gui/file/{data.sha256}":
            raise ValueError
        for key in data.stats or {}:
            _text(key, 128)
        categories, detections = set(), []
        for key, entry in (data.results or {}).items():
            _text(key, 512)
            for value in entry.model_dump().values():
                if value is not None:
                    _text(value, 4096)
            if entry.category is not None:
                categories.add(entry.category)
            if entry.result is not None:
                detections.append(entry.result)
        if (
            data.detections != detections
            or data.coverage.categories != sorted(categories)
            or data.coverage.engines != (len(data.results) if data.results is not None else None)
        ):
            raise ValueError
        if data.status == "completed":
            if (
                data.analysis_status != "completed"
                or data.stats is None
                or data.results is None
                or data.next_poll_after_seconds is not None
                or data.pending_reason is not None
            ):
                raise ValueError
        elif data.next_poll_after_seconds != 5:
            raise ValueError
        elif data.analysis_status is None:
            if (
                data.pending_reason != "not_available_yet"
                or data.stats is not None
                or data.results is not None
                or data.analysis_date is not None
            ):
                raise ValueError
        elif data.analysis_status == "completed":
            if (
                data.pending_reason != "result_not_ready"
                or data.stats is None
                or data.results is None
            ):
                raise ValueError
        elif data.pending_reason != "processing":
            raise ValueError
        result = data.model_dump()
    except (ValueError, TypeError, AttributeError, OverflowError, OSError):
        raise AnalysisError("invalid_response") from None
    _bounded(result, forbidden_values)
    return result


class _Submission(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    status: Literal["submitted", "submission_unknown", "exists"]
    mode: Literal["standard"]
    submission_id: SHA256
    sha256: SHA256
    size: int = Field(ge=0, le=MAX_SUBMISSION_BYTES)
    analysis_id: str | None
    analysis_status: Literal["queued", "in-progress", "completed"] | None
    next_poll_after_seconds: Literal[5] | None
    can_resubmit: Literal[False]
    report: dict | None


def format_submission_response(
    raw: Any,
    sha256: str,
    *,
    size: int | None = None,
    forbidden_values: tuple[str, ...] = (),
) -> dict[str, Any]:
    validate_sha256(sha256)
    _bounded(raw, forbidden_values)
    try:
        data = _Submission.model_validate(raw)
        if (
            data.sha256 != sha256
            or data.submission_id != sha256
            or (size is not None and data.size != size)
            or raw["can_resubmit"] is not False
        ):
            raise ValueError
        if data.status == "submitted":
            validate_analysis_id(data.analysis_id)
            if (
                data.analysis_status is not None
                or data.next_poll_after_seconds != 5
                or data.report is not None
            ):
                raise ValueError
        else:
            if (
                data.analysis_id is not None
                or data.analysis_status is not None
                or data.next_poll_after_seconds is not None
            ):
                raise ValueError
            if data.status == "submission_unknown" and data.report is not None:
                raise ValueError
            if data.status == "exists":
                normalized = format_file_report(
                    data.report["data"],
                    sha256,
                    retrieved_at=datetime(1970, 1, 1, tzinfo=UTC),
                    forbidden_values=forbidden_values,
                )
                data.report = {"data": normalized["data"]}
        result = data.model_dump()
    except (ValueError, TypeError, KeyError, VTAIError):
        raise AnalysisError("invalid_response") from None
    _bounded(result, forbidden_values)
    return result


def unknown_submission(sha256: str, size: int) -> dict[str, Any]:
    return {
        "status": "submission_unknown",
        "mode": "standard",
        "submission_id": sha256,
        "sha256": sha256,
        "size": size,
        "analysis_id": None,
        "analysis_status": None,
        "next_poll_after_seconds": None,
        "can_resubmit": False,
        "report": None,
    }
