"""Pure report validation and presentation shared by HTTP and direct readers."""

import json
import re
from datetime import UTC, datetime
from typing import Annotated, Any, Literal, Protocol
from urllib.parse import quote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

MAX_RESPONSE_BYTES = 256 * 1024
HASH_PATTERN = r"(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})"
INDICATOR_LIMITS = {"url": 8192, "domain": 1024, "ip": 45}


class ReportReader(Protocol):
    """A reader bound by its host to the caller authorized for this tool call."""

    async def get_file_report(self, file_hash: str) -> dict[str, Any]: ...

    async def get_url_report(self, url: str) -> dict[str, Any]: ...

    async def get_domain_report(self, domain: str) -> dict[str, Any]: ...

    async def get_ip_report(self, ip: str) -> dict[str, Any]: ...


def validate_indicator(value: str, kind: str) -> None:
    """Bound inputs and protect path segments; VTAI owns indicator validation."""
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= INDICATOR_LIMITS[kind]
        or any(0xD800 <= ord(char) <= 0xDFFF for char in value)
        or (
            kind != "url"
            and (
                value in {".", ".."}
                or any(char in "/\\?#%" or ord(char) <= 32 or ord(char) == 127 for char in value)
            )
        )
    ):
        raise VTAIError(f"invalid_{kind}", f"Provide a valid {kind} string within the input limit.")


class VTAIError(Exception):
    """Controlled failure. Never include an upstream body or credential in this error."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        retryable: bool = False,
        http_status: int | None = None,
        retry_after_seconds: int | None = None,
    ) -> None:
        super().__init__(message)
        self.error = {
            "code": code,
            "message": message,
            "retryable": retryable,
            "http_status": http_status,
            "retry_after_seconds": retry_after_seconds,
        }


def report_http_error(
    status: int,
    kind: str,
    *,
    retry_after_seconds: int | None = None,
    upstream_access_denied: bool = False,
) -> VTAIError:
    """Map a semantic HTTP status to the shared, sanitized report error contract.

    Adapters parse transport-specific bodies/headers before calling this helper.
    ``upstream_access_denied`` preserves the legacy file REST distinction;
    it must not be inferred from caller-supplied MCP arguments.
    """
    kind = "hash" if kind == "file" else kind
    if status == 422:
        return VTAIError(f"invalid_{kind}", f"VTAI rejected the {kind} input.", http_status=status)
    if status == 404:
        return VTAIError(
            "not_found",
            "No existing report was found. This does not establish safety.",
            http_status=status,
        )
    if status in {401, 403}:
        if upstream_access_denied:
            return VTAIError(
                "upstream_access_denied",
                "VTAI could not access its intelligence provider.",
                http_status=status,
            )
        return VTAIError(
            "access_denied",
            "VTAI rejected this request. Check the VTAI credential and access.",
            http_status=status,
        )
    if status == 429:
        seconds = retry_after_seconds
        if type(seconds) is not int or not 0 <= seconds <= 99_999_999:
            seconds = None
        return VTAIError(
            "rate_limited",
            "The VTAI or upstream quota is exhausted. Retry later.",
            retryable=True,
            http_status=status,
            retry_after_seconds=seconds,
        )
    if status == 504:
        return VTAIError(
            "timeout",
            "The VTAI request timed out. Retry later.",
            retryable=True,
            http_status=status,
        )
    return VTAIError(
        "upstream_error",
        "VTAI could not complete the request.",
        retryable=status >= 500,
        http_status=status,
    )


class AIInsight(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    verdict: str | None = None
    source: str | None = None
    analysis: str | None = None


class Coverage(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    engines: Annotated[int, Field(ge=0)] | None
    categories: list[str]


class ReportMetadata(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    source: Literal["VirusTotal"] = "VirusTotal"
    analysis_date: str | None = None
    report_url: str | None = None
    coverage: Coverage | None = None

    @field_validator("analysis_date")
    @classmethod
    def utc_analysis_date(cls, value: str | None) -> str | None:
        if value is not None:
            if not re.fullmatch(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)", value
            ):
                raise ValueError("Expected an ISO UTC analysis timestamp")
            datetime.fromisoformat(value)
        return value


class FileData(ReportMetadata):
    id: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    last_analysis_stats: dict[str, Annotated[int, Field(ge=0)]]
    type_description: str | None = None
    detections: list[str]
    ai_insights: list[AIInsight] | None = None


class IndicatorData(ReportMetadata):
    id: str = Field(min_length=1, max_length=1024)
    type: Literal["url", "domain", "ip_address"]
    url: str | None = Field(default=None, min_length=1, max_length=8192)
    domain: str | None = Field(default=None, min_length=1, max_length=253)
    ip: str | None = Field(default=None, min_length=1, max_length=45)
    source: Literal["VirusTotal"]
    last_analysis_stats: dict[str, Annotated[int, Field(ge=0)]] | None
    detections: list[str]
    analysis_date: str | None
    report_url: str
    coverage: Coverage


def validate_report_values(raw: Any, *, forbidden_values: tuple[str, ...] = ()) -> None:
    """Reject invalid Unicode and caller-supplied secrets without reflecting them."""
    pending = [raw]
    seen = set()
    while pending:
        value = pending.pop()
        if isinstance(value, str) and (
            any(secret in value for secret in forbidden_values)
            or any(0xD800 <= ord(char) <= 0xDFFF for char in value)
        ):
            raise ValueError("Invalid response string")
        if isinstance(value, (dict, list)):
            if id(value) in seen:
                continue
            seen.add(id(value))
            if isinstance(value, dict):
                pending.extend(value.keys())
                pending.extend(value.values())
            else:
                pending.extend(value)


def _validate_data(raw: Any, forbidden_values: tuple[str, ...]) -> None:
    try:
        validate_report_values(raw, forbidden_values=forbidden_values)
        payload = json.dumps(
            {"data": raw}, ensure_ascii=False, allow_nan=False, separators=(",", ":")
        )
        size = len(payload.encode("utf-8"))
    except (ValueError, TypeError, RecursionError):
        raise VTAIError("invalid_response", "VTAI returned an invalid report.") from None
    if size > MAX_RESPONSE_BYTES:
        raise VTAIError("response_too_large", "The VTAI response exceeds the supported size.")


def format_file_report(
    raw: Any,
    file_hash: str,
    *,
    retrieved_at: datetime,
    forbidden_values: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Validate REST data and present it without I/O, mutation or reading a clock.

    ``raw`` is the JSON-compatible object inside REST's ``data`` envelope.
    An adapter that has a credential may supply it in ``forbidden_values``;
    readers must never place credentials in report data or tool arguments.
    """
    if not isinstance(file_hash, str) or not re.fullmatch(HASH_PATTERN, file_hash):
        raise VTAIError("invalid_hash", "Provide a hexadecimal MD5, SHA-1 or SHA-256 hash.")
    _validate_data(raw, forbidden_values)
    try:
        data = FileData.model_validate(raw)
        if len(file_hash) == 64 and data.id.lower() != file_hash.lower():
            raise ValueError("Mismatched file identifier")
        report_url = _report_url(data.report_url, "file", data.id.lower())
    except (ValueError, TypeError, ValidationError):
        raise VTAIError("invalid_response", "VTAI returned an invalid file report.") from None
    # Preserve the original file data shape when an older VTAI omits metadata.
    omitted = set(ReportMetadata.model_fields) - data.model_fields_set
    return _result(data, data.model_dump(exclude=omitted), report_url, retrieved_at)


def format_indicator_report(
    raw: Any,
    kind: Literal["url", "domain", "ip"],
    *,
    retrieved_at: datetime,
    forbidden_values: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Present JSON-compatible indicator data; VTAI owns its normalization."""
    _validate_data(raw, forbidden_values)
    try:
        if kind not in {"url", "domain", "ip"}:
            raise ValueError("Invalid report kind")
        data = IndicatorData.model_validate(raw)
        expected_type = "ip_address" if kind == "ip" else kind
        if data.type != expected_type or not isinstance(getattr(data, kind), str):
            raise ValueError("Mismatched report type")
        other_fields = {"url", "domain", "ip"} - {kind}
        if other_fields & data.model_fields_set:
            raise ValueError("Unexpected indicator fields")
        if kind == "url":
            if not re.fullmatch(r"[a-fA-F0-9]{64}", data.id):
                raise ValueError("Invalid upstream URL identifier")
            url = urlsplit(data.url)
            if url.scheme not in {"http", "https"} or not url.hostname or url.username is not None:
                raise ValueError("Invalid URL report")
        else:
            validate_indicator(data.id, kind)
            if data.id != getattr(data, kind):
                raise ValueError("Mismatched indicator identifier")
        report_url = _report_url(data.report_url, kind, data.id)
    except (ValueError, TypeError, ValidationError, VTAIError):
        raise VTAIError("invalid_response", "VTAI returned an invalid indicator report.") from None
    return _result(data, data.model_dump(exclude=other_fields), report_url, retrieved_at)


def _report_url(value: str | None, kind: str, identifier: str) -> str:
    kind = "ip-address" if kind == "ip" else kind
    expected = f"https://www.virustotal.com/gui/{kind}/{quote(identifier, safe='')}"
    if value is None:
        return expected
    if value not in {expected, f"https://www.virustotal.com/gui/{kind}/{identifier}"}:
        raise ValueError("The report link does not match its VirusTotal identifier")
    return value


def _result(
    data: ReportMetadata, report: dict, report_url: str, retrieved_at: datetime
) -> dict[str, Any]:
    if not isinstance(retrieved_at, datetime) or retrieved_at.utcoffset() is None:
        raise VTAIError("invalid_response", "The report retrieval timestamp is unavailable.")
    return {
        "status": "found",
        "source": "VirusTotal via VTAI",
        "retrieved_at": retrieved_at.astimezone(UTC).isoformat(),
        "analysis_date": data.analysis_date,
        "report_url": report_url,
        "coverage": data.coverage.model_dump() if data.coverage is not None else None,
        "data": report,
    }
