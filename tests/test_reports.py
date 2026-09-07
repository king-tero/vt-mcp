"""Pure presentation preserves the shared data contract and controlled failures."""

import copy
from datetime import UTC, datetime

import httpx
import pytest

from vt_mcp.reports import (
    MAX_RESPONSE_BYTES,
    VTAIError,
    format_file_report,
    format_indicator_report,
    report_http_error,
)
from vt_mcp.vtai_client import Settings, VTAIClient
from vt_mcp.vtai_client import VTAIError as LegacyVTAIError

RETRIEVED = datetime(2026, 9, 6, 12, 30, tzinfo=UTC)


def test_file_presentation_is_pure_and_backward_compatible(file_hash, report):
    before = copy.deepcopy(report)
    first = format_file_report(report["data"], file_hash, retrieved_at=RETRIEVED)
    second = format_file_report(report["data"], file_hash, retrieved_at=RETRIEVED)
    assert first == second
    assert report == before
    assert first["data"] == report["data"]
    assert first["analysis_date"] is None and first["coverage"] is None
    assert first["retrieved_at"] == RETRIEVED.isoformat()
    first["data"]["detections"].append("synthetic-label")
    assert report == before
    assert LegacyVTAIError is VTAIError


@pytest.mark.parametrize("kind", ["url", "domain", "ip"])
def test_direct_presentation_preserves_dates_source_coverage(kind, indicator_report):
    raw = indicator_report(kind)["data"]
    before = copy.deepcopy(raw)
    result = format_indicator_report(raw, kind, retrieved_at=RETRIEVED)
    assert result["data"] == raw
    assert result["analysis_date"] == raw["analysis_date"]
    assert result["retrieved_at"] != result["analysis_date"]
    assert result["coverage"] == {"engines": 2, "categories": ["harmless"]}
    assert result["source"] == "VirusTotal via VTAI"
    assert raw == before


@pytest.mark.parametrize("fault", ["unicode", "secret", "negative", "date", "cycle", "oversized"])
def test_direct_reports_reject_bad_data_without_echo(fault, indicator_report):
    raw = indicator_report("domain")["data"]
    if fault == "unicode":
        raw["detections"] = ["\ud800"]
    elif fault == "secret":
        raw["detections"] = ["synthetic-private-credential"]
    elif fault == "negative":
        raw["last_analysis_stats"] = {"harmless": -1}
    elif fault == "date":
        raw["analysis_date"] = "not-a-date"
    elif fault == "cycle":
        raw["extra"] = raw
    else:
        raw["detections"] = ["x" * MAX_RESPONSE_BYTES]
    with pytest.raises(VTAIError) as error:
        format_indicator_report(
            raw,
            "domain",
            retrieved_at=RETRIEVED,
            forbidden_values=("synthetic-private-credential",),
        )
    assert error.value.error["code"] == (
        "response_too_large" if fault == "oversized" else "invalid_response"
    )
    assert "synthetic-private-credential" not in str(error.value.error)


def test_naive_retrieval_time_cannot_be_misrepresented_as_utc(file_hash, report):
    with pytest.raises(VTAIError, match="timestamp"):
        format_file_report(report["data"], file_hash, retrieved_at=datetime(2026, 9, 6))


@pytest.mark.anyio
@pytest.mark.parametrize("status", [401, 403, 404, 422, 429, 502, 503, 504, 307])
async def test_http_and_direct_semantic_errors_are_identical(status):
    async with VTAIClient(
        Settings("synthetic-credential"),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                status, json={"detail": "sanitized"}, headers={"Retry-After": "17"}
            )
        ),
    ) as client:
        with pytest.raises(VTAIError) as error:
            await client.get_domain_report("example.com")
    assert error.value.error == report_http_error(status, "domain", retry_after_seconds=17).error


@pytest.mark.parametrize("delay", [-1, True, "17", 100_000_000, None])
def test_direct_retry_delay_is_not_coerced_or_invented(delay):
    assert (
        report_http_error(429, "domain", retry_after_seconds=delay).error["retry_after_seconds"]
        is None
    )


def test_legacy_upstream_auth_and_file_error_names_are_preserved():
    assert report_http_error(403, "file").error["code"] == "access_denied"
    assert (
        report_http_error(403, "file", upstream_access_denied=True).error["code"]
        == "upstream_access_denied"
    )
    assert report_http_error(422, "file").error["code"] == "invalid_hash"
