import copy
import io
import json
from urllib.parse import quote

import anyio
import httpx
import pytest
from analysis_helpers import ANALYSIS_ID, BODY, SHA, TOKEN, analysis_response, submission_response

from vt_mcp.analyses import (
    AnalysisError,
    analysis_http_error,
    format_analysis_response,
    format_submission_response,
    validate_analysis_id,
)
from vt_mcp.client import AnalysisClient
from vt_mcp.vtai_client import Settings

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize("completed", [False, True])
async def test_analysis_is_its_own_evidence_and_opaque_id(completed):
    raw = analysis_response(completed=completed)
    calls = []

    def handler(request):
        calls.append(request)
        assert request.method == "GET" and request.content == b""
        assert request.url.raw_path == ("/api/v3/analyses/" + quote(ANALYSIS_ID, safe="")).encode()
        assert request.headers["x-apikey"] == TOKEN
        return httpx.Response(200, json=raw)

    async with AnalysisClient(Settings(TOKEN), transport=httpx.MockTransport(handler)) as client:
        result = await client.get_analysis(ANALYSIS_ID)
    assert result == raw and len(calls) == 1
    assert result["analysis_date"] != result["retrieved_at"]
    assert TOKEN not in json.dumps(result)


@pytest.mark.parametrize(
    "identifier",
    [
        "",
        ".",
        "..",
        "a b",
        "a\n",
        "x\x00",
        "a\u200b",
        "x" * 1025,
        "é" * 513,
        None,
        3,
        [],
        "a\ud800",
    ],
)
async def test_bad_analysis_ids_never_make_requests(identifier):
    async with AnalysisClient(
        Settings(TOKEN),
        transport=httpx.MockTransport(lambda _: pytest.fail("Invalid ID caused HTTP")),
    ) as client:
        with pytest.raises(AnalysisError) as error:
            await client.get_analysis(identifier)
    assert error.value.error["code"] == "invalid_input"


async def test_id_limit_is_utf8_bytes_and_separator_is_not_a_destination():
    assert validate_analysis_id("é" * 512) == "é" * 512
    assert validate_analysis_id("https://example.invalid/a?b#c%")


@pytest.mark.parametrize(
    "field,value",
    [
        ("analysis_id", "wrong"),
        ("analysis_date", "2026-09-05T12:00:00"),
        ("analysis_date", "1969-12-31T23:59:59Z"),
        ("retrieved_at", "private-date"),
        ("report_url", "https://example.invalid/private"),
        ("source", "invented"),
        ("stats", {"harmless": True}),
        ("stats", {"malicious": -1}),
        ("stats", {"key\n": 0}),
        ("coverage", {"engines": 2, "categories": ["harmless"]}),
        ("detections", []),
        ("next_poll_after_seconds", 0),
        ("pending_reason", None),
    ],
)
async def test_analysis_rejects_malformed_or_incoherent_evidence(field, value):
    raw = analysis_response()
    raw[field] = value
    with pytest.raises(AnalysisError) as caught:
        format_analysis_response(raw, ANALYSIS_ID)
    assert caught.value.error["code"] == "invalid_response"


async def test_analysis_does_not_invent_fields_when_provider_is_not_available():
    raw = analysis_response()
    raw.update(
        analysis_status=None,
        analysis_date=None,
        stats=None,
        results=None,
        detections=[],
        coverage={"engines": None, "categories": []},
        pending_reason="not_available_yet",
    )
    assert format_analysis_response(raw, ANALYSIS_ID) == raw
    raw["pending_reason"] = "processing"
    with pytest.raises(AnalysisError):
        format_analysis_response(raw, ANALYSIS_ID)


async def test_completed_status_can_still_wait_for_matching_item():
    raw = analysis_response(completed=True)
    raw.update(status="pending", pending_reason="result_not_ready", next_poll_after_seconds=5)
    assert format_analysis_response(raw, ANALYSIS_ID) == raw
    raw["results"] = None
    with pytest.raises(AnalysisError):
        format_analysis_response(raw, ANALYSIS_ID)


@pytest.mark.parametrize("value", ["private\ntext", "x" * 4097, TOKEN, "\ud800"])
async def test_result_strings_are_bounded_private_and_untrusted(value):
    raw = analysis_response()
    raw["results"]["Fixture engine"]["result"] = value
    raw["detections"] = [value]
    with pytest.raises(AnalysisError):
        format_analysis_response(raw, ANALYSIS_ID, forbidden_values=(TOKEN,))


async def test_unknown_fields_are_minimized_without_mutation():
    raw = analysis_response()
    original = copy.deepcopy(raw)
    raw["debug"] = "discard me"
    raw["results"]["Fixture engine"]["debug"] = "discard me too"
    result = format_analysis_response(raw, ANALYSIS_ID)
    assert result == original
    assert raw["debug"] == "discard me"


@pytest.mark.parametrize("status", ["submitted", "submission_unknown", "exists"])
async def test_submission_contract(status):
    raw = submission_response(status=status)
    assert format_submission_response(raw, SHA, size=len(BODY)) == raw
    raw["size"] += 1
    with pytest.raises(AnalysisError):
        format_submission_response(raw, SHA, size=len(BODY))


@pytest.mark.parametrize(
    "field,value",
    [
        ("sha256", "0" * 64),
        ("submission_id", "0" * 64),
        ("can_resubmit", True),
        ("can_resubmit", 0),
        ("mode", "private"),
        ("analysis_id", None),
        ("analysis_status", "completed"),
        ("next_poll_after_seconds", None),
        ("size", True),
        ("size", 32_000_001),
    ],
)
async def test_bad_receipts_are_not_accepted(field, value):
    raw = submission_response()
    raw[field] = value
    with pytest.raises(AnalysisError):
        format_submission_response(raw, SHA)


async def test_empty_file_submission_and_raw_headers_have_no_local_paths():
    sha256 = __import__("hashlib").sha256(b"").hexdigest()
    calls = []

    async def handler(request):
        body = await request.aread()
        calls.append(body)
        assert request.url.raw_path == f"/api/v3/submissions/{sha256}".encode()
        assert request.headers["content-type"] == "application/octet-stream"
        assert request.headers["x-vtai-consent"] == "standard-v1"
        assert request.headers["content-length"] == "0"
        assert "content-disposition" not in request.headers
        return httpx.Response(200, json=submission_response(sha256, 0))

    async with AnalysisClient(Settings(TOKEN), transport=httpx.MockTransport(handler)) as client:
        result = await client.submit(io.BytesIO(b""), sha256, 0)
    assert result["status"] == "submitted" and calls == [b""]


@pytest.mark.parametrize(
    "status,expected",
    [
        (401, "access_denied"),
        (403, "access_denied"),
        (404, "not_found"),
        (429, "rate_limited"),
        (503, "unavailable"),
        (504, "timeout"),
    ],
)
async def test_read_errors_are_closed_and_not_retried(status, expected):
    calls = []

    def handler(request):
        calls.append(request.method)
        return httpx.Response(
            status,
            json={
                "detail": {
                    "code": "untrusted-provider-error",
                    "message": TOKEN,
                    "retry_after_seconds": 17,
                }
            },
        )

    async with AnalysisClient(Settings(TOKEN), transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(AnalysisError) as error:
            await client.get_submission(SHA)
    assert error.value.error["code"] == expected
    assert TOKEN not in json.dumps(error.value.error)
    assert calls == ["GET"]


@pytest.mark.parametrize(
    "case", ["lost_reply", "bad_json", "wrong_sha", "redirect", "unknown", "timeout"]
)
async def test_post_ambiguity_never_repeats_and_retains_recovery(case):
    calls = []

    async def handler(request):
        calls.append(await request.aread())
        if case == "lost_reply":
            raise httpx.ReadError("synthetic-private-transport-detail")
        if case == "timeout":
            raise httpx.ReadTimeout("synthetic-private-timeout")
        if case == "bad_json":
            return httpx.Response(200, content=b"private-body")
        if case == "redirect":
            return httpx.Response(307, headers={"Location": "https://example.invalid"})
        if case == "unknown":
            return httpx.Response(503, json={"detail": {"code": "submission_unknown"}})
        return httpx.Response(200, json=submission_response("0" * 64))

    async with AnalysisClient(Settings(TOKEN), transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(AnalysisError) as error:
            await client.submit(io.BytesIO(BODY), SHA, len(BODY))
    assert calls == [BODY]
    assert error.value.error["code"] == "submission_unknown"
    assert error.value.error["retryable"] is False
    assert error.value.submission == submission_response(status="submission_unknown")
    assert "private" not in json.dumps(error.value.error)


@pytest.mark.parametrize(
    "body,headers",
    [
        (b"x" * (256 * 1024 + 1), {}),
        (b"{}", {"Content-Encoding": "gzip"}),
        (b'{"status":"pending","status":"completed"}', {}),
        (b'{"x":NaN}', {}),
    ],
)
async def test_bounded_wire_parsing(body, headers):
    async with AnalysisClient(
        Settings(TOKEN),
        transport=httpx.MockTransport(lambda _: httpx.Response(200, content=body, headers=headers)),
    ) as client:
        with pytest.raises(AnalysisError):
            await client.get_analysis(ANALYSIS_ID)


async def test_actual_async_request_deadline_is_bounded(monkeypatch):
    async def handler(request):
        await anyio.sleep(1)
        pytest.fail("Timeout failed")

    async with AnalysisClient(Settings(TOKEN), transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(AnalysisError) as error:
            await client._analysis_request("GET", "analyses/example", timeout=0.02)
    assert error.value.error["code"] == "timeout"


async def test_post_deadline_includes_dispatch_and_does_not_repeat(monkeypatch):
    calls = []
    monkeypatch.setattr("vt_mcp.client.SUBMIT_TIMEOUT", 0.02)

    async def handler(request):
        calls.append(await request.aread())
        await anyio.sleep(1)
        pytest.fail("POST exceeded its outer deadline")

    async with AnalysisClient(Settings(TOKEN), transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(AnalysisError) as error:
            await client.submit(io.BytesIO(BODY), SHA, len(BODY))
    assert calls == [BODY]
    assert error.value.error["code"] == "submission_unknown"
    assert error.value.submission["sha256"] == SHA


async def test_bad_error_codes_cannot_escape_closed_catalog():
    assert analysis_http_error(503, code=[]).error["code"] == "unavailable"
    assert analysis_http_error(503, retry_after_seconds=True).error["retry_after_seconds"] is None
