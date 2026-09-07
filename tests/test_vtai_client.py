import json
from datetime import UTC, datetime

import anyio
import httpx
import pytest

from vt_mcp.vtai_client import (
    MAX_RESPONSE_BYTES,
    ConfigurationError,
    Settings,
    VTAIClient,
    VTAIError,
)

pytestmark = pytest.mark.anyio
TOKEN = "vtai_synthetic_test_credential"


@pytest.mark.parametrize(
    "value,delay",
    [
        ("Sun, 06 Sep 2026 12:02:00 GMT", 120),
        ("Sun, 06 Sep 2026 11:59:00 GMT", 0),
        ("Sun, 06 Sep 2026 14:02:00 +0200", 120),
        ("Sun, 06 Sep 2026 12:02:00", None),
        ("Sun, 06 Sep 2037 12:02:00 GMT", None),
        ("invalid-private-delay", None),
        ("Sun, 06 Sep 2026 12:02:00 GMT\r\nprivate-header", None),
        ("Sun, 06 Sep 2026 12:02:00 GMT\x7f", None),
        ("17", 17),
    ],
)
async def test_http_retry_date_is_bounded_and_rounded_up(file_hash, monkeypatch, value, delay):
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 9, 6, 12, 0, 0, 250000, tzinfo=UTC)

    monkeypatch.setattr("vt_mcp.vtai_client.datetime", Clock)
    async with VTAIClient(
        Settings(TOKEN),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(429, headers={"Retry-After": value}, json={})
        ),
    ) as client:
        with pytest.raises(VTAIError) as caught:
            await client.get_file_report(file_hash)
    error = caught.value.error
    assert error["code"] == "rate_limited"
    assert error["retry_after_seconds"] == delay
    assert value not in error["message"] and TOKEN not in json.dumps(error)


async def test_report_uses_vtai_credential_and_preserves_evidence(file_hash, report):
    calls = []
    report["data"]["detections"] = ["Example.Detection", "Example.Detection"]
    report["data"]["ai_insights"] = [
        {"source": "code_insight", "verdict": None, "analysis": "Untrusted analysis text"}
    ]

    def handler(request):
        calls.append(request)
        assert request.method == "GET"
        assert str(request.url) == f"https://ai.virustotal.com/api/v3/files/{file_hash}"
        assert request.headers["x-apikey"] == TOKEN
        assert request.headers["accept-encoding"] == "identity"
        assert request.content == b""
        return httpx.Response(200, json=report)

    async with VTAIClient(Settings(TOKEN), transport=httpx.MockTransport(handler)) as client:
        result = await client.get_file_report(file_hash.upper())
    assert len(calls) == 1
    assert result["status"] == "found"
    assert result["data"] == report["data"]
    assert result["analysis_date"] is None
    assert result["retrieved_at"].endswith("+00:00")
    assert result["report_url"].endswith(file_hash)
    assert TOKEN not in json.dumps(result)


@pytest.mark.parametrize("digest", ["a" * 32, "b" * 40])
async def test_short_hashes_use_returned_sha256(digest, report, file_hash):
    async with VTAIClient(
        Settings(TOKEN), transport=httpx.MockTransport(lambda _: httpx.Response(200, json=report))
    ) as client:
        result = await client.get_file_report(digest)
    assert result["data"]["id"] == file_hash


@pytest.mark.parametrize(
    "digest", ["", "not-a-hash", "g" * 64, "../secret", "a" * 65, "a" * 64 + "\n"]
)
async def test_invalid_hash_never_reaches_backend(digest):
    def unexpected(_):
        pytest.fail("An invalid hash must not cause a request")

    async with VTAIClient(Settings(TOKEN), transport=httpx.MockTransport(unexpected)) as client:
        with pytest.raises(VTAIError) as caught:
            await client.get_file_report(digest)
    assert caught.value.error["code"] == "invalid_hash"


@pytest.mark.parametrize(
    ("status", "body", "code", "retryable"),
    [
        (401, {"detail": "Not authenticated"}, "access_denied", False),
        (403, {"detail": "Invalid Agent Token"}, "access_denied", False),
        (403, {"detail": {"status_code": 403}}, "upstream_access_denied", False),
        (404, {"detail": "Unknown file"}, "not_found", False),
        (429, {}, "rate_limited", True),
        (500, {}, "upstream_error", True),
        (503, {}, "upstream_error", True),
        (302, {}, "upstream_error", False),
    ],
)
async def test_errors_are_distinct_sanitized_and_not_retried(
    file_hash, status, body, code, retryable
):
    calls = []
    body["private_debug"] = TOKEN

    def handler(request):
        calls.append(request)
        return httpx.Response(
            status, json=body, headers={"Retry-After": "17", "Location": "https://example.org/"}
        )

    async with VTAIClient(Settings(TOKEN), transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(VTAIError) as caught:
            await client.get_file_report(file_hash)
    error = caught.value.error
    assert error["code"] == code
    assert error["retryable"] == retryable
    assert error["http_status"] == status
    assert TOKEN not in str(error)
    assert len(calls) == 1  # Includes redirect responses: the token stays at VTAI.
    assert error["retry_after_seconds"] == (17 if status == 429 else None)


@pytest.mark.parametrize("body", [b"not JSON", b"null", b"[]", b"{}", b'{"data":{}}'])
async def test_bad_response_never_becomes_a_report(file_hash, body):
    async with VTAIClient(
        Settings(TOKEN), transport=httpx.MockTransport(lambda _: httpx.Response(200, content=body))
    ) as client:
        with pytest.raises(VTAIError) as caught:
            await client.get_file_report(file_hash)
    assert caught.value.error["code"] == "invalid_response"


@pytest.mark.parametrize("fault", ["wrong_hash", "negative_count", "boolean_count", "secret"])
async def test_invalid_or_secret_containing_data_is_not_exposed(file_hash, report, fault):
    if fault == "wrong_hash":
        report["data"]["id"] = "0" * 64
    elif fault == "negative_count":
        report["data"]["last_analysis_stats"]["undetected"] = -1
    elif fault == "boolean_count":
        report["data"]["last_analysis_stats"]["undetected"] = True
    else:
        report["data"]["type_description"] = TOKEN
    async with VTAIClient(
        Settings(TOKEN), transport=httpx.MockTransport(lambda _: httpx.Response(200, json=report))
    ) as client:
        with pytest.raises(VTAIError) as caught:
            await client.get_file_report(file_hash)
    assert caught.value.error["code"] == "invalid_response"
    assert TOKEN not in str(caught.value)


async def test_response_size_is_bounded(file_hash):
    async with VTAIClient(
        Settings(TOKEN),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))
        ),
    ) as client:
        with pytest.raises(VTAIError) as caught:
            await client.get_file_report(file_hash)
    assert caught.value.error["code"] == "response_too_large"


async def test_encoded_response_is_rejected_before_reading_body(file_hash):
    class UnreadStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            pytest.fail("An encoded body must not be read or decompressed")
            yield b"unused benign fixture"

    async with VTAIClient(
        Settings(TOKEN),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200, headers={"Content-Encoding": "gzip"}, stream=UnreadStream()
            )
        ),
    ) as client:
        with pytest.raises(VTAIError) as caught:
            await client.get_file_report(file_hash)
    assert caught.value.error["code"] == "invalid_response"


@pytest.mark.parametrize("failure", [httpx.ReadTimeout, httpx.ConnectError])
async def test_network_failures_hide_exception_details(file_hash, failure):
    def handler(request):
        raise failure(TOKEN, request=request)

    async with VTAIClient(Settings(TOKEN), transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(VTAIError) as caught:
            await client.get_file_report(file_hash)
    assert caught.value.error["retryable"] is True
    assert TOKEN not in str(caught.value)


async def test_total_deadline_includes_a_slow_backend(file_hash):
    async def slow(_):
        await anyio.sleep(5)
        pytest.fail("The overall request deadline should have cancelled the backend")

    async with VTAIClient(
        Settings(TOKEN, timeout=1), transport=httpx.MockTransport(slow)
    ) as client:
        with pytest.raises(VTAIError) as caught:
            await client.get_file_report(file_hash)
    assert caught.value.error["code"] == "timeout"


@pytest.mark.parametrize(
    "url",
    [
        "http://example.org",
        "https://user:password@example.org",
        "https://example.org/?token=x",
        "https://example.org/#fragment",
        "https://example.org:invalid",
        "https://example.org:0",
    ],
)
def test_configuration_rejects_unsafe_service_urls(url):
    with pytest.raises(ConfigurationError):
        Settings(TOKEN, base_url=url)


def test_token_file_and_missing_configuration(monkeypatch, tmp_path):
    monkeypatch.delenv("VTAI_TOKEN", raising=False)
    monkeypatch.delenv("VTAI_TOKEN_FILE", raising=False)
    with pytest.raises(ConfigurationError):
        Settings.from_env()
    token_file = tmp_path / "token"
    token_file.write_text(TOKEN + "\n")
    monkeypatch.setenv("VTAI_TOKEN_FILE", str(token_file))
    assert Settings.from_env().token == TOKEN
    assert TOKEN not in repr(Settings.from_env())
    monkeypatch.setenv("VTAI_TOKEN", "different")
    with pytest.raises(ConfigurationError):
        Settings.from_env()


@pytest.mark.parametrize("value", ["nan", "inf", "0", "61", "not-a-number"])
def test_invalid_timeout_is_rejected(monkeypatch, value):
    monkeypatch.setenv("VTAI_TOKEN", TOKEN)
    monkeypatch.delenv("VTAI_TOKEN_FILE", raising=False)
    monkeypatch.setenv("VTAI_TIMEOUT", value)
    with pytest.raises(ConfigurationError):
        Settings.from_env()
