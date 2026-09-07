"""Observable transport and report fidelity for the three read-only lookups."""

import json

import httpx
import pytest

from vt_mcp.vtai_client import MAX_RESPONSE_BYTES, Settings, VTAIClient, VTAIError

pytestmark = pytest.mark.anyio
TOKEN = 'synthetic-"escaped\\credential'
INPUTS = {"url": "https://example.com/", "domain": "example.com", "ip": "192.0.2.1"}


async def lookup(client, kind, value=None):
    return await getattr(client, f"get_{kind}_report")(INPUTS[kind] if value is None else value)


@pytest.mark.parametrize("kind", INPUTS)
async def test_report_preserves_source_dates_detections_and_actual_coverage(kind, indicator_report):
    report = indicator_report(kind)
    async with VTAIClient(
        Settings(TOKEN), transport=httpx.MockTransport(lambda _: httpx.Response(200, json=report))
    ) as client:
        result = await lookup(client, kind)
    assert result["data"] == report["data"]
    assert result["analysis_date"] == report["data"]["analysis_date"]
    assert result["retrieved_at"] != result["analysis_date"]
    assert result["coverage"] == {"engines": 2, "categories": ["harmless"]}
    assert result["report_url"] == report["data"]["report_url"]


@pytest.mark.parametrize(
    "kind,value,raw_path",
    [
        ("domain", "BÜCHER.Example.", b"/api/v3/domains/B%C3%9CCHER.Example."),
        ("ip", "2001:0db8::1", b"/api/v3/ip_addresses/2001%3A0db8%3A%3A1"),
        ("url", "HTTPS://EXAMPLE.COM:443/?private=synthetic#fragment", b"/api/v3/urls/lookup"),
    ],
)
async def test_transport_keeps_origin_path_and_url_body_fixed(kind, value, raw_path):
    calls = []

    def handler(request):
        calls.append(request)
        assert request.url.host == "ai.virustotal.com"
        assert request.url.raw_path == raw_path
        assert request.url.query == b""
        assert request.headers["x-apikey"] == TOKEN
        assert request.headers["Accept-Encoding"] == "identity"
        if kind == "url":
            assert request.method == "POST"
            assert json.loads(request.content) == {"url": value}
        else:
            assert request.method == "GET"
            assert request.content == b""
        return httpx.Response(404, json={})

    async with VTAIClient(Settings(TOKEN), transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(VTAIError, match="No existing report"):
            await lookup(client, kind, value)
    assert len(calls) == 1  # Unknown never causes an analysis submission or target fetch.


@pytest.mark.parametrize("kind", INPUTS)
@pytest.mark.parametrize("value", ["", 4, [], "\ud800"])
async def test_invalid_type_or_empty_input_does_not_request(kind, value):
    async with VTAIClient(
        Settings(TOKEN), transport=httpx.MockTransport(lambda _: pytest.fail("Unexpected HTTP"))
    ) as client:
        with pytest.raises(VTAIError) as caught:
            await lookup(client, kind, value)
    assert caught.value.error["code"] == f"invalid_{kind}"


@pytest.mark.parametrize(
    "kind,value", [("url", "a" * 8193), ("domain", "a" * 1025), ("ip", "a" * 46)]
)
async def test_oversized_input_does_not_request(kind, value):
    async with VTAIClient(
        Settings(TOKEN), transport=httpx.MockTransport(lambda _: pytest.fail("Unexpected HTTP"))
    ) as client:
        with pytest.raises(VTAIError) as caught:
            await lookup(client, kind, value)
    assert caught.value.error["code"] == f"invalid_{kind}"


@pytest.mark.parametrize("kind", ["domain", "ip"])
@pytest.mark.parametrize(
    "value",
    [".", "..", "../agents", "//example.com", "a?b", "a#b", "a\\b", "%2e%2e", "a\nb", "a\x00b"],
)
async def test_path_delimiters_are_rejected_before_http(kind, value):
    async with VTAIClient(
        Settings(TOKEN), transport=httpx.MockTransport(lambda _: pytest.fail("Unexpected HTTP"))
    ) as client:
        with pytest.raises(VTAIError) as caught:
            await lookup(client, kind, value)
    assert caught.value.error["code"] == f"invalid_{kind}"


@pytest.mark.parametrize("kind", INPUTS)
@pytest.mark.parametrize(
    "status,code,retryable",
    [
        (401, "access_denied", False),
        (403, "access_denied", False),
        (404, "not_found", False),
        (422, "invalid", False),
        (429, "rate_limited", True),
        (502, "upstream_error", True),
        (503, "upstream_error", True),
        (504, "timeout", True),
        (307, "upstream_error", False),
    ],
)
async def test_controlled_errors_never_leak_or_retry(kind, status, code, retryable):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(
            status,
            json={"detail": TOKEN},
            headers={"Retry-After": "17", "Location": "https://example.org/"},
        )

    async with VTAIClient(Settings(TOKEN), transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(VTAIError) as caught:
            await lookup(client, kind)
    error = caught.value.error
    assert error["code"] == (f"invalid_{kind}" if status == 422 else code)
    assert error["http_status"] == status
    assert error["retryable"] is retryable
    assert error["retry_after_seconds"] == (17 if status == 429 else None)
    assert TOKEN not in str(error)
    assert len(calls) == 1


@pytest.mark.parametrize("kind", INPUTS)
@pytest.mark.parametrize(
    "fault",
    [
        "source",
        "type",
        "id",
        "origin",
        "link_id",
        "date",
        "engines",
        "stats",
        "token",
        "missing",
        "other_indicator",
        "invalid_unicode",
    ],
)
async def test_malformed_or_untrusted_report_fails_closed(kind, fault, indicator_report):
    report = indicator_report(kind)
    data = report["data"]
    if fault == "source":
        data["source"] = "another source"
    elif fault == "type":
        data["type"] = "file"
    elif fault == "id":
        data["id"] = "different"
    elif fault == "origin":
        data["report_url"] = "https://www.virustotal.com.example.org/"
    elif fault == "link_id":
        data["report_url"] += "mismatch"
    elif fault == "date":
        data["analysis_date"] = "2026-01-01T12:00:00+02:00"
    elif fault == "engines":
        data["coverage"]["engines"] = True
    elif fault == "stats":
        data["last_analysis_stats"]["malicious"] = -1
    elif fault == "token":
        data["detections"] = [TOKEN]
    elif fault == "missing":
        del data["coverage"]
    elif fault == "other_indicator":
        data["ip" if kind != "ip" else "url"] = None
    else:
        data["detections"] = ["\ud800"]
    async with VTAIClient(
        Settings(TOKEN),
        transport=httpx.MockTransport(lambda _: httpx.Response(200, content=json.dumps(report))),
    ) as client:
        with pytest.raises(VTAIError) as caught:
            await lookup(client, kind)
    assert caught.value.error["code"] == "invalid_response"
    assert TOKEN not in str(caught.value)


@pytest.mark.parametrize("kind", INPUTS)
async def test_missing_analysis_remains_unknown(kind, indicator_report):
    report = indicator_report(kind)
    report["data"].update(
        analysis_date=None, last_analysis_stats=None, coverage={"engines": None, "categories": []}
    )
    async with VTAIClient(
        Settings(TOKEN), transport=httpx.MockTransport(lambda _: httpx.Response(200, json=report))
    ) as client:
        result = await lookup(client, kind)
    assert result["analysis_date"] is None
    assert result["data"]["last_analysis_stats"] is None
    assert result["coverage"] == {"engines": None, "categories": []}


@pytest.mark.parametrize("kind", INPUTS)
async def test_encoded_and_oversized_bodies_are_bounded(kind):
    class UnreadStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            pytest.fail("Encoded bodies must not be read")
            yield b"unused"

    for response, code in [
        (
            httpx.Response(200, headers={"Content-Encoding": "gzip"}, stream=UnreadStream()),
            "invalid_response",
        ),
        (httpx.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1)), "response_too_large"),
    ]:
        async with VTAIClient(
            Settings(TOKEN), transport=httpx.MockTransport(lambda _, response=response: response)
        ) as client:
            with pytest.raises(VTAIError) as caught:
                await lookup(client, kind)
        assert caught.value.error["code"] == code


async def test_file_metadata_is_additive_and_uses_real_analysis(file_hash, report):
    report["data"].update(
        source="VirusTotal",
        analysis_date="2026-08-01T00:00:00Z",
        report_url=f"https://www.virustotal.com/gui/file/{file_hash}",
        coverage={"engines": 0, "categories": []},
    )
    async with VTAIClient(
        Settings(TOKEN), transport=httpx.MockTransport(lambda _: httpx.Response(200, json=report))
    ) as client:
        result = await client.get_file_report(file_hash)
    assert result["data"] == report["data"]
    assert result["analysis_date"] == "2026-08-01T00:00:00Z"
    assert result["coverage"]["engines"] == 0


@pytest.mark.parametrize("kind", INPUTS)
@pytest.mark.parametrize("failure", [httpx.ReadTimeout, httpx.ConnectError])
async def test_network_exception_details_are_not_exposed(kind, failure):
    def handler(request):
        raise failure(TOKEN, request=request)

    async with VTAIClient(Settings(TOKEN), transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(VTAIError) as caught:
            await lookup(client, kind)
    assert caught.value.error["code"] == (
        "timeout" if failure is httpx.ReadTimeout else "unavailable"
    )
    assert caught.value.error["retryable"] is True
    assert TOKEN not in str(caught.value)
