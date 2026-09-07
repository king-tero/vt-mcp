import json

import httpx
import pytest
from mcp import Client

from vt_mcp.server import create_server
from vt_mcp.vtai_client import Settings

pytestmark = pytest.mark.anyio


async def test_tool_surface_and_structured_result(file_hash, report, indicator_report):
    reports = {
        "files": report,
        "urls": indicator_report("url"),
        "domains": indicator_report("domain"),
        "ip_addresses": indicator_report("ip"),
    }
    server = create_server(
        Settings("synthetic-mcp-token"),
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json=reports[request.url.path.split("/")[3]])
        ),
    )
    async with Client(server) as client:
        tools = (await client.list_tools()).tools
        names = {tool.name for tool in tools}
        assert names == {
            "get_file_report",
            "get_url_report",
            "get_domain_report",
            "get_ip_report",
            "get_analysis",
        }
        inputs = {
            "get_file_report": ("hash", file_hash, "files"),
            "get_url_report": ("url", "https://example.com/", "urls"),
            "get_domain_report": ("domain", "example.com", "domains"),
            "get_ip_report": ("ip", "192.0.2.1", "ip_addresses"),
        }
        for tool in tools:
            if tool.name == "get_analysis":
                # Analysis-specific calls are exercised in test_analysis_mcp.py.
                assert set(tool.input_schema["properties"]) == {"analysis_id"}
                assert tool.annotations.read_only_hint is True
                assert tool.annotations.destructive_hint is False
                continue
            name, value, endpoint = inputs[tool.name]
            assert set(tool.input_schema["properties"]) == {name}
            assert tool.annotations.read_only_hint is True
            assert tool.annotations.destructive_hint is False
            assert tool.annotations.idempotent_hint is True
            result = await client.call_tool(tool.name, {name: value})
            assert result.is_error is False
            assert result.structured_content["data"] == reports[endpoint]["data"]
            assert json.loads(result.content[0].text) == result.structured_content


@pytest.mark.parametrize(
    "status,code", [(404, "not_found"), (429, "rate_limited"), (503, "upstream_error")]
)
async def test_mcp_failure_flag_matches_structured_failure(file_hash, status, code):
    server = create_server(
        Settings("synthetic-mcp-token"),
        transport=httpx.MockTransport(lambda _: httpx.Response(status, json={})),
    )
    async with Client(server) as client:
        result = await client.call_tool("get_file_report", {"hash": file_hash})
        assert result.is_error is True
        assert result.structured_content["status"] == "error"
        assert result.structured_content["error"]["code"] == code


async def test_unknown_tools_and_bad_arguments_do_not_call_vtai():
    def unexpected(_):
        pytest.fail("Invalid calls must not reach VTAI")

    server = create_server(
        Settings("synthetic-mcp-token"), transport=httpx.MockTransport(unexpected)
    )
    async with Client(server) as client:
        for name, args in [
            ("upload_file", {"path": "example.txt"}),
            ("get_file_report", {"hash": "x"}),
        ]:
            result = await client.call_tool(name, args)
            assert result.is_error is True


@pytest.mark.parametrize(
    "tool,argument",
    [
        ("get_file_report", "hash"),
        ("get_url_report", "url"),
        ("get_domain_report", "domain"),
        ("get_ip_report", "ip"),
    ],
)
@pytest.mark.parametrize("value", [None, 3, [], {}, "unexpected-argument"])
async def test_malformed_lookup_arguments_are_sanitized_and_structured(tool, argument, value):
    def unexpected(_):
        pytest.fail("Malformed arguments must not reach the HTTP backend")

    server = create_server(
        Settings("synthetic-mcp-token"), transport=httpx.MockTransport(unexpected)
    )
    async with Client(server) as client:
        arguments = {argument: value}
        if value == "unexpected-argument":
            arguments["token"] = "private"
        result = await client.call_tool(tool, arguments)
        assert result.is_error is True
        assert result.structured_content["error"]["code"] == f"invalid_{argument}"
        assert "input_value" not in result.content[0].text
        assert "private" not in result.content[0].text


@pytest.mark.parametrize(
    "tool,argument",
    [
        ("get_file_report", "hash"),
        ("get_url_report", "url"),
        ("get_domain_report", "domain"),
        ("get_ip_report", "ip"),
    ],
)
async def test_missing_arguments_do_not_leak_sdk_validation(tool, argument):
    server = create_server(
        Settings("synthetic-mcp-token"),
        transport=httpx.MockTransport(lambda _: pytest.fail("Unexpected HTTP")),
    )
    async with Client(server) as client:
        result = await client.call_tool(tool, {})
        assert result.is_error is True
        assert result.structured_content["error"]["code"] == f"invalid_{argument}"
        assert "input_value" not in result.content[0].text
