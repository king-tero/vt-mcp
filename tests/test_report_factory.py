"""Host-owned resources and binding, without cloud services or real credentials."""

import asyncio
import copy
import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime

import anyio
import httpx
import pytest
from mcp import Client

from vt_mcp.reports import (
    format_file_report,
    format_indicator_report,
    report_http_error,
)
from vt_mcp.server import create_report_server, create_server
from vt_mcp.vtai_client import Settings

pytestmark = pytest.mark.anyio
RETRIEVED = datetime(2026, 9, 6, 12, 30, tzinfo=UTC)
INPUTS = {"url": "https://example.com/", "domain": "example.com", "ip": "192.0.2.1"}


class FixtureReader:
    def __init__(self, reports):
        self.reports = reports

    async def get_file_report(self, file_hash):
        return format_file_report(self.reports["file"], file_hash, retrieved_at=RETRIEVED)

    async def get_url_report(self, url):
        return format_indicator_report(self.reports["url"], "url", retrieved_at=RETRIEVED)

    async def get_domain_report(self, domain):
        return format_indicator_report(self.reports["domain"], "domain", retrieved_at=RETRIEVED)

    async def get_ip_report(self, ip):
        return format_indicator_report(self.reports["ip"], "ip", retrieved_at=RETRIEVED)


async def test_shared_factory_preserves_local_surface_and_four_reports(
    file_hash, report, indicator_report
):
    reports = {"file": report["data"], **{k: indicator_report(k)["data"] for k in INPUTS}}
    resources = FixtureReader(reports)
    lifecycle = []
    bindings = []

    @asynccontextmanager
    async def lifespan(_):
        lifecycle.append("enter")
        yield resources
        lifecycle.append("exit")

    def bind(ctx):
        bindings.append(ctx)
        assert ctx.request_context.lifespan_context is resources
        return resources

    direct = create_report_server(lifespan=lifespan, bind_reports=bind)
    local = create_server(
        Settings("synthetic-local-credential"),
        transport=httpx.MockTransport(lambda _: pytest.fail("Discovery needs no HTTP")),
    )
    async with Client(local) as local_client, Client(direct) as direct_client:
        local_tools = (await local_client.list_tools()).model_dump()
        assert len([tool for tool in local_tools["tools"] if tool["name"] == "get_analysis"]) == 1
        local_tools["tools"] = [
            tool for tool in local_tools["tools"] if tool["name"] != "get_analysis"
        ]
        assert local_tools == (await direct_client.list_tools()).model_dump()
        assert bindings == []
        invalid = await direct_client.call_tool("get_url_report", {"url": [], "token": "fixture"})
        assert invalid.is_error
        assert bindings == []
        for kind, value in {"file": file_hash, **INPUTS}.items():
            result = await direct_client.call_tool(
                f"get_{kind}_report", {"hash" if kind == "file" else kind: value}
            )
            assert not result.is_error
            assert result.structured_content["data"] == reports[kind]
            assert result.structured_content["retrieved_at"] == RETRIEVED.isoformat()
            assert json.loads(result.content[0].text) == result.structured_content
        assert len(bindings) == 4
    assert lifecycle == ["enter", "exit"]


@pytest.mark.parametrize("failure", ["no_request", "none_reader", "exception", "denied"])
async def test_missing_or_failed_binding_has_no_fallback_and_no_private_error(failure, caplog):
    fallback_calls = []

    class ForbiddenFallback:
        async def get_domain_report(self, domain):
            fallback_calls.append(domain)
            return {"status": "found"}

    @asynccontextmanager
    async def lifespan(_):
        yield ForbiddenFallback()

    def bind(ctx):
        if failure == "no_request":
            return ctx.request_context.request.state.actor
        if failure == "none_reader":
            return None
        if failure == "exception":
            raise RuntimeError("synthetic-private-binding-detail")
        raise report_http_error(403, "domain")

    async with Client(create_report_server(lifespan=lifespan, bind_reports=bind)) as client:
        result = await client.call_tool("get_domain_report", {"domain": "example.com"})
    assert result.is_error
    error = result.structured_content["error"]
    assert error["code"] == ("access_denied" if failure == "denied" else "unavailable")
    assert "synthetic-private-binding-detail" not in result.content[0].text + caplog.text
    assert "NoneType" not in result.content[0].text
    assert fallback_calls == []


async def test_unexpected_reader_failure_is_sanitized(caplog):
    class BrokenReader:
        async def get_domain_report(self, domain):
            raise RuntimeError("synthetic-private-reader-detail")

    @asynccontextmanager
    async def lifespan(_):
        yield None

    server = create_report_server(lifespan=lifespan, bind_reports=lambda _: BrokenReader())
    async with Client(server) as client:
        result = await client.call_tool("get_domain_report", {"domain": "example.com"})
    assert result.is_error
    assert result.structured_content["error"]["code"] == "unavailable"
    assert "synthetic-private-reader-detail" not in result.content[0].text + caplog.text


@pytest.mark.parametrize("protocol", ["2025-11-25", "2026-07-28"])
async def test_http_context_binds_concurrent_actors_without_shared_actor(
    protocol, indicator_report
):
    resources = {"report": indicator_report("domain")["data"]}
    ready = anyio.Event()
    admitted = []
    lifecycle = []
    readers = []

    class BoundReader:
        def __init__(self, actor):
            self.actor = actor

        async def get_domain_report(self, domain):
            admitted.append(self.actor)
            if len(admitted) == 2:
                ready.set()
            with anyio.fail_after(5):
                await ready.wait()
            raw = copy.deepcopy(resources["report"])
            raw["detections"] = [f"benign-fixture-{self.actor}"]
            return format_indicator_report(raw, "domain", retrieved_at=RETRIEVED)

    @asynccontextmanager
    async def lifespan(_):
        lifecycle.append("enter")
        yield resources
        lifecycle.append("exit")

    def bind(ctx):
        assert ctx.request_context.lifespan_context is resources
        actor = getattr(ctx.request_context.request.state, "fixture_actor", None)
        if actor is None:
            raise report_http_error(403, "domain")
        reader = BoundReader(actor)
        readers.append(reader)
        return reader

    server = create_report_server(lifespan=lifespan, bind_reports=bind)
    child = server.streamable_http_app(
        streamable_http_path="/mcp", stateless_http=True, json_response=True
    )

    async def fixture_host(scope, receive, send):
        # Test-only host injects synthetic actors. This is not authentication.
        state = {}
        fixture = dict(scope.get("headers", [])).get(b"x-fixture-actor")
        if fixture in {b"alice", b"bob"}:
            state["fixture_actor"] = fixture.decode()
        await child({**scope, "state": state}, receive, send)

    async with (
        server.session_manager.run(),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=fixture_host), base_url="http://localhost:8000"
        ) as client,
    ):

        async def call(actor):
            headers = {
                "accept": "application/json, text/event-stream",
                "mcp-protocol-version": protocol,
            }
            if actor is not None:
                headers["x-fixture-actor"] = actor
            params = {"name": "get_domain_report", "arguments": {"domain": "example.com"}}
            if protocol == "2026-07-28":
                headers["mcp-method"] = "tools/call"
                headers["mcp-name"] = "get_domain_report"
                params["_meta"] = {
                    "io.modelcontextprotocol/protocolVersion": protocol,
                    "io.modelcontextprotocol/clientCapabilities": {},
                }
            return await client.post(
                "/mcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": actor or "missing",
                    "method": "tools/call",
                    "params": params,
                },
            )

        responses = await asyncio.gather(call("alice"), call("bob"))
        for actor, response in zip(("alice", "bob"), responses, strict=True):
            assert response.status_code == 200, response.text
            assert "mcp-session-id" not in response.headers
            result = response.json()["result"]
            assert not result["isError"]
            assert result["structuredContent"]["data"]["detections"] == [f"benign-fixture-{actor}"]
        missing = await call(None)
        assert missing.json()["result"]["isError"]
        assert missing.json()["result"]["structuredContent"]["error"]["code"] == "access_denied"
    assert len(readers) == 2 and readers[0] is not readers[1]
    assert resources == {"report": indicator_report("domain")["data"]}
    assert lifecycle == ["enter", "exit"]
