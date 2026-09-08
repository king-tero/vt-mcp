import asyncio
import json
from contextlib import asynccontextmanager

import anyio
import httpx
import pytest
from analysis_helpers import ANALYSIS_ID, SHA, TOKEN, analysis_response
from mcp import Client

from vt_mcp.analyses import AnalysisError, format_analysis_response
from vt_mcp.server import create_report_server, create_server
from vt_mcp.vtai_client import Settings

pytestmark = pytest.mark.anyio


async def test_local_analysis_read_preserves_structured_parity():
    calls = []

    def handler(request):
        calls.append(request.method)
        return httpx.Response(200, json=analysis_response())

    async with Client(
        create_server(Settings(TOKEN), transport=httpx.MockTransport(handler))
    ) as client:
        tools = (await client.list_tools()).tools
        assert len(tools) == 8
        assert {tool.name for tool in tools}.isdisjoint({"submit", "upload_file"})
        tool = next(tool for tool in tools if tool.name == "get_analysis")
        assert set(tool.input_schema["properties"]) == {"analysis_id"}
        assert tool.annotations.read_only_hint and tool.annotations.idempotent_hint
        assert not tool.annotations.destructive_hint
        result = await client.call_tool("get_analysis", {"analysis_id": ANALYSIS_ID})
    assert not result.is_error
    assert result.structured_content == analysis_response()
    assert json.loads(result.content[0].text) == result.structured_content
    assert calls == ["GET"]


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"analysis_id": 3},
        {"analysis_id": []},
        {"analysis_id": ANALYSIS_ID, "path": "synthetic-private-path"},
        {"analysis_id": "../ "},
        {"analysis_id": "é" * 513},
        {"analysis_id": ""},
    ],
)
async def test_invalid_analysis_arguments_never_bind_or_fetch(arguments):
    @asynccontextmanager
    async def lifespan(_):
        yield None

    server = create_report_server(
        lifespan=lifespan,
        bind_reports=lambda _: None,
        bind_analyses=lambda _: pytest.fail("Invalid arguments bound actor"),
    )
    async with Client(server) as client:
        result = await client.call_tool("get_analysis", arguments)
    assert result.is_error and result.structured_content["error"]["code"] == "invalid_input"
    assert "synthetic-private-path" not in result.content[0].text


@pytest.mark.parametrize("failure", ["none", "missing_context", "exception", "denied"])
async def test_analysis_binding_has_no_fallback_or_private_error(failure):
    class Reader:
        async def get_analysis(self, identifier):
            pytest.fail("Shared fallback reader was used")

    @asynccontextmanager
    async def lifespan(_):
        yield Reader()

    def bind(ctx):
        if failure == "none":
            return None
        if failure == "missing_context":
            return ctx.request_context.request.state.actor
        if failure == "exception":
            raise RuntimeError("synthetic-private-binding-detail")
        raise AnalysisError("access_denied")

    server = create_report_server(
        lifespan=lifespan, bind_reports=lambda _: None, bind_analyses=bind
    )
    async with Client(server) as client:
        result = await client.call_tool("get_analysis", {"analysis_id": ANALYSIS_ID})
    assert result.is_error
    assert result.structured_content["error"]["code"] == (
        "access_denied" if failure == "denied" else "unavailable"
    )
    assert "synthetic-private-binding-detail" not in result.content[0].text


@pytest.mark.parametrize("protocol", ["2025-11-25", "2026-07-28"])
async def test_two_protocols_bind_each_concurrent_analysis_to_its_actor(protocol):
    active, readers, lifetime = [], [], []
    ready = anyio.Event()

    class Reader:
        def __init__(self, actor):
            self.actor = actor

        async def get_analysis(self, identifier):
            active.append(self.actor)
            if len(active) == 2:
                ready.set()
            with anyio.fail_after(5):
                await ready.wait()
            return format_analysis_response(analysis_response(identifier, SHA), identifier)

    @asynccontextmanager
    async def lifespan(_):
        lifetime.append("start")
        yield {"public": True}
        lifetime.append("stop")

    def bind(ctx):
        actor = getattr(ctx.request_context.request.state, "fixture_actor", None)
        if actor is None:
            raise AnalysisError("access_denied")
        reader = Reader(actor)
        readers.append(reader)
        return reader

    server = create_report_server(
        lifespan=lifespan, bind_reports=lambda _: None, bind_analyses=bind
    )
    child = server.streamable_http_app(
        streamable_http_path="/mcp", stateless_http=True, json_response=True
    )

    async def fixture(scope, receive, send):
        actor = dict(scope.get("headers", [])).get(b"x-fixture-actor")
        state = {"fixture_actor": actor.decode()} if actor in {b"alice", b"bob"} else {}
        await child({**scope, "state": state}, receive, send)

    async with (
        server.session_manager.run(),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=fixture), base_url="http://localhost:8000"
        ) as client,
    ):

        async def call(actor):
            headers = {
                "accept": "application/json, text/event-stream",
                "mcp-protocol-version": protocol,
            }
            if actor:
                headers["x-fixture-actor"] = actor
            params = {"name": "get_analysis", "arguments": {"analysis_id": actor or "missing"}}
            if protocol == "2026-07-28":
                headers.update({"mcp-method": "tools/call", "mcp-name": "get_analysis"})
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
            assert response.status_code == 200
            assert response.json()["result"]["structuredContent"]["analysis_id"] == actor
        missing = await call(None)
        assert missing.json()["result"]["structuredContent"]["error"]["code"] == "access_denied"
    assert active == ["alice", "bob"] and len(readers) == 2 and readers[0] is not readers[1]
    assert lifetime == ["start", "stop"]
