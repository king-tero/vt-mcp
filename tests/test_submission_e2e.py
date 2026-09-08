"""Observable CLI behavior with generated text and a loopback backend only."""

import base64
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.parse import unquote

import pytest
from analysis_helpers import ANALYSIS_ID, BODY, SHA, TOKEN, analysis_response, submission_response
from mcp import Client, StdioServerParameters


@pytest.fixture
def fixture(tmp_path):
    source = tmp_path / "private-original-name.txt"
    source.write_bytes(BODY)
    state_dir = tmp_path / "state"
    temporary = tmp_path / "temporary"
    temporary.mkdir()
    state = SimpleNamespace(
        posts=[],
        gets=[],
        receipts={},
        behavior="accept",
        completed=False,
        seen=threading.Event(),
        release=threading.Event(),
        wait=False,
    )

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def respond(self, status, data):
            body = json.dumps(data).encode()
            try:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def disconnect(self):
            self.close_connection = True
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()

        def do_POST(self):
            assert self.headers["x-apikey"] == TOKEN
            assert self.headers["x-vtai-consent"] == "standard-v1"
            assert self.headers["content-type"] == "application/octet-stream"
            assert "content-disposition" not in self.headers
            size = int(self.headers["content-length"])
            body = self.rfile.read(size)
            sha256 = self.path.rsplit("/", 1)[-1]
            state.posts.append(
                {
                    "sha256": sha256,
                    "body": body,
                    "path_in_headers": str(source) in str(self.headers),
                }
            )
            assert hashlib.sha256(body).hexdigest() == sha256
            assert len(list(state_dir.rglob("*.json"))) == 1
            state.seen.set()
            if state.behavior != "lost_before_accept":
                state.receipts[sha256] = submission_response(sha256, size)
            if state.wait:
                state.release.wait(10)
            if state.behavior in {"lost_before_accept", "lost_after_accept"}:
                self.disconnect()
            elif state.behavior == "reject":
                self.respond(
                    429,
                    {
                        "detail": {
                            "code": "rate_limited",
                            "message": TOKEN,
                            "retry_after_seconds": 17,
                        }
                    },
                )
            else:
                self.respond(200, state.receipts[sha256])

        def do_GET(self):
            assert self.headers["x-apikey"] == TOKEN
            state.gets.append(self.path)
            if self.path.startswith("/api/v3/submissions/"):
                receipt = state.receipts.get(self.path.rsplit("/", 1)[-1])
                self.respond(200, receipt) if receipt else self.respond(
                    404, {"detail": {"code": "not_found"}}
                )
            else:
                identifier = unquote(self.path.removeprefix("/api/v3/analyses/"))
                assert identifier == ANALYSIS_ID
                self.respond(200, analysis_response(identifier, completed=state.completed))

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    environment = {key: value for key, value in os.environ.items() if not key.startswith("VTAI_")}
    environment.update(
        VTAI_TOKEN=TOKEN,
        VTAI_BASE_URL=f"http://127.0.0.1:{server.server_port}/api/v3",
        TMPDIR=str(temporary),
    )
    command = [
        sys.executable,
        "-I",
        "-m",
        "vt_mcp",
        "submit",
        str(source),
        "--mode",
        "standard",
        "--accept-standard",
        "--expected-sha256",
        SHA,
        "--state-dir",
        str(state_dir),
    ]
    try:
        yield SimpleNamespace(
            state=state,
            command=command,
            environment=environment,
            source=source,
            state_dir=state_dir,
            temporary=temporary,
            cwd=tmp_path,
        )
    finally:
        state.release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def invoke(fixture, command=None):
    result = subprocess.run(
        command or fixture.command,
        env=fixture.environment,
        cwd=fixture.cwd,
        capture_output=True,
        text=True,
        input="",
        timeout=10,
    )
    assert TOKEN not in result.stdout + result.stderr
    assert str(fixture.source) not in result.stdout + result.stderr
    assert list(fixture.temporary.iterdir()) == []
    return result, json.loads(result.stdout)


def test_submit_receipt_and_selected_analysis_are_separate_observable_steps(fixture):
    result, submitted = invoke(fixture)
    assert result.returncode == 0 and submitted["status"] == "submitted"
    assert submitted["analysis_status"] is None
    assert fixture.state.posts == [{"sha256": SHA, "body": BODY, "path_in_headers": False}]
    assert len(list(fixture.state_dir.rglob("*.json"))) == 1
    read = [sys.executable, "-I", "-m", "vt_mcp", "submission", SHA]
    result, receipt = invoke(fixture, read)
    assert result.returncode == 0 and receipt == submitted
    analysis = [sys.executable, "-I", "-m", "vt_mcp", "analysis", ANALYSIS_ID, "--wait", "0.05"]
    result, pending = invoke(fixture, analysis)
    assert result.returncode == 0 and pending["status"] == "pending"
    assert pending["wait"]["status"] == "budget_exhausted"
    fixture.state.completed = True
    result, completed = invoke(fixture, analysis[:-2])
    assert result.returncode == 0 and completed == analysis_response(completed=True)
    assert len(fixture.state.posts) == 1
    assert all("files/" not in path for path in fixture.state.gets)


@pytest.mark.parametrize("behavior", ["lost_before_accept", "lost_after_accept"])
def test_lost_response_keeps_reference_and_never_repeats_post(fixture, behavior):
    fixture.state.behavior = behavior
    result, outcome = invoke(fixture)
    assert result.returncode == 3
    assert outcome["error"]["code"] == "submission_unknown"
    assert outcome["submission"]["can_resubmit"] is False
    assert len(list(fixture.state_dir.rglob("*.json"))) == 1
    result, recovered = invoke(fixture)
    if behavior == "lost_after_accept":
        assert result.returncode == 0 and recovered["status"] == "submitted"
    else:
        assert result.returncode == 2 and recovered["error"]["code"] == "not_found"
        assert recovered["submission"]["status"] == "submission_unknown"
    assert len(fixture.state.posts) == 1
    assert fixture.state.gets == [f"/api/v3/submissions/{SHA}"]


def test_two_processes_share_exclusive_local_reference(fixture):
    processes = [
        subprocess.Popen(
            fixture.command,
            env=fixture.environment,
            cwd=fixture.cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(2)
    ]
    try:
        outputs = [process.communicate(timeout=10) for process in processes]
        for process, (stdout, stderr) in zip(processes, outputs, strict=True):
            result = json.loads(stdout)
            assert process.returncode in {0, 2}
            assert result["status"] in {"submitted", "error"}
            assert TOKEN not in stdout + stderr
        assert len(fixture.state.posts) == 1
        assert len(list(fixture.state_dir.rglob("*.json"))) == 1
        assert list(fixture.temporary.iterdir()) == []
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)


@pytest.mark.parametrize("interruption", [signal.SIGINT, signal.SIGTERM])
def test_interruption_after_dispatch_keeps_recovery_and_no_delayed_second_post(
    fixture, interruption
):
    fixture.state.wait = True
    process = subprocess.Popen(
        fixture.command,
        env=fixture.environment,
        cwd=fixture.cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert fixture.state.seen.wait(5)
        process.send_signal(interruption)
        stdout, stderr = process.communicate(timeout=5)
        if interruption == signal.SIGINT:
            assert process.returncode == 130
            assert json.loads(stdout)["status"] == "submission_unknown"
        else:
            assert process.returncode < 0 and stdout == ""
        assert TOKEN not in stdout + stderr
        assert len(list(fixture.state_dir.rglob("*.json"))) == 1
        fixture.state.release.set()
        result, recovered = invoke(fixture)
        assert result.returncode == 0 and recovered["status"] == "submitted"
        assert len(fixture.state.posts) == 1
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def test_console_without_consent_does_not_send_bytes_or_create_reference(fixture):
    command = fixture.command.copy()
    command.remove("--accept-standard")
    result, outcome = invoke(fixture, command)
    assert result.returncode == 2 and outcome["error"]["code"] == "consent_required"
    assert not fixture.state_dir.exists()
    assert fixture.state.posts == [] and fixture.state.gets == []


def test_retryable_rejection_does_not_repeat_post(fixture):
    fixture.state.behavior = "reject"
    result, outcome = invoke(fixture)
    assert result.returncode == 2 and outcome["error"]["code"] == "rate_limited"
    assert outcome["error"]["retry_after_seconds"] == 17
    assert len(fixture.state.posts) == 1
    assert outcome["submission"]["status"] == "submission_unknown"


@pytest.mark.anyio
async def test_new_analysis_tool_over_real_stdio_process(fixture):
    parameters = StdioServerParameters(
        command=sys.executable, args=["-I", "-m", "vt_mcp"], env=fixture.environment
    )
    async with Client(parameters, read_timeout_seconds=15) as client:
        tools = (await client.list_tools()).tools
        assert len(tools) == 8
        result = await client.call_tool("get_analysis", {"analysis_id": ANALYSIS_ID})
    assert not result.is_error and result.structured_content == analysis_response()
    assert json.loads(result.content[0].text) == result.structured_content
    assert TOKEN not in result.content[0].text
    assert len(fixture.state.gets) == 1 and fixture.state.posts == []


@pytest.mark.anyio
@pytest.mark.parametrize("first", ["submit_file", "submit_local_file"])
async def test_autonomous_submission_and_recovery_over_real_stdio(fixture, first):
    # State uses the standard XDG root; no credential or state argument enters MCP.
    fixture.state_dir = fixture.cwd / "state" / "vt-mcp"
    environment = {**fixture.environment, "XDG_STATE_HOME": str(fixture.cwd / "state")}
    parameters = StdioServerParameters(
        command=sys.executable, args=["-I", "-m", "vt_mcp"], env=environment
    )
    arguments = {
        "submit_file": {"sha256": SHA, "content_base64": base64.b64encode(BODY).decode()},
        "submit_local_file": {"path": str(fixture.source)},
    }
    async with Client(parameters, read_timeout_seconds=15) as client:
        result = await client.call_tool(first, arguments[first])
        assert not result.is_error and result.structured_content == submission_response()
        recovered = await client.call_tool("get_submission", {"sha256": SHA})
        assert recovered.structured_content == result.structured_content
        other = "submit_local_file" if first == "submit_file" else "submit_file"
        repeated = await client.call_tool(other, arguments[other])
        assert not repeated.is_error and repeated.structured_content == result.structured_content
        fixture.state.completed = True
        final = await client.call_tool("get_analysis", {"analysis_id": ANALYSIS_ID})
        assert not final.is_error and final.structured_content == analysis_response(completed=True)
        for item in (result, recovered, repeated, final):
            assert TOKEN not in item.content[0].text
            assert str(fixture.source) not in item.content[0].text
            assert json.loads(item.content[0].text) == item.structured_content
    assert fixture.state.posts == [{"sha256": SHA, "body": BODY, "path_in_headers": False}]
    assert len(fixture.state.gets) == 3
    assert list(fixture.temporary.iterdir()) == []
