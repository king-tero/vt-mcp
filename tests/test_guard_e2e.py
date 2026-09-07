"""Real guard processes against a loopback fixture; never fetch or upload a target."""

import hashlib
import json
import os
import shlex
import subprocess
import sys
import threading
import time
import tomllib
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

from vt_mcp import guard

SCRIPT = b"""import hashlib, importlib.util, json, os, sys
from pathlib import Path
extra = []
for name in os.listdir("/proc/self/fd"):
    if int(name) > 2:
        try:
            extra.append(os.readlink("/proc/self/fd/" + name))
        except FileNotFoundError:
            pass
print(json.dumps({
    "fixture": "A",
    "sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    "vtai_environment": sorted(key for key in os.environ if key.startswith("VTAI_")),
    "descriptor_file": __file__.startswith("/proc/self/fd/"),
    "argv0_is_file": sys.argv[0] == __file__,
    "isolated": sys.flags.isolated,
    "sibling_visible": importlib.util.find_spec("guard_fixture_neighbor") is not None,
    "extra_descriptors": extra,
    "pid": os.getpid(),
}))
raise SystemExit(7)
"""


@pytest.fixture
def local_runner(tmp_path):
    state = SimpleNamespace(
        status=200,
        case="qualified",
        requests=[],
        seen=threading.Event(),
        release=threading.Event(),
        wait=False,
        change=None,
    )
    token = "synthetic-guard-e2e-not-a-real-credential"
    script = tmp_path / "fixture.py"
    script.write_bytes(SCRIPT)
    (tmp_path / "guard_fixture_neighbor.py").write_text("VALUE = 'harmless'\n")
    token_file = tmp_path / "token"
    token_file.write_text(token + "\n")

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            sha256 = self.path.rsplit("/", 1)[-1]
            state.requests.append(
                {"path": self.path, "credential_ok": self.headers["x-apikey"] == token}
            )
            state.seen.set()
            if state.wait:
                state.release.wait(25)
            if state.change == "overwrite":
                script.write_bytes(SCRIPT.replace(b'"fixture": "A"', b'"fixture": "B"'))
            elif state.change == "replace":
                replacement = tmp_path / "replacement.py"
                replacement.write_bytes(SCRIPT.replace(b'"fixture": "A"', b'"fixture": "B"'))
                replacement.replace(script)
            stats = {"malicious": 0, "suspicious": 0, "harmless": 1, "undetected": 1}
            date = datetime.now(UTC) - timedelta(days=1)
            if state.case == "flagged":
                stats["malicious"] = 1
            elif state.case == "stale":
                date -= timedelta(days=31)
            elif state.case == "future":
                date += timedelta(days=2)
            elif state.case == "failed_engines":
                stats.update(harmless=0, undetected=0, timeout=100)
            data = {
                "id": sha256,
                "last_analysis_stats": stats,
                "detections": [],
                "analysis_date": date.isoformat(),
                "coverage": {"engines": 2, "categories": []},
            }
            if state.case == "missing_date":
                del data["analysis_date"]
            elif state.case == "mismatched_hash":
                data["id"] = "0" * 64
            raw = json.dumps({"data": data} if state.status == 200 else {"private": token}).encode()
            try:
                self.send_response(state.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    policy_file = tmp_path / "policy.json"

    def command(mode="control", action="run"):
        raw = json.dumps(
            {
                "schema_version": 1,
                "mode": mode,
                "token_file": str(token_file),
                "base_url": f"http://127.0.0.1:{server.server_port}/api/v3",
                "minimum_completed_engines": 1,
                "maximum_analysis_age_days": 30,
            }
        ).encode()
        policy_file.write_bytes(raw)
        args = [
            sys.executable,
            "-I",
            "-m",
            "vt_mcp",
            "guard",
            action,
            "--policy",
            str(policy_file),
            "--policy-sha256",
            hashlib.sha256(raw).hexdigest(),
        ]
        return args + (["--", str(script)] if action == "run" else [])

    environment = {key: value for key, value in os.environ.items() if not key.startswith("VTAI_")}
    environment.update(
        VTAI_TOKEN="synthetic-wrong-ambient-token",
        VTAI_TOKEN_FILE="/missing",
        VTAI_MCP_TOKEN="synthetic-wrong-ambient-mcp",
        VTAI_TIMEOUT="1",
    )
    try:
        yield SimpleNamespace(
            state=state,
            command=command,
            environment=environment,
            script=script,
            token_file=token_file,
            token=token,
            cwd=tmp_path,
        )
    finally:
        state.release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def invoke(fixture, mode="control", action="run", **kwargs):
    result = subprocess.run(
        fixture.command(mode, action),
        env=fixture.environment,
        cwd=fixture.cwd,
        capture_output=True,
        text=True,
        timeout=22,
        **kwargs,
    )
    assert fixture.token not in result.stdout + result.stderr
    assert "synthetic-wrong-ambient" not in result.stdout + result.stderr
    assert len(result.stderr.encode()) < 2048
    return result


@pytest.mark.parametrize("mode", ["control", "observe"])
@pytest.mark.parametrize(
    "status,case,reason",
    [
        (200, "qualified", "policy_satisfied"),
        (200, "flagged", "flagged"),
        (200, "stale", "insufficient_evidence"),
        (200, "future", "insufficient_evidence"),
        (200, "missing_date", "insufficient_evidence"),
        (200, "failed_engines", "insufficient_evidence"),
        (200, "mismatched_hash", "invalid_response"),
        (404, "qualified", "not_found"),
        (401, "qualified", "access_denied"),
        (403, "qualified", "access_denied"),
        (429, "qualified", "rate_limited"),
        (503, "qualified", "upstream_error"),
    ],
)
def test_observable_execution_policy_matrix(local_runner, mode, status, case, reason):
    fixture = local_runner
    fixture.state.status, fixture.state.case = status, case
    result = invoke(fixture, mode)
    should_run = mode == "observe" or reason == "policy_satisfied"
    assert result.returncode == (7 if should_run else 77)
    summary = json.loads(result.stderr)
    assert summary["reason"] == reason
    assert summary["decision"] == ("starting" if should_run else "blocked")
    assert summary["mode"] == mode
    assert len(fixture.state.requests) == 1
    request = fixture.state.requests[0]
    assert request == {
        "path": "/api/v3/files/" + hashlib.sha256(SCRIPT).hexdigest(),
        "credential_ok": True,
    }
    if should_run:
        observed = json.loads(result.stdout)
        assert observed["sha256"] == summary["sha256"] == hashlib.sha256(SCRIPT).hexdigest()
        assert observed["vtai_environment"] == []
        assert observed["descriptor_file"] and observed["argv0_is_file"]
        assert observed["isolated"] == 1 and not observed["sibling_visible"]
        assert len(observed["extra_descriptors"]) == 1
        assert "memfd:vt-mcp-checked-script" in observed["extra_descriptors"][0]
    else:
        assert result.stdout == ""


@pytest.mark.parametrize("change", ["overwrite", "replace"])
def test_actual_exec_uses_queried_bytes_after_source_changes(local_runner, change):
    fixture = local_runner
    fixture.state.change = change
    process = subprocess.Popen(
        fixture.command(),
        env=fixture.environment,
        cwd=fixture.cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout, stderr = process.communicate(timeout=10)
    assert process.returncode == 7
    observed = json.loads(stdout)
    assert observed["pid"] == process.pid  # Runner was replaced, no detached child.
    assert observed["fixture"] == "A"
    assert observed["sha256"] == json.loads(stderr)["sha256"] == hashlib.sha256(SCRIPT).hexdigest()
    assert hashlib.sha256(fixture.script.read_bytes()).hexdigest() != observed["sha256"]
    assert len(fixture.state.requests) == 1


@pytest.mark.parametrize("mode", ["observe", "control"])
def test_missing_credential_policy_has_no_ambient_fallback(local_runner, mode):
    fixture = local_runner
    fixture.token_file.unlink()
    result = invoke(fixture, mode)
    assert result.returncode == (7 if mode == "observe" else 77)
    assert json.loads(result.stderr)["reason"] == "credential_unavailable"
    assert fixture.state.requests == []


def test_actual_request_has_whole_fifteen_second_deadline(local_runner):
    fixture = local_runner
    fixture.state.wait = True
    start = time.monotonic()
    result = invoke(fixture)
    elapsed = time.monotonic() - start
    assert 14 <= elapsed < 19
    assert result.returncode == 77 and result.stdout == ""
    assert json.loads(result.stderr)["reason"] == "timeout"
    assert len(fixture.state.requests) == 1


@pytest.mark.parametrize("mode", ["control", "observe"])
def test_cancellation_before_report_never_starts_script(local_runner, mode):
    fixture = local_runner
    fixture.state.wait = True
    process = subprocess.Popen(
        fixture.command(mode),
        env=fixture.environment,
        cwd=fixture.cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert fixture.state.seen.wait(5)
        process.terminate()
        stdout, stderr = process.communicate(timeout=5)
        fixture.state.release.set()
        assert process.returncode < 0
        assert stdout == "" and "starting" not in stderr
        assert len(fixture.state.requests) == 1
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def test_hook_subprocess_rewrite_and_doctor_are_local(local_runner):
    fixture = local_runner
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "/usr/bin/python3 -I " + str(fixture.script)},
    }
    result = invoke(fixture, action="hook", input=json.dumps(event))
    assert result.returncode == 0 and result.stderr == ""
    rewritten = json.loads(result.stdout)["hookSpecificOutput"]["updatedInput"]["command"]
    assert shlex.split(rewritten) == fixture.command()
    assert fixture.state.requests == []
    result = invoke(fixture, action="doctor")
    assert result.returncode == 0 and result.stderr == ""
    observed = json.loads(result.stdout)
    assert observed["host_activation"] == "unverified"
    assert observed["network"] == observed["access"] == "not_checked"
    assert fixture.state.requests == []


def test_hook_input_is_bounded_without_reflecting_body(local_runner):
    fixture = local_runner
    result = invoke(fixture, action="hook", input="synthetic-input-body" * 4000)
    assert result.returncode == 0
    assert json.loads(result.stdout) == guard._deny()
    assert "synthetic-input-body" not in result.stdout + result.stderr


def test_hook_example_is_synchronous_and_does_not_weaken_host_permissions():
    root = Path(__file__).resolve().parents[1]
    example = tomllib.loads((root / "examples/hooks/codex-pretool.toml").read_text())
    (group,) = example["hooks"]["PreToolUse"]
    assert group["matcher"] == "^Bash$"
    (handler,) = group["hooks"]
    assert handler["type"] == "command" and handler["timeout"] == 5
    assert "async" not in handler
    assert "guard hook" in handler["command"]
    assert "--policy-sha256" in handler["command"]
    assert "dangerously" not in json.dumps(example)
