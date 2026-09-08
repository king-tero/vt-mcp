import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from mcp import Client, StdioServerParameters


@pytest.mark.anyio
async def test_real_stdio_subprocess_calls_http_backend(
    file_hash, report, indicator_report, tmp_path
):
    calls = []
    token = "synthetic-subprocess-token"

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append(("GET", self.path, self.headers.get("x-apikey"), None))
            reports = {
                f"/api/v3/files/{file_hash}": report,
                "/api/v3/domains/example.com": indicator_report("domain"),
                "/api/v3/ip_addresses/192.0.2.1": indicator_report("ip"),
            }
            self.respond(reports[self.path])

        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            calls.append(("POST", self.path, self.headers.get("x-apikey"), payload))
            assert self.path == "/api/v3/urls/lookup"
            self.respond(indicator_report("url"))

        def respond(self, payload):
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    token_file = tmp_path / "credential"
    token_file.write_text(token)
    backend = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=backend.serve_forever, daemon=True)
    thread.start()
    try:
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-m", "vt_mcp"],
            cwd=tmp_path,
            env={
                "VTAI_TOKEN_FILE": str(token_file),
                "VTAI_BASE_URL": f"http://127.0.0.1:{backend.server_port}/api/v3",
            },
        )
        async with Client(parameters, read_timeout_seconds=15) as client:
            assert len((await client.list_tools()).tools) == 8
            for tool, argument, value, expected in [
                ("get_file_report", "hash", file_hash, report),
                ("get_url_report", "url", "https://example.com/", indicator_report("url")),
                ("get_domain_report", "domain", "example.com", indicator_report("domain")),
                ("get_ip_report", "ip", "192.0.2.1", indicator_report("ip")),
            ]:
                result = await client.call_tool(tool, {argument: value})
                assert result.is_error is False
                assert result.structured_content["data"] == expected["data"]
                assert token not in result.content[0].text
        assert calls == [
            ("GET", f"/api/v3/files/{file_hash}", token, None),
            ("POST", "/api/v3/urls/lookup", token, {"url": "https://example.com/"}),
            ("GET", "/api/v3/domains/example.com", token, None),
            ("GET", "/api/v3/ip_addresses/192.0.2.1", token, None),
        ]
    finally:
        backend.shutdown()
        backend.server_close()
        thread.join(timeout=5)


def test_cli_missing_credentials_fails_without_protocol_noise():
    env = {key: value for key, value in os.environ.items() if not key.startswith("VTAI_")}
    result = subprocess.run(
        [sys.executable, "-m", "vt_mcp"], capture_output=True, text=True, env=env, timeout=10
    )
    assert result.returncode == 2
    assert result.stdout == ""
    assert "VTAI_TOKEN" in result.stderr
    assert "Traceback" not in result.stderr
