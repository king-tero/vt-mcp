# Configure free VTAI access

A VTAI credential identifies one registered agent and carries VTAI's current rights and quotas. It is not a VirusTotal API key or a model-provider key. Free access does not imply anonymous or unlimited use, or free inference from your chosen assistant.

Keep registration, credential entry, diagnosis and revocation outside model conversations. Use a terminal you control or the VTAI connection page. Do not ask an assistant to read your token file, environment or client credential settings.

## Register once or reuse existing access

Reuse an existing VTAI credential if you have one. Registration is an explicit setup action; it is not a tool and does not run when vt-mcp starts.

Use [Connect to VirusTotal MCP](https://ai.virustotal.com/connect/mcp) for browser setup. Reuse existing access; reconnecting or changing transport does not register another agent. Its flow lets you register explicitly, request a token-file download, check access and revoke a credential. A download request does not prove the file was saved; confirm protected storage yourself. Checking access consumes query quota and tests the report endpoint, not your model's use of MCP. Registration may have succeeded if the connection fails; do not register again automatically.

The [browser acceptance table](clients.md#distribution-and-browser-acceptance) records the real flow through a route pinned to the production candidate, separately from ordinary public navigation and package release acceptance. If the page is unavailable, check the exact endpoint/prefix and [service validation](clients.md#service-and-workflow-validation). For a terminal setup, the explicit API example below is an alternative; opening the API URL alone does not register an agent.

For local setup, this terminal script calls the existing registration API and writes the credential without printing it. It refuses an existing path and uses owner-only permissions on POSIX. Run it only once; if the request times out after registration, registration may have succeeded. Diagnose that uncertainty before creating another agent.

```bash
python3 - <<'PY'
import json
import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

path = Path.home() / ".config" / "vt-mcp" / "token"
path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
path.parent.chmod(0o700)
if path.exists() or path.is_symlink():
    raise SystemExit("An existing credential path is already configured.")
request = Request(
    "https://ai.virustotal.com/api/v3/agents/register",
    data=json.dumps({"agent_family": "vt-mcp", "agent_version": "0.8.0"}).encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
try:
    with build_opener(NoRedirect).open(request, timeout=20) as response:
        raw = response.read(65537)
        if len(raw) > 65536:
            raise ValueError("response limit")
        token = json.loads(raw)["agent_token"]
    if not isinstance(token, str) or not token.startswith("vtai_"):
        raise ValueError("credential format")
    if not 6 <= len(token) <= 256 or any(not 33 <= ord(c) <= 126 for c in token):
        raise ValueError("credential format")
except (HTTPError, URLError, TimeoutError, ValueError, KeyError, TypeError):
    raise SystemExit("Registration was not confirmed. No credential was saved.") from None
try:
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
        output.write(token)
except OSError:
    raise SystemExit("Registration returned access, but saving failed. Resolve local storage before retrying.") from None
print("VTAI credential saved. Registration is not needed at each startup.")
PY
```

An existing credential can instead be saved using a trusted editor or password manager to `~/.config/vt-mcp/token`, as a single value. Do not put it in a shell command or a project file. On POSIX, protect the directory with mode `0700` and the file with mode `0600`. If you downloaded a token, a browser does not guarantee those permissions: move it to protected storage and remove the extra download after verifying storage. Windows needs equivalent user-only file access; the POSIX instructions are not Windows validation.

## Local stdio

Install the wheel using the [README](../README.md), then add your client using [client setup](clients.md). Configure only the file path:

```text
VTAI_TOKEN_FILE=~/.config/vt-mcp/token
```

vt-mcp reads the file at startup and uses `x-apikey` for its VTAI requests. Restart its client process after replacing the file. `VTAI_TOKEN` is an alternative for direct process configuration; setting both credential options is an error.

## Remote client environment

Remote MCP uses `https://ai.virustotal.com/mcp`, not the REST URL ending `/api/v3`. VTAI requires **`x-apikey`**. It does not accept `Authorization: Bearer` as a replacement, and the current connection does not implement OAuth.

Use the host's supported environment-header reference from the [configuration fragments](../examples/client-configs/README.md). `VTAI_MCP_TOKEN` is an arbitrary host-side variable name, chosen to avoid conflict with a stdio server's `VTAI_TOKEN_FILE`.

For Antigravity CLI (`agy`) 1.1.27, use the [stdio token-file setup](clients.md#antigravity-cli-agy); tested HTTP header variables were sent literally. Claude Code and Codex support the remote configurations described here.

In a human-controlled Bash terminal, load the file without printing its value, then launch the client:

```bash
(
  set +x
  unset VTAI_MCP_TOKEN
  IFS= read -r VTAI_MCP_TOKEN < "$HOME/.config/vt-mcp/token" || test -n "$VTAI_MCP_TOKEN" || exit 1
  test -n "$VTAI_MCP_TOKEN" || exit 1
  export VTAI_MCP_TOKEN
  exec claude
)
```

Use `exec codex` instead for Codex, with its matching header configuration. A nonempty first line works with or without a trailing newline; a missing file or empty first line prevents launch. The subshell does not leave a new export in the parent shell. The variable lasts for that client process, and a previously opened GUI will not inherit it. Do not use a header flag containing an expanded credential: it can put the secret in process arguments and saved configuration. File and environment storage avoid normal disclosure in prompts; they do not isolate credentials from software with permission to read them.

## Diagnose the right layer

1. Check the installed client version and `vt-mcp --version` for stdio. Confirm the executable PATH and file access without displaying the credential.
2. Inspect the client's MCP status. A configuration parser or `tools/list` result proves only that layer. In stdio, discovery does not authenticate a VTAI request.
3. Make one explicit report query through the client. Use the empty-file SHA-256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`, or `example.com`. This consumes an admitted query and does not upload or start a scan. Check source, analysis date, coverage and report link.
4. Confirm that the assistant actually called a tool and used its result. A generic SDK test or successful connection does not establish a model workflow in another client.

| Observation | Meaning / action |
|---|---|
| 401 | `x-apikey` was absent. Check the header mapping and host environment source. |
| 403 / `access_denied` | The credential was not accepted; it may be revoked or expired. |
| 429 / `rate_limited` | Wait for a supplied retry delay; repeated retries consume resources. |
| Tool result `not_found` | No report was found; this is not a safety verdict. |
| HTTP 404 for `/mcp` or `/connect/mcp` | Check endpoint, prefix and deployment flags; this is not an unknown indicator result. |
| Timeout / service error | A failed lookup is not a clean report. Check service status; do not silently submit a sample. |

REST and MCP share VTAI admission and quotas. Unknown reports and upstream failures still consume an admitted query. The stdio wrapper defaults to a 15-second total request deadline; the backend lookup has its own 35-second limit. A client timeout can happen first, and an already admitted request may complete later. Show only sanitized errors to the model; never paste raw auth headers or debug logs into chat.

## Disconnect and reconnect

Remove or disable the `virustotal` entry in the client and restart/reload it. [Client setup](clients.md) lists removal commands. Verify that its tools disappear. This removes that connection; it does not revoke VTAI access or delete VTAI history.

Do not remove a credential file shared by other clients unless you intend to remove their local access too. After a local disconnect, a still-valid credential can be used to reconnect without registering again.

## Revoke access

Use the revocation form at [the VTAI connection page](https://ai.virustotal.com/connect/mcp) when its deployment enables revocation. Enter the credential in that human-facing form and confirm the action. Its API is `DELETE /api/v3/agents/me/token`, authenticated with `x-apikey`; this is an advanced setup operation, not an MCP tool.

A confirmed revocation returns 204. A timeout or service error does not confirm success; retain protected access to the credential so you can diagnose or retry. A 401/403 means it was not accepted, not proof that this particular action revoked it.

VTAI currently has one credential per agent. Revocation disables that agent across clients, REST and MCP; records remain, and a lookup admitted before revocation may finish. Remove the connection from every affected client afterward. To obtain access after revocation, explicitly register a new agent. This is not rotation of the old agent's credential.
