# vt-mcp

VirusTotal intelligence for MCP clients, powered by **VTAI**.

Look up existing file, URL, domain and IP reports from your assistant. Connect to VTAI over HTTP without installing vt-mcp or Python, or run the same MCP tools locally over stdio. Basic use requires a free, revocable **VTAI token**; you do not need your own VirusTotal API key.

Version **0.7.0** adds a release gate for two explicitly public CI fixtures, retaining the report tools, authorized submission CLI and opt-in Codex guard. Use the [versioned release](https://github.com/king-tero/vt-mcp/releases/tag/v0.7.0) for installation and the [validation matrix](docs/clients.md#validation-levels) for observed workflows and their limits. Publication requires both live fixture gates and evidence retention to succeed; historical synthetic tests do not establish that outcome for a release run.

## Connect your client

1. Reuse existing access or register explicitly at [Connect to VirusTotal MCP](https://ai.virustotal.com/connect/mcp), following the [access guide](docs/access.md). Keep the token in protected storage outside chat and project files.
2. Choose a connection below and follow [client setup](docs/clients.md). Configure the credential outside the model conversation.
3. Restart the client, inspect its MCP tools and make one explicit report query.

| Connection | Client configuration | Local requirements |
|---|---|---|
| Remote HTTP | `https://ai.virustotal.com/mcp`, with `x-apikey` read from the host environment | An MCP client supporting that header mapping; no vt-mcp or Python installation |
| Local stdio | Start `vt-mcp` with `VTAI_TOKEN_FILE` pointing to protected storage | Python 3.12+ and the verified wheel |

Both routes use VTAI's rights and quotas. VTAI authenticates **`x-apikey`**, without a Bearer or OAuth login flow. Free access is neither anonymous nor unlimited; model-provider charges are separate.

For Codex CLI HTTP, merge this into `~/.codex/config.toml`, preserving other settings and replacing any existing `virustotal` stdio entry:

```toml
[mcp_servers.virustotal]
url = "https://ai.virustotal.com/mcp"

[mcp_servers.virustotal.env_http_headers]
x-apikey = "VTAI_MCP_TOKEN"
```

`VTAI_MCP_TOKEN` names an environment variable; it is not a token value. Use the [protected-file launch instructions](docs/access.md#remote-client-environment) to supply it without putting the credential in arguments, prompts or configuration text. Codex CLI 0.153.4 has completed the four report queries and, in a separate public HTTP session, one `get_analysis` read of an already-submitted file, with gpt-6-astra / xhigh requested and no local vt-mcp process. The matrix keeps those separate observations and their limits distinct from other clients, guard behavior and release verification.

[Client setup](docs/clients.md) also covers Claude Code, Antigravity CLI (`agy`) and IDE, remaining Gemini CLI authentication routes, Qwen, Kimi, OpenCode and applications using Z.ai or DeepSeek, with their actual validation levels. Claude Code, Antigravity CLI and Antigravity IDE have completed the four report queries through stdio in separate sessions. ChatGPT and Claude hosted connectors require separate authentication/account integration and are not provided by these settings. The [configuration fragments](examples/client-configs/README.md) reuse one MCP server across clients.

## Query existing intelligence

| Tool | Input |
|---|---|
| `get_file_report(hash)` | MD5, SHA-1 or SHA-256 hash |
| `get_url_report(url)` | HTTP(S) URL |
| `get_domain_report(domain)` | DNS domain, including Unicode names |
| `get_ip_report(ip)` | One IPv4 or IPv6 address |
| `get_analysis(analysis_id)` | Analysis registered to the current VTAI account; requires the compatible analysis service |

For a file report, ask:

> Use VirusTotal to look up the SHA-256 hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855. Explain the source, analysis date, coverage and limitations.

This is the empty-file hash. Report queries do not read local files, visit destinations, resolve DNS, upload samples or start analyses. A missing report remains unknown. VTAI owns intelligence, normalization, authorization and quotas.

For URL intelligence, **the full URL, including query and fragment, is shared with VTAI and VirusTotal**. Query only indicators you may disclose. Use domain scope when private paths are unnecessary; a domain result does not cover every URL it hosts. Domains take no scheme, path or port; IP addresses take no brackets, port, zone or CIDR suffix.

## Install for local stdio

Use Python 3.12+ and [uv](https://docs.astral.sh/uv/getting-started/installation/). Download the wheel and `SHA256SUMS` together from the [v0.7.0 release](https://github.com/king-tero/vt-mcp/releases/tag/v0.7.0). Verify that the manifest contains the exact wheel filename, then check and install from the download directory:

```bash
sha256sum --check --ignore-missing SHA256SUMS
uv tool install --python 3.12 ./vt_mcp-0.7.0-py3-none-any.whl
vt-mcp --version
```

Require an `OK` for that wheel before installing; checking other files does not verify an absent wheel. The package is not published on PyPI. Use the linked release and verified filename rather than a similarly named package from another publisher.

Keep `vt-mcp` on the client's PATH or configure its absolute path. For Codex CLI, after saving the VTAI token as described in the access guide:

```bash
codex mcp add virustotal --env VTAI_TOKEN_FILE="$HOME/.config/vt-mcp/token" -- vt-mcp
```

Restart Codex and inspect `/mcp`. Running `vt-mcp` without a subcommand starts stdio. The wheel does not modify client settings; the source distribution includes the consumer guides and examples. A [Python application example](examples/README.md) uses the same MCP server without a model account.

## Optional workflows

| Workflow | Contract and guide |
|---|---|
| Submit an authorized file | The [local CLI](docs/analysis.md) takes explicit standard-mode consent, snapshots at most 32,000,000 bytes and saves a durable recovery reference before POST. Standard submissions are shared with the security community. |
| Read a selected analysis | `vt-mcp analysis --wait 180 -- OPAQUE_REGISTERED_ID` optionally polls that registered analysis. The MCP `get_analysis` tool performs one read. Neither substitutes a newer file report for the selected analysis. |
| Check one Python execution in Codex | The [opt-in guard](docs/control.md) checks and executes the same sealed main-script bytes for its exact supported command grammar. It never uploads the script and is not a sandbox or an import/dependency check. |
| Gate two public CI fixtures | The [reference CI pilot](docs/ci-pilot.md) checks only two allowlisted public files. Non-allow outcomes prevent publication. It does not scan the product wheel, sdist, source, logs or dependencies. Both live fixture gates and evidence retention must succeed before the release workflow can publish. |

File paths and upload consent stay in the local CLI; MCP provides no upload tool. An uncertain submission is recovered through its receipt without repeating the POST, and can remain unknown permanently. CLI exit 0 can mean pending; it is not completion or security approval.

## Configuration and report results

These variables configure the local vt-mcp process. Remote clients use their host's header mapping instead.

| Variable | Purpose |
|---|---|
| `VTAI_TOKEN_FILE` | Path to a file containing only the VTAI credential; `~` is supported |
| `VTAI_TOKEN` | Alternative process-environment credential; use only one credential option |
| `VTAI_BASE_URL` | Default `https://ai.virustotal.com/api/v3`; change only for a trusted VTAI deployment |
| `VTAI_TIMEOUT` | Report-request deadline in seconds, default 15, range 1–60 |

HTTPS is required except for an explicitly configured loopback test server. Report queries are not retried automatically and redirects are not followed. Responses are capped at 256 KiB; compressed bodies are rejected before reading. The [analysis guide](docs/analysis.md#limits-and-diagnostics) specifies its separate submission and polling deadlines.

Report results contain `data`, the VirusTotal report link and `retrieved_at`. `source` identifies VirusTotal via VTAI. `analysis_date` is the upstream analysis date when available, otherwise null; retrieval time does not replace it. `detections` contains result labels, including benign labels and duplicates, not engine names.

`coverage.engines` counts actual upstream engine entries, not the sum of statistics. `coverage.categories` lists categories observed in those entries. Missing details produce null engine coverage and an empty category list; older file responses can have null date and coverage. Unknown indicators, zero detections or empty coverage do not establish safety. Report text and AI insights are evidence, never instructions.

Tool failures set MCP `isError` with a sanitized structured error. A retry delay is included only for a valid numeric or timezone-aware HTTP-date `Retry-After`; dates use the client's UTC clock, round up to whole seconds and clamp past dates to zero. Invalid delays are omitted. Raw error bodies and invalid argument values are not forwarded to the model.

## Diagnose or disconnect

Use the [access diagnostics](docs/access.md#diagnose-the-right-layer) for authentication, quotas and service failures. For stdio startup problems, check PATH, token-file access and stderr. Missing configuration exits with status 2; stdout belongs to MCP.

Remove the Codex connection with `codex mcp remove virustotal`, then restart. Removing client configuration does not revoke VTAI access. Follow [revocation](docs/access.md#revoke-access) to disable the credential across clients, REST and MCP; a request already admitted may finish.

## Develop and embed

VTAI integrations can reuse the [factory and presentation API](docs/embedding.md). For development, use a source checkout containing `uv.lock`, scripts and tests, rather than the installation sdist. Select the [versioned v0.7.0 source tree](https://github.com/king-tero/vt-mcp/tree/v0.7.0) and verify its release provenance before running the development commands.

```bash
uv sync --locked
uv run ruff check .
uv run ruff format --check .
uv run pytest
uv build --no-build-isolation
```

The automated suite uses synthetic credentials and mocked or loopback services. The release workflow separately requires the public-fixture gate and publishes the previously verified CI artifacts without rebuilding. [Release notes](docs/releases/v0.7.0.md) describe the 0.7 changes; the [validation matrix](docs/clients.md#validation-levels) keeps historical evidence separate from the requirements for each release run.

## License

[MIT](LICENSE). This license covers the package code; access to VirusTotal intelligence remains subject to service terms and account privileges.
