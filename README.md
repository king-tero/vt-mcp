# vt-mcp

VirusTotal intelligence for MCP clients, powered by **VTAI**.

Look up file, URL, domain and IP reports, submit authorized files and recover their analyses from your assistant. Connect to VTAI over HTTP without installing vt-mcp or Python, or run the MCP server locally over stdio with an additional local-file tool. Basic use requires a free, revocable **VTAI token**; you do not need your own VirusTotal API key.

Version **0.8.0** adds autonomous MCP submission and receipt recovery over the existing VTAI service: **seven common tools over HTTP or stdio, plus one local-file tool over stdio**. Submission tools have no per-call confirmation or consent argument; configure your host to permit only the operations and files you authorize for standard public sharing. The existing CLI, report queries, opt-in guard and public-fixture release gates remain available. See the [release notes](docs/releases/v0.8.0.md) and [submission-workflow evidence](docs/clients.md#version-08-submission-evidence); five native-client sessions exercised the new cycle in staging and another five against a production candidate with zero public traffic. The public rollout is accepted, with separate direct SDK checks; the native sessions retain their candidate-route scope. The historical 0.7 sessions retain their read-only scope.

## Connect your client

1. Reuse existing access or register explicitly at [Connect to VirusTotal MCP](https://ai.virustotal.com/connect/mcp), following the [access guide](docs/access.md). Keep the token in protected storage outside chat and project files.
2. Choose a connection below and follow [client setup](docs/clients.md). Configure the credential outside the model conversation.
3. Restart the client, inspect its MCP tools and make one explicit report query.

| Connection | Client configuration | Local requirements |
|---|---|---|
| Remote HTTP | `https://ai.virustotal.com/mcp`, with `x-apikey` or the [VTAI 0.8.1 Bearer alternative](docs/access.md#choose-one-authentication-header) read from the host environment | An MCP client supporting the selected credential mapping; no vt-mcp or Python installation |
| Local stdio | Start `vt-mcp` with `VTAI_TOKEN_FILE` pointing to protected storage | Python 3.12+ and the verified wheel |

Both routes use VTAI's rights and quotas. VTAI 0.8.1 accepts the same VTAI token through **either `x-apikey` or `Authorization: Bearer`**; send only one. This is static token authentication, not OAuth, and needs no vt-mcp package upgrade. Existing `x-apikey` configurations and the local stdio wrapper keep working. Free access is neither anonymous nor unlimited; model-provider charges are separate.

Claude Code and Codex have each used Bearer for one report query in staging and one against a production candidate, through QA proxies. See the [scope and deployment status](docs/clients.md#bearer-authentication-validation); these were not ordinary public-direct sessions. Earlier accepted HTTP workflows used `x-apikey`.

| Client | Setup guide |
|---|---|
| Antigravity CLI (`agy`) | [Local stdio](docs/clients.md#antigravity-cli-agy) |
| Claude Code | [Client setup](docs/clients.md#claude-code) |
| Codex CLI | [Remote HTTP](docs/clients.md#codex-cli--remote-http) or [local stdio](docs/clients.md#codex-cli--local-stdio) |

`VTAI_MCP_TOKEN` names an environment variable; it is not a token value. Use the [protected-file launch instructions](docs/access.md#remote-client-environment) to supply it for HTTP without putting the credential in arguments, prompts or configuration text.

With **v0.7.0**, Antigravity CLI (`agy`) 1.1.27 completed all five tools through stdio. Claude Code 2.1.263 and Codex CLI 0.153.4 have each completed all five through both stdio and public HTTP. The [native-client validation](docs/client-validation-2026-09-07.md) records 25 MCP calls, the same selected analysis across sessions, and agy's auxiliary read of its generated analysis output. agy HTTP remains unvalidated: its tested header variables were sent literally. These observations are separate from guard behavior and release verification.

[Client setup](docs/clients.md) also covers Antigravity IDE, remaining Gemini CLI authentication routes, Qwen, Kimi, OpenCode and applications using Z.ai or DeepSeek, with their actual validation levels. Antigravity IDE has completed the four report queries through stdio in a separate session. ChatGPT and Claude hosted connectors require separate authentication/account integration and are not provided by these settings. The [configuration fragments](examples/client-configs/README.md) reuse one MCP server across clients.

## Tools

The compatible VTAI 0.8 service exposes these seven common tools. The four report queries and `get_analysis` keep their existing read-only behavior.

| Tool | Input |
|---|---|
| `get_file_report(hash)` | MD5, SHA-1 or SHA-256 hash |
| `get_url_report(url)` | HTTP(S) URL |
| `get_domain_report(domain)` | DNS domain, including Unicode names |
| `get_ip_report(ip)` | One IPv4 or IPv6 address |
| `get_analysis(analysis_id)` | One read of an analysis registered to the current VTAI account |
| `submit_file(sha256, content_base64)` | SHA-256 and base64-encoded authorized bytes, at most **24,000,000 decoded bytes** |
| `get_submission(sha256)` | Recover the current account’s submission receipt without sending the file again |

Local stdio additionally exposes **`submit_local_file(path, expected_sha256=None)`**: it copies a regular file accessible to the local vt-mcp process and submits at most **32,000,000 bytes**. The optional expected digest must match that copy. This tool is absent from remote HTTP; a remote server cannot read a path on your machine.

Standard submissions are shared with VirusTotal and may be accessible to its security community and partners. Inline file content also passes through your MCP host as tool arguments. Do not supply credentials or content you are not authorized to disclose. See the [submission and recovery guide](docs/analysis.md).

For a file report, ask:

> Use VirusTotal to look up the SHA-256 hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855. Explain the source, analysis date, coverage and limitations.

This is the empty-file hash. Report queries do not read local files, visit destinations, resolve DNS, upload samples or start analyses. A missing report remains unknown. VTAI owns intelligence, normalization, authorization and quotas.

For URL intelligence, **the full URL, including query and fragment, is shared with VTAI and VirusTotal**. Query only indicators you may disclose. Use domain scope when private paths are unnecessary; a domain result does not cover every URL it hosts. Domains take no scheme, path or port; IP addresses take no brackets, port, zone or CIDR suffix.

## Install for local stdio

Use Python 3.12+ and [uv](https://docs.astral.sh/uv/getting-started/installation/). Download the wheel and `SHA256SUMS` together from the [v0.8.0 release](https://github.com/king-tero/vt-mcp/releases/tag/v0.8.0). Verify that the manifest contains the exact wheel filename, then check and install from the download directory:

```bash
sha256sum --check --ignore-missing SHA256SUMS
uv tool install --python 3.12 ./vt_mcp-0.8.0-py3-none-any.whl
vt-mcp --version
```

Require an `OK` for that wheel before installing; checking other files does not verify an absent wheel. The package is not published on PyPI. Use the linked release and verified filename rather than a similarly named package from another publisher.

Keep `vt-mcp` on the client's PATH or configure its absolute path. After saving the VTAI token as described in the access guide, follow the setup for [Antigravity CLI (`agy`)](docs/clients.md#antigravity-cli-agy), [Claude Code](docs/clients.md#claude-code), or [Codex CLI stdio](docs/clients.md#codex-cli--local-stdio).

Restart the selected client and inspect `/mcp`. Running `vt-mcp` without a subcommand starts stdio. The wheel does not modify client settings; the source distribution includes the consumer guides and examples. A [Python application example](examples/README.md) uses the same MCP server without a model account.

## Optional workflows

| Workflow | Contract and guide |
|---|---|
| Submit and recover through MCP | Use `submit_file` for inline bytes or local stdio `submit_local_file` for a file; recover by SHA-256 with `get_submission`, then read the returned analysis ID with `get_analysis`. There is no per-call human confirmation. [Contract and limits](docs/analysis.md#autonomous-mcp-workflow). |
| Keep using the submission CLI | The [compatible CLI](docs/analysis.md#cli-authorize-one-copy) retains its explicit interactive confirmation or noninteractive acceptance/digest flags and its durable recovery reference. |
| Read a selected analysis | `vt-mcp analysis --wait 180 -- OPAQUE_REGISTERED_ID` optionally polls that registered analysis. The MCP `get_analysis` tool performs one read. Neither substitutes a newer file report for the selected analysis. |
| Check one Python execution in Codex | The [opt-in guard](docs/control.md) checks and executes the same sealed main-script bytes for its exact supported command grammar. It never uploads the script and is not a sandbox or an import/dependency check. |
| Gate two public CI fixtures | The [reference CI pilot](docs/ci-pilot.md) checks only two allowlisted public files. Non-allow outcomes prevent publication. It does not scan the product wheel, sdist, source, logs or dependencies. Both live fixture gates and evidence retention must succeed before the release workflow can publish. |

An uncertain submission is recovered through its receipt without repeating the POST, and can remain unknown permanently. `exists` is an existing file report, not a newly completed analysis; `submitted` only establishes a registered analysis ID. CLI exit 0 can mean pending. None of these states is security approval.

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

Remove the connection using the [Antigravity CLI (`agy`)](docs/clients.md#antigravity-cli-agy), [Claude Code](docs/clients.md#claude-code), or [Codex CLI](docs/clients.md#codex-cli--remote-http) instructions, then restart. Removing client configuration does not revoke VTAI access. Follow [revocation](docs/access.md#revoke-access) to disable the credential across clients, REST and MCP; a request already admitted may finish.

## Develop and embed

VTAI integrations can reuse the [factory and presentation API](docs/embedding.md). For development, use a source checkout containing `uv.lock`, scripts and tests, rather than the installation sdist. Select the [versioned v0.8.0 source tree](https://github.com/king-tero/vt-mcp/tree/v0.8.0) and verify its release provenance before running the development commands.

```bash
uv sync --locked
uv run ruff check .
uv run ruff format --check .
uv run pytest
uv build --no-build-isolation
```

The automated suite uses synthetic credentials and mocked or loopback services. The release workflow separately requires the public-fixture gate and publishes the previously verified CI artifacts without rebuilding. [Release notes](docs/releases/v0.8.0.md) describe the 0.8 changes; the [validation matrix](docs/clients.md#validation-levels) keeps historical evidence separate from the requirements for each release run.

## License

[MIT](LICENSE). This license covers the package code; access to VirusTotal intelligence remains subject to service terms and account privileges.
