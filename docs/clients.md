# Connect an MCP client

Choose remote HTTP or local stdio for the same four read-only report tools. Remote HTTP needs a client and a VTAI token, with no local vt-mcp or Python installation. stdio needs the verified wheel. These instructions cover version 0.7.0. The package also exposes `get_analysis` for an analysis registered to the current VTAI actor; see the [submission and recovery guide](analysis.md). Report-only evidence does not transfer to analysis; the separate Codex HTTP analysis run is recorded below, with other hosts retaining their own validation levels. Set up protected access using the [access guide](access.md), or the [README](../README.md#connect-your-client).

Codex has completed the four report queries directly against the production HTTP endpoint and one selected-analysis read in a separate public HTTP session. The [validation matrix](#validation-levels) records those report and analysis sessions separately from guard, browser and release acceptance. Use the [versioned installation instructions](../README.md#install-for-local-stdio) and verify the artifact associated with the selected release.

## Codex CLI — remote HTTP

Merge this entry into `~/.codex/config.toml`, preserving other settings. Replace an existing `virustotal` stdio entry instead of combining `command` and `url` or registering twice.

```toml
[mcp_servers.virustotal]
url = "https://ai.virustotal.com/mcp"

[mcp_servers.virustotal.env_http_headers]
x-apikey = "VTAI_MCP_TOKEN"
```

`VTAI_MCP_TOKEN` is an environment-variable name, not a credential value. In your own Bash terminal, start Codex from the protected file:

```bash
(
  set +x
  unset VTAI_MCP_TOKEN
  IFS= read -r VTAI_MCP_TOKEN < "$HOME/.config/vt-mcp/token" || test -n "$VTAI_MCP_TOKEN" || exit 1
  test -n "$VTAI_MCP_TOKEN" || exit 1
  export VTAI_MCP_TOKEN
  exec codex
)
```

This also accepts a nonempty credential file without a trailing newline. A missing file or an empty first line prevents launch. The subshell avoids leaving a new export in your parent shell. An already running app or a desktop launcher may not inherit this environment; close and restart the selected client through the configured launch path. Do not ask the model to read the file or environment.

VTAI accepts only `x-apikey`. Do not replace this with `--bearer-token-env-var`, `Authorization`, a literal token in the configuration, or `codex mcp login`. OAuth is a different authentication flow that this service does not provide. The `env_http_headers` mapping is documented in [official Codex MCP configuration](https://learn.chatgpt.com/docs/extend/mcp), accepted by the checked CLI 0.153.4 schema and used in the production workflow recorded below.

Restart and inspect `/mcp`, then [check the tools](#try-the-tools). Remove the connection with `codex mcp remove virustotal` and restart. Reuse the same active VTAI credential if you reconnect.

## Codex CLI — local stdio

Install the verified wheel first. Use an absolute executable path if `vt-mcp` is absent from the client's PATH. The command passes a credential-file path, not its contents:

```bash
codex mcp add virustotal --env VTAI_TOKEN_FILE="$HOME/.config/vt-mcp/token" -- vt-mcp
```

Restart Codex and use `/mcp` to inspect the integration. Remove it with `codex mcp remove virustotal`. The command syntax was checked against Codex CLI `0.153.4` and [official OpenAI documentation](https://learn.chatgpt.com/docs/extend/mcp) on 2026-09-06.

## Claude Code

Sign in with your existing Claude subscription using `claude auth login --claudeai` (or `/login` inside Claude Code). Vertex and ADC are optional cloud-provider choices, not vt-mcp requirements. This model-provider login is separate from your VTAI credential. [Claude Code authentication](https://code.claude.com/docs/en/authentication).

```bash
claude mcp add --env VTAI_TOKEN_FILE="$HOME/.config/vt-mcp/token" \
  --scope user --transport stdio virustotal -- vt-mcp
```

For HTTP, merge [claude-http.json](../examples/client-configs/claude-http.json) into a project `.mcp.json` you control and launch Claude Code with `VTAI_MCP_TOKEN`. Its documented `${VAR}` expansion applies to headers. Do not pass an expanded credential to `--header`: it may expose the value in process arguments or configuration.

Inspect `/mcp` or `claude mcp list`. Remove the stdio user entry with `claude mcp remove --scope user virustotal`. Remove the HTTP project entry from `.mcp.json` or use `claude mcp remove --scope project virustotal`, then restart/reload. The scope/transport options terminate the variadic `--env` option in the command above. CLI 2.1.257 help was checked on 2026-09-06 and 2.1.263 help on 2026-09-07. This setup is separate from a claude.ai connector. [Official Claude Code MCP documentation](https://code.claude.com/docs/en/mcp).

For a per-run connection, save an adjusted [stdio fragment](../examples/client-configs/stdio.json) in a local file and pass `--strict-mcp-config --mcp-config /absolute/path/vt-mcp.json`. This loads only the specified MCP configuration while preserving your native login. For unattended reports, `--allowedTools` accepts the four exact names `mcp__virustotal__get_file_report`, `mcp__virustotal__get_url_report`, `mcp__virustotal__get_domain_report` and `mcp__virustotal__get_ip_report` as a comma-separated list. The verified run used those grants with `--permission-mode dontAsk`, `--tools ""` and `--print --verbose --output-format stream-json`. Inspect tool results and permission denials as well as the final response. [Claude Code permissions](https://code.claude.com/docs/en/permissions).

CLI 2.1.263 completed all four production report queries through stdio using a native Claude subscription. The successful run used a terminal PTY; this observation does not establish that PTY is required. HTTP and `get_analysis` workflows remain untested for Claude Code.

## Gemini CLI

Google retired Gemini CLI access through **Sign in with Google** for Gemini Code Assist for individuals, Google AI Pro and Google AI Ultra on 2026-06-18. Use [Antigravity CLI (`agy`)](#antigravity-cli-agy) for those accounts. Standard and Enterprise are unaffected by that retirement; Gemini API-key authentication is a separate option. These remaining routes require their own account and model checks. [Official retirement notice](https://developers.google.com/gemini-code-assist/docs/deprecations/code-assist-individuals), [Gemini authentication](https://geminicli.com/docs/get-started/authentication/).

```bash
gemini mcp add --env VTAI_TOKEN_FILE="$HOME/.config/vt-mcp/token" \
  --scope user --transport stdio virustotal vt-mcp
```

For HTTP, merge [gemini-qwen-http.json](../examples/client-configs/gemini-qwen-http.json) into `~/.gemini/settings.json` and provide `VTAI_MCP_TOKEN` when launching Gemini. `httpUrl` selects Streamable HTTP; `url` denotes older SSE.

Restart and inspect `/mcp` or `gemini mcp list`. Remove with `gemini mcp remove --scope user virustotal`. Workspace trust can affect connection. Explicitly declare the stdio `env` entry: Gemini filters inherited sensitive names, including TOKEN. CLI 0.38.1 help and its installed environment resolver were checked on 2026-09-06; that is not an HTTP tool-call test. [Official Gemini MCP documentation](https://geminicli.com/docs/tools/mcp-server/).

## Antigravity CLI (`agy`)

Use your native Antigravity login, then install the verified vt-mcp wheel and configure its credential-file path:

```bash
agy mcp add --env VTAI_TOKEN_FILE="$HOME/.config/vt-mcp/token" virustotal vt-mcp
```

Flags must precede the server name. Use an absolute executable path if needed. CLI 1.1.27 saved this entry in `~/.gemini/config/mcp_config.json`; its fields match [stdio.json](../examples/client-configs/stdio.json). Restart `agy` and inspect `/mcp`. Remove it with `agy mcp remove virustotal`. The native model login is separate from VTAI access; this setup does not require Vertex or ADC. [Official MCP documentation](https://antigravity.google/docs/cli/mcp/).

Interactive sessions can ask permission for each tool. For unattended report queries, merge these specific rules into `permissions.allow` in `~/.gemini/antigravity-cli/settings.json`, preserving existing settings:

```json
{
  "permissions": {
    "allow": [
      "mcp(virustotal/get_file_report)",
      "mcp(virustotal/get_url_report)",
      "mcp(virustotal/get_domain_report)",
      "mcp(virustotal/get_ip_report)"
    ]
  }
}
```

Existing deny or ask rules take precedence over allow rules. Select a model available to your account with `agy models`; `agy -p 'Query the existing VirusTotal report for example.com and show its source, analysis date and coverage.'` runs a single prompt. A successful process exit alone does not prove that a tool ran: check the returned report or `--output-format stream-json` events. [Permissions](https://antigravity.google/docs/cli/permissions/), [headless execution](https://antigravity.google/docs/cli/headless/).

CLI 1.1.27 completed the four production report lookups through stdio with its native login, as recorded below. HTTP and analysis workflows remain untested for this client. Safe header environment expansion was not established, so use the token-file stdio setup.

## Antigravity IDE

Open **MCP Servers → Manage MCP Servers → View raw config** in the agent panel and merge [stdio.json](../examples/client-configs/stdio.json). Use an absolute executable path if needed, then reload and inspect the manager. Remove the entry or set `disabled: true` to disconnect.

The tested IDE is `1.20.6`; its CLI/base reports `1.107.0`, commit `135ccf460c67c4b900dc10aa71c978f27d78601c`, x64. Its bundled schema accepts `command`, `args`, `env`, `serverUrl`, `headers`, `disabled` and `disabledTools`. Current online documentation includes newer paths and fields rejected by that installed schema. Use **View raw config** to locate the file; do not apply the Gemini CLI path by analogy.

Safe HTTP-header environment expansion was not established for this version. Use stdio with a token file. The real stdio report workflow is recorded in the validation table below. [Official Antigravity MCP documentation](https://antigravity.google/docs/mcp).

If discovery succeeds but lookups return `unavailable`, check the MCP process's HTTPS configuration. In the tested Linux environment, Antigravity supplied an incomplete `SSL_CERT_FILE` bundle. Setting `SSL_CERT_FILE` to `/etc/ssl/certs/ca-certificates.crt` in this server's `env` and reloading resolved certificate verification errors. Use the trusted CA bundle appropriate to your machine; this Linux path is not portable. TLS verification remained enabled and proxy settings were preserved.

## Qwen Code

Proposed command, documented but not executed here:

```bash
qwen mcp add --env VTAI_TOKEN_FILE="$HOME/.config/vt-mcp/token" \
  --scope user --transport stdio virustotal vt-mcp
```

The [stdio fragment](../examples/client-configs/stdio.json) fits `mcpServers` in `~/.qwen/settings.json`. For HTTP, use [gemini-qwen-http.json](../examples/client-configs/gemini-qwen-http.json) with the host environment variable. Inspect `/mcp` or `qwen mcp list`; remove with `qwen mcp remove virustotal`.

Qwen was not installed. Field types and the recursive environment resolver were inspected at source commit `42481176c5e3c49911d4cc07a6d1e569312d0cf7`. Its published settings schema is permissive inside `mcpServers`; acceptance alone does not validate those fields. Parser, connection and model workflow remain pending. [Official Qwen MCP documentation](https://qwenlm.github.io/qwen-code-docs/en/users/features/mcp/).

## Kimi Code CLI

Proposed command, documented but not executed here:

```bash
kimi mcp add --env VTAI_TOKEN_FILE="$HOME/.config/vt-mcp/token" \
  --transport stdio virustotal -- vt-mcp
```

Alternatively merge [stdio.json](../examples/client-configs/stdio.json) into `~/.kimi/mcp.json`. Inspect `/mcp` or `kimi mcp test virustotal`; remove with `kimi mcp remove virustotal`. `--mcp-config-file` can load a separate configuration file.

Kimi was not installed. Source commit `86f136422a0aae6b217ea49e7ea1d2e8a1defcd2` declares Kimi 1.50.0 and FastMCP 3.2.4. Its loader/field definitions were inspected; safe environment expansion in HTTP headers was not established. Use stdio rather than another client's interpolation syntax. [Official Kimi MCP documentation](https://github.com/MoonshotAI/kimi-cli/blob/86f136422a0aae6b217ea49e7ea1d2e8a1defcd2/docs/en/customization/mcp.md).

## OpenCode and model providers

For OpenCode **V1**, merge [opencode-v1-stdio.json](../examples/client-configs/opencode-v1-stdio.json) or [opencode-v1-http.json](../examples/client-configs/opencode-v1-http.json) into `~/.config/opencode/opencode.json`. HTTP uses `{env:VTAI_MCP_TOKEN}` and disables OAuth auto-detection. Inspect `opencode mcp list`; remove the entry or set `enabled: false`, then restart.

OpenCode was not installed. On 2026-09-06, its [public schema](https://opencode.ai/config.json) accepted the V1 fragments but rejected the different nesting in its [V2 documentation](https://opencode.ai/v2/docs/mcp-servers). V2 remains pending a pinned binary/parser test. [Official V1 MCP documentation](https://opencode.ai/docs/mcp-servers/).

Applications using **Z.ai or DeepSeek** can reuse these MCP settings. Configure the model provider separately in OpenCode's credential interface. Z.ai documents `opencode auth login` with Z.AI or Z.AI Coding Plan, then `/models`. OpenCode documents `/connect` for DeepSeek and `/models` for model selection. Enter provider keys in that credential interface, never VTAI settings or chat. Neither provider flow was exercised here. [Z.ai with OpenCode](https://docs.z.ai/devpack/tool/opencode), [OpenCode DeepSeek setup](https://opencode.ai/docs/providers/#deepseek).

These are application integrations, not claims that Z.ai/DeepSeek chat websites directly accept this MCP. No provider-specific server or SDK is required.

## ChatGPT and Claude hosted connectors

Current OpenAI documentation says ChatGPT Desktop's local Codex host can share configuration with CLI/IDE; a CLI test does not prove Desktop behavior. ChatGPT web does not load local Codex configuration. Its MCP testing guide requires an account/workspace permitting Developer mode, a reachable endpoint and the appropriate authentication flow. The retrieved guide does not establish a subscription tier that guarantees that permission. [OpenAI MCP surfaces](https://learn.chatgpt.com/docs/extend/mcp), [connection testing](https://developers.openai.com/plugins/deploy/connect-chatgpt).

OpenAI documents OAuth 2.1 for authenticated hosted MCP. VTAI's static `x-apikey` credential does not implement it. ChatGPT web acceptance remains pending maintained OAuth integration and an actual account test. Do not put the VTAI credential in an OAuth field or disable VTAI access controls. [OpenAI authentication requirements](https://developers.openai.com/plugins/build/auth).

Claude remote connectors are separate from Claude Code and local Claude Desktop MCP. Documented remote plans include Free, Pro, Max, Team and Enterprise; Free has one custom connector, and Team/Enterprise require an Owner to add one. Requests originate from Anthropic infrastructure even when using Desktop. Account permissions and connectivity still need testing. [Claude remote connector requirements](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp).

Claude's fixed-header organization beta shares a credential across the organization. It does not meet this product's individual VTAI identity/quota model. Hosted Claude therefore remains pending individual OAuth integration and account validation. An OAuth client secret is not universally required. [Claude authentication](https://claude.com/docs/connectors/building/authentication), [request-header beta](https://claude.com/docs/connectors/custom/remote-mcp#authenticating-with-request-headers).

## Try the tools

Ask your client to query an existing report for `example.com`, `https://example.com/`, or an IP you are authorized to disclose. For file regression, use the SHA-256 of the empty file: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Ask for the source, analysis date and coverage, with missing data stated explicitly. A 404 is a valid unknown result. These queries never start a scan. A URL query discloses the complete URL to VTAI and VirusTotal; use domain scope when sufficient. Removing a client configuration does not revoke the VTAI credential.

## Connection problems

| Observation | Action |
|---|---|
| `/mcp` or `/connect/mcp` is unavailable | Check deployment availability and the exact service URL/prefix; do not treat this as an unknown indicator |
| 401 | Check that the configured environment supplies the VTAI header without displaying its value |
| 403 | The credential was not accepted; check expiry/revocation and reuse valid access instead of registering automatically |
| 429 | Wait for the supplied retry delay; REST and MCP share the agent's query quota |
| Tool error or timeout | Read the structured error without exposing credentials; a service failure is not a safety verdict |

The optional check on [the connection page](https://ai.virustotal.com/connect/mcp) consumes query quota and checks the VTAI report endpoint, not your model's use of MCP. Confirm tool discovery and one explicit call in the client separately. For stdio startup failures, inspect PATH and stderr; stdout belongs to MCP.

Use the connection page to revoke the credential when required. Only HTTP 204 confirms revocation; clearing the page or deleting client settings does not. Revocation disables that credential across REST and MCP, while an already admitted request may finish. Keep a protected copy while the revocation outcome is unconfirmed.

## Validation levels

Evidence reviewed through 2026-09-07 (UTC). Configuration parsing, MCP discovery, an actual tool call and a model-assisted workflow are separate observations. The generic Python SDK test is not evidence of a Claude or Gemini model workflow.

Client checks identify the artifact and date tested. Checks for earlier
versions describe private development, not installation from this public
repository. Each public release requires its own verified CI run and checksums.

| Client | Version | Transport | Configuration | Discovery / tool calls | Model workflow |
|---|---|---|---|---|---|
| Codex CLI | 0.153.4 | stdio | v0.2.0 CI wheel installed in a clean environment; token file configured | All four v0.2.0 tools called once against production VTAI | Validated with gpt-6-astra / xhigh; four existing reports found |
| Codex CLI | 0.153.4 | Production HTTP, `x-apikey` from environment | Direct public endpoint; no local vt-mcp process or Host override | Four calls once each; all found; wire protocol not captured | Validated with gpt-6-astra / xhigh; production source, date and coverage preserved |
| Codex CLI | 0.153.4 | Production HTTP, selected analysis | Direct public endpoint; credential supplied outside model context | One `get_analysis` call completed with the selected ID/SHA and 75 engines; no other calls | gpt-6-astra / xhigh requested; separate session, no new submission |
| Codex CLI | 0.153.4 | Local fixture HTTP | Isolated configuration exercised; local schema checked | Four synthetic calls once each; wire protocol 2025-06-18 | Earlier gpt-6-astra / xhigh fixture workflow; distinct from production |
| Claude Code | 2.1.257 | stdio | Add command executed and saved configuration inspected | Health check connected using synthetic credential; tool calls pending | Pending |
| Claude Code | 2.1.263 | stdio | Public v0.7.0 wheel; per-run token-file configuration; native subscription in a PTY | Five tools discovered; four report calls once each returned found; protocol 2025-11-25 | Validated report lookups; claude-opus-5 reported in assistant messages |
| Gemini CLI | 0.38.1 | stdio | Add command executed and saved configuration inspected | Health check connected in a trusted temporary folder using synthetic credential; tool calls pending | Pending |
| Claude Code | 2.1.257 | HTTP | Documented header expansion | Pending | Pending |
| Gemini CLI | 0.38.1 | HTTP | Installed pure resolver checked; client loading/network untested | Pending | Pending |
| Antigravity IDE | IDE 1.20.6 / CLI 1.107.0 / commit 135ccf4 | stdio | Public v0.7.0 wheel; token file and trusted system CA bundle | Five tools discovered; four report calls once each returned found; protocol 2025-06-18 | Validated report lookups; Gemini 3.6 Flash (High) shown in the UI |
| Antigravity CLI (`agy`) | 1.1.27 | stdio | Public v0.7.0 wheel; token file; native login and four specific MCP permissions | Five tools discovered; four report calls once each returned found; wire version not captured | Validated report lookups; gemini-3.8-flash-high selected and reported in the client init event |
| Qwen Code | Not installed; source 4248117 | stdio / proposed HTTP | Documentation/types/resolver inspected; schema limited | Pending | Pending |
| Kimi Code CLI | Not installed; source 1.50.0 / 86f1364 | stdio | Documentation/loader inspected | Pending | Pending |
| OpenCode V1 | Not installed | stdio / proposed HTTP | Public schema checked | Pending | Pending |
| OpenCode + Z.ai | Client/account untested | Proposed stdio / HTTP | Same MCP fragment; provider setup documented | Pending | Pending |
| OpenCode + DeepSeek | Client/account untested | Proposed stdio / HTTP | Same MCP fragment; provider setup documented | Pending | Pending |
| ChatGPT / Claude hosted | Account/interface untested | Individual OAuth pending | Requirements reviewed | Pending | Pending |
| Python MCP SDK | 2.1.1 | stdio | Executable and token file exercised | Four tools discovered and called against synthetic HTTP backend | No model used |

Earlier Claude and Gemini configuration checks used isolated client configuration directories and a synthetic token file; the VTAI base URL pointed to loopback. They did not query production or invoke a model. A listed example or handshake alone is not a claim of full host support. The service and workflow table below records the observed scope; no external catalog publication is claimed.

The Antigravity production run on 2026-09-07, 10:12:15–10:12:18 UTC, used the public v0.7.0 wheel (SHA256 `3e17703f2bdabbcc8db9708dee31ff7a89465365432878797385d04c419574c5`) and a dedicated test credential. A transparent stdio recorder captured the native client's five-tool discovery and exactly one call each for the empty-file hash, `https://example.com/`, `example.com` and `1.1.1.1`. All four returned `found`, with source, analysis date and coverage of 75/91/90/90 engine entries. Coverage includes incomplete outcomes and does not establish safety. The first four-call attempt returned `unavailable` because of the environment's certificate configuration; it remains recorded separately from the successful repeat after the CA adjustment. The UI showed Gemini 3.6 Flash (High); the provider's internal model identifier was not captured. The final answer preserved the report metadata and safety limitation. The temporary client configuration was removed and the test credential revoked after the run. There was no `get_analysis` call or submission. This evidence covers stdio report lookups, not Antigravity HTTP or analysis workflows.

Antigravity CLI 1.1.27 completed a separate production session on 2026-09-07, 18:11:13–18:11:43 UTC, using the same public v0.7.0 wheel. Client events and the transparent stdio trace show exactly four report calls, no other tool calls and four `found` results. The final response preserved source, analysis dates, engine coverage of 75/90/89/89 and category counts from `data.last_analysis_stats`, with the safety limitation. The model selection was `gemini-3.8-flash-high`; the provider's internal identifier and negotiated wire version were not captured. The native environment worked without a CA override. Temporary MCP configuration and permissions were removed, and the dedicated test credential was revoked. There was no analysis call or submission; this is separate evidence from the IDE run.

Earlier real-client attempts on 2026-09-07 did not establish Gemini CLI or Claude Code model workflows: Vertex authentication could not load ADC, and Claude Code returned an expired-OAuth error. The subsequent individual-account Gemini sign-in failure matches Google's retirement notice above; use `agy` for that account route. Historical configuration/discovery checks remain recorded at their tested versions. The later Claude Code stdio session below establishes the native report workflow; the earlier authentication failures are retained separately and do not establish MCP incompatibility.

Claude Code 2.1.263 completed a separate production session on 2026-09-07, 20:24:06–20:24:34 UTC, with the public v0.7.0 wheel and its native subscription login. The client reported `claude-opus-5[1m]` at initialization and `claude-opus-5` in assistant messages; usage also included an auxiliary Haiku model. A per-run configuration and four specific tool grants produced five-tool discovery, protocol `2025-11-25` and exactly four report calls, all `found`, with no other tool calls or permission denials. The final table preserved source, dates, engine coverage of 75/90/89/89 and category counts, and stated the safety limitation. It abbreviated the file hash for presentation; the complete expected hash is retained in the actual call. The temporary configuration was removed and the dedicated credential revoked after the run. No file was submitted and `get_analysis` was not called. The run used a PTY without a CA override; the cause of the earlier OAuth errors in pipe-based attempts was not established.

The earlier remote Codex fixture used a loopback VTAI deployment with synthetic identity storage and VirusTotal responses. The client did not launch vt-mcp. All four calls completed and the server closed its resources. Its host variable was named `VTAI_TOKEN`; the example above uses `VTAI_MCP_TOKEN` with the same header mapping. This fixture evidence remains separate from the production observation below and release installation.

The production HTTP run on 2026-09-06 at 23:56 UTC used the exact public URL above and the existing VTAI identity. Codex called the empty-file hash, `https://example.com/`, `example.com` and `1.1.1.1` sequentially, once each. All four returned `found`; the final answer retained their source, actual analysis dates and engine coverage. An independent offline review of the captured events confirmed the four completed calls, no other tools and no repeated tool calls. The runner confirmed the credential was absent from its captured output. No identity was registered or file submitted. The negotiated wire version and internal transport retries were not captured; this evidence does not certify other clients, complete rollout observation or a local package installation.

A separate public HTTP session on 2026-09-07, 01:56:48–01:57:11 UTC, used Codex CLI 0.153.4 with gpt-6-astra / xhigh requested. An independent event review confirmed exactly one `get_analysis` call for the account’s existing 383-byte public-file submission: `completed`, the same registered ID and SHA-256, and 75 engines (60 `undetected`, 14 `type-unsupported`, 1 `failure`). The tool response matched the selected REST analysis except for `retrieved_at`. There was no new submission or other tool call, Host override or local MCP server. The negotiated wire version and internal HTTP retries were not captured. This establishes that selected-analysis read over public HTTP, not analysis through stdio, other models/clients, completion of rollout observation or a safety verdict.

ChatGPT and Claude hosted connectors, OAuth and external catalogs are not validated or provided by these instructions. Claude Code and Gemini HTTP fragments are provided at the documented configuration level only; their HTTP calls and model workflows remain pending.

The v0.2.0 Codex acceptance used the exact reviewed CI wheel, SHA256 `900daff24717b19f4a92b53d7e31429a552b6ddeccce03db63b35ee034de5ac5`. Codex queried the empty-file SHA256, `https://example.com/`, `example.com` and `1.1.1.1`, in that order, once each. All returned existing VirusTotal reports through VTAI; source, actual date and engine coverage were preserved. The client used its normal existing login and no other tools. No actor was registered and nothing was submitted. This records the historical private CI candidate’s production model workflow; it does not verify installation of a release from this public repository.

## Optional Codex execution control

The optional local `vt-mcp guard` hook is separate from the MCP connection above. It
recognizes only `/usr/bin/python3 -I /absolute/path/script.py` under its documented
grammar, with Linux sealed-data support, a pinned policy and normal hook trust.
It does not add a sixth MCP tool or rely on a model choosing to query MCP.

| Guard evidence | Observed scope | Limits |
|---|---|---|
| Codex CLI 0.153.4 / gpt-6-astra xhigh, earlier local guard wheel | 20 accepted cases with normal UI trust, control/observe, source replacement, disabled and modified hooks | Harmless scripts and loopback VTAI fixture; no real VirusTotal lookup or restrictive-sandbox validation |
| Same Codex host, corrected e76 CI wheel | Two real control cases: qualified copy executes; synthetic suspicious result blocks | Runner Python 3.14.7; fixed script interpreter Python 3.12.3; earlier 20 cases were not repeated |

Both used the available `danger-full-access` test profile. That observation is
not a setup recommendation or validation of a restrictive sandbox. The
[control guide](control.md#observed-host-evidence) identifies the exact earlier
artifacts and limits. Verify the installed artifact and normal hook trust; these
earlier checks do not validate every later build. Other hosts and command forms
are not covered.

## Distribution and browser acceptance

| Surface | Observed scope | Limit |
|---|---|---|
| `/connect/mcp` in Chrome 146 | Real registration, download request, diagnosis and revocation through a route pinned to the production candidate; revoked access rejected | Separate from an ordinary public-browser journey and installation of the final package |
| Staging service and connection page | Existing MCP/browser checks with test identities and real read-only reports; rollback and denial checks | No new staging run is claimed by these instructions |
| Other listed clients | Individual schema, documentation or synthetic-health levels above | Actual report calls and model workflows where marked pending |

A browser download request is not proof of saved storage or permissions. Connection
checks consume query quota and exercise the report endpoint; they do not prove a
model called MCP. Registration can have succeeded after a connection failure;
only HTTP 204 confirms revocation.

## Service and workflow validation

| Surface | Observed scope | Limits and required verification |
|---|---|---|
| Report-only Codex stdio | Four real production queries using the exact 0.2 CI wheel | Does not establish installation of 0.7 or a model workflow using the fifth tool |
| Report-only Codex remote HTTP | Four production queries directly at the public endpoint; source, dates and coverage preserved | Negotiated wire version and internal transport retries were not captured; other clients retain their own levels |
| Selected analysis through Codex public HTTP | One separate model-assisted read of the existing public-file analysis: completed, same ID/SHA and 75 engines | No new upload, stdio-analysis validation, broader client/model support or completed rollout observation is inferred |
| Selected analysis on the VTAI staging candidate | An already-submitted analysis was recovered through CLI, REST and MCP without repeating submission | Recovery is not a new upload and does not establish a production or fifth-tool workflow with a model |
| Codex guard | Earlier local 20-case host matrix and two corrected 0.6 CI-wheel cases, as described above | Check the installed artifact and its release provenance; no broader commands, hosts or restrictive-sandbox claim |
| Public-fixture CI pilot | Eight synthetic policy cases in actual GitHub Actions, with publication-marker checks | Each release requires both live gates with the stable credential and successful evidence retention; the product itself is not scanned |
| Versioned release and source | Workflow verifies tag, same-commit main CI and exact distribution checksums | Verify the selected run, tag, retained fixture evidence and downloaded artifacts; package publication does not configure another repository’s credentials or protections |

These are separate observations. A passing synthetic workflow is not live
VirusTotal analysis, a report lookup does not upload a file, and a recovered
analysis does not establish a new submission. See [analysis](analysis.md),
[control](control.md) and [CI pilot](ci-pilot.md) for their individual contracts.
