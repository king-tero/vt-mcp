# Client configuration fragments

These fragments configure the common VirusTotal MCP server: four report tools and, with a compatible backend, `get_analysis`. Choose **stdio or HTTP** for a client, merge the selected entry into its existing configuration, and preserve unrelated servers. Do not replace an entire settings file with a fragment.

These files are included in the `v0.7.0` source distribution and the [versioned configuration directory](https://github.com/king-tero/vt-mcp/tree/v0.7.0/examples/client-configs). The wheel does not install them as client settings. Select the configuration matching your verified release and check [client validation levels](../../docs/clients.md) before choosing a setup.

| File | Client / destination | Configuration evidence; current scope in the client matrix |
|---|---|---|
| [stdio.json](stdio.json) | Claude Code project `.mcp.json`; Gemini/Qwen `settings.json`; Antigravity IDE's **View raw config**; Antigravity CLI `~/.gemini/config/mcp_config.json`; Kimi `~/.kimi/mcp.json` | Shared field layout; Antigravity IDE and CLI stdio report workflows validated separately; Qwen/Kimi binaries untested |
| [codex-stdio.toml](codex-stdio.toml) | Codex `~/.codex/config.toml` | Official schema checked; CLI 0.153.4 syntax checked |
| [codex-http.toml](codex-http.toml) | Codex `~/.codex/config.toml` | Schema and CLI 0.153.4 checked; `env_http_headers` exercised against a local fixture and the public production endpoint |
| [claude-http.json](claude-http.json) | Claude Code project `.mcp.json` | Documented environment expansion; HTTP calls pending |
| [gemini-qwen-http.json](gemini-qwen-http.json) | Gemini `~/.gemini/settings.json`; Qwen `~/.qwen/settings.json` | Gemini 0.38.1 resolver checked; Qwen source inspected; HTTP calls pending |
| [opencode-v1-stdio.json](opencode-v1-stdio.json) | OpenCode V1 `~/.config/opencode/opencode.json` | Public schema checked; client binary untested |
| [opencode-v1-http.json](opencode-v1-http.json) | OpenCode V1 `~/.config/opencode/opencode.json` | Public schema checked; client binary untested |

For stdio, install the verified wheel first. `vt-mcp` must be on the PATH used by the host; otherwise replace it with the absolute path reported by `command -v vt-mcp`. The token path is an example. vt-mcp expands `~` itself; no shell expansion of arbitrary JSON values is assumed. Declare `VTAI_TOKEN_FILE` explicitly, especially in Gemini, which filters sensitive inherited environment names. Gemini CLI no longer serves Code Assist individual, Google AI Pro or Ultra accounts through Google login; use [Antigravity CLI (`agy`)](../../docs/clients.md#antigravity-cli-agy) for those accounts.

For HTTP, no vt-mcp or Python installation is required. VTAI authenticates only the **`x-apikey`** header. The variable `VTAI_MCP_TOKEN` contains the credential and is expanded by the host; it is not an OAuth access flow. Never replace the reference in these files with the credential itself. Load the variable outside chat using the [access guide](../../docs/access.md#remote-client-environment). Do not substitute a client's generic Bearer-token option: VTAI does not authenticate that header.

Codex has completed the four report queries and a selected-analysis read in a separate session at the configured production URL; see the [client matrix](../../docs/clients.md#validation-levels). That does not validate other hosts or a different installed artifact; see the [service and workflow table](../../docs/clients.md#service-and-workflow-validation). For an authorized test deployment, replace the URL with that deployment's exact `/mcp` URL and prefix. The REST base ending `/api/v3` is not the MCP endpoint.

OpenCode has separate [V1](https://opencode.ai/docs/mcp-servers/) and [V2](https://opencode.ai/v2/docs/mcp-servers) layouts. On 2026-09-06, the [public schema](https://opencode.ai/config.json) accepted V1 `mcp.<name>` but rejected the documented V2 `mcp.servers.<name>`. These fragments target V1 only. Pin and test a V2 binary before translating them; changing the name of this file does not establish V2 support.

No HTTP fragment is provided for Antigravity or Kimi: their reviewed configurations accept headers, but safe environment expansion of those headers was not established for the versions inspected. Use the shared stdio fragment until that path is tested. No bridge package or provider-specific MCP server is needed.
