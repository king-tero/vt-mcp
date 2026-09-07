# Native client validation — 7 September 2026

The following sessions exercised the production VTAI service with native client
logins. Each session called `get_file_report`, `get_url_report`,
`get_domain_report`, `get_ip_report` and `get_analysis` once, in that order.
The four reports returned `found`; the selected analysis returned `completed`.
There were **25 MCP tool calls across five sessions**.

| Client | Version | Transport | Session, UTC | Result |
|---|---|---|---|---|
| Antigravity CLI (`agy`) | 1.1.27 | stdio | 21:35:09–21:36:31 | Five successful MCP calls; one additional read of the client's generated analysis-output file |
| Claude Code | 2.1.263 | stdio | 21:38:47–21:39:27 | Five successful MCP calls; no other tool calls |
| Claude Code | 2.1.263 | Public HTTP | 21:35:58–21:36:41 | Five successful MCP calls; no other tool calls |
| Codex CLI | 0.153.4 | stdio | 21:38:52–21:40:05 | Five successful MCP calls; no other tool calls |
| Codex CLI | 0.153.4 | Public HTTP | 21:40:22–21:41:25 | Five successful MCP calls; no other tool calls |

## Inputs and analysis identity

The report inputs were the empty-file SHA-256
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`,
`https://example.com/`, `example.com` and `1.1.1.1`. Their engine coverage was
75, 90, 89 and 89. Report dates can change between sessions; the captured
responses and final answers were compared within each session.

The coordinator submitted **one 330-byte harmless text fixture created expressly
for public standard scanning**, using the released CLI's explicit consent and
expected-SHA controls. After it completed, all five sessions read that same
registered analysis using the same dedicated VTAI identity. The models did not
submit files. The selected analysis retained its ID, SHA-256 and 75-engine result:
60 `undetected`, 14 `type-unsupported` and one `failure`. Completion and absence
of detections do not establish safety; engine coverage includes incomplete outcomes.

## Client-specific observations

- **agy:** `gemini-3.8-flash-high` was requested. The analysis output exceeded the
  client's inline-output size and was stored in a system-generated file. The
  model used `view_file` on that output to finish its answer. This was an extra
  host-tool call despite the original prompt's five-tool-only instruction; the
  evidence does not claim that prompting prevents other tools or file access.
- **Claude Code:** native subscription authentication, a per-run MCP configuration,
  five specific tool grants and disabled built-in tools were used in a PTY.
  Initialization reported `claude-opus-5[1m]`; assistant messages reported
  `claude-opus-5`. Usage also recorded an auxiliary Haiku model. This observation
  does not establish that a PTY is required.
- **Codex:** the native login was retained, with `gpt-6-astra` and `xhigh`
  requested. Per-run configuration selected only this MCP server and its five
  tools; the runs used the read-only sandbox and disabled web search.

The stdio executable's nine Python modules matched the public v0.7.0 wheel,
SHA-256 `3e17703f2bdabbcc8db9708dee31ff7a89465365432878797385d04c419574c5`.
The transparent recorder observed protocol `2025-11-25` for Claude Code and
`2025-06-18` for Codex. It did not retain agy's negotiated version. HTTP sessions
connected directly to `https://ai.virustotal.com/mcp`, using `x-apikey` from the
client process environment, without a local MCP server or proxy. Their negotiated
protocol versions and internal HTTP retries were not captured.

## agy HTTP limitation

A separate agy 1.1.27 loopback discovery test used only harmless marker values.
Headers containing `$VAR`, `${VAR}` and `${env:VAR}` arrived **literally**, without
environment expansion. It completed discovery without a model, VTAI request or
tool call. That test does not establish production HTTP tool support. Use the
protected token-file **stdio** configuration for this version; no production
HTTP workflow with safely expanded headers is claimed for agy.

## Cleanup and scope

Temporary MCP entries, permissions and processes were removed, preserving native
logins. agy's first cleanup stopped when settings bytes differed; scoped cleanup
then removed only its test entry and five rules, preserving other settings.
Byte-for-byte restoration of that first configuration is not claimed.

The dedicated VTAI credential was revoked: HTTP 204 confirmed revocation, followed
by HTTP 403 from REST and MCP. Its local credential file was removed. Captured
outputs were checked for that credential; the stable CI identity was not used.

Independent review checked the captured calls, arguments, results and final
answers. These sessions extend the [client matrix](clients.md#validation-levels);
they do not revalidate the optional execution guard, hosted ChatGPT/Claude
connectors, Antigravity IDE, other model providers or external catalogs. The
existing v0.7.0 package and production backend were unchanged.
