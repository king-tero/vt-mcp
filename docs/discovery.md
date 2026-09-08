# Find and connect to VirusTotal MCP

The canonical source is [king-tero/vt-mcp](https://github.com/king-tero/vt-mcp).
Start with the setup for [Antigravity CLI (`agy`)](clients.md#antigravity-cli-agy),
[Claude Code](clients.md#claude-code), or [Codex](clients.md#codex-cli--remote-http).

## MCP Registry

[`server.json`](../server.json) describes `io.github.king-tero/vt-mcp`: the existing
Streamable HTTP endpoint at `https://ai.virustotal.com/mcp`. It includes the source
repository ID and a link to [free VTAI registration](https://ai.virustotal.com/connect/mcp).

The manifest requests one secret VTAI token and constructs `Authorization: Bearer`
for the client. Use the host's protected credential settings; no token belongs in
the manifest, chat, source control or a shared installation URL. The alternative
`x-apikey` configuration remains documented in the [access guide](access.md).
Send only one authentication header. This is static token authentication, not OAuth.

The entry describes seven remote tools, including file submission and recovery.
The eighth tool, `submit_local_file`, requires the local stdio package. Registry
discovery does not establish support in every client, approval by a model provider,
or a connection to hosted ChatGPT/Claude. Consult the [client evidence](clients.md).

The registry manifest uses MCP server version **0.8.0**, matching the tool interface
and published package. Backend VTAI 0.8.1 supplies the Bearer alternative. A remote
entry needs no PyPI package; the verified [GitHub release](https://github.com/king-tero/vt-mcp/releases/tag/v0.8.0)
remains the local installation channel.

### Maintaining the entry

The `MCP Registry` workflow validates metadata on pull requests and main. After
independent review, merge the change and wait for that exact main commit's CI to
succeed. Dispatch the workflow on main with its full SHA in `reviewed_sha`. Only
the canonical repository can publish, using GitHub Actions OIDC and a publisher
binary fixed by version and SHA-256. It needs no permanent registry secret.
The final step reads the published version anonymously and checks the full manifest
and active status.

Published versions are immutable. Check the [registry API](https://registry.modelcontextprotocol.io/v0.1/servers/io.github.king-tero%2Fvt-mcp/versions/latest)
before retrying a failed run: publication may have succeeded before a later step
failed. Update metadata with a new version; never overwrite a published release
or relabel an existing package. Package publication and backend deployment remain
separate operations.

See the official [remote server format](https://modelcontextprotocol.io/registry/remote-servers)
and [GitHub Actions publication guide](https://modelcontextprotocol.io/registry/github-actions).

## Glama

[`glama.json`](../glama.json) identifies `king-tero` as the GitHub maintainer using
Glama's documented schema. The [Glama directory entry](https://glama.ai/mcp/servers/king-tero/vt-mcp)
is maintained by Glama; committing metadata does not by itself prove that its
crawler has refreshed the entry, verified ownership, or enabled managed hosting.

Use the setup links above for the working connection. Do not put a VTAI token in
a shareable inspector or installation URL. Glama's listing status is distinct
from the availability of the live MCP endpoint.
