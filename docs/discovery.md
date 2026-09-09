# Find and connect to VirusTotal MCP

The public source and installation releases remain available at
[king-tero/vt-mcp](https://github.com/king-tero/vt-mcp). The active Registry entry
is now `io.github.VirusTotal/virustotal-mcp`. Endpoint-based configurations keep
the same URL and credential settings.
Start with the setup for [Antigravity CLI (`agy`)](clients.md#antigravity-cli-agy),
[Claude Code](clients.md#claude-code), or [Codex](clients.md#codex-cli--remote-http).

## MCP Registry

The active entry is
[`io.github.VirusTotal/virustotal-mcp` version 0.8.2](https://registry.modelcontextprotocol.io/v0.1/servers/io.github.VirusTotal%2Fvirustotal-mcp/versions/0.8.2),
published on 9 September 2026. It describes the existing Streamable HTTP endpoint
at `https://ai.virustotal.com/mcp` and links to
[free VTAI registration](https://ai.virustotal.com/connect/mcp). The corporate
source remains private; this remote-only entry does not advertise a private
repository URL or require a PyPI package.

The previous [`io.github.king-tero/vt-mcp` 0.8.0 entry](https://registry.modelcontextprotocol.io/v0.1/servers/io.github.king-tero%2Fvt-mcp/versions/0.8.0?include_deleted=true)
is retired with a message pointing to the corporate name. Its original manifest
is retained in [`server.json`](../server.json) for recovery, and remains readable
in the Registry with `include_deleted=true`. Select the corporate name when
connecting through a Registry catalogue.

The manifest requests one secret VTAI token and constructs `Authorization: Bearer`
for the client. Use the host's protected credential settings; no token belongs in
the manifest, chat, source control or a shared installation URL. The alternative
`x-apikey` configuration remains documented in the [access guide](access.md).
Send only one authentication header. This is static token authentication, not OAuth.

The entry describes seven remote tools, including file submission and recovery.
The eighth tool, `submit_local_file`, requires the local stdio package. Registry
discovery does not establish support in every client, approval by a model provider,
or a connection to hosted ChatGPT/Claude. Consult the [client evidence](clients.md).

The corporate Registry version **0.8.2** identifies the licensing and packaging
revision that preserves the tool interface introduced in 0.8.0. Backend VTAI
0.8.1 supplies the Bearer alternative. The verified
[MIT v0.8.0 GitHub release](https://github.com/king-tero/vt-mcp/releases/tag/v0.8.0)
remains the public local-installation channel; its bytes and license are unchanged.

### Maintaining the entry

The `MCP Registry` workflow validates metadata on pull requests and main. After
independent review, merge the change and wait for that exact main commit's CI to
succeed. Dispatch the workflow on main with its full SHA in `reviewed_sha`.
GitHub repository ID, owner and namespace are checked before using the publisher
fixed by version and SHA-256. No permanent Registry secret or VTAI token is needed.

- `verify-identity`, the default, checks the ephemeral GitHub Actions OIDC identity
  and current entries without changing their state.
- `publish` creates the exact reviewed version, or verifies an identical active
  entry. It cannot overwrite or reactivate an existing deleted version.
- `retire` marks only the reviewed version as deleted, retaining its manifest and
  a migration message in the Registry's `include_deleted=true` view.
- `restore` reactivates that same version and clears its retirement message.

Each mutating operation checks the exact entry anonymously afterwards. Deleted
entries retain their metadata; this operation does not delete GitHub source,
releases or the hosted MCP service. The workflow removes its temporary local
credential when the operation finishes.

Published versions are immutable. Check the [retained entry](https://registry.modelcontextprotocol.io/v0.1/servers/io.github.king-tero%2Fvt-mcp/versions/0.8.0?include_deleted=true)
before retrying a failed run: publication may have succeeded before a later step
failed. Update metadata with a new version; never overwrite a published release
or relabel an existing package. Package publication and backend deployment remain
separate operations.

For the corporate cutover, verify both owner identities first, retire the old
entry, then publish the corporate entry from its repository. The Registry rejects
two names with the same remote URL unless the previous entry is deleted;
deprecation does not release that URL. Catalogue replacement is not atomic, while
the existing MCP endpoint continues serving clients.

If a workflow fails or times out, read both entries with `include_deleted=true`
before taking another action: a request can succeed before its response is lost.
An exact active corporate entry establishes publication. To restore the personal
entry, first retire any corporate entry occupying the URL, then run `restore`
here. Unexpected versions or metadata require review; the workflow never mutates
all versions or retries a failed mutation automatically.

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
