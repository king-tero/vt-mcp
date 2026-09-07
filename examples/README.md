# Query from a Python application

The [lookup example](lookup.py) launches `vt-mcp` as a subprocess using the official MCP Python SDK `2.1.1`. It calls the same four tools as an assistant, without a provider-specific SDK or model account.

After downloading and verifying the release wheel as described in the main README, run from the repository directory:

```bash
uv run --no-project --python 3.12 --with /absolute/path/to/vt_mcp-0.7.0-py3-none-any.whl \
  examples/lookup.py domain example.com
```

`--no-project` prevents a local development checkout from replacing the selected wheel. The example reads the credential file at `~/.config/vt-mcp/token`; `--token-file` accepts an alternative path. It prints the structured tool result and exits with status 1 when the MCP tool reports an error. Other kinds are `file`, `url` and `ip`. `VTAI_BASE_URL` and `VTAI_TIMEOUT` work as described in the main README; change the base URL only for a trusted VTAI deployment.

Only disclose indicators you are authorized to share. URL input includes its query and fragment; use `domain` when sufficient. This example retrieves existing reports and cannot initiate analyses. A result of `not_found` means unknown, not safe.
