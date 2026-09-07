"""Read an existing report through the installed vt-mcp stdio server."""

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from mcp import Client, StdioServerParameters


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=["file", "url", "domain", "ip"])
    parser.add_argument("indicator")
    parser.add_argument("--token-file", default="~/.config/vt-mcp/token")
    args = parser.parse_args()
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "vt_mcp"],
        env={
            **{
                key: os.environ[key]
                for key in ("VTAI_BASE_URL", "VTAI_TIMEOUT")
                if key in os.environ
            },
            "VTAI_TOKEN_FILE": str(Path(args.token_file).expanduser()),
        },
    )
    async with Client(parameters, read_timeout_seconds=70) as client:
        argument = "hash" if args.kind == "file" else args.kind
        result = await client.call_tool(f"get_{args.kind}_report", {argument: args.indicator})
        print(json.dumps(result.structured_content, ensure_ascii=True, indent=2))
        return int(bool(result.is_error))


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
