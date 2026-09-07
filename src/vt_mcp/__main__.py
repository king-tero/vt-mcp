"""Run the local MCP server. stdout is reserved for the MCP protocol."""

import argparse
import sys

from vt_mcp import __version__
from vt_mcp.vtai_client import ConfigurationError, Settings


def main() -> None:
    if sys.argv[1:2] and sys.argv[1] in {"submit", "submission", "analysis"}:
        from vt_mcp.submission_cli import main as analysis_main

        raise SystemExit(analysis_main(sys.argv[1:]))
    if sys.argv[1:2] == ["guard"]:
        from vt_mcp.guard import main as guard_main

        raise SystemExit(guard_main(sys.argv[2:]))
    from vt_mcp.server import create_server

    parser = argparse.ArgumentParser(
        description="VirusTotal MCP server over stdio (powered by VTAI)"
    )
    parser.add_argument("--version", action="version", version=f"vt-mcp {__version__}")
    parser.parse_args()
    try:
        settings = Settings.from_env()
    except ConfigurationError as exc:
        print(f"vt-mcp: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    create_server(settings).run(transport="stdio")


if __name__ == "__main__":
    main()
