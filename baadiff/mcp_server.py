"""BAADIFF MCP server -- exposes baadiff_scan() as an MCP tool."""
from __future__ import annotations

import json
import sys

from baadiff.core import scan_path, score_findings


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-baadiff[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print(
            "Install the MCP extra: pip install 'cognis-baadiff[mcp]'",
            file=sys.stderr,
        )
        return 1
    app = FastMCP("baadiff")

    @app.tool()
    def baadiff_scan(target: str) -> str:
        """Scan a repo or infra manifest for HIPAA Security Rule gaps.

        Returns JSON findings as a Business Associate readiness scorecard.
        """
        if not target or not target.strip():
            return json.dumps({"error": "target path must not be empty"})
        try:
            findings = scan_path(target)
        except (FileNotFoundError, ValueError, TypeError) as exc:
            return json.dumps({"error": str(exc)})
        sc = score_findings(findings)
        return json.dumps(sc.to_dict(), indent=2)

    app.run()
    return 0
