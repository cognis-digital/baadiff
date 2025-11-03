"""BAADIFF MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from baadiff.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-baadiff[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-baadiff[mcp]'")
        return 1
    app = FastMCP("baadiff")

    @app.tool()
    def baadiff_scan(target: str) -> str:
        """Scan a repo or infra manifest for HIPAA Security Rule gaps and produce a Business Associate readiness scorecard.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
