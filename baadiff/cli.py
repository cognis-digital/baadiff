"""Command-line interface for BAADIFF.

Examples
--------
    # Human-readable scorecard for the current repo
    python -m baadiff scan .

    # JSON for CI pipelines (exit code is non-zero if not shippable)
    python -m baadiff scan ./service --format json > report.json

    # Emit a shields.io badge endpoint for your README
    python -m baadiff scan . --badge badge.json

    # Tighten the bar
    python -m baadiff scan . --threshold 90
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import TOOL_NAME, TOOL_VERSION
from .core import scan_path, score_findings, badge_for, to_sarif, SEVERITY_ORDER


def _color(s: str, code: str, on: bool) -> str:
    return f"\033[{code}m{s}\033[0m" if on else s


def _render_table(scorecard, color: bool) -> str:
    lines = []
    sev_code = {"critical": "1;31", "high": "31", "medium": "33",
                "low": "36", "info": "32"}
    lines.append("")
    lines.append(_color("  BAADIFF — HIPAA Security Rule Readiness",
                        "1;37", color))
    lines.append("  " + "-" * 56)

    fails = [f for f in scorecard.findings if f.status == "fail"]
    passes = [f for f in scorecard.findings if f.status == "pass"]

    if fails:
        lines.append("  GAPS:")
        for f in fails:
            tag = _color(f.severity.upper().ljust(8),
                         sev_code.get(f.severity, "0"), color)
            loc = f"{f.file}:{f.line}" if f.file else "(corpus)"
            lines.append(f"   {tag} [{f.check_id} {f.safeguard}] {loc}")
            lines.append(f"            {f.message}")
    else:
        lines.append("  GAPS: none \U0001f389")

    if passes:
        lines.append("")
        lines.append("  CONTROLS SATISFIED:")
        for f in passes:
            ok = _color("PASS", "32", color)
            lines.append(f"   {ok} [{f.check_id} {f.safeguard}] {f.title}")

    lines.append("  " + "-" * 56)
    grade_code = ("32" if scorecard.score >= 80 else
                  "33" if scorecard.score >= 60 else "1;31")
    lines.append("  SCORE: " + _color(
        f"{scorecard.score}/100  grade {scorecard.grade}",
        grade_code, color))
    ship = (_color("SHIPPABLE", "1;32", color) if scorecard.shippable
            else _color("NOT SHIPPABLE", "1;31", color))
    lines.append(f"  STATUS: {ship}   "
                 f"({scorecard.passed} controls, {scorecard.failed} gaps)")
    lines.append("")
    lines.append("  Note: static best-effort signal, not legal advice.")
    lines.append("")
    return "\n".join(lines)


def _cmd_scan(args) -> int:
    try:
        findings = scan_path(args.path)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    scorecard = score_findings(findings, pass_threshold=args.threshold)

    if args.badge:
        Path(args.badge).write_text(badge_for(scorecard), encoding="utf-8")
    if getattr(args, "sarif", None):
        Path(args.sarif).write_text(to_sarif(scorecard), encoding="utf-8")

    if args.format == "json":
        print(json.dumps(scorecard.to_dict(), indent=2))
    elif args.format == "sarif":
        print(to_sarif(scorecard))
    else:
        use_color = sys.stdout.isatty() and not args.no_color
        print(_render_table(scorecard, use_color))

    # CI gate: non-zero when not shippable.
    return 0 if scorecard.shippable else 1


def _cmd_mcp(args) -> int:
    """Start the MCP stdio server (requires the optional 'mcp' extra)."""
    from .mcp_server import serve
    return serve()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="BAADIFF — scan a repo or manifest for HIPAA Security "
                    "Rule gaps and produce an are-we-shippable readiness "
                    "scorecard with a badge.",
        epilog="examples:\n"
               "  baadiff scan .\n"
               "  baadiff scan ./svc --format json > report.json\n"
               "  baadiff scan . --threshold 90 --badge badge.json\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    scan = sub.add_parser(
        "scan",
        help="scan a path and emit a readiness scorecard",
        description="Scan a file or directory for HIPAA Security Rule gaps.",
    )
    scan.add_argument("path", help="file or directory to scan")
    scan.add_argument("--format", choices=("table", "json", "sarif"),
                      default="table",
                      help="output format: table|json|sarif (default: table)")
    scan.add_argument("--threshold", type=int, default=80, metavar="N",
                      help="min score (0-100) to be 'shippable' (default: 80)")
    scan.add_argument("--badge", metavar="FILE",
                      help="write a shields.io endpoint badge JSON to FILE")
    scan.add_argument("--sarif", metavar="FILE",
                      help="also write a SARIF 2.1.0 report to FILE "
                           "(GitHub code-scanning)")
    scan.add_argument("--no-color", action="store_true",
                      help="disable ANSI colors in table output")
    scan.set_defaults(func=_cmd_scan)

    mcp = sub.add_parser(
        "mcp",
        help="run the MCP stdio server (needs the 'mcp' extra)",
        description="Expose baadiff scan() as an MCP tool for AI agents.",
    )
    mcp.set_defaults(func=_cmd_mcp)
    return p


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
