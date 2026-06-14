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
from .core import scan_path, score_findings, badge_for


def _color(s: str, code: str, on: bool) -> str:
    return f"\033[{code}m{s}\033[0m" if on else s


def _render_table(scorecard, color: bool) -> str:
    lines = []
    sev_code = {"critical": "1;31", "high": "31", "medium": "33",
                "low": "36", "info": "32"}
    lines.append("")
    lines.append(_color("  BAADIFF -- HIPAA Security Rule Readiness",
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
    # Validate --threshold range before doing any I/O.
    if not (0 <= args.threshold <= 100):
        print(
            f"error: --threshold must be between 0 and 100, got {args.threshold}",
            file=sys.stderr,
        )
        return 2

    try:
        findings = scan_path(args.path)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except PermissionError as e:
        print(f"error: permission denied - {e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"error: could not read path - {e}", file=sys.stderr)
        return 2

    try:
        scorecard = score_findings(findings, pass_threshold=args.threshold)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.badge:
        try:
            Path(args.badge).write_text(badge_for(scorecard), encoding="utf-8")
        except OSError as e:
            print(f"error: could not write badge file - {e}", file=sys.stderr)
            return 2

    if args.format == "json":
        try:
            print(json.dumps(scorecard.to_dict(), indent=2))
        except (TypeError, ValueError) as e:
            print(f"error: failed to serialize results - {e}", file=sys.stderr)
            return 2
    else:
        use_color = sys.stdout.isatty() and not args.no_color
        print(_render_table(scorecard, use_color))

    # CI gate: non-zero when not shippable.
    return 0 if scorecard.shippable else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="BAADIFF -- scan a repo or manifest for HIPAA Security "
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
    scan.add_argument("--format", choices=("table", "json"), default="table",
                      help="output format (default: table)")
    scan.add_argument("--threshold", type=int, default=80, metavar="N",
                      help="min score (0-100) to be 'shippable' (default: 80)")
    scan.add_argument("--badge", metavar="FILE",
                      help="write a shields.io endpoint badge JSON to FILE")
    scan.add_argument("--no-color", action="store_true",
                      help="disable ANSI colors in table output")
    scan.set_defaults(func=_cmd_scan)
    return p


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except Exception as e:  # pragma: no cover -- last-resort guard
        print(f"error: unexpected failure - {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
