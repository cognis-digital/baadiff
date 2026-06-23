"""CLI integration tests for BAADIFF. Subprocess + in-process. No network."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from baadiff import cli, core

REPO = Path(__file__).resolve().parents[1]
DEMO = REPO / "demos" / "01-basic" / "patient_service.py"


def run(*args, cwd=REPO):
    return subprocess.run(
        [sys.executable, "-m", "baadiff", *args],
        cwd=str(cwd), capture_output=True, text=True,
    )


def test_no_args_prints_help_rc0():
    p = run()
    assert p.returncode == 0
    assert "usage" in (p.stdout + p.stderr).lower()


def test_version_flag():
    p = run("--version")
    assert p.returncode == 0
    assert core.TOOL_VERSION in p.stdout


def test_scan_table_default():
    p = run("scan", str(DEMO), "--no-color")
    assert p.returncode == 1  # demo is not shippable
    assert "BAADIFF" in p.stdout
    assert "SCORE" in p.stdout
    assert "NOT SHIPPABLE" in p.stdout


def test_scan_json_shape():
    p = run("scan", str(DEMO), "--format", "json")
    assert p.returncode == 1
    d = json.loads(p.stdout)
    for k in ("score", "grade", "shippable", "total_checks", "failed",
              "passed", "by_severity", "findings"):
        assert k in d
    assert d["shippable"] is False
    assert len(d["findings"]) > 0


def test_scan_sarif_format():
    p = run("scan", str(DEMO), "--format", "sarif")
    d = json.loads(p.stdout)
    assert d["version"] == "2.1.0"
    assert d["runs"][0]["results"]


def test_scan_missing_path_rc2():
    p = run("scan", "/no/such/path/xyzzy")
    assert p.returncode == 2
    assert "error" in p.stderr.lower()


def test_scan_writes_badge_file(tmp_path):
    badge = tmp_path / "badge.json"
    p = run("scan", str(DEMO), "--badge", str(badge), "--no-color")
    assert badge.exists()
    b = json.loads(badge.read_text(encoding="utf-8"))
    assert b["label"] == "HIPAA readiness"


def test_scan_writes_sarif_file(tmp_path):
    out = tmp_path / "out.sarif"
    run("scan", str(DEMO), "--sarif", str(out), "--no-color")
    assert out.exists()
    assert json.loads(out.read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_threshold_makes_clean_unshippable(tmp_path):
    clean = tmp_path / "ok.py"
    clean.write_text(
        "import os, hashlib, logging\n"
        "from flask_login import login_required\n"
        "log = logging.getLogger('s')\n"
        "DB = os.environ['DB']\n"
        "API='https://x.example'\n"
        "storage_encrypted = True\n"
        "DEBUG = True            # one medium gap -> score below 100\n"
        "# backup snapshot ; audit_log ; session_timeout=900 ; retention RPO\n"
        "def h(x):\n    return hashlib.sha256(x).hexdigest()\n",
        encoding="utf-8",
    )
    lenient = run("scan", str(clean), "--threshold", "50", "--no-color")
    strict = run("scan", str(clean), "--threshold", "100", "--no-color")
    assert lenient.returncode == 0
    assert strict.returncode == 1


def test_build_parser_exposes_subcommands():
    p = cli.build_parser()
    # parse a scan invocation
    ns = p.parse_args(["scan", "."])
    assert ns.command == "scan"
    assert ns.format == "table"
    assert ns.threshold == 80


def test_main_in_process_json(capsys):
    rc = cli.main(["scan", str(DEMO), "--format", "json"])
    assert rc == 1
    out = capsys.readouterr().out
    assert json.loads(out)["shippable"] is False


def test_render_table_no_color_has_no_ansi():
    sc = core.score_findings(core.scan_path(DEMO))
    txt = cli._render_table(sc, color=False)
    assert "\033[" not in txt
    assert "GAPS" in txt


def test_render_table_color_has_ansi():
    sc = core.score_findings(core.scan_path(DEMO))
    txt = cli._render_table(sc, color=True)
    assert "\033[" in txt
