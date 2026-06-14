"""Smoke tests for BAADIFF: import the library, scan the demo, assert behavior.

No network calls. Pure stdlib + pytest.
"""

import json
import subprocess
import sys
from pathlib import Path

import baadiff
from baadiff import core

REPO = Path(__file__).resolve().parents[1]
DEMO = REPO / "demos" / "01-basic" / "patient_service.py"


def test_exports():
    assert baadiff.TOOL_NAME == "baadiff"
    assert isinstance(baadiff.TOOL_VERSION, str) and baadiff.TOOL_VERSION
    assert callable(baadiff.scan_path)
    assert callable(baadiff.score_findings)


def test_demo_file_exists():
    assert DEMO.exists(), "demo input file missing"


def test_scan_text_detects_secret_and_http():
    text = DEMO.read_text(encoding="utf-8")
    findings = core.scan_text(text, "patient_service.py")
    ids = {f.check_id for f in findings}
    # hardcoded secret + plaintext http + verify=False + md5
    assert "BD001" in ids
    assert "BD002" in ids
    assert "BD003" in ids
    # all scan_text findings are fails
    assert all(f.status == "fail" for f in findings)


def test_scan_path_has_pass_and_fail():
    findings = core.scan_path(DEMO)
    statuses = {f.status for f in findings}
    assert "fail" in statuses
    assert "pass" in statuses  # auth/logging/sha256 markers satisfied
    # presence checks present
    ids = {f.check_id for f in findings}
    assert {"BD005", "BD006", "BD007", "BD008", "BD009"} <= ids


def test_scorecard_not_shippable_due_to_critical():
    findings = core.scan_path(DEMO)
    sc = core.score_findings(findings)
    assert sc.by_severity.get("critical", 0) >= 1
    assert sc.shippable is False
    assert 0 <= sc.score < 80
    assert sc.grade in {"A", "B", "C", "D", "F"}
    assert sc.failed > 0 and sc.passed > 0
    assert sc.total_checks == len({c["id"] for c in core.CHECKS})


def test_badge_is_valid_json():
    findings = core.scan_path(DEMO)
    sc = core.score_findings(findings)
    badge = json.loads(core.badge_for(sc))
    assert badge["label"] == "HIPAA readiness"
    assert str(sc.score) in badge["message"]
    assert badge["color"] in {"brightgreen", "green", "yellow", "orange", "red"}


def test_clean_text_scores_higher_and_can_ship(tmp_path):
    clean = tmp_path / "clean_service.py"
    clean.write_text(
        "import os, hashlib, logging\n"
        "log = logging.getLogger('svc')\n"
        "DB_PASSWORD = os.environ['DB_PASSWORD']  # managed secret\n"
        "API = 'https://api.example.com'\n"
        "# encryption at rest: storage_encrypted = true\n"
        "storage_encrypted = True\n"
        "# backup snapshot enabled\n"
        "def login_required(f):\n    return f\n"
        "def h(x):\n    return hashlib.sha256(x).hexdigest()\n"
        "def audit():\n    log.info('access')\n",
        encoding="utf-8",
    )
    sc = core.score_findings(core.scan_path(clean))
    assert sc.by_severity.get("critical", 0) == 0
    assert sc.score >= 80
    assert sc.shippable is True


def test_cli_json_and_exit_code():
    proc = subprocess.run(
        [sys.executable, "-m", "baadiff", "scan", str(DEMO), "--format", "json"],
        cwd=str(REPO), capture_output=True, text=True,
    )
    # not shippable -> exit 1 (CI gate)
    assert proc.returncode == 1
    data = json.loads(proc.stdout)
    assert data["shippable"] is False
    assert "findings" in data and len(data["findings"]) > 0


def test_cli_version():
    proc = subprocess.run(
        [sys.executable, "-m", "baadiff", "--version"],
        cwd=str(REPO), capture_output=True, text=True,
    )
    assert proc.returncode == 0
    assert baadiff.TOOL_VERSION in proc.stdout


# ---------------------------------------------------------------------------
# Hardening tests: error paths, edge cases, and input validation
# ---------------------------------------------------------------------------

def test_scan_path_missing_file():
    """scan_path raises FileNotFoundError for a non-existent path."""
    with __import__("pytest").raises(FileNotFoundError, match="path not found"):
        core.scan_path("/nonexistent/path/does_not_exist_xyz")


def test_scan_path_missing_file_cli_exit2():
    """CLI returns exit code 2 with an error message for a missing path."""
    proc = subprocess.run(
        [sys.executable, "-m", "baadiff", "scan", "/no/such/path/xyz"],
        cwd=str(REPO), capture_output=True, text=True,
    )
    assert proc.returncode == 2
    assert "error" in proc.stderr.lower()


def test_cli_threshold_out_of_range():
    """--threshold outside 0-100 returns exit code 2 with an error."""
    for bad in ["-1", "101", "200"]:
        proc = subprocess.run(
            [sys.executable, "-m", "baadiff", "scan", str(DEMO),
             "--threshold", bad],
            cwd=str(REPO), capture_output=True, text=True,
        )
        assert proc.returncode == 2, f"expected 2 for threshold={bad}"
        assert "error" in proc.stderr.lower()


def test_score_findings_empty_list():
    """score_findings on an empty list returns a valid all-pass scorecard."""
    sc = core.score_findings([])
    assert sc.score == 100
    assert sc.failed == 0
    assert sc.passed == 0
    assert sc.grade == "A"


def test_score_findings_invalid_threshold():
    """score_findings raises ValueError for an out-of-range pass_threshold."""
    import pytest
    with pytest.raises(ValueError, match="pass_threshold"):
        core.score_findings([], pass_threshold=150)
    with pytest.raises(ValueError, match="pass_threshold"):
        core.score_findings([], pass_threshold=-5)


def test_scan_text_none_raises():
    """scan_text with None raises TypeError."""
    import pytest
    with pytest.raises(TypeError, match="scan_text"):
        core.scan_text(None)


def test_scan_path_empty_directory(tmp_path):
    """scan_path on an empty directory returns presence-only findings (no crash)."""
    sc = core.score_findings(core.scan_path(tmp_path))
    # Empty dir has no evidence of any control — all presence checks fail.
    assert sc.failed > 0
    assert sc.passed == 0
    # Score is well-defined and in range.
    assert 0 <= sc.score <= 100


def test_badge_unreadable_path_cli_exit2(tmp_path):
    """Writing badge to an unwritable path returns exit code 2."""
    # Create a directory where the badge file should be — writing to it fails.
    bad_badge = tmp_path / "subdir_not_file"
    bad_badge.mkdir()
    proc = subprocess.run(
        [sys.executable, "-m", "baadiff", "scan", str(DEMO),
         "--badge", str(bad_badge)],
        cwd=str(REPO), capture_output=True, text=True,
    )
    assert proc.returncode == 2
    assert "error" in proc.stderr.lower()
