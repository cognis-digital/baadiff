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
