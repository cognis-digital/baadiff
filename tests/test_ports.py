"""Cross-language parity tests for the ports.

These run a port's CLI against the same fixture the Python reference scans and
assert the shippable verdict and check coverage agree. A port is skipped if its
runtime isn't installed (CI installs Node/Go/Rust; shell uses /bin/sh).

No network. All scans hit local fixtures only.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from baadiff import core

REPO = Path(__file__).resolve().parents[1]
PORTS = REPO / "ports"


@pytest.fixture
def bad_repo(tmp_path):
    (tmp_path / "app.py").write_text(
        'DB_PASSWORD = "S3cr3tP@ssw0rd123"\n'
        "from flask_login import login_required\n",
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def clean_repo(tmp_path):
    (tmp_path / "app.py").write_text(
        "import os, hashlib, logging\n"
        "from flask_login import login_required\n"
        "log = logging.getLogger('s')\n"
        "DB = os.environ['DB']\n"
        "API = 'https://x.example'\n"
        "storage_encrypted = true\n"
        "# backup snapshot ; cloudtrail audit_log\n"
        "def h(x):\n    return hashlib.sha256(x).hexdigest()\n",
        encoding="utf-8",
    )
    return tmp_path


def _py_verdict(path):
    sc = core.score_findings(core.scan_path(path))
    return sc.shippable


# --------------------------------------------------------------------------- #
# Port source files exist and are non-trivial
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("rel", [
    "javascript/index.js", "javascript/test.js", "javascript/package.json",
    "go/main.go", "go/main_test.go", "go/go.mod",
    "rust/src/main.rs", "rust/Cargo.toml",
    "shell/baadiff.sh", "shell/test.sh",
    "README.md",
])
def test_port_file_present(rel):
    p = PORTS / rel
    assert p.exists(), f"missing {rel}"
    assert p.stat().st_size > 0


@pytest.mark.parametrize("src,needles", [
    ("javascript/index.js", ["BD001", "BD002", "BD003", "BD004", "BD007", "shippable"]),
    ("go/main.go", ["BD001", "BD002", "BD003", "BD004", "BD007", "Shippable"]),
    ("rust/src/main.rs", ["BD001", "BD002", "BD003", "BD004", "BD007", "shippable"]),
    ("shell/baadiff.sh", ["BD001", "BD002", "BD003", "BD004", "BD007", "shippable"]),
])
def test_port_implements_core_checks(src, needles):
    text = (PORTS / src).read_text(encoding="utf-8")
    for n in needles:
        assert n in text, f"{src} missing {n}"


def test_all_ports_are_offline():
    # No port should open a socket / fetch a URL — guard against regressions.
    banned = ["http.get(", "fetch(", "net.Dial", "reqwest", "urllib.request",
              "requests.get", "curl http", "wget "]
    for src in ("javascript/index.js", "go/main.go", "rust/src/main.rs",
                "shell/baadiff.sh"):
        text = (PORTS / src).read_text(encoding="utf-8")
        for b in banned:
            assert b not in text, f"{src} contains network call {b!r}"


# --------------------------------------------------------------------------- #
# JS port parity (Node available in CI)
# --------------------------------------------------------------------------- #

NODE = shutil.which("node")
SH = shutil.which("sh") or shutil.which("bash")


def _run(cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


@pytest.mark.skipif(not NODE, reason="node not installed")
def test_js_port_bad_repo_not_shippable(bad_repo):
    p = _run([NODE, str(PORTS / "javascript" / "index.js"), str(bad_repo), "--json"])
    assert p.returncode == 1
    d = json.loads(p.stdout)
    assert d["shippable"] is False
    assert d["total_checks"] == 9
    assert d["by_severity"].get("critical", 0) >= 1
    assert _py_verdict(bad_repo) == d["shippable"]


@pytest.mark.skipif(not NODE, reason="node not installed")
def test_js_port_clean_repo_shippable(clean_repo):
    p = _run([NODE, str(PORTS / "javascript" / "index.js"), str(clean_repo), "--json"])
    assert p.returncode == 0
    d = json.loads(p.stdout)
    assert d["shippable"] is True
    assert d["score"] >= 80
    assert _py_verdict(clean_repo) == d["shippable"]


@pytest.mark.skipif(not NODE, reason="node not installed")
def test_js_port_self_test_passes():
    p = _run([NODE, "test.js"], cwd=str(PORTS / "javascript"))
    assert p.returncode == 0, p.stdout + p.stderr


# --------------------------------------------------------------------------- #
# Shell port parity (/bin/sh available on POSIX + Git Bash)
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(not SH, reason="sh not available")
def test_shell_port_bad_repo_not_shippable(bad_repo):
    p = _run([SH, str(PORTS / "shell" / "baadiff.sh"), str(bad_repo), "--json"])
    assert p.returncode == 1
    d = json.loads(p.stdout)
    assert d["shippable"] is False
    assert _py_verdict(bad_repo) == d["shippable"]


@pytest.mark.skipif(not SH, reason="sh not available")
def test_shell_port_clean_repo_shippable(clean_repo):
    p = _run([SH, str(PORTS / "shell" / "baadiff.sh"), str(clean_repo), "--json"])
    assert p.returncode == 0
    d = json.loads(p.stdout)
    assert d["shippable"] is True
    assert _py_verdict(clean_repo) == d["shippable"]


@pytest.mark.skipif(not SH, reason="sh not available")
def test_shell_port_self_test_passes():
    p = _run([SH, "test.sh"], cwd=str(PORTS / "shell"))
    assert p.returncode == 0, p.stdout + p.stderr
