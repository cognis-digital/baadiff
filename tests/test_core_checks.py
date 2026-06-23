"""Deterministic unit tests for every BAADIFF check (BD001-BD015).

Each check is exercised with a positive (gap present) and, where meaningful, a
negative (no false positive) fixture. Pure stdlib + pytest, no network.
"""

import re

import pytest

from baadiff import core
from baadiff.core import (
    CHECKS,
    Finding,
    Scorecard,
    scan_text,
    scan_path,
    score_findings,
    badge_for,
    to_sarif,
    to_json,
    scan,
    SEVERITY_ORDER,
    SEVERITY_WEIGHT,
)


# --------------------------------------------------------------------------- #
# Registry sanity
# --------------------------------------------------------------------------- #

def test_checks_have_unique_ids():
    ids = [c["id"] for c in CHECKS]
    assert len(ids) == len(set(ids))


def test_checks_cover_expected_ids():
    ids = {c["id"] for c in CHECKS}
    for n in range(1, 16):
        assert f"BD{n:03d}" in ids


def test_every_check_has_required_fields():
    for c in CHECKS:
        assert c["id"].startswith("BD")
        assert c["title"]
        assert re.match(r"^164\.\d", c["safeguard"]), c["safeguard"]
        assert c["kind"] in ("scan", "presence")
        if c["kind"] == "scan":
            assert callable(c["fn"])
        else:
            assert hasattr(c["marker"], "search")
            assert c["severity"] in SEVERITY_ORDER


def test_severity_weight_ordering():
    assert SEVERITY_WEIGHT["critical"] > SEVERITY_WEIGHT["high"]
    assert SEVERITY_WEIGHT["high"] > SEVERITY_WEIGHT["medium"]
    assert SEVERITY_WEIGHT["medium"] > SEVERITY_WEIGHT["low"]
    assert SEVERITY_WEIGHT["info"] == 0


# --------------------------------------------------------------------------- #
# BD001 — secrets
# --------------------------------------------------------------------------- #

def test_bd001_detects_hardcoded_password():
    fs = scan_text('DB_PASSWORD = "S3cr3tP@ssw0rd123"\n', "c.py")
    assert any(f.check_id == "BD001" and f.severity == "critical" for f in fs)


def test_bd001_detects_private_key_block():
    fs = scan_text("-----BEGIN RSA PRIVATE KEY-----\n", "k.pem")
    assert any(f.check_id == "BD001" for f in fs)


def test_bd001_detects_aws_key():
    fs = scan_text('aws_secret_access_key = "AKIA1234567890ABCDEF"\n', "c.cfg")
    assert any(f.check_id == "BD001" for f in fs)


def test_bd001_ignores_env_var_reference():
    fs = scan_text('password = os.environ["DB_PASSWORD"]\n', "c.py")
    assert not any(f.check_id == "BD001" for f in fs)


def test_bd001_ignores_placeholder():
    for ph in ('password = "changeme"', 'token = "your-token-here"',
               'api_key = "<your-key>"', 'secret = "example-secret"'):
        fs = scan_text(ph + "\n", "c.py")
        assert not any(f.check_id == "BD001" for f in fs), ph


def test_bd001_ignores_comment_lines():
    fs = scan_text('# password = "realsecretvalue"\n', "c.py")
    assert not any(f.check_id == "BD001" for f in fs)


def test_bd001_reports_correct_line():
    text = "ok = 1\nok2 = 2\nDB_PASSWORD = \"S3cr3tP@ssw0rd\"\n"
    fs = [f for f in scan_text(text, "c.py") if f.check_id == "BD001"]
    assert fs and fs[0].line == 3


# --------------------------------------------------------------------------- #
# BD002 — transport security
# --------------------------------------------------------------------------- #

def test_bd002_flags_plaintext_http():
    fs = scan_text('API = "http://labs.example.com/v1"\n', "c.py")
    assert any(f.check_id == "BD002" for f in fs)


def test_bd002_allows_https():
    fs = scan_text('API = "https://labs.example.com/v1"\n', "c.py")
    assert not any(f.check_id == "BD002" for f in fs)


def test_bd002_allows_localhost_http():
    fs = scan_text('API = "http://localhost:8080"\n', "c.py")
    assert not any(f.check_id == "BD002" for f in fs)


def test_bd002_allows_loopback_http():
    fs = scan_text('API = "http://127.0.0.1:5000"\n', "c.py")
    assert not any(f.check_id == "BD002" for f in fs)


def test_bd002_flags_verify_false():
    fs = scan_text("requests.get(u, verify=False)\n", "c.py")
    assert any(f.check_id == "BD002" for f in fs)


def test_bd002_flags_reject_unauthorized_false():
    fs = scan_text("{ rejectUnauthorized: false }\n", "c.js")
    assert any(f.check_id == "BD002" for f in fs)


def test_bd002_flags_insecure_skip_verify():
    fs = scan_text("tls.Config{ InsecureSkipVerify: true }\n", "c.go")
    assert any(f.check_id == "BD002" for f in fs)


def test_bd002_ignores_schema_namespace_urls():
    fs = scan_text('xmlns="http://www.w3.org/2001/XMLSchema"\n', "c.xml")
    assert not any(f.check_id == "BD002" for f in fs)


# --------------------------------------------------------------------------- #
# BD003 — weak crypto
# --------------------------------------------------------------------------- #

def test_bd003_flags_md5():
    fs = scan_text("h = hashlib.md5(x)\n", "c.py")
    assert any(f.check_id == "BD003" for f in fs)


def test_bd003_flags_sha1():
    fs = scan_text("d = sha1(data)\n", "c.py")
    assert any(f.check_id == "BD003" for f in fs)


def test_bd003_allows_sha256():
    fs = scan_text("h = hashlib.sha256(x)\n", "c.py")
    assert not any(f.check_id == "BD003" for f in fs)


def test_bd003_skips_checksum_context():
    fs = scan_text("md5(file)  # checksum only, not security\n", "c.py")
    assert not any(f.check_id == "BD003" for f in fs)


# --------------------------------------------------------------------------- #
# BD004 — IAM least privilege
# --------------------------------------------------------------------------- #

def test_bd004_flags_wildcard_action():
    fs = scan_text('"Action": "*"\n', "policy.json")
    assert any(f.check_id == "BD004" for f in fs)


def test_bd004_flags_wildcard_resource():
    fs = scan_text('"Resource": "*"\n', "policy.json")
    assert any(f.check_id == "BD004" for f in fs)


def test_bd004_flags_open_ingress():
    fs = scan_text("cidr_blocks = [\"0.0.0.0/0\"]\n", "main.tf")
    assert any(f.check_id == "BD004" for f in fs)


def test_bd004_only_runs_on_config_files():
    # plain .py without "policy" in name should not run IAM check
    fs = scan_text('x = "0.0.0.0/0"\n', "app.py")
    assert not any(f.check_id == "BD004" for f in fs)


def test_bd004_runs_on_policy_named_py():
    fs = scan_text("ingress = \"0.0.0.0/0\"\n", "iam_policy.py")
    assert any(f.check_id == "BD004" for f in fs)


# --------------------------------------------------------------------------- #
# BD010 — debug mode
# --------------------------------------------------------------------------- #

def test_bd010_flags_debug_true():
    fs = scan_text("DEBUG = True\n", "settings.py")
    assert any(f.check_id == "BD010" for f in fs)


def test_bd010_flags_flask_run_debug():
    fs = scan_text("app.run(host='0.0.0.0', debug=True)\n", "app.py")
    assert any(f.check_id == "BD010" for f in fs)


def test_bd010_allows_debug_false():
    fs = scan_text("DEBUG = False\n", "settings.py")
    assert not any(f.check_id == "BD010" for f in fs)


# --------------------------------------------------------------------------- #
# BD011 — encryption explicitly disabled
# --------------------------------------------------------------------------- #

def test_bd011_flags_storage_encrypted_false():
    fs = scan_text("storage_encrypted = false\n", "rds.tf")
    assert any(f.check_id == "BD011" for f in fs)


def test_bd011_flags_encryption_off():
    fs = scan_text("encryption: off\n", "config.yaml")
    assert any(f.check_id == "BD011" for f in fs)


def test_bd011_allows_encrypted_true():
    fs = scan_text("storage_encrypted = true\n", "rds.tf")
    assert not any(f.check_id == "BD011" for f in fs)


# --------------------------------------------------------------------------- #
# BD012 — public storage
# --------------------------------------------------------------------------- #

def test_bd012_flags_public_read_acl():
    fs = scan_text("acl = \"public-read\"\n", "bucket.tf")
    assert any(f.check_id == "BD012" and f.severity == "critical" for f in fs)


def test_bd012_flags_all_users_grant():
    fs = scan_text("grantee: AllUsers\n", "bucket_policy.yaml")
    assert any(f.check_id == "BD012" for f in fs)


def test_bd012_skips_non_infra_files():
    fs = scan_text("acl = \"public-read\"\n", "notes.txt")
    assert not any(f.check_id == "BD012" for f in fs)


# --------------------------------------------------------------------------- #
# BD013 — PHI in logs
# --------------------------------------------------------------------------- #

def test_bd013_flags_ssn_in_log():
    fs = scan_text('log.info("patient ssn 123-45-6789")\n', "svc.py")
    assert any(f.check_id == "BD013" for f in fs)


def test_bd013_flags_console_log_ssn():
    fs = scan_text('console.log("ssn=123-45-6789")\n', "svc.js")
    assert any(f.check_id == "BD013" for f in fs)


def test_bd013_ignores_ssn_not_in_log():
    fs = scan_text('ssn = "123-45-6789"\n', "svc.py")
    assert not any(f.check_id == "BD013" for f in fs)


def test_bd013_ignores_log_without_ssn():
    fs = scan_text('log.info("access granted")\n', "svc.py")
    assert not any(f.check_id == "BD013" for f in fs)


# --------------------------------------------------------------------------- #
# Presence checks (BD005-009, BD014-015) via scan_path
# --------------------------------------------------------------------------- #

@pytest.fixture
def clean_repo(tmp_path):
    (tmp_path / "app.py").write_text(
        "import os, hashlib, logging\n"
        "log = logging.getLogger('svc')\n"
        "DB = os.environ['DB_PASSWORD']\n"
        "API = 'https://api.example.com'\n"
        "storage_encrypted = True            # encryption at rest\n"
        "# audit_log cloudtrail enabled\n"
        "# backup snapshot pg_dump nightly\n"
        "# session_timeout = 900  auto logoff\n"
        "# retention policy: RPO 1h, RTO 4h failover\n"
        "from flask_login import login_required\n"
        "def h(x):\n    return hashlib.sha256(x).hexdigest()\n"
        "def hmac_check(m):\n    return hmac\n"
        "def audit():\n    log.info('access')\n",
        encoding="utf-8",
    )
    return tmp_path


def test_presence_all_satisfied(clean_repo):
    findings = scan_path(clean_repo)
    passes = {f.check_id for f in findings if f.status == "pass"}
    for cid in ("BD005", "BD006", "BD007", "BD008", "BD009", "BD014", "BD015"):
        assert cid in passes, cid


def test_presence_missing_emits_fail(tmp_path):
    (tmp_path / "empty.py").write_text("x = 1\n", encoding="utf-8")
    findings = scan_path(tmp_path)
    fails = {f.check_id for f in findings if f.status == "fail"}
    # nothing satisfied -> presence checks fail
    for cid in ("BD005", "BD006", "BD007", "BD008", "BD009"):
        assert cid in fails, cid


def test_presence_fail_carries_registry_severity(tmp_path):
    (tmp_path / "empty.py").write_text("x = 1\n", encoding="utf-8")
    findings = scan_path(tmp_path)
    bd007 = [f for f in findings if f.check_id == "BD007" and f.status == "fail"]
    assert bd007 and bd007[0].severity == "critical"


# --------------------------------------------------------------------------- #
# scan_path mechanics
# --------------------------------------------------------------------------- #

def test_scan_path_missing_raises():
    with pytest.raises(FileNotFoundError):
        scan_path("/no/such/path/xyz")


def test_scan_path_skips_git_dir(tmp_path):
    g = tmp_path / ".git"
    g.mkdir()
    (g / "config").write_text('password = "shouldbeignored123"\n', encoding="utf-8")
    (tmp_path / "ok.py").write_text("x = 1\n", encoding="utf-8")
    findings = scan_path(tmp_path)
    assert not any(f.check_id == "BD001" for f in findings if f.status == "fail")


def test_scan_path_single_file(tmp_path):
    f = tmp_path / "x.py"
    f.write_text('password = "S3cr3tP@ssw0rd"\n', encoding="utf-8")
    findings = scan_path(f)
    assert any(x.check_id == "BD001" for x in findings)


def test_findings_sorted_fails_first(tmp_path):
    (tmp_path / "x.py").write_text(
        'password = "S3cr3tP@ssw0rd"\n'
        "from flask_login import login_required\n",
        encoding="utf-8",
    )
    findings = scan_path(tmp_path)
    statuses = [f.status for f in findings]
    # all fails precede all passes after the sort
    if "pass" in statuses:
        last_fail = max(i for i, s in enumerate(statuses) if s == "fail")
        first_pass = min(i for i, s in enumerate(statuses) if s == "pass")
        assert last_fail < first_pass


def test_finding_to_dict_roundtrip():
    f = Finding("BDX", "t", "164.312(a)", "high", "fail", "msg", "f.py", 3)
    d = f.to_dict()
    assert d["check_id"] == "BDX" and d["line"] == 3 and d["severity"] == "high"


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #

def test_score_clean_is_high_and_shippable(clean_repo):
    sc = score_findings(scan_path(clean_repo))
    assert sc.by_severity.get("critical", 0) == 0
    assert sc.score >= 80
    assert sc.shippable is True
    assert sc.grade in ("A", "B")


def test_score_critical_blocks_shippable(tmp_path):
    (tmp_path / "x.py").write_text('password = "S3cr3tP@ssw0rd"\n', encoding="utf-8")
    sc = score_findings(scan_path(tmp_path))
    assert sc.by_severity.get("critical", 0) >= 1
    assert sc.shippable is False


def test_score_never_negative(tmp_path):
    # pile on many criticals
    lines = "\n".join(f'password{i} = "S3cr3tP@ssw0rd{i}"' for i in range(50))
    (tmp_path / "x.py").write_text(lines + "\n", encoding="utf-8")
    sc = score_findings(scan_path(tmp_path))
    assert 0 <= sc.score <= 100


def test_per_check_cap_limits_single_noisy_file(tmp_path):
    # 100 secrets in one file must not deduct more than PER_CHECK_CAP for BD001
    lines = "\n".join(f'password{i} = "S3cr3tP@ssw0rd{i}"' for i in range(100))
    (tmp_path / "x.py").write_text(lines + "\n", encoding="utf-8")
    sc = score_findings(scan_path(tmp_path))
    # 100 criticals * 18 would be 1800, but cap is 30 for that one check id
    assert sc.score >= 100 - core.PER_CHECK_CAP - 60  # other presence fails


def test_threshold_param_changes_shippable(tmp_path):
    # A repo with one medium gap (debug on) scores <100 but has no critical,
    # so it ships at a relaxed threshold and fails a perfect-score threshold.
    (tmp_path / "app.py").write_text(
        "import os, hashlib, logging\n"
        "from flask_login import login_required\n"
        "log = logging.getLogger('s')\n"
        "DB = os.environ['DB']\n"
        "API = 'https://x.example'\n"
        "storage_encrypted = True\n"
        "DEBUG = True            # one medium gap -> score below 100\n"
        "# backup snapshot ; audit_log cloudtrail ; session_timeout=900\n"
        "# retention RPO RTO failover ; hmac integrity\n"
        "def h(x):\n    return hashlib.sha256(x).hexdigest()\n",
        encoding="utf-8",
    )
    findings = scan_path(tmp_path)
    lenient = score_findings(findings, pass_threshold=50)
    strict = score_findings(findings, pass_threshold=100)
    assert lenient.shippable is True
    assert strict.shippable is False
    assert strict.score < 100


def test_grade_boundaries():
    from baadiff.core import _grade
    assert _grade(95) == "A"
    assert _grade(85) == "B"
    assert _grade(75) == "C"
    assert _grade(65) == "D"
    assert _grade(10) == "F"


def test_scorecard_to_dict_serializable(clean_repo):
    import json as _json
    sc = score_findings(scan_path(clean_repo))
    d = sc.to_dict()
    s = _json.dumps(d)
    assert "findings" in d and isinstance(d["findings"], list)
    assert _json.loads(s)["score"] == sc.score


def test_scorecard_total_checks_matches_registry(clean_repo):
    sc = score_findings(scan_path(clean_repo))
    assert sc.total_checks == len({c["id"] for c in CHECKS})


# --------------------------------------------------------------------------- #
# Badge
# --------------------------------------------------------------------------- #

def test_badge_schema(clean_repo):
    import json as _json
    sc = score_findings(scan_path(clean_repo))
    b = _json.loads(badge_for(sc))
    assert b["schemaVersion"] == 1
    assert b["label"] == "HIPAA readiness"
    assert str(sc.score) in b["message"]


@pytest.mark.parametrize("score,color", [
    (95, "brightgreen"), (85, "green"), (75, "yellow"),
    (65, "orange"), (30, "red"),
])
def test_badge_color_thresholds(score, color):
    import json as _json
    sc = Scorecard(score=score, grade="X", shippable=False, total_checks=15,
                   failed=0, passed=0)
    assert _json.loads(badge_for(sc))["color"] == color


# --------------------------------------------------------------------------- #
# SARIF
# --------------------------------------------------------------------------- #

def test_sarif_is_valid_json_and_versioned(tmp_path):
    import json as _json
    (tmp_path / "x.py").write_text('password = "S3cr3tP@ssw0rd"\n', encoding="utf-8")
    sc = score_findings(scan_path(tmp_path))
    d = _json.loads(to_sarif(sc))
    assert d["version"] == "2.1.0"
    assert d["runs"][0]["tool"]["driver"]["name"] == "baadiff"


def test_sarif_only_includes_fails(tmp_path):
    import json as _json
    (tmp_path / "x.py").write_text('password = "S3cr3tP@ssw0rd"\n', encoding="utf-8")
    sc = score_findings(scan_path(tmp_path))
    d = _json.loads(to_sarif(sc))
    results = d["runs"][0]["results"]
    fails = [f for f in sc.findings if f.status == "fail"]
    assert len(results) == len(fails)


def test_sarif_levels_mapped(tmp_path):
    import json as _json
    (tmp_path / "x.py").write_text('password = "S3cr3tP@ssw0rd"\n', encoding="utf-8")
    sc = score_findings(scan_path(tmp_path))
    d = _json.loads(to_sarif(sc))
    levels = {r["level"] for r in d["runs"][0]["results"]}
    assert levels <= {"error", "warning", "note"}
    # at least one critical -> error
    assert "error" in levels


def test_sarif_rules_cover_all_checks(tmp_path):
    import json as _json
    (tmp_path / "x.py").write_text("x=1\n", encoding="utf-8")
    sc = score_findings(scan_path(tmp_path))
    d = _json.loads(to_sarif(sc))
    rule_ids = {r["id"] for r in d["runs"][0]["tool"]["driver"]["rules"]}
    assert rule_ids == {c["id"] for c in CHECKS}


def test_sarif_carries_score_properties(tmp_path):
    import json as _json
    (tmp_path / "x.py").write_text("x=1\n", encoding="utf-8")
    sc = score_findings(scan_path(tmp_path))
    d = _json.loads(to_sarif(sc))
    props = d["runs"][0]["properties"]
    assert props["score"] == sc.score
    assert props["grade"] == sc.grade


# --------------------------------------------------------------------------- #
# Convenience API
# --------------------------------------------------------------------------- #

def test_scan_returns_scorecard(clean_repo):
    sc = scan(str(clean_repo))
    assert isinstance(sc, Scorecard)
    assert 0 <= sc.score <= 100


def test_to_json_roundtrip(clean_repo):
    import json as _json
    sc = scan(str(clean_repo))
    d = _json.loads(to_json(sc))
    assert d["score"] == sc.score
    assert d["grade"] == sc.grade
