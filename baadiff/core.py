"""Core engine for BAADIFF.

Real, deterministic, standard-library-only detection logic that walks a repo
or reads a single manifest, runs a battery of HIPAA Security Rule checks, and
scores the results.

The checks map to concrete, machine-detectable proxies for HIPAA Security Rule
safeguards (45 CFR 164.308 administrative, 164.310 physical, 164.312
technical). Each check is intentionally evidence-based: we either find a
positive marker (something is configured) or flag a risk marker (a plaintext
secret, an unencrypted protocol, an over-broad permission, etc.).

This is a static, best-effort readiness signal -- not legal advice and not a
guarantee of compliance.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable, Iterable, Optional

# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Severity -> points deducted from a 100-point readiness budget per occurrence,
# capped per check so one noisy file can't zero the whole score on its own.
SEVERITY_WEIGHT = {
    "critical": 18,
    "high": 10,
    "medium": 5,
    "low": 2,
    "info": 0,
}
PER_CHECK_CAP = 30  # max points a single check id can deduct


@dataclass
class Finding:
    """A single detected gap (or satisfied control)."""

    check_id: str
    title: str
    safeguard: str          # e.g. "164.312(a)(2)(iv)"
    severity: str           # critical|high|medium|low|info
    status: str             # "fail" (gap) or "pass" (control present)
    message: str
    file: str = ""
    line: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Scorecard:
    score: int
    grade: str
    shippable: bool
    total_checks: int
    failed: int
    passed: int
    by_severity: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["findings"] = [
            f.to_dict() if isinstance(f, Finding) else f for f in self.findings
        ]
        return d


# --------------------------------------------------------------------------- #
# File collection
# --------------------------------------------------------------------------- #

_TEXT_EXT = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rb", ".php", ".java",
    ".cs", ".sh", ".bash", ".env", ".cfg", ".ini", ".conf", ".toml",
    ".yaml", ".yml", ".json", ".tf", ".hcl", ".md", ".txt", ".xml",
    ".properties", ".gradle", ".dockerfile", "",
}
_SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist",
    "build", ".mypy_cache", ".pytest_cache", ".tox", "vendor",
}
_MAX_BYTES = 2_000_000  # skip very large files


def _iter_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        name = p.name.lower()
        ext = p.suffix.lower()
        if ext in _TEXT_EXT or name in {
            "dockerfile", "makefile", ".gitignore", ".env", "requirements.txt",
        }:
            try:
                if p.stat().st_size <= _MAX_BYTES:
                    yield p
            except OSError:
                continue


def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


# --------------------------------------------------------------------------- #
# Detection helpers (regex-based, deterministic)
# --------------------------------------------------------------------------- #

CheckFn = Callable[[str, str, dict], list]

# A check returns a list of (severity, line_no, message, status) for fails,
# and may register a "pass" via the shared `state` dict (file-spanning).

SECRET_PATTERNS = [
    re.compile(r"(?i)(aws_secret_access_key|aws_access_key_id)\s*[:=]\s*['\"]?[A-Za-z0-9/+]{16,}"),
    re.compile(r"(?i)(secret|password|passwd|pwd|api[_-]?key|token)\s*[:=]\s*['\"][^'\"]{6,}['\"]"),
    re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"),
]
_PLACEHOLDER = re.compile(
    r"(?i)(your[_-]?|example|changeme|placeholder|xxxx|<.*?>|\$\{|os\.environ|getenv|process\.env)"
)

INSECURE_URL = re.compile(r"(?i)\bhttp://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[\w.-]+")
WEAK_HASH = re.compile(r"(?i)\b(md5|sha1)\b\s*\(")
VERIFY_FALSE = re.compile(r"(?i)(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true)")
WILDCARD_IAM = re.compile(r'["\']Action["\']\s*:\s*["\']\*["\']|["\']Resource["\']\s*:\s*["\']\*["\']')
OPEN_INGRESS = re.compile(r"0\.0\.0\.0/0")


def _check_secrets(text: str, fname: str, state: dict) -> list:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#") and "BEGIN" not in line:
            continue
        for pat in SECRET_PATTERNS:
            if pat.search(line) and not _PLACEHOLDER.search(line):
                out.append(("critical", i,
                            "Hardcoded credential/secret detected (ePHI access "
                            "controls require managed secrets, not plaintext).",
                            "fail"))
                break
    return out


def _check_transport(text: str, fname: str, state: dict) -> list:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        if INSECURE_URL.search(line) and "://schemas" not in line and "w3.org" not in line:
            out.append(("high", i,
                        "Plaintext http:// endpoint -- transmission security "
                        "(164.312(e)(1)) expects encryption in transit (TLS).",
                        "fail"))
        if VERIFY_FALSE.search(line):
            out.append(("high", i,
                        "TLS verification disabled -- defeats transmission "
                        "security / integrity controls.", "fail"))
    return out


def _check_crypto(text: str, fname: str, state: dict) -> list:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        if WEAK_HASH.search(line) and "checksum" not in line.lower():
            out.append(("medium", i,
                        "Weak hash (MD5/SHA1) -- not acceptable for protecting "
                        "or authenticating ePHI integrity (164.312(c)).",
                        "fail"))
    return out


def _check_iam(text: str, fname: str, state: dict) -> list:
    out = []
    low = fname.lower()
    if not (low.endswith((".tf", ".json", ".yaml", ".yml", ".hcl")) or "policy" in low):
        return out
    for i, line in enumerate(text.splitlines(), 1):
        if WILDCARD_IAM.search(line):
            out.append(("high", i,
                        "Wildcard IAM Action/Resource '*' -- violates minimum-"
                        "necessary / least-privilege access (164.312(a)(1)).",
                        "fail"))
        if OPEN_INGRESS.search(line):
            out.append(("high", i,
                        "Network rule open to 0.0.0.0/0 -- unrestricted ingress "
                        "to systems that may hold ePHI.", "fail"))
    return out


# Positive-marker (presence) checks: scanned across the whole corpus.
_ENCRYPTION_AT_REST = re.compile(
    r"(?i)(encrypt(ed|ion)?[\s_-]*(at[\s_-]*rest|enabled|true)|kms[_-]?key|"
    r"server_side_encryption|sse_algorithm|storage_encrypted\s*=\s*true|"
    r"encrypted\s*[:=]\s*true)"
)
_AUDIT_LOG = re.compile(
    r"(?i)(audit[_-]?log|cloudtrail|access[_-]?log|enable_logging|"
    r"log_group|logging\.(info|warning|error)|structured[_-]?log)"
)
_AUTH = re.compile(
    r"(?i)(oauth|openid|jwt|authenticat|authoriz|rbac|@login_required|"
    r"ensure_authenticated|session\[|mfa|two[_-]?factor|bcrypt|argon2|pbkdf2)"
)
_BACKUP = re.compile(
    r"(?i)(backup|snapshot|pg_dump|mysqldump|point[_-]?in[_-]?time|"
    r"disaster[_-]?recovery|restore)"
)
_INTEGRITY = re.compile(
    r"(?i)(checksum|sha256|sha-256|sha512|hmac|signature[_-]?verif|hashlib\.sha)"
)


# --------------------------------------------------------------------------- #
# Check registry
# --------------------------------------------------------------------------- #
# Each entry: id, title, safeguard, kind, severity (for presence-fail).
# kind == "scan": uses a per-line CheckFn that emits fails.
# kind == "presence": passes if a marker regex appears anywhere; else fails.

CHECKS = [
    {"id": "BD001", "title": "No hardcoded secrets / credentials",
     "safeguard": "164.312(a)(2)(i)", "kind": "scan", "fn": _check_secrets},
    {"id": "BD002", "title": "Encryption in transit (no plaintext HTTP / TLS verify on)",
     "safeguard": "164.312(e)(1)", "kind": "scan", "fn": _check_transport},
    {"id": "BD003", "title": "No weak cryptographic hashing of ePHI",
     "safeguard": "164.312(c)(1)", "kind": "scan", "fn": _check_crypto},
    {"id": "BD004", "title": "Least-privilege access (no wildcard IAM / open ingress)",
     "safeguard": "164.312(a)(1)", "kind": "scan", "fn": _check_iam},
    {"id": "BD005", "title": "Encryption at rest is configured",
     "safeguard": "164.312(a)(2)(iv)", "kind": "presence",
     "marker": _ENCRYPTION_AT_REST, "severity": "high"},
    {"id": "BD006", "title": "Audit controls / logging present",
     "safeguard": "164.312(b)", "kind": "presence",
     "marker": _AUDIT_LOG, "severity": "high"},
    {"id": "BD007", "title": "Authentication / access control present",
     "safeguard": "164.312(d)", "kind": "presence",
     "marker": _AUTH, "severity": "critical"},
    {"id": "BD008", "title": "Backup / contingency plan present",
     "safeguard": "164.308(a)(7)", "kind": "presence",
     "marker": _BACKUP, "severity": "medium"},
    {"id": "BD009", "title": "Integrity verification (hashing/HMAC) present",
     "safeguard": "164.312(c)(2)", "kind": "presence",
     "marker": _INTEGRITY, "severity": "medium"},
]


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #

def scan_text(text: str, fname: str = "<text>") -> list:
    """Run only the per-line 'scan' checks against a single text blob.

    Returns a list of Finding (fails only). Presence checks need the full
    corpus, so use :func:`scan_path` for a complete scorecard.
    """
    findings: list = []
    state: dict = {}
    for chk in CHECKS:
        if chk["kind"] != "scan":
            continue
        for severity, line, msg, status in chk["fn"](text, fname, state):
            findings.append(Finding(
                check_id=chk["id"], title=chk["title"],
                safeguard=chk["safeguard"], severity=severity,
                status=status, message=msg, file=fname, line=line,
            ))
    return findings


def scan_path(path) -> list:
    """Walk a file or directory and return all Findings (pass and fail).

    Per-line 'scan' checks emit a Finding per hit. 'presence' checks emit a
    single pass/fail Finding for the whole corpus.
    """
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"path not found: {path}")

    findings: list = []
    presence_hit: dict = {c["id"]: None for c in CHECKS if c["kind"] == "presence"}
    files = list(_iter_files(root))
    base = root if root.is_dir() else root.parent

    for fp in files:
        text = _read(fp)
        if not text:
            continue
        try:
            rel = str(fp.relative_to(base))
        except ValueError:
            rel = str(fp)

        findings.extend(scan_text(text, rel))

        for chk in CHECKS:
            if chk["kind"] != "presence":
                continue
            if presence_hit[chk["id"]] is None and chk["marker"].search(text):
                presence_hit[chk["id"]] = rel

    # Emit presence pass/fail.
    for chk in CHECKS:
        if chk["kind"] != "presence":
            continue
        hit = presence_hit[chk["id"]]
        if hit:
            findings.append(Finding(
                check_id=chk["id"], title=chk["title"],
                safeguard=chk["safeguard"], severity="info",
                status="pass",
                message=f"Control evidence found in {hit}.",
                file=hit, line=0,
            ))
        else:
            findings.append(Finding(
                check_id=chk["id"], title=chk["title"],
                safeguard=chk["safeguard"], severity=chk["severity"],
                status="fail",
                message="No evidence of this safeguard anywhere in the scanned "
                        "sources.",
                file="", line=0,
            ))

    findings.sort(key=lambda f: (f.status != "fail",
                                 SEVERITY_ORDER.get(f.severity, 9),
                                 f.check_id, f.file, f.line))
    return findings


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #

def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def score_findings(findings: list, pass_threshold: int = 80) -> Scorecard:
    """Turn findings into a 0-100 readiness scorecard.

    Deductions are weighted by severity and capped per check id so a single
    noisy file cannot dominate the score.
    """
    fails = [f for f in findings if f.status == "fail"]
    passes = [f for f in findings if f.status == "pass"]

    by_sev: dict = {}
    deduction_by_check: dict = {}
    for f in fails:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        w = SEVERITY_WEIGHT.get(f.severity, 0)
        deduction_by_check[f.check_id] = deduction_by_check.get(f.check_id, 0) + w

    total_deduction = sum(min(v, PER_CHECK_CAP) for v in deduction_by_check.values())
    score = max(0, 100 - total_deduction)
    # Critical fails hard-cap the ceiling: cannot be "shippable" with a
    # critical open finding.
    has_critical = by_sev.get("critical", 0) > 0
    shippable = (score >= pass_threshold) and not has_critical

    distinct_checks = len({c["id"] for c in CHECKS})
    return Scorecard(
        score=score,
        grade=_grade(score),
        shippable=shippable,
        total_checks=distinct_checks,
        failed=len(fails),
        passed=len(passes),
        by_severity=by_sev,
        findings=findings,
    )


# --------------------------------------------------------------------------- #
# Badge
# --------------------------------------------------------------------------- #

def badge_for(scorecard: Scorecard) -> str:
    """Return a shields.io-style endpoint JSON string for a README badge."""
    color = ("brightgreen" if scorecard.score >= 90 else
             "green" if scorecard.score >= 80 else
             "yellow" if scorecard.score >= 70 else
             "orange" if scorecard.score >= 60 else "red")
    return json.dumps({
        "schemaVersion": 1,
        "label": "HIPAA readiness",
        "message": f"{scorecard.score}/100 ({scorecard.grade})",
        "color": color,
    })
