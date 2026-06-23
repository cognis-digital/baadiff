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
# Tool identity
# --------------------------------------------------------------------------- #
# Resolve the version from the repo VERSION file when available so the CLI,
# package metadata, and badge all agree; fall back to a pinned default.

TOOL_NAME = "baadiff"


def _resolve_version() -> str:
    try:
        vf = Path(__file__).resolve().parent.parent / "VERSION"
        v = vf.read_text(encoding="utf-8").strip()
        if v:
            return v
    except OSError:
        pass
    return "0.3.0"


TOOL_VERSION = _resolve_version()

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


# Additional deterministic scan checks (additive — broaden coverage).

DEBUG_ON = re.compile(
    r"(?i)\b(DEBUG\s*=\s*True|FLASK_DEBUG\s*=\s*1|app\.run\([^)]*debug\s*=\s*True"
    r"|DJANGO_DEBUG\s*=\s*True|NODE_ENV\s*=\s*['\"]?development)"
)
# Encryption explicitly turned OFF (a stronger signal than mere absence).
ENCRYPTION_DISABLED = re.compile(
    r"(?i)(encrypt(ed|ion)?\s*[:=]\s*(false|no|0|off)|"
    r"storage_encrypted\s*=\s*false|"
    r"server_side_encryption[^\n]{0,40}(disabled|none))"
)
# Public object storage / buckets exposed.
PUBLIC_BUCKET = re.compile(
    r"(?i)(acl\s*[:=]\s*['\"]?public-read|public_access_block[^\n]{0,40}false|"
    r"AllUsers|AuthenticatedUsers)"
)
# PHI-shaped identifiers logged in cleartext (SSN/MRN patterns in log calls).
LOG_CALL = re.compile(r"(?i)\b(log(ger)?\.(info|debug|warning|error)|console\.log|print)\s*\(")
SSN_LITERAL = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


def _check_debug(text: str, fname: str, state: dict) -> list:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        if DEBUG_ON.search(line):
            out.append(("medium", i,
                        "Debug mode enabled -- verbose error pages can leak "
                        "ePHI and stack traces (164.308(a)(1) risk management).",
                        "fail"))
    return out


def _check_encryption_disabled(text: str, fname: str, state: dict) -> list:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        if ENCRYPTION_DISABLED.search(line):
            out.append(("high", i,
                        "Encryption explicitly disabled -- ePHI at rest must be "
                        "protected (164.312(a)(2)(iv)).", "fail"))
    return out


def _check_public_storage(text: str, fname: str, state: dict) -> list:
    out = []
    low = fname.lower()
    if not (low.endswith((".tf", ".json", ".yaml", ".yml", ".hcl")) or "policy" in low
            or "bucket" in low):
        return out
    for i, line in enumerate(text.splitlines(), 1):
        if PUBLIC_BUCKET.search(line):
            out.append(("critical", i,
                        "Public object-storage access -- ePHI must never be "
                        "world-readable (164.312(a)(1) access control).",
                        "fail"))
    return out


def _check_phi_in_logs(text: str, fname: str, state: dict) -> list:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        if LOG_CALL.search(line) and SSN_LITERAL.search(line):
            out.append(("high", i,
                        "Possible PHI (SSN-shaped value) written to logs -- "
                        "audit logs must not expose raw ePHI (164.312(b)).",
                        "fail"))
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
    r"(?i)(oauth|openid|jwt|authenticat|authoriz|rbac|login_required|"
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
    {"id": "BD010", "title": "Debug mode disabled in deployable config",
     "safeguard": "164.308(a)(1)(ii)(B)", "kind": "scan", "fn": _check_debug},
    {"id": "BD011", "title": "Encryption at rest not explicitly disabled",
     "safeguard": "164.312(a)(2)(iv)", "kind": "scan",
     "fn": _check_encryption_disabled},
    {"id": "BD012", "title": "No world-readable / public object storage",
     "safeguard": "164.312(a)(1)", "kind": "scan", "fn": _check_public_storage},
    {"id": "BD013", "title": "No raw PHI written to logs",
     "safeguard": "164.312(b)", "kind": "scan", "fn": _check_phi_in_logs},
    {"id": "BD014", "title": "Automatic logoff / session timeout configured",
     "safeguard": "164.312(a)(2)(iii)", "kind": "presence",
     "marker": re.compile(
         r"(?i)(session[_-]?timeout|idle[_-]?timeout|auto[_-]?logoff|"
         r"PERMANENT_SESSION_LIFETIME|max[_-]?age|expires_in|token[_-]?ttl)"),
     "severity": "medium"},
    {"id": "BD015", "title": "Contingency / data-retention policy documented",
     "safeguard": "164.308(a)(7)(ii)", "kind": "presence",
     "marker": re.compile(
         r"(?i)(retention|contingency|incident[_-]?response|business[_-]?"
         r"continuity|RTO|RPO|failover|replicat)"),
     "severity": "low"},
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


# --------------------------------------------------------------------------- #
# SARIF (code-scanning) output
# --------------------------------------------------------------------------- #

# SARIF severity maps to a "level": error | warning | note.
_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def to_sarif(scorecard: Scorecard) -> str:
    """Render a scorecard as a SARIF 2.1.0 log (GitHub code-scanning ready).

    Only failing findings become SARIF results (a 'pass' is the absence of a
    problem). Each distinct check id becomes a reusable rule descriptor.
    """
    rules_by_id: dict = {}
    for c in CHECKS:
        rules_by_id[c["id"]] = {
            "id": c["id"],
            "name": c["title"].replace(" ", ""),
            "shortDescription": {"text": c["title"]},
            "fullDescription": {
                "text": f"HIPAA Security Rule safeguard {c['safeguard']}: "
                        f"{c['title']}."},
            "helpUri": "https://www.ecfr.gov/current/title-45/part-164",
            "properties": {"safeguard": c["safeguard"]},
        }

    results = []
    for f in scorecard.findings:
        if f.status != "fail":
            continue
        loc = []
        if f.file:
            loc = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file.replace("\\", "/")},
                    "region": {"startLine": max(1, f.line)},
                }
            }]
        results.append({
            "ruleId": f.check_id,
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f"[{f.safeguard}] {f.message}"},
            "locations": loc,
            "properties": {"severity": f.severity, "safeguard": f.safeguard},
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "informationUri": "https://github.com/cognis-digital/baadiff",
                "rules": list(rules_by_id.values()),
            }},
            "results": results,
            "properties": {
                "score": scorecard.score,
                "grade": scorecard.grade,
                "shippable": scorecard.shippable,
            },
        }],
    }
    return json.dumps(sarif, indent=2)


# --------------------------------------------------------------------------- #
# Convenience / compatibility API
# --------------------------------------------------------------------------- #

def scan(target, pass_threshold: int = 80) -> Scorecard:
    """One-shot: walk ``target`` and return a scored :class:`Scorecard`.

    Thin convenience wrapper used by the MCP server and embedders who want a
    single call instead of ``score_findings(scan_path(...))``.
    """
    return score_findings(scan_path(target), pass_threshold=pass_threshold)


def to_json(scorecard: Scorecard) -> str:
    """Serialize a :class:`Scorecard` to indented JSON."""
    if isinstance(scorecard, Scorecard):
        return json.dumps(scorecard.to_dict(), indent=2)
    return json.dumps(scorecard, indent=2)
