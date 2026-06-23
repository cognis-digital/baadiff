#!/usr/bin/env node
// JavaScript / Node port of baadiff — scan a repo or manifest for HIPAA
// Security Rule gaps and emit a Business Associate readiness scorecard.
// Mirrors the Python reference: same check IDs (BD001..BD004 line scans +
// BD005..BD009 presence), same JSON shape, same 0-100 scoring (per-check cap,
// critical blocks "shippable"). Stdlib only. Passive/offline — reads files,
// never the network.
//
//   node index.js <path>          # human table
//   node index.js <path> --json   # machine-readable scorecard
import { readdirSync, statSync, readFileSync } from "fs";
import { join, extname, basename, relative } from "path";
import { pathToFileURL } from "url";

const SEV_WEIGHT = { critical: 18, high: 10, medium: 5, low: 2, info: 0 };
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const PER_CHECK_CAP = 30;

const SECRET = [
  /(aws_secret_access_key|aws_access_key_id)\s*[:=]\s*['"]?[A-Za-z0-9/+]{16,}/i,
  /(secret|password|passwd|pwd|api[_-]?key|token)\s*[:=]\s*['"][^'"]{6,}['"]/i,
  /-----BEGIN (RSA |EC )?PRIVATE KEY-----/,
];
const PLACEHOLDER = /(your[_-]?|example|changeme|placeholder|xxxx|<.*?>|\$\{|os\.environ|getenv|process\.env)/i;
const INSECURE_URL = /\bhttp:\/\//i;
const LOCALHOST = /http:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0)/i;
const VERIFY_FALSE = /(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true)/i;
const WEAK_HASH = /\b(md5|sha1)\b\s*\(/i;
const WILDCARD_IAM = /["']Action["']\s*:\s*["']\*["']|["']Resource["']\s*:\s*["']\*["']/;
const OPEN_INGRESS = /0\.0\.0\.0\/0/;

const PRESENCE = [
  ["BD005", "Encryption at rest is configured", "164.312(a)(2)(iv)", "high",
    /(encrypt(ed|ion)?[\s_-]*(at[\s_-]*rest|enabled|true)|kms[_-]?key|server_side_encryption|sse_algorithm|storage_encrypted\s*=\s*true|encrypted\s*[:=]\s*true)/i],
  ["BD006", "Audit controls / logging present", "164.312(b)", "high",
    /(audit[_-]?log|cloudtrail|access[_-]?log|enable_logging|log_group|logging\.(info|warning|error)|structured[_-]?log)/i],
  ["BD007", "Authentication / access control present", "164.312(d)", "critical",
    /(oauth|openid|jwt|authenticat|authoriz|rbac|login_required|ensure_authenticated|session\[|mfa|two[_-]?factor|bcrypt|argon2|pbkdf2)/i],
  ["BD008", "Backup / contingency plan present", "164.308(a)(7)", "medium",
    /(backup|snapshot|pg_dump|mysqldump|point[_-]?in[_-]?time|disaster[_-]?recovery|restore)/i],
  ["BD009", "Integrity verification present", "164.312(c)(2)", "medium",
    /(checksum|sha256|sha-256|sha512|hmac|signature[_-]?verif|hashlib\.sha)/i],
];

const SKIP = new Set([".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", "vendor"]);
const EXTS = new Set([".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rb", ".php", ".java",
  ".cs", ".sh", ".env", ".cfg", ".ini", ".conf", ".toml", ".yaml", ".yml",
  ".json", ".tf", ".hcl", ".md", ".txt", ".xml", ""]);

function wanted(name) {
  if (EXTS.has(extname(name).toLowerCase())) return true;
  const n = name.toLowerCase();
  return n === "dockerfile" || n === "makefile" || n === "requirements.txt";
}

function walk(p) {
  let st;
  try { st = statSync(p); } catch { return []; }
  if (st.isDirectory()) {
    if (SKIP.has(basename(p))) return [];
    return readdirSync(p).flatMap((f) => walk(join(p, f)));
  }
  return st.size <= 2_000_000 && wanted(basename(p)) ? [p] : [];
}

function isComment(line) {
  const t = line.trimStart();
  return t.startsWith("#") && !t.includes("BEGIN");
}

const F = (check_id, title, safeguard, severity, status, message, file, line) =>
  ({ check_id, title, safeguard, severity, status, message, file, line });

export function scanText(text, fname, out) {
  const low = fname.toLowerCase();
  const iam = /\.(tf|json|ya?ml|hcl)$/.test(low) || low.includes("policy");
  text.split("\n").forEach((line, i) => {
    const ln = i + 1;
    if (!isComment(line)) {
      for (const re of SECRET) {
        if (re.test(line) && !PLACEHOLDER.test(line)) {
          out.push(F("BD001", "No hardcoded secrets / credentials", "164.312(a)(2)(i)",
            "critical", "fail", "Hardcoded credential/secret detected.", fname, ln));
          break;
        }
      }
    }
    if (INSECURE_URL.test(line) && !LOCALHOST.test(line) &&
        !line.includes("w3.org") && !line.includes("://schemas"))
      out.push(F("BD002", "Encryption in transit", "164.312(e)(1)", "high", "fail",
        "Plaintext http:// endpoint (expect TLS).", fname, ln));
    if (VERIFY_FALSE.test(line))
      out.push(F("BD002", "Encryption in transit", "164.312(e)(1)", "high", "fail",
        "TLS verification disabled.", fname, ln));
    if (WEAK_HASH.test(line) && !line.toLowerCase().includes("checksum"))
      out.push(F("BD003", "No weak cryptographic hashing", "164.312(c)(1)", "medium", "fail",
        "Weak hash (MD5/SHA1) for ePHI integrity.", fname, ln));
    if (iam) {
      if (WILDCARD_IAM.test(line))
        out.push(F("BD004", "Least-privilege access", "164.312(a)(1)", "high", "fail",
          "Wildcard IAM Action/Resource '*'.", fname, ln));
      if (OPEN_INGRESS.test(line))
        out.push(F("BD004", "Least-privilege access", "164.312(a)(1)", "high", "fail",
          "Network rule open to 0.0.0.0/0.", fname, ln));
    }
  });
}

function grade(s) {
  return s >= 90 ? "A" : s >= 80 ? "B" : s >= 70 ? "C" : s >= 60 ? "D" : "F";
}

export function scan(target) {
  let single = false;
  try { single = statSync(target).isFile(); } catch { /* ignore */ }
  const files = single ? [target] : walk(target);
  const findings = [];
  const presenceHit = {};
  for (const fp of files) {
    let text = "";
    try { text = readFileSync(fp, "utf8"); } catch { continue; }
    const rel = single ? basename(fp) : relative(target, fp).replace(/\\/g, "/");
    scanText(text, rel, findings);
    for (const [id, , , , re] of PRESENCE)
      if (!(id in presenceHit) && re.test(text)) presenceHit[id] = rel;
  }
  for (const [id, title, safeguard, severity] of PRESENCE) {
    if (presenceHit[id])
      findings.push(F(id, title, safeguard, "info", "pass",
        `Control evidence found in ${presenceHit[id]}.`, presenceHit[id], 0));
    else
      findings.push(F(id, title, safeguard, severity, "fail",
        "No evidence of this safeguard.", "", 0));
  }
  findings.sort((a, b) =>
    (a.status !== "fail") - (b.status !== "fail") ||
    SEV_ORDER[a.severity] - SEV_ORDER[b.severity] ||
    a.check_id.localeCompare(b.check_id));

  const bySev = {};
  const ded = {};
  let failed = 0, passed = 0;
  for (const f of findings) {
    if (f.status === "fail") {
      failed++;
      bySev[f.severity] = (bySev[f.severity] || 0) + 1;
      ded[f.check_id] = (ded[f.check_id] || 0) + SEV_WEIGHT[f.severity];
    } else passed++;
  }
  let total = 0;
  for (const v of Object.values(ded)) total += Math.min(v, PER_CHECK_CAP);
  const score = Math.max(0, 100 - total);
  const shippable = score >= 80 && !(bySev.critical > 0);
  return {
    score, grade: grade(score), shippable,
    total_checks: 4 + PRESENCE.length, failed, passed,
    by_severity: bySev, findings,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = process.argv.slice(2);
  const asJSON = args.includes("--json");
  const target = args.find((a) => !a.startsWith("-")) || ".";
  const sc = scan(target);
  if (asJSON) {
    console.log(JSON.stringify(sc, null, 2));
  } else {
    console.log("baadiff (node) — HIPAA readiness");
    for (const f of sc.findings)
      if (f.status === "fail")
        console.log(`  ${f.severity.toUpperCase().padEnd(8)} [${f.check_id} ${f.safeguard}] ${f.file ? f.file + ":" + f.line : "(corpus)"}`);
    console.log(`SCORE ${sc.score}/100 grade ${sc.grade}  shippable=${sc.shippable} (${sc.passed} controls, ${sc.failed} gaps)`);
  }
  process.exit(sc.shippable ? 0 : 1);
}
