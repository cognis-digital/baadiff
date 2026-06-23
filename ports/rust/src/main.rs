// Rust port of baadiff — scan a repo/manifest for HIPAA Security Rule gaps and
// produce a Business Associate readiness scorecard. Single static binary, ZERO
// external crates (std only, so `cargo build` works fully offline / air-gapped).
//
// It mirrors the Python reference's check IDs and scoring. To stay
// dependency-free the matchers use case-insensitive substring logic instead of
// a regex engine; the rule IDs, safeguards, severities, and 0-100 scoring
// (per-check cap, critical blocks "shippable") match the reference.
//
// Passive and offline: reads local files only, never the network.
//
//   cargo run -- <path>            # human table
//   cargo run -- <path> --json     # machine-readable scorecard

use std::collections::BTreeMap;
use std::{env, fs, path::Path, process};

struct Finding {
    check_id: &'static str,
    safeguard: &'static str,
    severity: &'static str,
    status: &'static str,
    file: String,
    line: usize,
}

fn sev_weight(s: &str) -> i32 {
    match s {
        "critical" => 18,
        "high" => 10,
        "medium" => 5,
        "low" => 2,
        _ => 0,
    }
}
fn sev_order(s: &str) -> i32 {
    match s {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}
const PER_CHECK_CAP: i32 = 30;

fn lc(s: &str) -> String {
    s.to_lowercase()
}

// crude key:value secret heuristic: a secret-ish key followed by a quoted value
fn looks_like_secret(line: &str) -> bool {
    let l = lc(line);
    let keys = ["secret", "password", "passwd", "pwd", "api_key", "apikey",
        "api-key", "token", "aws_secret_access_key", "aws_access_key_id"];
    let has_key = keys.iter().any(|k| l.contains(k));
    let has_assign = line.contains('=') || line.contains(':');
    // a quoted value of >=6 chars, or a private-key header
    let quoted = quoted_value_len(line) >= 6;
    (has_key && has_assign && quoted) || line.contains("-----BEGIN")
}

fn quoted_value_len(line: &str) -> usize {
    for q in ['"', '\''] {
        if let Some(a) = line.find(q) {
            if let Some(b) = line[a + 1..].find(q) {
                return b;
            }
        }
    }
    0
}

fn is_placeholder(line: &str) -> bool {
    let l = lc(line);
    ["your", "example", "changeme", "placeholder", "xxxx", "os.environ",
        "getenv", "process.env", "${", "<"]
        .iter()
        .any(|p| l.contains(p))
}

fn insecure_http(line: &str) -> bool {
    let l = lc(line);
    l.contains("http://")
        && !l.contains("http://localhost")
        && !l.contains("http://127.0.0.1")
        && !l.contains("http://0.0.0.0")
        && !l.contains("w3.org")
        && !l.contains("://schemas")
}

fn verify_disabled(line: &str) -> bool {
    let l = lc(line).replace(' ', "");
    l.contains("verify=false")
        || l.contains("rejectunauthorized:false")
        || l.contains("insecureskipverify:true")
}

fn weak_hash(line: &str) -> bool {
    let l = lc(line);
    (l.contains("md5(") || l.contains("sha1(")) && !l.contains("checksum")
}

fn wildcard_iam(line: &str) -> bool {
    let l = line.replace(' ', "");
    l.contains("\"Action\":\"*\"")
        || l.contains("\"Resource\":\"*\"")
        || l.contains("'Action':'*'")
        || l.contains("'Resource':'*'")
}

fn is_iam_file(name: &str) -> bool {
    let l = lc(name);
    l.ends_with(".tf")
        || l.ends_with(".json")
        || l.ends_with(".yaml")
        || l.ends_with(".yml")
        || l.ends_with(".hcl")
        || l.contains("policy")
}

const PRESENCE: [(&str, &str, &str, &[&str]); 5] = [
    ("BD005", "164.312(a)(2)(iv)", "high",
        &["encrypted=true", "encrypted: true", "kms_key", "server_side_encryption",
          "sse_algorithm", "storage_encrypted = true", "encryption at rest"]),
    ("BD006", "164.312(b)", "high",
        &["audit_log", "audit-log", "cloudtrail", "access_log", "enable_logging",
          "log_group", "logging.info", "logging.warning", "logging.error"]),
    ("BD007", "164.312(d)", "critical",
        &["oauth", "openid", "jwt", "authenticat", "authoriz", "rbac",
          "login_required", "ensure_authenticated", "mfa", "bcrypt", "argon2", "pbkdf2"]),
    ("BD008", "164.308(a)(7)", "medium",
        &["backup", "snapshot", "pg_dump", "mysqldump", "point-in-time",
          "disaster-recovery", "restore"]),
    ("BD009", "164.312(c)(2)", "medium",
        &["checksum", "sha256", "sha-256", "sha512", "hmac", "hashlib.sha"]),
];

fn wanted(name: &str) -> bool {
    let n = lc(name);
    let exts = [".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rb", ".php",
        ".java", ".cs", ".sh", ".env", ".cfg", ".ini", ".conf", ".toml",
        ".yaml", ".yml", ".json", ".tf", ".hcl", ".md", ".txt", ".xml"];
    exts.iter().any(|e| n.ends_with(e))
        || n == "dockerfile"
        || n == "makefile"
        || n == "requirements.txt"
        || !n.contains('.')
}

const SKIP: [&str; 8] = [".git", "node_modules", ".venv", "venv", "__pycache__",
    "dist", "build", "vendor"];

fn collect(p: &Path, out: &mut Vec<String>) {
    if p.is_dir() {
        if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
            if SKIP.contains(&name) {
                return;
            }
        }
        if let Ok(rd) = fs::read_dir(p) {
            for e in rd.flatten() {
                collect(&e.path(), out);
            }
        }
    } else if let Some(s) = p.to_str() {
        if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
            if wanted(name) {
                out.push(s.to_string());
            }
        }
    }
}

fn scan_text(text: &str, fname: &str, out: &mut Vec<Finding>) {
    let iam = is_iam_file(fname);
    for (i, line) in text.lines().enumerate() {
        let ln = i + 1;
        let trimmed = line.trim_start();
        let comment = trimmed.starts_with('#') && !trimmed.contains("BEGIN");
        if !comment && looks_like_secret(line) && !is_placeholder(line) {
            out.push(Finding { check_id: "BD001", safeguard: "164.312(a)(2)(i)",
                severity: "critical", status: "fail", file: fname.into(), line: ln });
        }
        if insecure_http(line) {
            out.push(Finding { check_id: "BD002", safeguard: "164.312(e)(1)",
                severity: "high", status: "fail", file: fname.into(), line: ln });
        }
        if verify_disabled(line) {
            out.push(Finding { check_id: "BD002", safeguard: "164.312(e)(1)",
                severity: "high", status: "fail", file: fname.into(), line: ln });
        }
        if weak_hash(line) {
            out.push(Finding { check_id: "BD003", safeguard: "164.312(c)(1)",
                severity: "medium", status: "fail", file: fname.into(), line: ln });
        }
        if iam && (wildcard_iam(line) || line.contains("0.0.0.0/0")) {
            out.push(Finding { check_id: "BD004", safeguard: "164.312(a)(1)",
                severity: "high", status: "fail", file: fname.into(), line: ln });
        }
    }
}

fn grade(s: i32) -> &'static str {
    match s {
        x if x >= 90 => "A",
        x if x >= 80 => "B",
        x if x >= 70 => "C",
        x if x >= 60 => "D",
        _ => "F",
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");
    let target = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .cloned()
        .unwrap_or_else(|| ".".into());

    let root = Path::new(&target);
    let mut files = Vec::new();
    if root.is_file() {
        files.push(target.clone());
    } else {
        collect(root, &mut files);
    }

    let mut findings = Vec::new();
    let mut presence_hit: BTreeMap<&str, String> = BTreeMap::new();
    for f in &files {
        let text = match fs::read_to_string(f) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let rel = Path::new(f)
            .strip_prefix(root)
            .ok()
            .and_then(|p| p.to_str())
            .map(|s| s.replace('\\', "/"))
            .unwrap_or_else(|| f.clone());
        scan_text(&text, &rel, &mut findings);
        let low = lc(&text);
        for (id, _, _, needles) in PRESENCE.iter() {
            if !presence_hit.contains_key(id)
                && needles.iter().any(|n| low.contains(&lc(n)))
            {
                presence_hit.insert(id, rel.clone());
            }
        }
    }
    for (id, safeguard, severity, _) in PRESENCE.iter() {
        if let Some(hit) = presence_hit.get(id) {
            findings.push(Finding { check_id: id, safeguard, severity: "info",
                status: "pass", file: hit.clone(), line: 0 });
        } else {
            findings.push(Finding { check_id: id, safeguard, severity,
                status: "fail", file: String::new(), line: 0 });
        }
    }

    findings.sort_by(|a, b| {
        let af = (a.status != "fail") as i32;
        let bf = (b.status != "fail") as i32;
        af.cmp(&bf)
            .then(sev_order(a.severity).cmp(&sev_order(b.severity)))
            .then(a.check_id.cmp(b.check_id))
    });

    let mut by_sev: BTreeMap<&str, i32> = BTreeMap::new();
    let mut ded: BTreeMap<&str, i32> = BTreeMap::new();
    let (mut failed, mut passed) = (0, 0);
    for f in &findings {
        if f.status == "fail" {
            failed += 1;
            *by_sev.entry(f.severity).or_insert(0) += 1;
            *ded.entry(f.check_id).or_insert(0) += sev_weight(f.severity);
        } else {
            passed += 1;
        }
    }
    let total: i32 = ded.values().map(|v| (*v).min(PER_CHECK_CAP)).sum();
    let score = (100 - total).max(0);
    let shippable = score >= 80 && by_sev.get("critical").copied().unwrap_or(0) == 0;
    let distinct = 4 + PRESENCE.len();

    if as_json {
        let mut items = Vec::new();
        for f in &findings {
            items.push(format!(
                "{{\"check_id\":\"{}\",\"safeguard\":\"{}\",\"severity\":\"{}\",\"status\":\"{}\",\"file\":\"{}\",\"line\":{}}}",
                f.check_id, f.safeguard, f.severity, f.status, f.file, f.line));
        }
        println!(
            "{{\"score\":{},\"grade\":\"{}\",\"shippable\":{},\"total_checks\":{},\"failed\":{},\"passed\":{},\"findings\":[{}]}}",
            score, grade(score), shippable, distinct, failed, passed, items.join(","));
    } else {
        println!("baadiff (rust) — HIPAA readiness");
        for f in &findings {
            if f.status == "fail" {
                let loc = if f.file.is_empty() {
                    "(corpus)".to_string()
                } else {
                    format!("{}:{}", f.file, f.line)
                };
                println!("  {:<8} [{} {}] {}", f.severity.to_uppercase(), f.check_id, f.safeguard, loc);
            }
        }
        println!("SCORE {}/100 grade {}  shippable={} ({} controls, {} gaps)",
            score, grade(score), shippable, passed, failed);
    }
    if !shippable {
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(text: &str, fname: &str) -> Vec<&'static str> {
        let mut out = Vec::new();
        scan_text(text, fname, &mut out);
        out.iter().map(|f| f.check_id).collect()
    }

    #[test]
    fn detects_secret() {
        assert!(ids("DB_PASSWORD = \"S3cr3tP@ssw0rd123\"", "c.py").contains(&"BD001"));
    }

    #[test]
    fn ignores_env_secret() {
        assert!(!ids("pw = os.environ[\"DB_PASSWORD\"]", "c.py").contains(&"BD001"));
    }

    #[test]
    fn ignores_placeholder() {
        assert!(!ids("password = \"changeme\"", "c.py").contains(&"BD001"));
    }

    #[test]
    fn detects_http_allows_https() {
        assert!(ids("API = \"http://labs.example.com\"", "c.py").contains(&"BD002"));
        assert!(!ids("API = \"https://labs.example.com\"", "c.py").contains(&"BD002"));
    }

    #[test]
    fn allows_localhost_http() {
        assert!(!ids("API = \"http://localhost:8080\"", "c.py").contains(&"BD002"));
    }

    #[test]
    fn detects_md5_allows_sha256() {
        assert!(ids("h = md5(x)", "c.py").contains(&"BD003"));
        assert!(!ids("h = sha256(x)", "c.py").contains(&"BD003"));
    }

    #[test]
    fn iam_only_on_config() {
        assert!(ids("cidr = \"0.0.0.0/0\"", "main.tf").contains(&"BD004"));
        assert!(!ids("x = \"0.0.0.0/0\"", "app.py").contains(&"BD004"));
    }

    #[test]
    fn weak_hash_skips_checksum() {
        assert!(!weak_hash("md5(file) # checksum only"));
    }

    #[test]
    fn grade_boundaries() {
        assert_eq!(grade(95), "A");
        assert_eq!(grade(85), "B");
        assert_eq!(grade(75), "C");
        assert_eq!(grade(65), "D");
        assert_eq!(grade(10), "F");
    }

    #[test]
    fn sev_ordering() {
        assert!(sev_weight("critical") > sev_weight("high"));
        assert!(sev_order("critical") < sev_order("high"));
    }
}
