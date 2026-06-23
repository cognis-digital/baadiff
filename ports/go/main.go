// Go port of baadiff — scan a repo/manifest for HIPAA Security Rule gaps and
// produce a Business Associate readiness scorecard. Single static binary, only
// the Go standard library. Mirrors the Python reference: same check IDs
// (BD001..BD004 line scans + BD005..BD009 presence), same JSON shape, same
// 0-100 scoring with a per-check cap and a critical-blocks-shippable rule.
//
// Passive and offline: it only reads local files. No network access.
//
//	go run . <path>            # human table
//	go run . <path> --json     # machine-readable scorecard
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type Finding struct {
	CheckID   string `json:"check_id"`
	Title     string `json:"title"`
	Safeguard string `json:"safeguard"`
	Severity  string `json:"severity"`
	Status    string `json:"status"`
	Message   string `json:"message"`
	File      string `json:"file"`
	Line      int    `json:"line"`
}

type Scorecard struct {
	Score       int            `json:"score"`
	Grade       string         `json:"grade"`
	Shippable   bool           `json:"shippable"`
	TotalChecks int            `json:"total_checks"`
	Failed      int            `json:"failed"`
	Passed      int            `json:"passed"`
	BySeverity  map[string]int `json:"by_severity"`
	Findings    []Finding      `json:"findings"`
}

var severityWeight = map[string]int{
	"critical": 18, "high": 10, "medium": 5, "low": 2, "info": 0,
}
var severityOrder = map[string]int{
	"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}

const perCheckCap = 30

var (
	reSecret = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(aws_secret_access_key|aws_access_key_id)\s*[:=]\s*['"]?[A-Za-z0-9/+]{16,}`),
		regexp.MustCompile(`(?i)(secret|password|passwd|pwd|api[_-]?key|token)\s*[:=]\s*['"][^'"]{6,}['"]`),
		regexp.MustCompile(`-----BEGIN (RSA |EC )?PRIVATE KEY-----`),
	}
	rePlaceholder = regexp.MustCompile(`(?i)(your[_-]?|example|changeme|placeholder|xxxx|<.*?>|\$\{|os\.environ|getenv|process\.env)`)
	reInsecureURL = regexp.MustCompile(`(?i)\bhttp://`)
	reLocalHost   = regexp.MustCompile(`(?i)http://(localhost|127\.0\.0\.1|0\.0\.0\.0)`)
	reVerifyFalse = regexp.MustCompile(`(?i)(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true)`)
	reWeakHash    = regexp.MustCompile(`(?i)\b(md5|sha1)\b\s*\(`)
	reWildcardIAM = regexp.MustCompile(`["']Action["']\s*:\s*["']\*["']|["']Resource["']\s*:\s*["']\*["']`)
	reOpenIngress = regexp.MustCompile(`0\.0\.0\.0/0`)

	reEncRest   = regexp.MustCompile(`(?i)(encrypt(ed|ion)?[\s_-]*(at[\s_-]*rest|enabled|true)|kms[_-]?key|server_side_encryption|sse_algorithm|storage_encrypted\s*=\s*true|encrypted\s*[:=]\s*true)`)
	reAuditLog  = regexp.MustCompile(`(?i)(audit[_-]?log|cloudtrail|access[_-]?log|enable_logging|log_group|logging\.(info|warning|error)|structured[_-]?log)`)
	reAuth      = regexp.MustCompile(`(?i)(oauth|openid|jwt|authenticat|authoriz|rbac|login_required|ensure_authenticated|session\[|mfa|two[_-]?factor|bcrypt|argon2|pbkdf2)`)
	reBackup    = regexp.MustCompile(`(?i)(backup|snapshot|pg_dump|mysqldump|point[_-]?in[_-]?time|disaster[_-]?recovery|restore)`)
	reIntegrity = regexp.MustCompile(`(?i)(checksum|sha256|sha-256|sha512|hmac|signature[_-]?verif|hashlib\.sha)`)
)

type presenceCheck struct {
	id, title, safeguard, severity string
	re                             *regexp.Regexp
}

var presenceChecks = []presenceCheck{
	{"BD005", "Encryption at rest is configured", "164.312(a)(2)(iv)", "high", reEncRest},
	{"BD006", "Audit controls / logging present", "164.312(b)", "high", reAuditLog},
	{"BD007", "Authentication / access control present", "164.312(d)", "critical", reAuth},
	{"BD008", "Backup / contingency plan present", "164.308(a)(7)", "medium", reBackup},
	{"BD009", "Integrity verification present", "164.312(c)(2)", "medium", reIntegrity},
}

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, ".venv": true, "venv": true,
	"__pycache__": true, "dist": true, "build": true, "vendor": true,
}

func isComment(line string) bool {
	t := strings.TrimSpace(line)
	return strings.HasPrefix(t, "#") && !strings.Contains(t, "BEGIN")
}

func scanText(text, fname string, out *[]Finding) {
	low := strings.ToLower(fname)
	iamFile := strings.HasSuffix(low, ".tf") || strings.HasSuffix(low, ".json") ||
		strings.HasSuffix(low, ".yaml") || strings.HasSuffix(low, ".yml") ||
		strings.HasSuffix(low, ".hcl") || strings.Contains(low, "policy")
	for i, line := range strings.Split(text, "\n") {
		ln := i + 1
		if !isComment(line) {
			for _, p := range reSecret {
				if p.MatchString(line) && !rePlaceholder.MatchString(line) {
					*out = append(*out, Finding{"BD001", "No hardcoded secrets / credentials",
						"164.312(a)(2)(i)", "critical", "fail",
						"Hardcoded credential/secret detected.", fname, ln})
					break
				}
			}
		}
		if reInsecureURL.MatchString(line) && !reLocalHost.MatchString(line) &&
			!strings.Contains(line, "w3.org") && !strings.Contains(line, "://schemas") {
			*out = append(*out, Finding{"BD002", "Encryption in transit",
				"164.312(e)(1)", "high", "fail",
				"Plaintext http:// endpoint (expect TLS).", fname, ln})
		}
		if reVerifyFalse.MatchString(line) {
			*out = append(*out, Finding{"BD002", "Encryption in transit",
				"164.312(e)(1)", "high", "fail",
				"TLS verification disabled.", fname, ln})
		}
		if reWeakHash.MatchString(line) && !strings.Contains(strings.ToLower(line), "checksum") {
			*out = append(*out, Finding{"BD003", "No weak cryptographic hashing",
				"164.312(c)(1)", "medium", "fail",
				"Weak hash (MD5/SHA1) for ePHI integrity.", fname, ln})
		}
		if iamFile {
			if reWildcardIAM.MatchString(line) {
				*out = append(*out, Finding{"BD004", "Least-privilege access",
					"164.312(a)(1)", "high", "fail",
					"Wildcard IAM Action/Resource '*'.", fname, ln})
			}
			if reOpenIngress.MatchString(line) {
				*out = append(*out, Finding{"BD004", "Least-privilege access",
					"164.312(a)(1)", "high", "fail",
					"Network rule open to 0.0.0.0/0.", fname, ln})
			}
		}
	}
}

func wanted(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rb", ".php", ".java",
		".cs", ".sh", ".env", ".cfg", ".ini", ".conf", ".toml", ".yaml",
		".yml", ".json", ".tf", ".hcl", ".md", ".txt", ".xml", "":
		return true
	}
	n := strings.ToLower(name)
	return n == "dockerfile" || n == "makefile" || n == "requirements.txt"
}

func grade(s int) string {
	switch {
	case s >= 90:
		return "A"
	case s >= 80:
		return "B"
	case s >= 70:
		return "C"
	case s >= 60:
		return "D"
	default:
		return "F"
	}
}

func scan(target string) Scorecard {
	var findings []Finding
	presenceHit := map[string]string{}
	info, err := os.Stat(target)
	if err == nil && !info.IsDir() {
		b, _ := os.ReadFile(target)
		scanText(string(b), filepath.Base(target), &findings)
		for _, pc := range presenceChecks {
			if pc.re.Match(b) {
				presenceHit[pc.id] = filepath.Base(target)
			}
		}
	} else {
		filepath.Walk(target, func(p string, fi os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if fi.IsDir() {
				if skipDirs[fi.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			if !wanted(fi.Name()) || fi.Size() > 2_000_000 {
				return nil
			}
			b, _ := os.ReadFile(p)
			rel, _ := filepath.Rel(target, p)
			scanText(string(b), rel, &findings)
			for _, pc := range presenceChecks {
				if _, ok := presenceHit[pc.id]; !ok && pc.re.Match(b) {
					presenceHit[pc.id] = rel
				}
			}
			return nil
		})
	}
	for _, pc := range presenceChecks {
		if hit, ok := presenceHit[pc.id]; ok {
			findings = append(findings, Finding{pc.id, pc.title, pc.safeguard,
				"info", "pass", "Control evidence found in " + hit + ".", hit, 0})
		} else {
			findings = append(findings, Finding{pc.id, pc.title, pc.safeguard,
				pc.severity, "fail", "No evidence of this safeguard.", "", 0})
		}
	}
	sort.SliceStable(findings, func(i, j int) bool {
		fi, fj := findings[i], findings[j]
		if (fi.Status == "fail") != (fj.Status == "fail") {
			return fi.Status == "fail"
		}
		if severityOrder[fi.Severity] != severityOrder[fj.Severity] {
			return severityOrder[fi.Severity] < severityOrder[fj.Severity]
		}
		return fi.CheckID < fj.CheckID
	})

	bySev := map[string]int{}
	dedByCheck := map[string]int{}
	failed, passed := 0, 0
	for _, f := range findings {
		if f.Status == "fail" {
			failed++
			bySev[f.Severity]++
			dedByCheck[f.CheckID] += severityWeight[f.Severity]
		} else {
			passed++
		}
	}
	total := 0
	for _, v := range dedByCheck {
		if v > perCheckCap {
			v = perCheckCap
		}
		total += v
	}
	score := 100 - total
	if score < 0 {
		score = 0
	}
	shippable := score >= 80 && bySev["critical"] == 0
	distinct := 4 + len(presenceChecks)
	return Scorecard{score, grade(score), shippable, distinct, failed, passed, bySev, findings}
}

func main() {
	target := "."
	asJSON := false
	for _, a := range os.Args[1:] {
		if a == "--json" {
			asJSON = true
		} else if !strings.HasPrefix(a, "-") {
			target = a
		}
	}
	sc := scan(target)
	if asJSON {
		out, _ := json.MarshalIndent(sc, "", "  ")
		fmt.Println(string(out))
		if !sc.Shippable {
			os.Exit(1)
		}
		return
	}
	fmt.Printf("baadiff (go) — HIPAA readiness\n")
	for _, f := range sc.Findings {
		if f.Status == "fail" {
			loc := "(corpus)"
			if f.File != "" {
				loc = fmt.Sprintf("%s:%d", f.File, f.Line)
			}
			fmt.Printf("  %-8s [%s %s] %s\n", strings.ToUpper(f.Severity), f.CheckID, f.Safeguard, loc)
		}
	}
	fmt.Printf("SCORE %d/100 grade %s  shippable=%v (%d controls, %d gaps)\n",
		sc.Score, sc.Grade, sc.Shippable, sc.Passed, sc.Failed)
	if !sc.Shippable {
		os.Exit(1)
	}
}
