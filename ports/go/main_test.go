package main

import (
	"os"
	"path/filepath"
	"testing"
)

func hasID(fs []Finding, id, status string) bool {
	for _, f := range fs {
		if f.CheckID == id && f.Status == status {
			return true
		}
	}
	return false
}

func TestScanTextDetectsSecret(t *testing.T) {
	var out []Finding
	scanText(`DB_PASSWORD = "S3cr3tP@ssw0rd123"`, "c.py", &out)
	if !hasID(out, "BD001", "fail") {
		t.Fatal("BD001 not detected")
	}
}

func TestScanTextAllowsHTTPS(t *testing.T) {
	var out []Finding
	scanText(`API = "https://labs.example.com"`, "c.py", &out)
	if hasID(out, "BD002", "fail") {
		t.Fatal("BD002 false positive on https")
	}
}

func TestScanTextDetectsHTTP(t *testing.T) {
	var out []Finding
	scanText(`API = "http://labs.example.com"`, "c.py", &out)
	if !hasID(out, "BD002", "fail") {
		t.Fatal("BD002 not detected")
	}
}

func TestScanTextDetectsMD5(t *testing.T) {
	var out []Finding
	scanText(`h := md5(x)`, "c.go", &out)
	if !hasID(out, "BD003", "fail") {
		t.Fatal("BD003 not detected")
	}
}

func TestScanTextIgnoresEnvSecret(t *testing.T) {
	var out []Finding
	scanText(`pw = os.environ["DB_PASSWORD"]`, "c.py", &out)
	if hasID(out, "BD001", "fail") {
		t.Fatal("BD001 false positive on env reference")
	}
}

func TestScanCriticalBlocksShippable(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "app.py"),
		[]byte("DB_PASSWORD = \"S3cr3tP@ssw0rd123\"\nfrom flask_login import login_required\n"), 0o644)
	sc := scan(dir)
	if sc.Shippable {
		t.Fatal("critical secret should block shippable")
	}
	if sc.Score < 0 || sc.Score > 100 {
		t.Fatalf("score out of range: %d", sc.Score)
	}
	if sc.TotalChecks != 9 {
		t.Fatalf("expected 9 checks, got %d", sc.TotalChecks)
	}
	if sc.BySeverity["critical"] < 1 {
		t.Fatal("critical not counted")
	}
}

func TestScanCleanIsShippable(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "app.py"), []byte(
		"import os, hashlib, logging\n"+
			"from flask_login import login_required\n"+
			"log = logging.getLogger('s')\n"+
			"DB = os.environ['DB']\n"+
			"API = 'https://x.example'\n"+
			"storage_encrypted = true\n"+
			"# backup snapshot ; cloudtrail audit_log\n"+
			"func h(x) { return sha256(x) }\n"), 0o644)
	sc := scan(dir)
	if sc.Score < 80 || !sc.Shippable {
		t.Fatalf("clean repo should ship; score=%d shippable=%v", sc.Score, sc.Shippable)
	}
}

func TestGradeBoundaries(t *testing.T) {
	cases := map[int]string{95: "A", 85: "B", 75: "C", 65: "D", 10: "F"}
	for score, want := range cases {
		if got := grade(score); got != want {
			t.Fatalf("grade(%d)=%s want %s", score, got, want)
		}
	}
}
