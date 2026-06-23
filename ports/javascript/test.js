// Smoke test for the JavaScript port. Run: node test.js  (exit 0 on success)
import { scan, scanText } from "./index.js";
import { mkdtempSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

let failures = 0;
function ok(cond, msg) {
  if (!cond) { console.error("FAIL:", msg); failures++; }
  else { console.log("ok -", msg); }
}

// scanText detects a hardcoded secret + plaintext http + weak hash
const fs = [];
scanText('DB_PASSWORD = "S3cr3tP@ssw0rd123"', "c.py", fs);
ok(fs.some((f) => f.check_id === "BD001" && f.severity === "critical"),
  "BD001 detects hardcoded secret");

const fs2 = [];
scanText('API = "http://labs.example.com"', "c.py", fs2);
ok(fs2.some((f) => f.check_id === "BD002"), "BD002 detects plaintext http");

const fs3 = [];
scanText('API = "https://labs.example.com"', "c.py", fs3);
ok(!fs3.some((f) => f.check_id === "BD002"), "BD002 allows https");

const fs4 = [];
scanText('h = hashlib.md5(x)', "c.py", fs4);
ok(fs4.some((f) => f.check_id === "BD003"), "BD003 detects md5");

const fs5 = [];
scanText('pw = os.environ["DB_PASSWORD"]', "c.py", fs5);
ok(!fs5.some((f) => f.check_id === "BD001"), "BD001 ignores env reference");

// scan a tiny repo: a critical secret blocks shippable
const dir = mkdtempSync(join(tmpdir(), "baadiff-js-"));
writeFileSync(join(dir, "app.py"),
  'DB_PASSWORD = "S3cr3tP@ssw0rd123"\nfrom flask_login import login_required\n');
const sc = scan(dir);
ok(typeof sc.score === "number" && sc.score >= 0 && sc.score <= 100,
  "score in range");
ok(sc.shippable === false, "critical secret blocks shippable");
ok(sc.total_checks === 9, "reports 9 checks");
ok(sc.by_severity.critical >= 1, "counts the critical");
ok(sc.grade.length === 1, "grade is a letter");

// a clean repo can ship
const dir2 = mkdtempSync(join(tmpdir(), "baadiff-js-"));
writeFileSync(join(dir2, "app.py"),
  "import os, hashlib, logging\n" +
  "from flask_login import login_required\n" +
  "log = logging.getLogger('s')\n" +
  "DB = os.environ['DB']\n" +
  "API = 'https://x.example'\n" +
  "storage_encrypted = true\n" +
  "# backup snapshot ; cloudtrail audit_log\n" +
  "def h(x):\n    return hashlib.sha256(x).hexdigest()\n");
const sc2 = scan(dir2);
ok(sc2.score >= 80 && sc2.shippable === true, "clean repo is shippable");

if (failures) { console.error(`\n${failures} test(s) failed`); process.exit(1); }
console.log("\nall JS port tests passed");
