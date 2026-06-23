#!/usr/bin/env sh
# Smoke test for the POSIX shell port. Exit 0 on success.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
BD="$HERE/baadiff.sh"
fails=0
check() { # description expr
  if [ "$2" = "1" ]; then echo "ok - $1"; else echo "FAIL: $1"; fails=$((fails+1)); fi
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# 1) a repo with a hardcoded secret is NOT shippable (exit 1)
mkdir -p "$tmp/bad"
printf 'DB_PASSWORD = "S3cr3tP@ssw0rd123"\nfrom flask_login import login_required\n' > "$tmp/bad/app.py"
out=$(sh "$BD" "$tmp/bad" --json); rc=$?
check "critical secret -> non-zero exit" "$([ $rc -ne 0 ] && echo 1 || echo 0)"
check "critical secret -> shippable false" "$(echo "$out" | grep -q '"shippable":false' && echo 1 || echo 0)"
check "json reports 9 checks" "$(echo "$out" | grep -q '"total_checks":9' && echo 1 || echo 0)"

# 2) a clean repo IS shippable (exit 0)
mkdir -p "$tmp/ok"
cat > "$tmp/ok/app.py" <<'PY'
import os, hashlib, logging
from flask_login import login_required
log = logging.getLogger('s')
DB = os.environ['DB']
API = 'https://x.example'
storage_encrypted = true
# backup snapshot ; cloudtrail audit_log
def h(x):
    return hashlib.sha256(x).hexdigest()
PY
out2=$(sh "$BD" "$tmp/ok" --json); rc2=$?
check "clean repo -> zero exit" "$([ $rc2 -eq 0 ] && echo 1 || echo 0)"
check "clean repo -> shippable true" "$(echo "$out2" | grep -q '"shippable":true' && echo 1 || echo 0)"
check "clean repo -> grade A or B" "$(echo "$out2" | grep -Eq '"grade":"(A|B)"' && echo 1 || echo 0)"

# 3) https is not flagged but http is
mkdir -p "$tmp/http"
printf 'X = "http://plain.example.com"\n' > "$tmp/http/a.py"
out3=$(sh "$BD" "$tmp/http");
check "plaintext http flagged BD002" "$(echo "$out3" | grep -q 'BD002' && echo 1 || echo 0)"

if [ "$fails" -ne 0 ]; then echo ""; echo "$fails test(s) failed"; exit 1; fi
echo ""; echo "all shell port tests passed"
