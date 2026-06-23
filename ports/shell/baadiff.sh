#!/usr/bin/env sh
# POSIX shell port of baadiff — scan a repo/manifest for HIPAA Security Rule
# gaps and print a Business Associate readiness scorecard. Uses only awk/grep/
# find that ship with any POSIX system, so it runs in tiny / air-gapped images
# where no language runtime is installed. Passive and offline: reads local
# files only, never the network.
#
#   sh baadiff.sh <path>          # human table
#   sh baadiff.sh <path> --json   # machine-readable scorecard
#
# It mirrors the reference check IDs (BD001..BD004 line scans, BD005..BD009
# presence), severities, and the 0-100 scoring (per-check cap 30, a critical
# finding blocks "shippable", threshold 80).

set -eu

TARGET="."
JSON=0
for a in "$@"; do
  case "$a" in
    --json) JSON=1 ;;
    -*) ;;
    *) TARGET="$a" ;;
  esac
done

# Build the candidate file list (skip vcs/build/vendor dirs).
list_files() {
  if [ -f "$TARGET" ]; then
    printf '%s\n' "$TARGET"
    return
  fi
  find "$TARGET" \
    \( -name .git -o -name node_modules -o -name .venv -o -name venv \
       -o -name __pycache__ -o -name dist -o -name build -o -name vendor \) -prune \
    -o -type f \( -name '*.py' -o -name '*.js' -o -name '*.ts' -o -name '*.go' \
       -o -name '*.rb' -o -name '*.php' -o -name '*.java' -o -name '*.cs' \
       -o -name '*.sh' -o -name '*.env' -o -name '*.cfg' -o -name '*.ini' \
       -o -name '*.conf' -o -name '*.toml' -o -name '*.yaml' -o -name '*.yml' \
       -o -name '*.json' -o -name '*.tf' -o -name '*.hcl' -o -name '*.md' \
       -o -name '*.txt' -o -name '*.xml' -o -name 'Dockerfile' \
       -o -name 'requirements.txt' \) -print 2>/dev/null
}

# Emit "check_id|severity" lines for line-scan gaps, and presence flags.
FILES=$(list_files)

# Run one awk pass over all files collecting findings + presence markers.
RESULT=$(printf '%s\n' "$FILES" | awk '
  BEGIN { IGNORECASE=1 }
  function lc(s){ return tolower(s) }
  # read each file path from stdin list, process its lines
  {
    fn=$0
    if (fn=="") next
    while ((getline line < fn) > 0) {
      l=lc(line)
      # BD001 secret
      if (line !~ /^[ \t]*#/ ) {
        if ((l ~ /(secret|password|passwd|pwd|api[_-]?key|token|aws_secret_access_key|aws_access_key_id)/) \
            && (line ~ /[:=]/) && (line ~ /["\x27][^"\x27]{6,}["\x27]/) \
            && (l !~ /(your|example|changeme|placeholder|xxxx|os\.environ|getenv|process\.env|\$\{|<)/)) {
          fail["BD001"]++; sev["BD001"]="critical"
        }
        if (line ~ /-----BEGIN/) { fail["BD001"]++; sev["BD001"]="critical" }
      }
      # BD002 transport
      if ((l ~ /http:\/\//) && (l !~ /http:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0)/) \
          && (l !~ /w3\.org/) && (l !~ /:\/\/schemas/)) { fail["BD002"]++; sev["BD002"]="high" }
      if (l ~ /verify[ ]*=[ ]*false/ || l ~ /rejectunauthorized[ ]*:[ ]*false/ \
          || l ~ /insecureskipverify[ ]*:[ ]*true/) { fail["BD002"]++; sev["BD002"]="high" }
      # BD003 weak hash
      if ((l ~ /\<(md5|sha1)\>[ ]*\(/) && (l !~ /checksum/)) { fail["BD003"]++; sev["BD003"]="medium" }
      # BD004 IAM (only on config-ish files)
      if (fn ~ /\.(tf|json|ya?ml|hcl)$/ || fn ~ /policy/) {
        if (line ~ /["\x27](Action|Resource)["\x27][ ]*:[ ]*["\x27]\*["\x27]/ || line ~ /0\.0\.0\.0\/0/) {
          fail["BD004"]++; sev["BD004"]="high"
        }
      }
      # presence markers
      if (l ~ /(encrypted[ ]*[:=][ ]*true|kms_key|server_side_encryption|sse_algorithm|storage_encrypted[ ]*=[ ]*true|encryption at rest)/) pres["BD005"]=1
      if (l ~ /(audit[_-]?log|cloudtrail|access[_-]?log|enable_logging|log_group|logging\.(info|warning|error))/) pres["BD006"]=1
      if (l ~ /(oauth|openid|jwt|authenticat|authoriz|rbac|login_required|ensure_authenticated|mfa|bcrypt|argon2|pbkdf2)/) pres["BD007"]=1
      if (l ~ /(backup|snapshot|pg_dump|mysqldump|point[_-]?in[_-]?time|disaster[_-]?recovery|restore)/) pres["BD008"]=1
      if (l ~ /(checksum|sha256|sha-256|sha512|hmac|hashlib\.sha)/) pres["BD009"]=1
    }
    close(fn)
  }
  END {
    for (k in fail) printf "FAIL %s %s %d\n", k, sev[k], fail[k]
    split("BD005 BD006 BD007 BD008 BD009", pids, " ")
    split("high high critical medium medium", psev, " ")
    for (i=1;i<=5;i++) {
      if (pres[pids[i]]==1) printf "PASS %s\n", pids[i]
      else printf "PFAIL %s %s\n", pids[i], psev[i]
    }
  }
')

# Score in shell. Per check id, accumulate a deduction, cap it at CAP, sum.
weight() { case "$1" in critical) echo 18;; high) echo 10;; medium) echo 5;; low) echo 2;; *) echo 0;; esac; }
CAP=30
crit=0
failed=0
passed=0
GAPS=""
DED=""   # space-separated "ID:points" tokens

add_ded() { # id points
  _id="$1"; _add="$2"; _new=""; _found=0
  for tok in $DED; do
    tid=${tok%%:*}; tval=${tok#*:}
    if [ "$tid" = "$_id" ]; then tval=$((tval + _add)); _found=1; fi
    _new="$_new $tid:$tval"
  done
  [ "$_found" -eq 0 ] && _new="$_new $_id:$_add"
  DED="$_new"
}

while IFS= read -r row; do
  [ -z "$row" ] && continue
  set -- $row
  kind="${1:-}"; id="${2:-}"; sv="${3:-info}"; n="${4:-1}"
  case "$kind" in
    FAIL)
      w=$(weight "$sv"); add_ded "$id" $((w * n))
      failed=$((failed + n))
      [ "$sv" = "critical" ] && crit=$((crit + n))
      GAPS="$GAPS  $(echo "$sv" | tr a-z A-Z) [$id]\n"
      ;;
    PFAIL)
      w=$(weight "$sv"); add_ded "$id" "$w"
      failed=$((failed + 1))
      [ "$sv" = "critical" ] && crit=$((crit + 1))
      GAPS="$GAPS  $(echo "$sv" | tr a-z A-Z) [$id] (corpus)\n"
      ;;
    PASS) passed=$((passed + 1)) ;;
  esac
done <<EOF
$RESULT
EOF

# apply per-check cap and compute score
total=0
for tok in $DED; do
  d=${tok#*:}
  [ "$d" -gt "$CAP" ] && d=$CAP
  total=$((total + d))
done
score=$((100 - total))
[ "$score" -lt 0 ] && score=0

if   [ "$score" -ge 90 ]; then grade=A
elif [ "$score" -ge 80 ]; then grade=B
elif [ "$score" -ge 70 ]; then grade=C
elif [ "$score" -ge 60 ]; then grade=D
else grade=F; fi

shippable=false
if [ "$score" -ge 80 ] && [ "$crit" -eq 0 ]; then shippable=true; fi

if [ "$JSON" -eq 1 ]; then
  printf '{"score":%d,"grade":"%s","shippable":%s,"total_checks":9,"failed":%d,"passed":%d}\n' \
    "$score" "$grade" "$shippable" "$failed" "$passed"
else
  printf 'baadiff (sh) — HIPAA readiness\n'
  printf "%b" "$GAPS"
  printf 'SCORE %d/100 grade %s  shippable=%s (%d controls, %d gaps)\n' \
    "$score" "$grade" "$shippable" "$passed" "$failed"
fi

[ "$shippable" = "true" ] && exit 0 || exit 1
