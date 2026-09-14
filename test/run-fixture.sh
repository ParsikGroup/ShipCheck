#!/usr/bin/env bash
# End-to-end test: run the whole pipeline against the deliberately vulnerable
# fixture, assert every planted problem is detected, then run the contract tests.
#
#   ./test/run-fixture.sh
#
# This is what CI runs. It needs nothing but bash, python3 and git.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
S="$ROOT/skills/shipcheck/scripts"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

echo "==> preparing fixture"
cp -r "$ROOT/test/fixture-app" "$WORK/app"
mv "$WORK/app/.env.fixture" "$WORK/app/.env"
printf 'node_modules\n' > "$WORK/app/.gitignore"   # note: .env NOT ignored, on purpose
git -C "$WORK/app" init -q
git -C "$WORK/app" config user.email ci@example.com
git -C "$WORK/app" config user.name CI
git -C "$WORK/app" add -A >/dev/null 2>&1
git -C "$WORK/app" commit -qm "fixture" >/dev/null 2>&1

echo "==> running shipcheck (code only)"
bash "$S/shipcheck.sh" --no-host --app "$WORK/app" --out "$WORK/run" >/dev/null 2>&1
[ -s "$WORK/run/evidence.json" ] || { echo "FAIL: no evidence.json produced"; exit 1; }
python3 -c "import json;json.load(open('$WORK/run/evidence.json'))" || { echo "FAIL: evidence.json is not valid JSON"; exit 1; }

python3 "$S/analyze.py" "$WORK/run" >/dev/null 2>&1 || { echo "FAIL: analyze.py errored"; exit 1; }
python3 "$S/report.py"  "$WORK/run" >/dev/null 2>&1 || { echo "FAIL: report.py errored"; exit 1; }

echo
echo "==> every planted problem must be detected"
FAIL=0
expect() {  # expect <substring of title> <label>
  if python3 - "$WORK/run/findings.json" "$1" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
sys.exit(0 if any(sys.argv[2].lower() in f["title"].lower() for f in d["findings"]) else 1)
PY
  then echo "  ok    $2"
  else echo "  FAIL  $2  (no finding matching '$1')"; FAIL=1; fi
}
expect "rate limiting"          "no rate limiting on login"
expect "uploads with no checks" "unvalidated file upload"
expect "compiled into your web" "secret behind a public prefix"
expect "service role"           "Supabase service_role key in app code"
expect "firebase rules"         "Firebase rules wide open"
expect "gluing strings"         "SQL string concatenation"
expect "password hashing"       "no password hashing"
expect "any website"            "wildcard CORS"
expect "checks who is calling"  "routes with no auth checks"
expect "committed to git"       ".env committed to git"
expect "credentials are sitting" "hardcoded credentials"

echo
echo "==> contract tests"
bash "$ROOT/test/contract-test.sh" "$WORK/run" || FAIL=1

echo
if [ "$FAIL" -eq 0 ]; then
  echo "FIXTURE TEST PASSED"
else
  echo "FIXTURE TEST FAILED"
fi
exit $FAIL
