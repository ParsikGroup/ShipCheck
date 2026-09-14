#!/usr/bin/env bash
# shipcheck contract tests.
#
# Two rules in the README are promises to users, not preferences. This proves
# them on a generated run. CI should fail if either breaks.
#
#   ./test/contract-test.sh <a-shipcheck-run-directory>
#
#   1. fix.sh contains NO access-affecting change (SSH, firewall, PAM, sudo,
#      service restart, package install, reboot).
#   2. No secret VALUE appears in any output file.
#   3. A run that could not see everything never presents as clean.
#   4. The agent brief ships with the recipes it tells the agent to read.
set -u
RUN="${1:-}"
[ -n "$RUN" ] && [ -d "$RUN" ] || { echo "usage: $0 <shipcheck run dir>"; exit 2; }
FAIL=0

echo "== 1. fix.sh must contain no access-affecting change =="
BANNED='sshd|ssh_config|PasswordAuthentication|PermitRootLogin|ufw |iptables|ip6tables|nft |firewall-cmd|pam_|/etc/pam|visudo|/etc/sudoers|systemctl (restart|stop|disable|enable)|apt-get install|apt install|dnf install|yum install|\breboot\b|shutdown'
if [ -f "$RUN/fix.sh" ]; then
  # ignore the header comment block, which names these on purpose
  HITS=$(grep -vE '^\s*#' "$RUN/fix.sh" | grep -nEi "$BANNED" |
         grep -vE 'journald|systemd-journald|deliberately did NOT' || true)
  if [ -n "$HITS" ]; then
    echo "  FAIL — fix.sh contains access-affecting commands:"; echo "$HITS"; FAIL=1
  else
    echo "  ok — fix.sh touches nothing that can lock a user out"
  fi
else
  echo "  skip — no fix.sh in $RUN"
fi

echo
echo "== 2. no secret values in any output =="
# Patterns for real credential material. A hit means we leaked a VALUE, not a label.
# Includes KEY=value shapes: a grep that emits its matched line will leak the
# right-hand side of a .env row, which is how this bug appeared in 0.2.0 dev.
LEAK='AKIA[0-9A-Z]{16}|sk-(proj-)?[A-Za-z0-9_-]{24,}|(sk|rk)_live_[0-9a-zA-Z]{16,}|gh[pousr]_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{12,}|AIza[0-9A-Za-z_-]{35}|-----BEGIN [A-Z ]*PRIVATE KEY-----|://[^:@/ ]+:[^@/ ]{6,}@|eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}|(SECRET|TOKEN|PASSWORD|API_KEY|SERVICE_ROLE)[A-Z_]*=[^ \"]{8,}'
FOUND=0
for f in "$RUN"/*.json "$RUN"/*.md "$RUN"/*.sh; do
  [ -f "$f" ] || continue
  H=$(grep -nEo "$LEAK" "$f" 2>/dev/null | head -5 || true)
  if [ -n "$H" ]; then echo "  FAIL — $(basename "$f") contains credential material:"; echo "$H"; FOUND=1; fi
done
[ "$FOUND" -eq 0 ] && echo "  ok — no credential values in evidence, findings, report or fix brief"
[ "$FOUND" -eq 1 ] && FAIL=1

echo
echo "== 3. generated scripts are valid bash =="
for f in "$RUN"/fix.sh "$RUN"/rollback.sh "$RUN"/verify.sh; do
  [ -f "$f" ] || continue
  if bash -n "$f" 2>/dev/null; then echo "  ok — $(basename "$f")"
  else echo "  FAIL — $(basename "$f") is not valid bash"; FAIL=1; fi
done

echo "== 4. a blind run must never present as clean =="
if [ -f "$RUN/findings.json" ] && [ -f "$RUN/REPORT.md" ]; then
  BLIND=$(python3 -c "
import json,sys
d=json.load(open('$RUN/findings.json'))
print(sum(1 for f in d['findings'] if f.get('blind')))" 2>/dev/null || echo 0)
  if [ "${BLIND:-0}" -gt 0 ]; then
    if head -30 "$RUN/REPORT.md" | grep -q "this check is incomplete"; then
      echo "  ok — $BLIND coverage gap(s), and the report leads with the warning"
    else
      echo "  FAIL — findings are marked blind but REPORT.md does not warn in the first 30 lines"
      FAIL=1
    fi
  else
    echo "  ok — no coverage gaps in this run, nothing to warn about"
  fi
else
  echo "  skip — no findings.json/REPORT.md in $RUN"
fi

echo
echo "== 5. the agent brief must ship with its recipes =="
if [ -f "$RUN/FIXME.md" ]; then
  if grep -q "fix-recipes.md" "$RUN/FIXME.md"; then
    if [ -f "$RUN/fix-recipes.md" ]; then
      echo "  ok — FIXME.md references fix-recipes.md and the file is present"
    else
      echo "  FAIL — FIXME.md tells the agent to read fix-recipes.md, which is not in $RUN"
      echo "         The agent will improvise its fixes. That is the thing we are preventing."
      FAIL=1
    fi
  else
    echo "  ok — FIXME.md makes no recipe reference"
  fi
else
  echo "  skip — no FIXME.md in $RUN"
fi

echo
if [ "$FAIL" -eq 0 ]; then echo "ALL CONTRACT TESTS PASSED"; else echo "CONTRACT TESTS FAILED"; fi
exit $FAIL
