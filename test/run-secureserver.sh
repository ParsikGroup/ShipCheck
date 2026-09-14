#!/usr/bin/env bash
# Behavioural test for secureserver.
#
# The static contract tests prove the script does not CONTAIN anything
# dangerous. This proves the two things that actually matter in practice:
#
#   A. apply -> rollback leaves the machine byte-identical to how it started.
#   B. the deadman switch really does revert on its own when nobody confirms.
#
# Needs root and a disposable machine. Refuses to run on anything that looks
# like somebody's real server.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SS="$HERE/../skills/shipcheck/scripts/secureserver.sh"
FAIL=0
pass() { echo "  ok   — $*"; }
fail() { echo "  FAIL — $*"; FAIL=1; }

echo "==> secureserver behavioural test"

[ -f "$SS" ] || { echo "secureserver.sh not found at $SS"; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
  echo "  skip — needs root. Run under sudo, or in CI."
  exit 0
fi

# Refuse to mutate a machine that is doing real work. A test that hardens
# somebody's production box and then rolls it back is not a good test.
if [ -z "${CI:-}" ] && [ ! -f /.dockerenv ] && [ -z "${SECURESERVER_TEST_FORCE:-}" ]; then
  echo "  skip — not in CI or a container."
  echo "         This test modifies the machine and undoes it. Set"
  echo "         SECURESERVER_TEST_FORCE=1 if you really mean it."
  exit 0
fi

. /etc/os-release 2>/dev/null || true
case "${ID:-}" in
  ubuntu|debian|raspbian|linuxmint|pop) ;;
  *) echo "  skip — secureserver only supports Debian/Ubuntu, this is ${ID:-unknown}"; exit 0 ;;
esac

WATCH_SYSCTL="kernel.dmesg_restrict kernel.kptr_restrict net.ipv4.conf.all.accept_redirects
              net.ipv4.conf.all.log_martians fs.protected_symlinks"
WATCH_FILES="/etc/cron.d /etc/cron.daily /etc/crontab /root /etc/shadow"
MADE="/etc/sysctl.d/99-secureserver.conf
      /etc/profile.d/99-secureserver-autologout.sh
      /etc/systemd/journald.conf.d/99-secureserver.conf"

snapshot() {
  for k in $WATCH_SYSCTL; do printf 'sysctl %s=%s\n' "$k" "$(sysctl -n "$k" 2>/dev/null)"; done
  for f in $WATCH_FILES; do
    [ -e "$f" ] && printf 'mode %s=%s %s\n' "$f" "$(stat -c '%a' "$f")" "$(stat -c '%U:%G' "$f")"
  done
  for f in $MADE; do printf 'exists %s=%s\n' "$f" "$([ -e "$f" ] && echo yes || echo no)"; done
}

rm -rf /var/backups/secureserver
BEFORE="$(snapshot)"

# ---------------------------------------------------------------- A. round trip
echo
echo "== A. apply, then roll back, and land exactly where we started =="

# Package installs need the network and are slow; the round-trip property is
# what is under test, not apt. Those steps have their own coverage in CI.
if ! "$SS" --yes --no-deadman --skip updates,fail2ban >/dev/null 2>&1; then
  fail "secureserver.sh exited non-zero"
fi

BK="$(ls -d /var/backups/secureserver/*/ 2>/dev/null | head -1)"
if [ -z "$BK" ]; then
  fail "no backup directory was created — there is nothing to roll back to"
  echo; echo "SECURESERVER TEST FAILED"; exit 1
fi
pass "backup directory created at $BK"

for f in manifest rollback.sh confirm.sh SUMMARY.md; do
  [ -s "$BK/$f" ] && pass "wrote $f" || fail "$f missing or empty"
done

APPLIED="$(snapshot)"
if [ "$APPLIED" = "$BEFORE" ]; then
  fail "nothing actually changed — the test proves nothing"
else
  pass "the machine changed ($(diff <(echo "$BEFORE") <(echo "$APPLIED") | grep -c '^>') settings)"
fi

for f in $MADE; do
  [ -e "$f" ] && pass "created $(basename "$f")" || fail "expected $f to exist after apply"
done

"$BK/rollback.sh" --auto >/dev/null 2>&1
AFTER="$(snapshot)"
if [ "$AFTER" = "$BEFORE" ]; then
  pass "rollback restored every watched value exactly"
else
  fail "rollback did not restore the original state:"
  diff <(echo "$BEFORE") <(echo "$AFTER") | sed 's/^/         /'
fi

# ------------------------------------------------------------------ B. deadman
echo
echo "== B. the guard reverts on its own when nobody confirms =="

rm -rf /var/backups/secureserver
if ! command -v script >/dev/null 2>&1; then
  echo "  skip — util-linux 'script' not available to fake a terminal"
else
  script -qec "$SS --yes --skip updates,fail2ban --timeout 20" /dev/null >/dev/null 2>&1
  BK="$(ls -d /var/backups/secureserver/*/ 2>/dev/null | head -1)"
  if [ -z "$BK" ]; then
    fail "apply did not run under a pty"
  elif [ ! -e /etc/sysctl.d/99-secureserver.conf ]; then
    fail "apply did not take effect, so the revert proves nothing"
  else
    pass "applied, guard armed, deliberately not confirming"
    sleep 30
    if [ -e /etc/sysctl.d/99-secureserver.conf ]; then
      fail "the guard did NOT fire — the machine stayed changed with nobody confirming"
      fail "this is the single most important promise the tool makes"
    else
      pass "the machine reverted itself with no human involved"
    fi
    AFTER="$(snapshot)"
    [ "$AFTER" = "$BEFORE" ] && pass "and it landed back on the original state" \
                             || fail "guard fired but state does not match the original"
  fi
fi

# --------------------------------------------------------------------- C. clean
rm -rf /var/backups/secureserver

echo
if [ "$FAIL" -eq 0 ]; then echo "SECURESERVER TEST PASSED"; else echo "SECURESERVER TEST FAILED"; fi
exit $FAIL
