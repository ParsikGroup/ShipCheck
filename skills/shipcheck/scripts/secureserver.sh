#!/usr/bin/env bash
# secureserver — apply the obvious hardening, automatically, without ever
# costing you access to your own machine.
#
#   sudo ./secureserver.sh                 # show the plan, then apply it
#   sudo ./secureserver.sh --dry-run       # show the plan and stop
#   sudo ./secureserver.sh --yes           # no countdown, still guarded
#   sudo ./secureserver.sh --timeout 1200  # give yourself 20 min to confirm
#   sudo ./secureserver.sh --skip fail2ban,autologout
#   sudo ./secureserver.sh --only sysctl,perms
#
# WHAT IT WILL NEVER DO
#   It does not edit sshd_config. It does not change firewall rules or default
#   policy. It does not touch PAM, sudoers, user accounts or passwords. It does
#   not reboot. Every one of those can end your session on a headless box, and a
#   script cannot know whether you have console access. Those fixes are real and
#   they matter — they live in SECURESERVER.md as a supervised procedure with
#   the two-terminal drill spelled out.
#
# THE DEADMAN SWITCH
#   Every change is backed up before it is made, and a timer is armed BEFORE the
#   first change. If you do not run confirm.sh from a SECOND terminal within the
#   timeout, the machine reverts itself to exactly how it was. You cannot lose
#   the box by walking away.
set -uo pipefail

VERSION="0.3.0"
TIMEOUT=600
TMOUT_SECS=900
DRY=0; ASSUME_YES=0; NO_DEADMAN=0
ONLY=""; SKIP=""

STEPS="updates fail2ban sysctl journald perms autologout timesync ctrlaltdel"

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)     DRY=1 ;;
    --yes|-y)      ASSUME_YES=1 ;;
    --no-deadman)  NO_DEADMAN=1 ;;
    --timeout)     TIMEOUT="${2:-600}"; shift ;;
    --tmout)       TMOUT_SECS="${2:-900}"; shift ;;
    --only)        ONLY="${2:-}"; shift ;;
    --skip)        SKIP="${2:-}"; shift ;;
    --version)     echo "secureserver $VERSION"; exit 0 ;;
    -h|--help)     sed -n '2,28p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac; shift
done

c_red=''; c_grn=''; c_ylw=''; c_dim=''; c_off=''
if [ -t 1 ]; then
  c_red=$'\033[31m'; c_grn=$'\033[32m'; c_ylw=$'\033[33m'
  c_dim=$'\033[2m'; c_off=$'\033[0m'
fi
say()  { printf '%s\n' "$*" >&2; }
# "0 minutes" is a bug report waiting to happen. Say what a person would say.
dur() {
  local s="$1"
  if   [ "$s" -lt 120 ];  then echo "$s seconds"
  elif [ "$s" -lt 7200 ]; then echo "$((s/60)) minutes"
  else echo "$((s/3600)) hours"; fi
}
ok()   { printf '  %s+%s %s\n' "$c_grn" "$c_off" "$*" >&2; }
warn() { printf '  %s!%s %s\n' "$c_ylw" "$c_off" "$*" >&2; }
bad()  { printf '  %sx%s %s\n' "$c_red" "$c_off" "$*" >&2; }
dim()  { printf '  %s%s%s\n' "$c_dim" "$*" "$c_off" >&2; }

wanted() {
  local s="$1"
  [ -n "$ONLY" ] && { printf '%s' ",$ONLY," | grep -q ",$s," || return 1; }
  [ -n "$SKIP" ] && { printf '%s' ",$SKIP," | grep -q ",$s," && return 1; }
  return 0
}
have() { command -v "$1" >/dev/null 2>&1; }

# `dpkg -s pkg` succeeds for a package that was REMOVED but not purged — its
# status is then "deinstall ok config-files" and the binaries are gone. Using it
# as an is-installed test means we skip the install and then try to configure
# software that is not there. Ask for the status explicitly.
pkg_installed() {
  dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q '^install ok installed$'
}

# ---------------------------------------------------------------- preconditions
say ""
say "secureserver $VERSION — conservative hardening with an auto-revert guard"
say ""
say "== checking this machine =="

[ "$(id -u)" -eq 0 ] || { bad "must run as root:  sudo $0"; exit 1; }
ok "running as root"

OS_ID=""; OS_VER=""
[ -r /etc/os-release ] && . /etc/os-release && OS_ID="${ID:-}" && OS_VER="${VERSION_ID:-}"
case "$OS_ID" in
  ubuntu|debian|raspbian|linuxmint|pop) ok "supported OS: ${PRETTY_NAME:-$OS_ID $OS_VER}" ;;
  "") bad "cannot identify this OS (no /etc/os-release). Refusing to guess."; exit 1 ;;
  *)  bad "unsupported OS: ${PRETTY_NAME:-$OS_ID}"
      say ""
      say "  secureserver only handles Debian and Ubuntu family systems, because"
      say "  every step below has been tested there and nowhere else. Applying"
      say "  half of it to a distro it does not understand is worse than doing"
      say "  nothing. Use SECURESERVER.md and do it by hand."
      exit 1 ;;
esac

have systemctl || { bad "no systemd — the auto-revert guard depends on it"; exit 1; }
ok "systemd present"

if ! have apt-get; then
  bad "no apt-get; cannot install packages safely here"; exit 1
fi

# Disk space. An apt install that fills / is a genuine way to break a server.
FREE_MB=$(df -Pm / 2>/dev/null | awk 'NR==2{print $4}')
if [ -n "${FREE_MB:-}" ] && [ "$FREE_MB" -lt 500 ]; then
  bad "only ${FREE_MB}MB free on / — refusing to install packages"
  say "  Free some space, or re-run with:  --skip updates,fail2ban"
  [ -z "$ONLY" ] && [ -z "$SKIP" ] && exit 1
fi
[ -n "${FREE_MB:-}" ] && ok "${FREE_MB}MB free on /"

# A held dpkg lock means another install is in flight. Installing on top of that
# is how you end up with a half-configured package manager.
if have fuser && fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then
  bad "another package manager is running (dpkg lock held)"
  say "  Wait for it to finish, or re-run with:  --skip updates,fail2ban"
  exit 1
fi

# Where are we connecting from? fail2ban must never ban this address.
ADMIN_IP=""
for src in "${SSH_CLIENT:-}" "${SSH_CONNECTION:-}"; do
  [ -n "$src" ] && ADMIN_IP="${src%% *}" && break
done
if [ -z "$ADMIN_IP" ] && have who; then
  ADMIN_IP=$(who -m 2>/dev/null | sed -n 's/.*(\([0-9a-fA-F.:]*\)).*/\1/p' | head -1)
fi
if [ -z "$ADMIN_IP" ] && have ss; then
  ADMIN_IP=$(ss -tnH state established 2>/dev/null |
             awk '$3 ~ /:22$/ {print $4}' | sed 's/:[0-9]*$//' | head -1)
fi
if [ -n "$ADMIN_IP" ]; then
  ok "your address is $ADMIN_IP — fail2ban will be told never to ban it"
else
  warn "could not determine your address; fail2ban will whitelist private ranges only"
fi

ON_TTY=0; [ -t 0 ] && ON_TTY=1
if [ "$ON_TTY" -eq 0 ] && [ "$NO_DEADMAN" -eq 0 ] && [ "$DRY" -eq 0 ]; then
  bad "no terminal attached, so nobody can confirm within the timeout"
  say ""
  say "  Left alone, the guard would revert everything in $(dur "$TIMEOUT") and the run"
  say "  would be pointless. If this is deliberate — a build image, config"
  say "  management, a provisioning script — say so explicitly:"
  say ""
  say "      $0 --yes --no-deadman"
  say ""
  say "  You are then responsible for your own console access."
  exit 1
fi

# ------------------------------------------------------------------------ plan
say ""
say "== plan =="

PLAN=""
add_plan() { PLAN="$PLAN$1"$'\n'; }

if wanted updates; then
  if [ -f /etc/apt/apt.conf.d/20auto-upgrades ] &&
     grep -q '^APT::Periodic::Unattended-Upgrade *"1"' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null; then
    add_plan "  updates     already on — will confirm reboots stay disabled"
  else
    add_plan "  updates     install unattended-upgrades, security patches only, NEVER auto-reboot"
  fi
fi
wanted fail2ban  && add_plan "  fail2ban    install + enable the ssh jail, 5 tries, 1h ban, your IP whitelisted"
wanted sysctl    && add_plan "  sysctl      kernel and network hardening (no forwarding or routing changes)"
wanted journald  && add_plan "  journald    make logs survive a reboot, capped at 500M"
wanted perms     && add_plan "  perms       tighten /etc/shadow, /root, cron, SSH host keys, docker.sock"
wanted autologout && add_plan "  autologout  disconnect idle shells after $((TMOUT_SECS/60)) minutes"
wanted timesync  && add_plan "  timesync    enable clock sync so your logs have honest timestamps"
wanted ctrlaltdel && add_plan "  ctrlaltdel  stop Ctrl+Alt+Del from rebooting the box from the console"

printf '%s' "$PLAN" >&2
say ""
say "  Not touched, on purpose: sshd_config, firewall rules, PAM, sudoers,"
say "  user accounts, reboots. See SECURESERVER.md for those."
say ""

if [ "$DRY" -eq 1 ]; then
  say "Dry run. Nothing was changed."
  exit 0
fi

if [ "$ASSUME_YES" -eq 0 ] && [ "$ON_TTY" -eq 1 ]; then
  printf '  Starting in ' >&2
  for i in 5 4 3 2 1; do printf '%s ' "$i" >&2; sleep 1; done
  printf -- '- Ctrl+C now to stop.\n' >&2
fi

# -------------------------------------------------------------- backup + undo
TS="$(date +%Y%m%d-%H%M%S)"
BK="/var/backups/secureserver/$TS"
mkdir -p "$BK" || { bad "cannot create $BK"; exit 1; }
chmod 700 "$BK"
MANIFEST="$BK/manifest"
: > "$MANIFEST"

# Record an undo entry. rollback.sh replays these in reverse.
undo() { printf '%s\n' "$*" >> "$MANIFEST"; }

# Back up a file before we touch it. If it does not exist yet, record that
# rollback should delete whatever we are about to create.
bk_file() {
  local f="$1"
  if [ -e "$f" ]; then
    mkdir -p "$BK/files$(dirname "$f")"
    cp -a "$f" "$BK/files$f" 2>/dev/null && undo "RESTORE|$f"
  else
    undo "DELETE|$f"
  fi
}

# Record a file's current mode and ownership so rollback can put them back.
bk_mode() {
  local f="$1"
  [ -e "$f" ] || return 0
  local m o
  m=$(stat -c '%a' "$f" 2>/dev/null) || return 0
  o=$(stat -c '%U:%G' "$f" 2>/dev/null) || return 0
  undo "MODE|$f|$m|$o"
}

bk_sysctl() {
  local k="$1" v
  v=$(sysctl -n "$k" 2>/dev/null) || return 0
  undo "SYSCTL|$k|$v"
}

bk_cmd() { undo "CMD|$*"; }

cat > "$BK/rollback.sh" <<'ROLLBACK'
#!/usr/bin/env bash
# Undo one secureserver run. Generated automatically; safe to run more than once.
#   sudo ./rollback.sh          # ask before each step
#   sudo ./rollback.sh --auto   # no questions (this is what the guard uses)
set -uo pipefail
BK="$(cd "$(dirname "$0")" && pwd)"
AUTO=0; [ "${1:-}" = "--auto" ] && AUTO=1
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
[ -f "$BK/manifest" ] || { echo "no manifest in $BK"; exit 1; }

echo "secureserver rollback: undoing $BK"
# Reverse order: the last change made is the first one undone.
tac "$BK/manifest" | while IFS='|' read -r kind a b c; do
  case "$kind" in
    RESTORE)
      if [ -e "$BK/files$a" ]; then
        cp -a "$BK/files$a" "$a" && echo "  restored $a"
      fi ;;
    DELETE)
      if [ -e "$a" ]; then rm -f "$a" && echo "  removed  $a"; fi ;;
    MODE)
      if [ -e "$a" ]; then
        chmod "$b" "$a" 2>/dev/null
        chown "$c" "$a" 2>/dev/null
        echo "  mode     $a -> $b $c"
      fi ;;
    SYSCTL)
      sysctl -q -w "$a=$b" 2>/dev/null && echo "  sysctl   $a -> $b" ;;
    CMD)
      echo "  run      $a"
      [ "$AUTO" -eq 1 ] && sh -c "$a" >/dev/null 2>&1
      [ "$AUTO" -eq 0 ] && sh -c "$a" ;;
  esac
done

systemctl daemon-reload >/dev/null 2>&1
echo "secureserver rollback: done. Your machine is back to how it was."
ROLLBACK
chmod 700 "$BK/rollback.sh"

# ------------------------------------------------------------ arm the deadman
# This happens BEFORE the first change, not after. If the script dies halfway
# through, the guard still brings the machine back.
DEADMAN_ARMED=0
SENTINEL="/run/secureserver.confirmed"
rm -f "$SENTINEL"

if [ "$NO_DEADMAN" -eq 0 ]; then
  if systemd-run --quiet --unit=secureserver-revert --collect \
       --on-active="$TIMEOUT" --description="secureserver auto-revert" \
       /bin/sh -c "[ -f $SENTINEL ] || $BK/rollback.sh --auto" >/dev/null 2>&1; then
    DEADMAN_ARMED=1
  else
    # No transient timers available. A detached sleep does the same job.
    nohup setsid /bin/sh -c \
      "sleep $TIMEOUT; [ -f $SENTINEL ] || $BK/rollback.sh --auto" \
      >/dev/null 2>&1 &
    echo "$!" > /run/secureserver.deadman.pid
    DEADMAN_ARMED=1
  fi
fi

say ""
if [ "$DEADMAN_ARMED" -eq 1 ]; then
  say "== guard armed: this machine reverts itself in $(dur "$TIMEOUT") unless you confirm =="
else
  warn "guard NOT armed (--no-deadman). You are on your own."
fi
say ""
say "== applying =="

CHANGED=0
NOTE=""
note() { NOTE="$NOTE  - $1"$'\n'; }

# --------------------------------------------------------------- 1. updates
if wanted updates; then
  export DEBIAN_FRONTEND=noninteractive
  if ! pkg_installed unattended-upgrades; then
    if apt-get update -qq >/dev/null 2>&1 &&
       apt-get install -y -qq unattended-upgrades >/dev/null 2>&1; then
      bk_cmd "apt-get remove -y -qq unattended-upgrades"
      ok "installed unattended-upgrades"; CHANGED=1
    else
      bad "could not install unattended-upgrades (no network? apt lock held?)"
      note "unattended-upgrades failed to install — run 'apt-get install unattended-upgrades' yourself"
    fi
  else
    dim "unattended-upgrades already installed"
  fi

  if pkg_installed unattended-upgrades; then
    F=/etc/apt/apt.conf.d/20auto-upgrades
    bk_file "$F"
    cat > "$F" <<'AUTOUP'
// managed by secureserver
APT::Periodic::Enable "1";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
AUTOUP
    F=/etc/apt/apt.conf.d/99-secureserver-unattended
    bk_file "$F"
    # Security updates only, and never reboot on its own. A server that reboots
    # itself at 3am without being asked is a worse problem than a stale package.
    cat > "$F" <<'UNATT'
// managed by secureserver
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Mail "";
UNATT
    ok "security updates apply automatically; automatic reboot is off"
    CHANGED=1
    note "updates install on their own now, but a kernel update needs a reboot you choose. Check with: ls /var/run/reboot-required"
  fi
fi

# --------------------------------------------------------------- 2. fail2ban
if wanted fail2ban; then
  if ! pkg_installed fail2ban; then
    export DEBIAN_FRONTEND=noninteractive
    if apt-get install -y -qq fail2ban >/dev/null 2>&1; then
      bk_cmd "apt-get remove -y -qq fail2ban"
      ok "installed fail2ban"; CHANGED=1
    else
      bad "could not install fail2ban"
      note "fail2ban failed to install — try 'apt-get install fail2ban'"
    fi
  else
    dim "fail2ban already installed"
  fi

  if pkg_installed fail2ban; then
    IGNORE="127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 fc00::/7"
    [ -n "$ADMIN_IP" ] && IGNORE="$IGNORE $ADMIN_IP"
    F=/etc/fail2ban/jail.d/secureserver.local
    mkdir -p /etc/fail2ban/jail.d
    bk_file "$F"
    cat > "$F" <<JAIL
# managed by secureserver — delete this file to undo
[DEFAULT]
# Never lock out the address this was configured from, or anything on the LAN.
ignoreip = $IGNORE
bantime  = 1h
findtime = 10m
maxretry = 5
# A permanent ban on a box with no console is how people lose servers. An hour
# is long enough to make brute force pointless and short enough to survive.

[sshd]
enabled = true
JAIL
    bk_cmd "systemctl restart fail2ban"
    if systemctl enable --now fail2ban >/dev/null 2>&1 &&
       systemctl restart fail2ban >/dev/null 2>&1; then
      ok "fail2ban watching SSH — 5 failures = 1 hour ban, your IP exempt"
      CHANGED=1
    else
      bad "fail2ban would not start — check: journalctl -u fail2ban -n 30"
      note "fail2ban is installed but not running"
    fi
  fi
fi

# ---------------------------------------------------------------- 3. sysctl
if wanted sysctl; then
  F=/etc/sysctl.d/99-secureserver.conf
  bk_file "$F"
  # Deliberately absent: ip_forward (breaks Docker), rp_filter (breaks
  # asymmetric routing and some VPNs), accept_ra (breaks IPv6 on most VPS).
  # Every line below is safe on a normal server and reversible without a reboot.
  KEYS="kernel.randomize_va_space kernel.dmesg_restrict kernel.kptr_restrict
        kernel.yama.ptrace_scope fs.protected_hardlinks fs.protected_symlinks
        fs.protected_fifos fs.protected_regular fs.suid_dumpable
        net.ipv4.tcp_syncookies
        net.ipv4.conf.all.accept_source_route net.ipv4.conf.default.accept_source_route
        net.ipv6.conf.all.accept_source_route net.ipv6.conf.default.accept_source_route
        net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects
        net.ipv6.conf.all.accept_redirects net.ipv6.conf.default.accept_redirects
        net.ipv4.conf.all.secure_redirects net.ipv4.conf.default.secure_redirects
        net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects
        net.ipv4.icmp_echo_ignore_broadcasts net.ipv4.icmp_ignore_bogus_error_responses
        net.ipv4.conf.all.log_martians net.ipv4.conf.default.log_martians"
  for k in $KEYS; do bk_sysctl "$k"; done

  cat > "$F" <<'SYSCTL'
# managed by secureserver
# Address space layout randomisation, fully on.
kernel.randomize_va_space = 2
# Stop unprivileged users reading the kernel log and kernel pointers.
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
# A process may only be debugged by its own parent.
kernel.yama.ptrace_scope = 1
# Classic /tmp symlink and hardlink races.
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
# Never dump core from a setuid binary.
fs.suid_dumpable = 0
# Survive a SYN flood.
net.ipv4.tcp_syncookies = 1
# Attacker-chosen routing. No legitimate use on a server.
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
# ICMP redirects can silently rewrite your routing table.
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
# Do not answer broadcast pings; do not amplify.
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
# Log packets with impossible source addresses.
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
SYSCTL
  # Apply only our file, so an unrelated broken sysctl file elsewhere cannot
  # turn this into a surprise.
  if sysctl -q -p "$F" 2>/dev/null; then
    ok "kernel hardening applied ($(grep -c '^[a-z]' "$F") settings)"
    CHANGED=1
  else
    warn "some sysctl keys are not available on this kernel — the rest applied"
    CHANGED=1
  fi
fi

# -------------------------------------------------------------- 4. journald
if wanted journald; then
  D=/etc/systemd/journald.conf.d
  F="$D/99-secureserver.conf"
  mkdir -p "$D"
  bk_file "$F"
  cat > "$F" <<'JOURNAL'
# managed by secureserver
[Journal]
# Logs that vanish on reboot are useless the one time you need them.
Storage=persistent
SystemMaxUse=500M
SystemMaxFileSize=50M
SystemMaxFiles=20
JOURNAL
  bk_cmd "systemctl restart systemd-journald"
  if systemctl restart systemd-journald >/dev/null 2>&1; then
    ok "logs now survive a reboot, capped at 500M"
    CHANGED=1
  else
    warn "journald would not reload; the config is in place for next boot"
  fi
fi

# ----------------------------------------------------------------- 5. perms
if wanted perms; then
  n=0
  fix_mode() {
    local f="$1" want="$2" owner="${3:-}"
    [ -e "$f" ] || return 0
    local cur; cur=$(stat -c '%a' "$f" 2>/dev/null) || return 0
    [ "$cur" = "$want" ] && return 0
    bk_mode "$f"
    chmod "$want" "$f" 2>/dev/null || return 0
    [ -n "$owner" ] && chown "$owner" "$f" 2>/dev/null
    n=$((n+1))
  }

  # Account databases. /etc/shadow readable by anyone is game over.
  fix_mode /etc/shadow  640 root:shadow
  fix_mode /etc/gshadow 640 root:shadow
  fix_mode /etc/passwd  644 root:root
  fix_mode /etc/group   644 root:root

  # Root's home and scheduled jobs. A writable cron file is a root shell.
  fix_mode /root 700
  fix_mode /etc/crontab 600 root:root
  for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    fix_mode "$d" 700 root:root
  done

  # SSH host PRIVATE keys only. This changes file modes; it does not read,
  # move, regenerate or reconfigure anything, and it cannot affect your login.
  for k in /etc/ssh/ssh_host_*_key; do
    [ -e "$k" ] && fix_mode "$k" 600 root:root
  done

  # The docker socket is root on the host to anyone who can reach it.
  if [ -S /var/run/docker.sock ]; then
    cur=$(stat -c '%a' /var/run/docker.sock 2>/dev/null)
    if [ "$cur" != "660" ]; then
      bk_mode /var/run/docker.sock
      chmod 660 /var/run/docker.sock 2>/dev/null && n=$((n+1))
    fi
  fi

  if [ "$n" -gt 0 ]; then ok "tightened permissions on $n files"; CHANGED=1
  else dim "file permissions were already correct"; fi
fi

# ------------------------------------------------------------ 6. autologout
if wanted autologout; then
  F=/etc/profile.d/99-secureserver-autologout.sh
  bk_file "$F"
  cat > "$F" <<AUTOLOG
# managed by secureserver
# Disconnect interactive shells left idle at a prompt. This counts idle time at
# the prompt only — it will not interrupt a long-running command, an editor, or
# a tail. Deliberately not readonly: if you need a longer session, 'unset TMOUT'
# works, and a control people can turn off is a control they leave on.
if [ -n "\${PS1-}" ]; then
  TMOUT=$TMOUT_SECS
  export TMOUT
fi
AUTOLOG
  chmod 644 "$F"
  ok "idle shells disconnect after $((TMOUT_SECS/60)) minutes"
  CHANGED=1
  note "auto-logout applies to NEW logins. Your current shell keeps its old setting."
fi

# -------------------------------------------------------------- 7. timesync
if wanted timesync; then
  if systemctl list-unit-files 2>/dev/null | grep -q '^systemd-timesyncd'; then
    if ! timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -q yes; then
      bk_cmd "timedatectl set-ntp false"
      timedatectl set-ntp true >/dev/null 2>&1 && { ok "clock sync enabled"; CHANGED=1; }
    else
      dim "clock already synchronised"
    fi
  elif have chronyc; then
    dim "chrony is handling time sync"
  else
    warn "no time sync service found — log timestamps may drift"
    note "install chrony so your logs are trustworthy: apt-get install chrony"
  fi
fi

# ------------------------------------------------------------ 8. ctrlaltdel
if wanted ctrlaltdel; then
  if ! systemctl is-enabled ctrl-alt-del.target 2>/dev/null | grep -q masked; then
    bk_cmd "systemctl unmask ctrl-alt-del.target"
    systemctl mask ctrl-alt-del.target >/dev/null 2>&1 &&
      { ok "Ctrl+Alt+Del no longer reboots the machine"; CHANGED=1; }
  else
    dim "Ctrl+Alt+Del already disabled"
  fi
fi

# ---------------------------------------------------------------- confirm.sh
cat > "$BK/confirm.sh" <<CONFIRM
#!/usr/bin/env bash
# Tell secureserver you are still here. Run this from a SECOND terminal, after
# proving you can open a NEW connection to this machine.
set -u
[ "\$(id -u)" -eq 0 ] || { echo "run as root: sudo \$0"; exit 1; }
touch "$SENTINEL"
systemctl stop secureserver-revert.timer >/dev/null 2>&1
systemctl stop secureserver-revert.service >/dev/null 2>&1
[ -f /run/secureserver.deadman.pid ] && kill "\$(cat /run/secureserver.deadman.pid)" 2>/dev/null
rm -f /run/secureserver.deadman.pid
echo "Confirmed. The auto-revert is cancelled and your changes are permanent."
echo "To undo them later:  sudo $BK/rollback.sh"
CONFIRM
chmod 700 "$BK/confirm.sh"

# -------------------------------------------------------------------- report
{
  echo "# secureserver run $TS"
  echo
  echo "Version $VERSION. Backup and undo live in \`$BK\`."
  echo
  echo "## Changed"
  echo
  printf '%s' "$PLAN"
  echo
  [ -n "$NOTE" ] && { echo "## Worth knowing"; echo; printf '%s' "$NOTE"; echo; }
  echo "## Not done, deliberately"
  echo
  echo "- sshd_config: key-only login, no root login"
  echo "- firewall: default-deny inbound"
  echo "- PAM, sudoers, user accounts, reboots"
  echo
  echo "Each of these can end your session on a machine with no console, so no"
  echo "script here will do them unattended. They are the highest-value fixes"
  echo "left; SECURESERVER.md walks a human through them with a second terminal"
  echo "open."
  echo
  echo "## Undo"
  echo
  echo '```'
  echo "sudo $BK/rollback.sh"
  echo '```'
} > "$BK/SUMMARY.md"

say ""
if [ "$CHANGED" -eq 0 ]; then
  say "== nothing needed changing =="
  [ "$DEADMAN_ARMED" -eq 1 ] && sh -c "[ -f '$SENTINEL' ] || true; $BK/confirm.sh" >/dev/null 2>&1
  say "  This machine already had everything secureserver applies."
  exit 0
fi

if [ -n "$NOTE" ]; then
  say "== worth knowing =="
  printf '%s' "$NOTE" >&2
  say ""
fi

if [ "$DEADMAN_ARMED" -eq 1 ]; then
  cat >&2 <<BANNER

  ================================================================
   ACTION REQUIRED — you have $(dur "$TIMEOUT")
  ================================================================

   Everything above is applied but NOT yet permanent. In $(dur "$TIMEOUT")
   this machine will undo all of it by itself unless you confirm.

   1. Leave this terminal open. Do not close it.
   2. Open a NEW terminal and connect to this machine again.
   3. In that new session, run:

          sudo $BK/confirm.sh

   If step 2 fails, do nothing. Wait. The machine repairs itself
   and you will be able to get back in.

  ================================================================

BANNER
else
  say "  Applied. Undo any time with:  sudo $BK/rollback.sh"
fi

say "  Summary: $BK/SUMMARY.md"
say ""
exit 0
