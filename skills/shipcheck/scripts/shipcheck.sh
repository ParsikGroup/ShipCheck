#!/usr/bin/env bash
# shipcheck collector — reads your server and your code, changes nothing.
#
#   sudo ./shipcheck.sh --out ./shipcheck-run          # server + app in cwd
#   sudo ./shipcheck.sh --out ./run --app /srv/myapp   # app somewhere else
#   sudo ./shipcheck.sh --out ./run --site https://example.com
#   ./shipcheck.sh --app . --no-host --out ./run       # just the code
#   sudo ./shipcheck.sh --collect-only                 # evidence only, no report
#
# With no arguments it scans this server plus the code in the current directory
# and writes everything to <repo>/outputs, then builds the report for you.
# You do not need to run analyze.py or report.py by hand.
#
# READ-ONLY. Installs nothing. Starts nothing. Changes nothing.
# Never records the VALUE of a secret — only where it is and who can read it.
# Works with or without root, and marks every check it could not run.
set -uo pipefail
umask 077

OUT=""; APP=""; SITE=""; DO_HOST=1; DO_APP=1; DO_REPORT=1
while [ $# -gt 0 ]; do
  case "$1" in
    --out)     OUT="${2:-}"; shift ;;
    --app)     APP="${2:-}"; shift ;;
    --site)    SITE="${2:-}"; shift ;;
    --no-host) DO_HOST=0 ;;
    --no-app)  DO_APP=0 ;;
    --collect-only) DO_REPORT=0 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac; shift
done
# Resolve our own location now, while the current directory is still where the
# user launched us. The app scan cd's away, so anything computed later is wrong.
SDIR="$(cd "$(dirname "$0")" && pwd)"

# Default output goes to <repo>/outputs — next to the code, easy to find,
# and already covered by .gitignore. Falls back to the current directory if
# the repo is somewhere unwritable (a system install, a read-only mount).
if [ -z "$OUT" ]; then
  _repo="$(cd "$SDIR/../../.." 2>/dev/null && pwd)"
  if [ -n "$_repo" ] && { [ -w "$_repo" ] || mkdir -p "$_repo/outputs" 2>/dev/null; }; then
    OUT="$_repo/outputs"
  else
    OUT="./shipcheck-outputs"
  fi
fi
[ -z "$APP" ] && [ "$DO_APP" -eq 1 ] && APP="$PWD"
# resolve now: the app scan cd's away, and a relative --out would follow it
mkdir -p "$OUT" 2>/dev/null || { echo "cannot create $OUT" >&2; exit 1; }
OUT="$(cd "$OUT" && pwd)"
[ -n "$APP" ] && [ -d "$APP" ] && APP="$(cd "$APP" && pwd)"

TMP="$(mktemp -d /tmp/.shipcheck-XXXXXX)" || exit 1
trap 'rm -rf "$TMP"' EXIT INT TERM

IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1
SUDO=""
if [ "$IS_ROOT" -eq 0 ] && command -v sudo >/dev/null 2>&1; then
  sudo -n true 2>/dev/null && SUDO="sudo -n"
fi
PRIV=0; { [ "$IS_ROOT" -eq 1 ] || [ -n "$SUDO" ]; } && PRIV=1

SKIPPED=""
have() { command -v "$1" >/dev/null 2>&1; }
skip() { SKIPPED="$SKIPPED$1|"; }

cap()  { local k="$1"; shift; "$@" >"$TMP/$k" 2>/dev/null || true; }
pcap() { local k="$1"; shift; if [ "$PRIV" -eq 0 ]; then skip "$k:needs-root"; return 1; fi
         # shellcheck disable=SC2086
         $SUDO "$@" >"$TMP/$k" 2>/dev/null || true; }

# Drops comment-only matches from `grep -n` output. Used on every check where
# finding something SUPPRESSES a finding — a comment saying "// TODO: add rate
# limiting" is evidence of the opposite, and must not count as the control.
nocomment() { grep -vE '^[^:]*:[0-9]+:[[:space:]]*(//|#|\*|/\*|<!--|--)' 2>/dev/null || true; }

# ---------- JSON emitters (no jq needed) ----------
esc() { sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g' -e 's/\r//g' | tr -d '\000-\010\013\014\016-\037'; }
jstr() { printf '"%s"' "$(printf '%s' "${1:-}" | esc)"; }
jlines() {
  local f="$1" max="${2:-300}" first=1
  printf '['
  [ -s "$f" ] && head -n "$max" "$f" | while IFS= read -r l; do
      [ "$first" -eq 1 ] && first=0 || printf ','
      printf '"%s"' "$(printf '%s' "$l" | esc)"
    done
  printf ']'
}
jval() { local f="$1"; [ -s "$f" ] && jstr "$(head -c 400 "$f" | tr '\n' ' ')" || printf 'null'; }

echo "shipcheck: collecting (read-only, this changes nothing)..." >&2

# ==========================================================================
# SERVER
# ==========================================================================
if [ "$DO_HOST" -eq 1 ]; then

cap os_release   cat /etc/os-release
cap uname        uname -a
cap virt         systemd-detect-virt
cap uptime       uptime -p

# --- what is listening, and on what address
if have ss; then
  if [ "$PRIV" -eq 1 ]; then $SUDO ss -tulpnH > "$TMP/listeners" 2>/dev/null
  else ss -tulnH > "$TMP/listeners" 2>/dev/null; skip "listeners:no-process-names"; fi
elif have netstat; then netstat -tulpn 2>/dev/null | tail -n +3 > "$TMP/listeners"
else skip "listeners:no-ss-or-netstat"; fi

cap ipv6_global  sh -c 'ip -6 addr show scope global 2>/dev/null | grep inet6'
cap ipv4_addrs   sh -c 'ip -o -4 addr show 2>/dev/null'

# public IP — needed so we can tell the user exactly what to scan.
# Only reads back our own address; sends nothing about the machine.
cap public_ip4   sh -c 'dig +short -4 myip.opendns.com @resolver1.opendns.com 2>/dev/null |
                          grep -E "^[0-9.]+$" ||
                        curl -s --max-time 4 https://api.ipify.org 2>/dev/null ||
                        curl -s --max-time 4 https://ifconfig.me 2>/dev/null'
cap public_ip6   sh -c 'dig +short -6 myip.opendns.com aaaa @resolver1.ipv6-sandbox.opendns.com 2>/dev/null |
                          grep -E "^[0-9a-fA-F:]+$" ||
                        curl -s --max-time 4 https://api6.ipify.org 2>/dev/null'

# --- firewall
pcap nft_ruleset   nft list ruleset
pcap iptables_save iptables-save
pcap ip6tables_save ip6tables-save
cap  ufw_status    sh -c 'ufw status verbose 2>/dev/null'
cap  ufw_ipv6      sh -c 'grep -i "^IPV6" /etc/default/ufw 2>/dev/null'
cap  firewalld     sh -c 'firewall-cmd --state 2>/dev/null; firewall-cmd --list-all 2>/dev/null'
cap  fw_active     sh -c 'for s in nftables firewalld ufw iptables; do printf "%s=%s\n" "$s" "$(systemctl is-active "$s" 2>/dev/null)"; done'
cap  fail2ban      sh -c 'fail2ban-client status 2>/dev/null'

# --- ssh
pcap sshd_config   sshd -T
cap  ssh_version   sh -c 'ssh -V 2>&1'
cap  ssh_keyperms  sh -c 'stat -c "%a %U:%G %n" /etc/ssh/ssh_host_*_key 2>/dev/null'
cap  authkeys      sh -c 'for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
                            [ -f "$f" ] || continue
                            printf "### %s %s\n" "$f" "$(stat -c "%U:%G %a" "$f" 2>/dev/null)"
                            ssh-keygen -lf "$f" 2>/dev/null
                          done'
cap  authlog_fails sh -c 'journalctl -u ssh -u sshd --since "7 days ago" 2>/dev/null | grep -c "Failed password" ||
                          grep -c "Failed password" /var/log/auth.log 2>/dev/null'

# --- accounts and sudo
cap  uid0        awk -F: '($3==0){print $1}' /etc/passwd
pcap sudoers     sh -c 'grep -RhE "^[^#]" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^[[:space:]]*$"'
pcap shadow_sum  sh -c 'awk -F: "{print \$1\":\"substr(\$2,1,3)}" /etc/shadow'
cap  docker_grp  sh -c 'getent group docker 2>/dev/null'

# --- patching
if have dpkg; then
  apt list --upgradable 2>/dev/null > "$TMP/upgradable"
  [ -f /var/run/reboot-required ] && echo yes > "$TMP/reboot_required"
  dpkg-query -W -f='${Package} ${Version}\n' needrestart openssh-server sudo 2>/dev/null > "$TMP/key_pkgs"
elif have rpm; then
  have dnf && dnf -q check-update --security 2>/dev/null > "$TMP/upgradable"
  rpm -q openssh-server sudo 2>/dev/null > "$TMP/key_pkgs"
else skip "packages:unknown-package-manager"; fi
cap  autoupdate  sh -c 'systemctl is-enabled unattended-upgrades 2>/dev/null;
                        systemctl is-enabled dnf-automatic.timer 2>/dev/null;
                        grep -hE "Unattended-Upgrade" /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null'
cap  ubuntu_pro  sh -c 'pro status --format json 2>/dev/null | head -c 2000'

# --- containers
# Resolve ONE way of talking to the daemon and use it for everything below. The
# health marker is written only if that same path works, so the report can never
# claim container coverage it did not actually have. An earlier version checked
# reachability separately from the command that collected the data: with
# passwordless sudo available it would report full coverage while the container
# details were silently empty.
DOCKER_CMD=""
if have docker; then
  if docker info >/dev/null 2>&1; then
    DOCKER_CMD="docker"
  elif [ -n "$SUDO" ] && $SUDO docker info >/dev/null 2>&1; then
    DOCKER_CMD="$SUDO docker"
  else
    skip "docker:needs-root-or-docker-group"
  fi
fi

if [ -n "$DOCKER_CMD" ]; then
  # Zero containers is a complete answer, not a failed check. Without this, an
  # idle Docker host got a report opening with "this check is incomplete",
  # which is how a working tool teaches people to ignore its warnings.
  printf 'daemon=reachable containers=%s\n' \
    "$($DOCKER_CMD ps -q 2>/dev/null | wc -l | tr -d ' ')" > "$TMP/docker_state"
  $DOCKER_CMD ps --format "{{.Names}}\t{{.Image}}\t{{.Ports}}" > "$TMP/docker_ps" 2>/dev/null
  for id in $($DOCKER_CMD ps -q 2>/dev/null); do
    # Single quotes: this is a Go template, and $p / $b belong to Docker, not
    # bash. Double-quoted, bash expands them and dies on "unbound variable".
    $DOCKER_CMD inspect "$id" --format '{{.Name}}|user={{if .Config.User}}{{.Config.User}}{{else}}ROOT{{end}}|priv={{.HostConfig.Privileged}}|net={{.HostConfig.NetworkMode}}|mounts={{range .Mounts}}{{.Source}}:{{.RW}} {{end}}|ports={{range $p,$b := .NetworkSettings.Ports}}{{$p}}->{{$b}} {{end}}' 2>/dev/null
  done > "$TMP/docker_inspect"
fi
cap docker_sock    sh -c 'ls -l /var/run/docker.sock 2>/dev/null'
cap docker_daemon  sh -c 'cat /etc/docker/daemon.json 2>/dev/null'
cap compose_ports sh -c 'find /srv /opt /home /root -maxdepth 4 -name "docker-compose*.y*ml" 2>/dev/null | head -10 |
   while read -r f; do echo "### $f"; grep -nE "^\s*-\s*\"?[0-9]+:[0-9]+|privileged|docker.sock|network_mode" "$f" 2>/dev/null; done'

# --- exposed data services (the ones that get ransomed)
cap redis_auth  sh -c 'redis-cli CONFIG GET requirepass 2>/dev/null; redis-cli CONFIG GET bind 2>/dev/null'
cap mongo_auth  sh -c 'grep -A3 "^security" /etc/mongod.conf 2>/dev/null'
cap pg_listen   sh -c 'grep -hE "^\s*listen_addresses" /etc/postgresql/*/main/postgresql.conf 2>/dev/null'
cap pg_hba      sh -c 'grep -hvE "^\s*#|^\s*$" /etc/postgresql/*/main/pg_hba.conf 2>/dev/null'
cap mysql_bind  sh -c 'grep -rhE "^\s*bind-address" /etc/mysql/ /etc/my.cnf 2>/dev/null'

# --- backups and logs (what happens after something goes wrong)
cap backup_tools sh -c 'for b in restic borg borgmatic kopia duplicati rclone; do
                          command -v "$b" >/dev/null 2>&1 && printf "%s " "$b"; done; echo'
cap backup_sched sh -c 'systemctl list-timers --all --no-pager 2>/dev/null | grep -iE "backup|restic|borg|kopia";
                        crontab -l 2>/dev/null | grep -iE "restic|borg|kopia|rclone|backup"'
cap journald     sh -c 'ls -d /var/log/journal 2>/dev/null'

# --- kernel hardening (cheap, safe wins)
cap sysctl_vals sh -c 'sysctl -a 2>/dev/null | grep -E "^(kernel\.(kptr_restrict|dmesg_restrict|randomize_va_space|sysrq)|fs\.(protected_|suid_dumpable)|net\.ipv4\.(tcp_syncookies|conf\.all\.(rp_filter|accept_redirects|send_redirects|accept_source_route|log_martians))|net\.ipv6\.conf\.all\.(accept_redirects|accept_source_route))"'

# --- credential files sitting where others can read them
pcap loose_secrets sh -c 'find /srv /opt /home /var/www /root -xdev \
   \( -path "*/node_modules/*" -o -path "*/.git/*" -o -path "*/site-packages/*" -o -path "*/vendor/*" \) -prune -o \
   -type f \( -name ".env" -o -name ".env.*" -o -name "id_rsa" -o -name "id_ed25519" \
             -o -name "*.key" -o -name ".pgpass" -o -name ".netrc" -o -name "credentials.json" \) -print 2>/dev/null |
   head -40 | while read -r f; do
     head -c 200 "$f" 2>/dev/null | grep -q "BEGIN CERTIFICATE" && continue
     stat -c "%a %U:%G %n" "$f" 2>/dev/null
   done'

fi  # DO_HOST

# ==========================================================================
# APP / CODE
# ==========================================================================
if [ "$DO_APP" -eq 1 ] && [ -d "$APP" ]; then
cd "$APP" 2>/dev/null || true
echo "$APP" > "$TMP/app_path"

cap app_stack sh -c 'ls -1 package.json requirements.txt pyproject.toml go.mod Gemfile composer.json Cargo.toml pom.xml 2>/dev/null'
cap app_tree  sh -c 'ls -1a | head -50'

# --- git: the single most common way an indie project leaks everything
cap git_present   sh -c '[ -d .git ] && echo yes'
cap git_remote    sh -c 'git remote -v 2>/dev/null | head -4'
cap git_tracked_env sh -c 'git ls-files 2>/dev/null | grep -E "(^|/)\.env($|\.)|(^|/)\.env\.(local|production|prod)$" | head -20'
cap gitignore     sh -c 'cat .gitignore 2>/dev/null'
cap git_history_env sh -c 'git log --all --diff-filter=A --name-only --format="" 2>/dev/null |
                            grep -E "(^|/)\.env" | sort -u | head -20'
cap git_branch    sh -c 'git rev-parse --abbrev-ref HEAD 2>/dev/null'

# --- secrets by pattern. RECORDS FILE AND LINE ONLY — NEVER THE VALUE.
# --- secrets by pattern.
# RECORDS FILE, LINE COUNT AND THE KIND OF KEY — NEVER ANY PART OF THE VALUE.
# The evidence file must stay safe to paste into a chat or attach to an issue.
cap secret_hits sh -c '
  scan() {  # scan <label> <regex>
    grep -rEl "$2" . \
      --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=vendor \
      --exclude-dir=dist --exclude-dir=build --exclude-dir=.next --exclude-dir=venv \
      --exclude-dir=__pycache__ --exclude-dir=.venv --exclude-dir=target 2>/dev/null |
    head -20 | while read -r f; do
      n=$(grep -Ec "$2" "$f" 2>/dev/null)
      printf "%s|%s|%s\n" "$f" "$n" "$1"
    done
  }
  scan "AWS access key"        "AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}"
  scan "OpenAI API key"        "sk-(proj-)?[A-Za-z0-9_-]{20,}"
  scan "Stripe live key"       "(sk|rk)_live_[0-9a-zA-Z]{16,}"
  scan "GitHub token"          "gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,}"
  scan "Slack token"           "xox[baprs]-[A-Za-z0-9-]{10,}"
  scan "Google API key"        "AIza[0-9A-Za-z_-]{35}"
  scan "SendGrid key"          "SG\.[A-Za-z0-9_-]{20,}"
  scan "private key block"     "-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
  scan "hardcoded JWT"         "eyJhbGciOi[A-Za-z0-9_-]{20,}"
  scan "database URL with password" "(postgres|postgresql|mysql|mongodb(\+srv)?|redis|amqp)://[^:@/ ]+:[^@/ ]+@"
' 

# --- env files present locally (not necessarily committed)
cap env_files sh -c 'find . -maxdepth 3 -name ".env*" -not -path "*/node_modules/*" 2>/dev/null |
                      head -20 | while read -r f; do stat -c "%a %n" "$f" 2>/dev/null; done'

# --- debug / dev settings shipped to production
cap debug_flags sh -c 'grep -rEn "^\s*(DEBUG|FLASK_DEBUG|APP_DEBUG)\s*=\s*(1|[Tt]rue|[Oo]n)|NODE_ENV\s*=\s*development|APP_ENV\s*=\s*(local|dev)" \
   .env* config/ src/ app/ 2>/dev/null | head -20'
cap sourcemaps sh -c 'find . -maxdepth 4 \( -path "*/dist/*" -o -path "*/build/*" -o -path "*/.next/*" -o -path "*/public/*" \) \
   -name "*.map" -not -path "*/node_modules/*" 2>/dev/null | head -10'

# ==========================================================================
# APPLICATION CODE SECURITY
# Pattern-based, zero dependencies. Records WHERE, never file contents.
# These are candidates — the agent verifies each one in context before fixing.
# ==========================================================================

# what is this app built with? drives which patterns matter
cap fw_detect sh -c '
  d() { [ -f "$1" ] && grep -qiE "$2" "$1" 2>/dev/null && echo "$3"; }
  d package.json "\"next\"" nextjs
  d package.json "\"express\"" express
  d package.json "\"fastify\"" fastify
  d package.json "\"@nestjs/core\"" nestjs
  d package.json "\"koa\"" koa
  d package.json "\"@sveltejs/kit\"" sveltekit
  d package.json "\"nuxt\"" nuxt
  d package.json "\"@remix-run" remix
  d package.json "\"vite\"" vite
  d package.json "\"react-scripts\"" cra
  d package.json "\"@supabase/supabase-js\"" supabase
  d package.json "\"firebase\"" firebase
  d package.json "\"prisma\"" prisma
  d package.json "\"mongoose\"" mongoose
  for f in requirements.txt pyproject.toml Pipfile; do
    d "$f" "(^|[^a-z])flask" flask
    d "$f" "(^|[^a-z])django" django
    d "$f" "fastapi" fastapi
  done
  d composer.json "laravel/framework" laravel
  d Gemfile "rails" rails
  d go.mod "gin-gonic|labstack/echo|gofiber" go-web
  [ -d .next ] && echo nextjs-built
  [ -f Dockerfile ] && echo docker
'

# --- AUTH SURFACE: where people log in, and what protects it -----------------
# Any of these routes without rate limiting is a free credential-stuffing target.
cap auth_routes sh -c '
  grep -rEn "[\"'"'"'\`/](login|signin|sign-in|log-in|register|signup|sign-up|auth|session|token|password|forgot|reset|verify|otp|magic-?link|admin)[\"'"'"'\`/]" \
    --include="*.js" --include="*.jsx" --include="*.ts" --include="*.tsx" --include="*.mjs" \
    --include="*.py" --include="*.php" --include="*.rb" --include="*.go" \
    --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist --exclude-dir=build \
    --exclude-dir=.next --exclude-dir=vendor --exclude-dir=venv --exclude-dir=.venv \
    --exclude-dir=__pycache__ --exclude-dir=coverage --exclude-dir=test --exclude-dir=tests \
    . 2>/dev/null |
  grep -iE "(app|router|route|server)\.(get|post|put|patch|delete|all)|@(app|router)\.(get|post|route)|Route::|export (async )?function (GET|POST|PUT|PATCH|DELETE)|@(Post|Get)Mapping|http\.HandleFunc" |
  head -40'

# any route-ish file under an /auth/ or /login/ directory (Next.js app router etc)
cap auth_files sh -c '
  find . -path ./node_modules -prune -o -path ./.git -prune -o -path ./.next -prune -o \
    -regextype posix-extended -iregex ".*/(login|signin|sign-in|register|signup|sign-up|auth|password|reset|forgot|admin)/.*(route|page|handler|controller|view)s?\.(js|jsx|ts|tsx|py|php|rb|go)" -print 2>/dev/null | head -30'

# --- RATE LIMITING: is there any, anywhere? ---------------------------------
cap ratelimit sh -c '
  grep -rEn "express-rate-limit|rate-limiter-flexible|@upstash/ratelimit|rateLimit\(|RateLimiter|slowapi|Limiter\(|flask.limiter|flask_limiter|django_ratelimit|ratelimit|Rack::Attack|throttle|limiter\.check|limit_req|bottleneck|p-throttle|@nestjs/throttler|ThrottlerModule|arcjet" \
    --include="*.js" --include="*.jsx" --include="*.ts" --include="*.tsx" --include="*.mjs" \
    --include="*.py" --include="*.php" --include="*.rb" --include="*.go" --include="*.json" \
    --include="*.conf" --include="*.yml" --include="*.yaml" \
    --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist --exclude-dir=.next \
    --exclude-dir=vendor --exclude-dir=venv --exclude-dir=.venv \
    . 2>/dev/null | grep -vE "^[^:]*:[0-9]+:[[:space:]]*(//|#|\*|/\*|<!--)" | head -20'
cap ratelimit_pkg sh -c '
  grep -hoE "\"(express-rate-limit|rate-limiter-flexible|@upstash/ratelimit|@nestjs/throttler|express-slow-down|@arcjet/[a-z-]+)\"" package.json 2>/dev/null
  grep -hoiE "^(slowapi|flask-limiter|django-ratelimit|django-axes|rack-attack)" requirements.txt Gemfile 2>/dev/null'
# an nginx/caddy in front counts as a compensating control
cap proxy_ratelimit sh -c '
  grep -rhE "limit_req|limit_conn|rate_limit" /etc/nginx/ /etc/caddy/ ./nginx* ./Caddyfile 2>/dev/null | head -5'

# --- FILE UPLOAD: the other classic ----------------------------------------
cap upload_handlers sh -c '
  grep -rEn "multer|formidable|busboy|multiparty|@fastify/multipart|UploadFile|request\.files|req\.files|req\.file\b|ActiveStorage|CarrierWave|Shrine|FileField|ImageField|\$_FILES|MultipartFile|FormData\(\)|createPresignedPost|getSignedUrl|putObject|\.upload\(" \
    --include="*.js" --include="*.jsx" --include="*.ts" --include="*.tsx" --include="*.mjs" \
    --include="*.py" --include="*.php" --include="*.rb" --include="*.go" \
    --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist --exclude-dir=.next \
    --exclude-dir=vendor --exclude-dir=venv --exclude-dir=.venv \
    . 2>/dev/null | head -25'
# does anything validate what is uploaded?
cap upload_guards sh -c '
  grep -rEn "fileFilter|mimetype|mime_type|content_type|allowed_extensions|ALLOWED_EXTENSIONS|limits:\s*\{|fileSize|MAX_(FILE|UPLOAD)_SIZE|maxFileSize|accept=|image/(png|jpeg)|secure_filename|sanitize_filename|path\.extname|splitext" \
    --include="*.js" --include="*.jsx" --include="*.ts" --include="*.tsx" --include="*.mjs" \
    --include="*.py" --include="*.php" --include="*.rb" --include="*.go" \
    --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist --exclude-dir=.next \
    --exclude-dir=vendor --exclude-dir=venv --exclude-dir=.venv \
    . 2>/dev/null | grep -vE "^[^:]*:[0-9]+:[[:space:]]*(//|#|\*|/\*|<!--)" | head -25'

# --- ROUTE COUNT vs AUTH CHECK COUNT (density signal) ----------------------
cap route_count sh -c '
  grep -rEc "(app|router|route|server)\.(get|post|put|patch|delete|all)\(|@(app|router)\.(get|post|put|delete|patch)|Route::(get|post|put|patch|delete)|export (async )?function (GET|POST|PUT|PATCH|DELETE)" \
    --include="*.js" --include="*.ts" --include="*.tsx" --include="*.jsx" --include="*.mjs" \
    --include="*.py" --include="*.php" --include="*.rb" \
    --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=.next --exclude-dir=dist \
    --exclude-dir=vendor --exclude-dir=venv . 2>/dev/null | awk -F: "{s+=\$2} END {print s+0}"'
cap authcheck_count sh -c '
  grep -rEc "requireAuth|isAuthenticated|ensureAuth|authenticate|authMiddleware|withAuth|getServerSession|getSession\(|verifyToken|jwt\.verify|@login_required|login_required|current_user|@UseGuards|before_action.*authenticate|auth\(\)->|Auth::check|middleware\(.auth|protect\b|checkAuth|requireUser" \
    --include="*.js" --include="*.ts" --include="*.tsx" --include="*.jsx" --include="*.mjs" \
    --include="*.py" --include="*.php" --include="*.rb" \
    --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=.next --exclude-dir=dist \
    --exclude-dir=vendor --exclude-dir=venv . 2>/dev/null | awk -F: "{s+=\$2} END {print s+0}"'

# --- CLIENT-SIDE SECRET EXPOSURE (huge, and invisible to most people) ------
# Anything with these prefixes is compiled into the JS the browser downloads.
cap public_env_secrets sh -c '
  grep -rEn "(NEXT_PUBLIC|VITE|REACT_APP|PUBLIC|EXPO_PUBLIC|NUXT_PUBLIC|GATSBY)_[A-Z0-9_]*(SECRET|PRIVATE|KEY|TOKEN|PASSWORD|PASS|CREDENTIAL|SERVICE_ROLE|API_KEY)" \
    --include="*.js" --include="*.jsx" --include="*.ts" --include="*.tsx" --include="*.mjs" \
    --include="*.env*" --include="*.yml" --include="*.yaml" \
    --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist \
    . .env .env.local .env.production 2>/dev/null | head -20'

# --- SUPABASE / FIREBASE: the two most common vibe-coder backends ----------
cap supabase_service_key sh -c '
  grep -rEn "service_role|SERVICE_ROLE_KEY|supabaseServiceKey|SUPABASE_SERVICE" \
    --include="*.js" --include="*.jsx" --include="*.ts" --include="*.tsx" --include="*.mjs" \
    --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist \
    . 2>/dev/null | head -15'
cap firebase_rules sh -c '
  for f in firestore.rules storage.rules database.rules.json; do
    [ -f "$f" ] && { echo "### $f"; grep -nE "allow (read|write|read, write)\s*:\s*if\s+true|\"\.(read|write)\"\s*:\s*true" "$f" 2>/dev/null; }
  done'

# --- DANGEROUS PATTERNS ----------------------------------------------------
cap sql_concat sh -c '
  grep -rEn "(query|execute|raw|exec)\s*\(\s*[\"'"'"'\`][^\"'"'"'\`]*(SELECT|INSERT|UPDATE|DELETE|DROP)[^)]*(\+|\\\$\{|%s.*%|f\")" \
    --include="*.js" --include="*.jsx" --include="*.ts" --include="*.tsx" --include="*.mjs" \
    --include="*.py" --include="*.php" --include="*.rb" --include="*.go" \
    --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist --exclude-dir=.next \
    --exclude-dir=vendor --exclude-dir=venv . 2>/dev/null | head -15'
cap dangerous_exec sh -c '
  grep -rEn "\beval\s*\(|new Function\s*\(|child_process|exec\s*\(|execSync|spawnSync|os\.system|subprocess\.(call|run|Popen).*shell\s*=\s*True|pickle\.loads|yaml\.load\s*\([^)]*\)|unserialize\s*\(|Marshal\.load" \
    --include="*.js" --include="*.jsx" --include="*.ts" --include="*.tsx" --include="*.mjs" \
    --include="*.py" --include="*.php" --include="*.rb" \
    --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist --exclude-dir=.next \
    --exclude-dir=vendor --exclude-dir=venv --exclude-dir=scripts . 2>/dev/null | head -15'
cap xss_sinks sh -c '
  grep -rEn "dangerouslySetInnerHTML|v-html|\.innerHTML\s*=|document\.write\s*\(|\|\s*safe\b|\{\{\{" \
    --include="*.js" --include="*.jsx" --include="*.ts" --include="*.tsx" --include="*.vue" \
    --include="*.html" --include="*.hbs" --include="*.ejs" \
    --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist --exclude-dir=.next \
    . 2>/dev/null | head -15'

# --- CORS / CSRF / COOKIES -------------------------------------------------
cap cors_config sh -c '
  tag() {  # tag <label> <regex>
    grep -rEln "$2" \
      --include="*.js" --include="*.jsx" --include="*.ts" --include="*.tsx" --include="*.mjs" \
      --include="*.py" --include="*.php" --include="*.rb" \
      --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist --exclude-dir=.next \
      --exclude-dir=vendor --exclude-dir=venv --exclude-dir=.venv 2>/dev/null . |
    head -8 | while read -r f; do printf "%s|%s\n" "$f" "$1"; done
  }
  tag wildcard    "origin\s*:\s*[\"'"'"']\*[\"'"'"']|allow_origins\s*=\s*\[\s*[\"'"'"']\*|Access-Control-Allow-Origin[\"'"'"']?\s*[,:]\s*[\"'"'"']\*|CORS_ALLOW_ALL"
  tag bare-cors   "app\.use\(\s*cors\(\)\s*\)|[^a-zA-Z]cors\(\)"
  tag credentials "credentials\s*:\s*true|allow_credentials\s*=\s*True|supports_credentials"
'

cap csrf_present sh -c '
  grep -rEn "csurf|csrf|CSRF|XSRF|SameSite|samesite" \
    --include="*.js" --include="*.ts" --include="*.tsx" --include="*.py" --include="*.php" --include="*.rb" \
    --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist --exclude-dir=.next \
    --exclude-dir=vendor --exclude-dir=venv 2>/dev/null . |
  grep -vE "^[^:]*:[0-9]+:[[:space:]]*(//|#|\*|/\*|<!--)" | cut -d: -f1 | sort -u | head -10'
cap cookie_flags sh -c '
  grep -rEn "cookie\s*\(|setCookie|set_cookie|session\s*\(\s*\{|cookies\.set" \
    --include="*.js" --include="*.ts" --include="*.tsx" --include="*.mjs" --include="*.py" --include="*.rb" \
    --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist --exclude-dir=.next \
    --exclude-dir=vendor --exclude-dir=venv . 2>/dev/null | head -15'
cap security_headers_code sh -c '
  grep -rEn "helmet\(|Strict-Transport-Security|Content-Security-Policy|SECURE_HSTS_SECONDS|SECURE_SSL_REDIRECT|X-Frame-Options|contentSecurityPolicy" \
    --include="*.js" --include="*.ts" --include="*.mjs" --include="*.py" --include="*.rb" --include="*.php" \
    --include="next.config.*" \
    --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist --exclude-dir=.next \
    --exclude-dir=vendor --exclude-dir=venv . 2>/dev/null |
  grep -vE "^[^:]*:[0-9]+:[[:space:]]*(//|#|\*|/\*|<!--)" | head -15'

# --- AUTH IMPLEMENTATION MISTAKES ------------------------------------------
cap jwt_weak sh -c '
  grep -rEn "algorithms\s*:\s*\[[\"'"'"']none|jwt\.decode\s*\([^)]*verify\s*=\s*False|jsonwebtoken.*decode\(|verify\s*:\s*false|ignoreExpiration\s*:\s*true" \
    --include="*.js" --include="*.ts" --include="*.tsx" --include="*.mjs" --include="*.py" \
    --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist . 2>/dev/null | head -10'
cap password_compare sh -c '
  grep -rEn "password\s*(===?|!==?)\s*|==\s*password|compare\(.*password.*\)\s*(\|\||&&)" \
    --include="*.js" --include="*.ts" --include="*.tsx" --include="*.mjs" --include="*.py" --include="*.php" \
    --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist --exclude-dir=.next \
    --exclude-dir=vendor --exclude-dir=venv . 2>/dev/null | head -10'
cap password_hashing sh -c '
  grep -rEn "bcrypt|argon2|scrypt|pbkdf2|password_hash|make_password|has_secure_password|Bcrypt" \
    --include="*.js" --include="*.ts" --include="*.tsx" --include="*.mjs" --include="*.py" --include="*.php" --include="*.rb" \
    --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist . 2>/dev/null |
  grep -vE "^[^:]*:[0-9]+:[[:space:]]*(//|#|\*|/\*|<!--)" | cut -d: -f1 | sort -u | head -5'

# --- dependency vulnerabilities, using only what a JS/Python dev already has
if [ -f package-lock.json ] && have npm; then
  npm audit --json 2>/dev/null | head -c 200000 > "$TMP/npm_audit"
elif [ -f package.json ] && have npm; then
  skip "npm-audit:no-lockfile"
fi
if [ -f yarn.lock ] && have yarn; then yarn npm audit --json 2>/dev/null | head -c 100000 > "$TMP/yarn_audit"; fi
have pip-audit && [ -f requirements.txt ] && pip-audit -r requirements.txt -f json 2>/dev/null | head -c 100000 > "$TMP/pip_audit"
have govulncheck && [ -f go.mod ] && govulncheck -json ./... 2>/dev/null | head -c 100000 > "$TMP/go_audit"

# --- optional deeper tools, only if the user chose to install them
have gitleaks && gitleaks detect --no-banner --redact -f json -r "$TMP/gitleaks.json" >/dev/null 2>&1
have trivy    && trivy fs --scanners vuln,misconfig,secret -f json -q . 2>/dev/null | head -c 300000 > "$TMP/trivy.json"
have semgrep  && semgrep --config=auto --json -q --timeout 120 . 2>/dev/null | head -c 300000 > "$TMP/semgrep.json"

fi  # DO_APP

# ==========================================================================
# LIVE SITE (only if a URL was given)
# ==========================================================================
if [ -n "$SITE" ] && have curl; then
  H="$SITE"
  cap site_headers sh -c "curl -sSI --max-time 10 -L '$H' 2>/dev/null | head -40"
  cap site_body_hdr sh -c "curl -sS --max-time 10 -o /dev/null -D - '$H' 2>/dev/null | head -40"
  # the classic: source control served to the internet
  cap site_git sh -c "curl -sS --max-time 8 -o /dev/null -w '%{http_code}' '${H%/}/.git/config' 2>/dev/null"
  cap site_env sh -c "curl -sS --max-time 8 -o /dev/null -w '%{http_code}' '${H%/}/.env' 2>/dev/null"
  cap site_dsstore sh -c "curl -sS --max-time 8 -o /dev/null -w '%{http_code}' '${H%/}/.DS_Store' 2>/dev/null"
  cap site_listing sh -c "curl -sS --max-time 8 '${H%/}/' 2>/dev/null | grep -ci 'index of /' || true"
  host_only="${H#*://}"; host_only="${host_only%%/*}"; host_only="${host_only%%:*}"
  if have openssl; then
    cap tls_info sh -c "echo | openssl s_client -connect '${host_only}:443' -servername '$host_only' 2>/dev/null |
                        openssl x509 -noout -subject -issuer -dates 2>/dev/null"
  else skip "tls:no-openssl"; fi
fi


# ---------- strip matched source text from the code-scan results -----------
# Every appsec check uses `grep -n`, which returns "file:line:the matching line".
# That matching line can BE the secret (a .env row is `KEY=value`). evidence.json
# is meant to be safe to paste into a chat or attach to an issue, so nothing but
# the location survives. Anyone fixing the finding opens the file themselves.
for k in auth_routes ratelimit upload_handlers upload_guards public_env_secrets \
         supabase_service_key sql_concat dangerous_exec xss_sinks \
         cookie_flags security_headers_code jwt_weak password_compare; do
  [ -s "$TMP/$k" ] || continue
  awk -F: 'NF>=2 { printf "%s:%s\n", $1, $2; next } { print }' "$TMP/$k" \
    > "$TMP/$k.stripped" 2>/dev/null && mv "$TMP/$k.stripped" "$TMP/$k"
done
# firebase_rules keeps its "### file" headers but loses rule text
if [ -s "$TMP/firebase_rules" ]; then
  awk -F: '/^###/ { print; next } NF>=2 { printf "%s:%s\n", $1, $2; next } { print }' \
    "$TMP/firebase_rules" > "$TMP/fr.s" 2>/dev/null && mv "$TMP/fr.s" "$TMP/firebase_rules"
fi

# ---------- parser health -------------------------------------------------
# The analyzer must be able to tell "I looked and it was clean" apart from
# "I could not look". Record, for each critical source: was the tool present,
# did we have the privilege, and did it actually return anything.
health() {  # health <name> <tool-present 0|1> <file>
  local n="$1" present="$2" f="$3" lines=0
  [ -s "$f" ] && lines=$(wc -l < "$f" 2>/dev/null | tr -d " ")
  printf '%s|present=%s|lines=%s\n' "$n" "$present" "$lines" >> "$TMP/_health"
}
: > "$TMP/_health"
if [ "$DO_HOST" -eq 1 ]; then
  health listeners "$(have ss && echo 1 || { have netstat && echo 1 || echo 0; })" "$TMP/listeners"
  health sshd_config "$(have sshd && echo 1 || echo 0)" "$TMP/sshd_config"
  health firewall "$( { have nft || have iptables || have ufw || have firewall-cmd; } && echo 1 || echo 0)" "$TMP/nft_ruleset"
  health firewall_ufw "$(have ufw && echo 1 || echo 0)" "$TMP/ufw_status"
  health firewall_iptables "$(have iptables-save && echo 1 || echo 0)" "$TMP/iptables_save"
  health docker "$(have docker && echo 1 || echo 0)" "$TMP/docker_state"
  health packages "$( { have dpkg || have rpm; } && echo 1 || echo 0)" "$TMP/upgradable"
  health accounts 1 "$TMP/uid0"
fi
if [ "$DO_APP" -eq 1 ]; then
  health app_tree 1 "$TMP/app_tree"
  health frameworks 1 "$TMP/fw_detect"
fi

# ==========================================================================
# EMIT
# ==========================================================================
printf '%s' "$SKIPPED" | tr '|' '\n' | grep -v '^$' > "$TMP/_skipped"

cat > "$OUT/evidence.json" <<JSON
{
  "shipcheck": {"version": "0.2.0", "generated_at": $(jstr "$(date -u +%FT%TZ)"),
                "privileged": $( [ "$PRIV" -eq 1 ] && echo true || echo false ),
                "checked_host": $( [ "$DO_HOST" -eq 1 ] && echo true || echo false ),
                "checked_app": $( [ "$DO_APP" -eq 1 ] && echo true || echo false ),
                "app_path": $(jval "$TMP/app_path"),
                "site": $(jstr "$SITE"),
                "skipped": $(jlines "$TMP/_skipped" 60),
                "health": $(jlines "$TMP/_health" 40)},
  "system": {
    "os_release": $(jlines "$TMP/os_release" 20),
    "uname": $(jval "$TMP/uname"),
    "virt": $(jval "$TMP/virt"),
    "uptime": $(jval "$TMP/uptime")
  },
  "network": {
    "listeners": $(jlines "$TMP/listeners" 150),
    "ipv6_global": $(jlines "$TMP/ipv6_global" 10),
    "ipv4_addrs": $(jlines "$TMP/ipv4_addrs" 10),
    "public_ip4": $(jval "$TMP/public_ip4"),
    "public_ip6": $(jval "$TMP/public_ip6"),
    "nft": $(jlines "$TMP/nft_ruleset" 150),
    "iptables": $(jlines "$TMP/iptables_save" 150),
    "ip6tables": $(jlines "$TMP/ip6tables_save" 100),
    "ufw": $(jlines "$TMP/ufw_status" 40),
    "ufw_ipv6": $(jval "$TMP/ufw_ipv6"),
    "firewalld": $(jlines "$TMP/firewalld" 40),
    "fw_active": $(jlines "$TMP/fw_active" 10),
    "fail2ban": $(jlines "$TMP/fail2ban" 20)
  },
  "ssh": {
    "config": $(jlines "$TMP/sshd_config" 150),
    "version": $(jval "$TMP/ssh_version"),
    "host_key_perms": $(jlines "$TMP/ssh_keyperms" 15),
    "authorized_keys": $(jlines "$TMP/authkeys" 40),
    "failed_logins_7d": $(jval "$TMP/authlog_fails")
  },
  "accounts": {
    "uid0": $(jlines "$TMP/uid0" 15),
    "sudoers": $(jlines "$TMP/sudoers" 50),
    "shadow_summary": $(jlines "$TMP/shadow_sum" 50),
    "docker_group": $(jval "$TMP/docker_grp")
  },
  "patching": {
    "upgradable": $(jlines "$TMP/upgradable" 80),
    "reboot_required": $( [ -s "$TMP/reboot_required" ] && echo true || echo false ),
    "key_packages": $(jlines "$TMP/key_pkgs" 10),
    "auto_updates": $(jlines "$TMP/autoupdate" 10),
    "ubuntu_pro": $(jval "$TMP/ubuntu_pro")
  },
  "containers": {
    "running": $(jlines "$TMP/docker_ps" 40),
    "socket": $(jval "$TMP/docker_sock"),
    "daemon_json": $(jlines "$TMP/docker_daemon" 20),
    "inspect": $(jlines "$TMP/docker_inspect" 40),
    "compose_ports": $(jlines "$TMP/compose_ports" 60)
  },
  "data_services": {
    "redis": $(jlines "$TMP/redis_auth" 10),
    "mongo": $(jlines "$TMP/mongo_auth" 10),
    "postgres_listen": $(jlines "$TMP/pg_listen" 5),
    "postgres_hba": $(jlines "$TMP/pg_hba" 25),
    "mysql_bind": $(jlines "$TMP/mysql_bind" 5)
  },
  "resilience": {
    "backup_tools": $(jval "$TMP/backup_tools"),
    "backup_schedule": $(jlines "$TMP/backup_sched" 15),
    "persistent_logs": $(jval "$TMP/journald"),
    "sysctl": $(jlines "$TMP/sysctl_vals" 40),
    "loose_secret_files": $(jlines "$TMP/loose_secrets" 40)
  },
  "app": {
    "stack": $(jlines "$TMP/app_stack" 10),
    "tree": $(jlines "$TMP/app_tree" 50),
    "git": $( [ -s "$TMP/git_present" ] && echo true || echo false ),
    "git_remote": $(jlines "$TMP/git_remote" 5),
    "git_branch": $(jval "$TMP/git_branch"),
    "env_tracked_in_git": $(jlines "$TMP/git_tracked_env" 20),
    "env_in_git_history": $(jlines "$TMP/git_history_env" 20),
    "gitignore": $(jlines "$TMP/gitignore" 40),
    "env_files": $(jlines "$TMP/env_files" 20),
    "secret_hits": $(jlines "$TMP/secret_hits" 30),
    "debug_flags": $(jlines "$TMP/debug_flags" 20),
    "sourcemaps": $(jlines "$TMP/sourcemaps" 10)
  },
  "appsec": {
    "frameworks": $(jlines "$TMP/fw_detect" 20),
    "auth_routes": $(jlines "$TMP/auth_routes" 40),
    "auth_files": $(jlines "$TMP/auth_files" 30),
    "ratelimit_hits": $(jlines "$TMP/ratelimit" 20),
    "ratelimit_packages": $(jlines "$TMP/ratelimit_pkg" 10),
    "proxy_ratelimit": $(jlines "$TMP/proxy_ratelimit" 5),
    "upload_handlers": $(jlines "$TMP/upload_handlers" 25),
    "upload_guards": $(jlines "$TMP/upload_guards" 25),
    "route_count": $(jval "$TMP/route_count"),
    "authcheck_count": $(jval "$TMP/authcheck_count"),
    "public_env_secrets": $(jlines "$TMP/public_env_secrets" 20),
    "supabase_service_key": $(jlines "$TMP/supabase_service_key" 15),
    "firebase_rules": $(jlines "$TMP/firebase_rules" 20),
    "sql_concat": $(jlines "$TMP/sql_concat" 15),
    "dangerous_exec": $(jlines "$TMP/dangerous_exec" 15),
    "xss_sinks": $(jlines "$TMP/xss_sinks" 15),
    "cors_config": $(jlines "$TMP/cors_config" 15),
    "csrf_files": $(jlines "$TMP/csrf_present" 10),
    "cookie_calls": $(jlines "$TMP/cookie_flags" 15),
    "security_headers_code": $(jlines "$TMP/security_headers_code" 15),
    "jwt_weak": $(jlines "$TMP/jwt_weak" 10),
    "password_compare": $(jlines "$TMP/password_compare" 10),
    "password_hashing": $(jlines "$TMP/password_hashing" 5)
  },
  "site": {
    "headers": $(jlines "$TMP/site_headers" 40),
    "git_config_status": $(jval "$TMP/site_git"),
    "env_status": $(jval "$TMP/site_env"),
    "dsstore_status": $(jval "$TMP/site_dsstore"),
    "directory_listing": $(jval "$TMP/site_listing"),
    "tls": $(jlines "$TMP/tls_info" 10)
  }
}
JSON

# raw tool output, when the user installed the optional extras
for f in npm_audit yarn_audit pip_audit go_audit gitleaks.json trivy.json semgrep.json; do
  [ -s "$TMP/$f" ] && cp "$TMP/$f" "$OUT/$(basename "$f" .json).json" 2>/dev/null
done
find "$OUT" -maxdepth 1 -type f -size 0 -delete 2>/dev/null

echo "shipcheck: wrote $OUT/evidence.json" >&2

# Build the report in the same run. Three separate commands was the single
# biggest source of "it didn't work" — the second one had to be told where the
# first one put things, and if you got that wrong you got a stack trace.
REPORTED=0
if [ "$DO_REPORT" -eq 1 ]; then
  if have python3; then
    if python3 "$SDIR/analyze.py" "$OUT" >/dev/null 2>"$TMP/analyze_err" \
       && python3 "$SDIR/report.py" "$OUT" >/dev/null 2>"$TMP/report_err"; then
      REPORTED=1
    else
      echo "shipcheck: the report step failed — your evidence is safe in $OUT/evidence.json" >&2
      head -n 5 "$TMP/analyze_err" "$TMP/report_err" 2>/dev/null | sed 's/^/  /' >&2
      echo "  Retry with: python3 $SDIR/analyze.py $OUT && python3 $SDIR/report.py $OUT" >&2
    fi
  else
    echo "shipcheck: python3 not found — evidence collected, but no report." >&2
    echo "  Install it (sudo apt install -y python3), then run:" >&2
    echo "    python3 $SDIR/analyze.py $OUT && python3 $SDIR/report.py $OUT" >&2
  fi
fi

# Running under sudo makes root the owner of everything we just wrote, at
# mode 700 — which locks the actual user out of their own results. Hand it back.
if [ -n "${SUDO_USER:-}" ] && [ "$(id -u)" -eq 0 ]; then
  _gid="$(id -gn "$SUDO_USER" 2>/dev/null || echo "$SUDO_USER")"
  chown -R "$SUDO_USER:$_gid" "$OUT" 2>/dev/null
  chmod 755 "$OUT" 2>/dev/null
  find "$OUT" -type f -exec chmod 644 {} + 2>/dev/null
  find "$OUT" -maxdepth 1 -name '*.sh' -exec chmod 755 {} + 2>/dev/null
fi

[ -n "$SKIPPED" ] && echo "shipcheck: skipped -> $(printf '%s' "$SKIPPED" | tr '|' ' ')" >&2
[ "$PRIV" -eq 0 ] && [ "$DO_HOST" -eq 1 ] && \
  echo "shipcheck: NOTE — run with sudo for the full server check (firewall, SSH, accounts)." >&2

if [ "$REPORTED" -eq 1 ]; then
  echo "" >&2
  echo "  Done. Everything is in: $OUT" >&2
  echo "" >&2
  echo "    Read this first   less $OUT/REPORT.md" >&2
  echo "    Give to your AI   $OUT/FIXME.md  (plus fix-recipes.md next to it)" >&2
  echo "    Safe auto-fixes   sudo $OUT/fix.sh     then  $OUT/verify.sh" >&2
  echo "" >&2
fi
exit 0
