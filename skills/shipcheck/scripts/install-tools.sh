#!/usr/bin/env bash
# shipcheck optional extras.
#
#   ./install-tools.sh            # see what it would install, install nothing
#   ./install-tools.sh --install  # actually install
#
# shipcheck works WITHOUT any of this. These four tools make the code half of
# the check deeper: real secret scanning across your whole git history, known
# vulnerabilities in your dependencies and container images, and static analysis
# of your source.
#
# Everything here installs to /usr/local/bin (or ~/.local/bin without root) from
# the project's own official release, with the version pinned and printed. Read
# it before you run it — that is the entire point of a tool like this.
set -uo pipefail

INSTALL=0
[ "${1:-}" = "--install" ] && INSTALL=1

# Pinned. Bump deliberately; do not float to "latest" in a security tool.
GITLEAKS_VERSION="8.28.0"
TRIVY_VERSION="0.67.0"

BIN="/usr/local/bin"
SUDO="sudo"
if [ "$(id -u)" -eq 0 ]; then SUDO=""; fi
if ! [ -w "$BIN" ] && ! command -v sudo >/dev/null 2>&1; then
  BIN="$HOME/.local/bin"; SUDO=""; mkdir -p "$BIN"
  echo "No root available — installing to $BIN (make sure it is on your PATH)."
fi

case "$(uname -m)" in
  x86_64|amd64) ARCH=x64;  GOARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64; GOARCH=arm64 ;;
  *) echo "Unsupported CPU architecture: $(uname -m)"; exit 1 ;;
esac

have() { command -v "$1" >/dev/null 2>&1; }
say()  { printf '  %s\n' "$*"; }

echo
echo "shipcheck optional extras"
echo "========================="
echo

PLAN=()

if have gitleaks; then say "gitleaks    already installed ($(gitleaks version 2>&1 | head -1))"
else PLAN+=("gitleaks"); say "gitleaks    WILL INSTALL v$GITLEAKS_VERSION — finds secrets across your whole git history,"
     say "                                     not just the current files"; fi

if have trivy; then say "trivy       already installed ($(trivy --version 2>/dev/null | head -1))"
else PLAN+=("trivy"); say "trivy       WILL INSTALL v$TRIVY_VERSION — known vulnerabilities in your dependencies,"
     say "                                  Docker images and infrastructure config"; fi

if have semgrep; then say "semgrep     already installed"
elif have pipx || have pip3; then PLAN+=("semgrep"); say "semgrep     WILL INSTALL (via pipx/pip) — static analysis of your source code"
else say "semgrep     SKIPPED — needs python3 with pip or pipx"; fi

if have npm; then say "npm audit   available (npm is installed) — nothing to do"
else say "npm audit   n/a — npm not installed"; fi

echo
if [ "${#PLAN[@]}" -eq 0 ]; then
  echo "Nothing to install. You're set — re-run shipcheck and it will pick these up."
  exit 0
fi

if [ "$INSTALL" -eq 0 ]; then
  echo "This was a preview. Nothing was installed."
  echo "To install: ./install-tools.sh --install"
  echo
  echo "Prefer your own package manager? These are all available elsewhere:"
  echo "  brew install gitleaks trivy semgrep      # macOS / Linuxbrew"
  echo "  Debian/Ubuntu apt repos exist for trivy — see aquasecurity.github.io/trivy"
  exit 0
fi

TMPD="$(mktemp -d)"; trap 'rm -rf "$TMPD"' EXIT

for tool in "${PLAN[@]}"; do
  case "$tool" in
    gitleaks)
      echo "==> gitleaks v$GITLEAKS_VERSION"
      URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GOARCH/amd64/x64}.tar.gz"
      curl -fsSL "$URL" -o "$TMPD/gitleaks.tgz" || { echo "  download failed — skipping"; continue; }
      tar -xzf "$TMPD/gitleaks.tgz" -C "$TMPD" gitleaks 2>/dev/null || { echo "  extract failed — skipping"; continue; }
      $SUDO install -m 0755 "$TMPD/gitleaks" "$BIN/gitleaks" && echo "  installed to $BIN/gitleaks"
      ;;
    trivy)
      echo "==> trivy v$TRIVY_VERSION"
      case "$GOARCH" in amd64) T_ARCH="Linux-64bit" ;; arm64) T_ARCH="Linux-ARM64" ;; esac
      URL="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${T_ARCH}.tar.gz"
      curl -fsSL "$URL" -o "$TMPD/trivy.tgz" || { echo "  download failed — skipping"; continue; }
      tar -xzf "$TMPD/trivy.tgz" -C "$TMPD" trivy 2>/dev/null || { echo "  extract failed — skipping"; continue; }
      $SUDO install -m 0755 "$TMPD/trivy" "$BIN/trivy" && echo "  installed to $BIN/trivy"
      ;;
    semgrep)
      echo "==> semgrep"
      if have pipx; then pipx install semgrep && echo "  installed via pipx"
      else pip3 install --user semgrep 2>/dev/null && echo "  installed via pip3 --user" \
           || echo "  pip install failed — try: pipx install semgrep"; fi
      ;;
  esac
done

echo
echo "Done. Re-run shipcheck and it will use whatever installed successfully."
echo "Anything that failed just means that part of the check stays shallow —"
echo "shipcheck still works and will tell you what it could not do."
