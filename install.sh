#!/bin/sh
set -eu

# Spider portable installer.
# Works with Termux, iSH/Alpine, Debian/Ubuntu, Arch, Fedora/RHEL,
# openSUSE, macOS and other Unix-like shells with Python 3 support.
#
# Local install: sh ./install.sh
# GitHub one-liner (no raw.githubusercontent.com required):
# sh -c 'd="$(mktemp -d)" && curl -fsSL https://github.com/amirh00sain/spiderscanner/archive/refs/heads/main.tar.gz -o "$d/spider.tgz" && tar -xzf "$d/spider.tgz" -C "$d" && sh "$d/spiderscanner-main/install.sh"; r=$?; rm -rf "$d"; exit $r'

PYTHON_BIN="${PYTHON:-}"
TERMUX_ENV_PREFIX="${PREFIX:-}"
REPO="${SPIDER_REPO:-https://github.com/amirh00sain/spiderscanner.git}"
BRANCH="${SPIDER_BRANCH:-main}"
PREFIX="${SPIDER_HOME:-$HOME/.local/share/spider}"
if [ -n "${SPIDER_BIN_DIR:-}" ]; then
  BIN_DIR="$SPIDER_BIN_DIR"
elif [ "$(id -u 2>/dev/null || echo 1)" = "0" ] && [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
  # Root-based iSH/Alpine shells commonly do not include /root/.local/bin in PATH.
  # Install the command in /usr/local/bin so `spider` works immediately.
  BIN_DIR="/usr/local/bin"
else
  BIN_DIR="$HOME/.local/bin"
fi

say() { printf '%s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die() { printf '[x] %s\n' "$*" >&2; exit 1; }

SCRIPT_DIR=""
case "${0:-}" in
  */*|install.sh)
    CANDIDATE=$(CDPATH= cd -- "$(dirname -- "${0:-install.sh}")" 2>/dev/null && pwd || true)
    if [ -f "$CANDIDATE/warp_scan.py" ] && [ -d "$CANDIDATE/warp_scan" ]; then
      SCRIPT_DIR="$CANDIDATE"
    fi
    ;;
esac

# -------------------------
# Privilege / package helpers
# -------------------------
run_root() {
  if [ "$(id -u 2>/dev/null || echo 1)" = "0" ]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    return 127
  fi
}

has_cmd() { command -v "$1" >/dev/null 2>&1; }


install_aether_build_deps() {
  [ "${SPIDER_SKIP_AETHER_DEPS:-0}" = "1" ] && return 0
  # Aether is shipped as a prebuilt Linux x86_64 bundle (binary + PT helpers).
  # No Rust/Cargo/CMake toolchain is needed for normal installation anymore.
  say "[i] Using bundled prebuilt Aether (Linux x86_64); no build toolchain required."
}


install_system_packages() {
  # Returns success even when optional package installation cannot be completed;
  # the dependency verification below decides whether the install can continue.
  if has_cmd pkg && { printf '%s' "${TERMUX_VERSION:-}" | grep -q . || printf '%s' "$TERMUX_ENV_PREFIX" | grep -q '/com.termux/'; }; then
    say "[i] Detected Termux. Installing Python ..."
    pkg update -y >/dev/null 2>&1 || true
    pkg install -y python >/dev/null 2>&1 || true
    return 0
  fi

  if has_cmd apk; then
    say "[i] Detected Alpine/iSH. Installing Python ..."
    COMMUNITY_REPO=""
    if [ -r /etc/alpine-release ]; then
      ALPINE_VER=$(cut -d. -f1,2 /etc/alpine-release 2>/dev/null || true)
      if [ -n "$ALPINE_VER" ]; then
        COMMUNITY_REPO="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VER}/community"
      fi
    fi
    run_root apk add --no-cache python3 >/dev/null 2>&1 || true
    if [ -n "$COMMUNITY_REPO" ]; then
      run_root apk add --no-cache --repository "$COMMUNITY_REPO" py3-pip >/dev/null 2>&1 || true
      run_root apk add --no-cache --repository "$COMMUNITY_REPO" py3-rich >/dev/null 2>&1 || true
    else
      run_root apk add --no-cache py3-pip >/dev/null 2>&1 || true
      run_root apk add --no-cache py3-rich >/dev/null 2>&1 || true
    fi
    return 0
  fi

  if has_cmd apt-get; then
    say "[i] Detected Debian/Ubuntu. Installing Python packages ..."
    run_root apt-get update >/dev/null 2>&1 || true
    run_root apt-get install -y python3 python3-pip >/dev/null 2>&1 || true
    run_root apt-get install -y python3-rich >/dev/null 2>&1 || true
    return 0
  fi

  if has_cmd pacman; then
    say "[i] Detected Arch Linux. Installing Python packages ..."
    run_root pacman -Sy --needed --noconfirm python python-pip >/dev/null 2>&1 || true
    run_root pacman -Sy --needed --noconfirm python-rich >/dev/null 2>&1 || true
    return 0
  fi

  if has_cmd dnf; then
    say "[i] Detected Fedora/RHEL. Installing Python packages ..."
    run_root dnf install -y python3 python3-pip >/dev/null 2>&1 || true
    run_root dnf install -y python3-rich >/dev/null 2>&1 || true
    return 0
  fi

  if has_cmd yum; then
    say "[i] Detected yum-based Linux. Installing Python packages ..."
    run_root yum install -y python3 python3-pip >/dev/null 2>&1 || true
    run_root yum install -y python3-rich >/dev/null 2>&1 || true
    return 0
  fi

  if has_cmd zypper; then
    say "[i] Detected openSUSE. Installing Python packages ..."
    run_root zypper --non-interactive install -y python3 python3-pip >/dev/null 2>&1 || true
    run_root zypper --non-interactive install -y python3-rich >/dev/null 2>&1 || true
    return 0
  fi

  if has_cmd brew; then
    say "[i] Detected Homebrew. Installing Python ..."
    brew install python3 >/dev/null 2>&1 || true
    return 0
  fi

  return 0
}

# -------------------------
# Source download
# -------------------------
TMP=""
cleanup() {
  if [ -n "$TMP" ] && [ -d "$TMP" ]; then rm -rf "$TMP"; fi
}
trap cleanup EXIT HUP INT TERM

if [ -z "$SCRIPT_DIR" ]; then
  say "[1/5] Downloading Spider from $REPO ..."
  TMP=$(mktemp -d 2>/dev/null || mktemp -d -t spider)
  has_cmd curl || die "curl is required. On Alpine/iSH: apk add curl. On Termux: pkg install curl."
  ARCHIVE_URL="${REPO%.git}/archive/refs/heads/${BRANCH}.tar.gz"
  curl -fL --retry 3 --retry-delay 1 --connect-timeout 15 --max-time 120 "$ARCHIVE_URL" -o "$TMP/spider.tar.gz" || die "Could not download Spider from GitHub."
  mkdir -p "$TMP/unpack"
  tar -xzf "$TMP/spider.tar.gz" -C "$TMP/unpack" || die "Could not extract Spider archive."
  SCRIPT_DIR=$(find "$TMP/unpack" -mindepth 1 -maxdepth 1 -type d -print | head -n 1)
else
  say "[1/5] Using local source: $SCRIPT_DIR"
fi

[ -f "$SCRIPT_DIR/warp_scan.py" ] || die "Invalid Spider source: $SCRIPT_DIR"
[ -d "$SCRIPT_DIR/warp_scan" ] || die "Invalid Spider source: $SCRIPT_DIR"

# -------------------------
# Python / dependency setup
# -------------------------
say "[2/5] Detecting Python and dependencies ..."
if [ -z "$PYTHON_BIN" ]; then
  if has_cmd python3; then PYTHON_BIN="$(command -v python3)"
  elif has_cmd python; then PYTHON_BIN="$(command -v python)"
  fi
fi

NEED_SYSTEM_INSTALL=0
if [ -z "$PYTHON_BIN" ]; then
  NEED_SYSTEM_INSTALL=1
elif ! "$PYTHON_BIN" -c 'import sys; assert sys.version_info >= (3,9)' >/dev/null 2>&1; then
  NEED_SYSTEM_INSTALL=1
fi

if [ "$NEED_SYSTEM_INSTALL" = "1" ] && [ "${SPIDER_SKIP_SYSTEM_PACKAGES:-0}" != "1" ]; then
  install_system_packages
fi

if [ -z "$PYTHON_BIN" ]; then
  if has_cmd python3; then PYTHON_BIN="$(command -v python3)"
  elif has_cmd python; then PYTHON_BIN="$(command -v python)"
  else die "Python 3 is required and could not be installed automatically."
  fi
fi

"$PYTHON_BIN" -c 'import sys; assert sys.version_info >= (3,9), sys.version' >/dev/null 2>&1 || die "Spider requires Python 3.9+."

ensure_python_package() {
  module="$1"
  package="$2"
  if "$PYTHON_BIN" -c "import $module" >/dev/null 2>&1; then
    return 0
  fi

  has_cmd "$PYTHON_BIN" || die "Python executable not found: $PYTHON_BIN"
  PIP_ARGS=""
  case "$($PYTHON_BIN -c 'import sys; print(sys.version_info[0])' 2>/dev/null || true)" in
    3) PIP_ARGS="--user" ;;
  esac

  # PEP 668 environments such as modern Alpine/Debian may require this flag.
  if "$PYTHON_BIN" -m pip install --disable-pip-version-check --timeout 25 --retries 2 $PIP_ARGS "$package" >/dev/null 2>&1; then
    :
  elif "$PYTHON_BIN" -m pip install --disable-pip-version-check --break-system-packages --timeout 25 --retries 2 "$package" >/dev/null 2>&1; then
    :
  else
    return 1
  fi

  "$PYTHON_BIN" -c "import $module" >/dev/null 2>&1
}

# Rich is optional in the application, but install it whenever possible for the full UI.
if ! "$PYTHON_BIN" -c 'import rich' >/dev/null 2>&1; then
  ensure_python_package rich 'rich>=13.9,<16' || warn "Rich could not be installed; Spider will use its built-in plain-terminal fallback."
fi

install_aether_build_deps

say "[3/5] Copying Spider application ..."
mkdir -p "$PREFIX" "$BIN_DIR"
rm -rf "$PREFIX.new"
mkdir -p "$PREFIX.new"
cp -R "$SCRIPT_DIR/." "$PREFIX.new/"
rm -rf "$PREFIX"
mv "$PREFIX.new" "$PREFIX"

# Ensure bundled connect components are present. Xray and Aether are supplied as prebuilt Linux x86_64 binaries.
if [ -f "$PREFIX/connect/xray/xray" ]; then chmod +x "$PREFIX/connect/xray/xray" || true; fi
if [ -x "$PREFIX/connect/aether/aether" ]; then
  say "[i] Bundled prebuilt Aether detected. No compilation is required on first run."
else
  warn "Bundled Aether binary is missing from this Spider package."
fi

# If the source copy contains an up-to-date bundled data file, keep it. Otherwise attempt GitHub.
mkdir -p "$PREFIX/data"
if [ ! -s "$PREFIX/data/cf_subnets.txt" ]; then
  say "[i] cf_subnets.txt is missing; downloading it from GitHub ..."
  CF_URL="https://github.com/amirh00sain/spiderscanner/raw/refs/heads/main/data/cf_subnets.txt"
  if curl -fL --retry 3 --connect-timeout 15 --max-time 120 "$CF_URL" -o "$PREFIX/data/cf_subnets.txt" >/dev/null 2>&1; then
    :
  else
    warn "cf_subnets.txt could not be downloaded. Cloudflare file scan will report the missing file."
  fi
fi

# -------------------------
# Fastfetch (optional)
# -------------------------
install_fastfetch() {
  [ "${SPIDER_SKIP_FASTFETCH:-0}" = "1" ] && return 0
  has_cmd fastfetch && return 0

  say "[i] Fastfetch is optional; trying a best-effort install ..."
  if has_cmd pkg && { printf '%s' "${TERMUX_VERSION:-}" | grep -q . || printf '%s' "$TERMUX_ENV_PREFIX" | grep -q '/com.termux/'; }; then
    pkg install -y fastfetch >/dev/null 2>&1 || true
  elif has_cmd apk; then
    run_root apk add --no-cache fastfetch >/dev/null 2>&1 || true
  elif has_cmd apt-get; then
    run_root apt-get install -y fastfetch >/dev/null 2>&1 || true
  elif has_cmd pacman; then
    run_root pacman -Sy --needed --noconfirm fastfetch >/dev/null 2>&1 || true
  elif has_cmd dnf; then
    run_root dnf install -y fastfetch >/dev/null 2>&1 || true
  elif has_cmd brew; then
    brew install fastfetch >/dev/null 2>&1 || true
  fi
}
install_fastfetch

# -------------------------
# Launcher
# -------------------------
cat > "$BIN_DIR/spider" <<LAUNCHER
#!/bin/sh
set -eu
cd "$PREFIX"
exec "$PYTHON_BIN" "$PREFIX/warp_scan.py" "\$@"
LAUNCHER
chmod +x "$BIN_DIR/spider"

# Ensure the installer can invoke the command even when the caller
# started from a shell that does not currently include BIN_DIR in PATH.
case ":$PATH:" in
  *":$BIN_DIR:"*) : ;;
  *) PATH="$BIN_DIR:$PATH"; export PATH ;;
esac

say "[4/5] Installing command: spider"

# -------------------------
# Self check
# -------------------------
say "[5/5] Running self-check ..."
"$PYTHON_BIN" -m py_compile "$PREFIX/warp_scan/main.py" "$PREFIX/warp_scan.py"
"$BIN_DIR/spider" --help >/dev/null

cat <<MSG

[+] Spider installed successfully.

Command:
  spider

Files:
  App    : $PREFIX
  Command: $BIN_DIR/spider

If "$BIN_DIR" is not in PATH in a new shell, run:
  export PATH="$BIN_DIR:\$PATH"

MSG
