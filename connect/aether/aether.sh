#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

AETHER_BIND="${AETHER_BIND:-127.0.0.1:1819}"
AETHER_CONFIG="${AETHER_CONFIG:-${HOME}/.aether/aether.toml}"
AETHER_PROTOCOL="${AETHER_PROTOCOL:-masque}"
AETHER_SCAN="${AETHER_SCAN:-balanced}"
AETHER_QUICK_RECONNECT="${AETHER_QUICK_RECONNECT:-1}"
AETHER_SOCKS="${AETHER_SOCKS:-$AETHER_BIND}"

exec env \
  AETHER_PROTOCOL="$AETHER_PROTOCOL" \
  AETHER_SCAN="$AETHER_SCAN" \
  AETHER_QUICK_RECONNECT="$AETHER_QUICK_RECONNECT" \
  AETHER_SOCKS="$AETHER_SOCKS" \
  "$SCRIPT_DIR/aether" \
  --masque \
  --scan "$AETHER_SCAN" \
  --quick-reconnect \
  --bind "$AETHER_BIND" \
  --config "$AETHER_CONFIG" \
  "$@"
