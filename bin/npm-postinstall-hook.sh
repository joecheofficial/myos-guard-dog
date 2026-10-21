#!/bin/bash
# Guard Dog npm postinstall hook
# Legacy/manual secondary scan. The supported pre-install gate is:
#   myos-guard-dog install <package>

GUARD_DOG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG_JSON="${INIT_CWD:-$(pwd)}/package.json"

if [ ! -f "$PKG_JSON" ]; then
  exit 0
fi

echo "🐕 Guard Dog: Post-install scan triggered..."
node "$GUARD_DOG_DIR/bin/scan-deps.js" "$PKG_JSON" 2>&1

# Don't block install on scan failures (network issues, etc.)
# Only exit non-zero if dangerous packages found (scan-deps.js handles this)
exit $?
