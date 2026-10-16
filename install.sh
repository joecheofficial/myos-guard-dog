#!/usr/bin/env bash
set -euo pipefail

guard_dog_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
  echo "MyOS Guard Dog requires Node.js 22 or 24 LTS: https://nodejs.org/"
  exit 1
fi

node_version=$(node --version 2>/dev/null || true)
node_major=${node_version#v}
node_major=${node_major%%.*}
case "$node_major" in
  ''|*[!0-9]*)
    echo "MyOS Guard Dog could not verify the installed Node.js version. Node 22 or 24 LTS is required."
    exit 1
    ;;
esac
if [ "$node_major" -ne 22 ] && [ "$node_major" -ne 24 ]; then
  echo "MyOS Guard Dog requires Node.js 22 or 24 LTS. Found $node_version: https://nodejs.org/"
  exit 1
fi

echo "Installing MyOS Guard Dog from this folder..."
npm install --global --ignore-scripts "$guard_dog_dir"

echo "Applying safe local defaults..."
node "$guard_dog_dir/src/index.js" setup --quick

echo ""
echo "MyOS Guard Dog is ready."
if command -v myos-guard-dog >/dev/null 2>&1; then
  echo "Try: myos-guard-dog analyze lodash npm"
  echo "Optional VirusTotal setup: myos-guard-dog setup"
else
  echo "MyOS Guard Dog installed, but npm's global command folder is not on PATH yet."
  echo "Open a new terminal, then run: myos-guard-dog doctor"
fi
