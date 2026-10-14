#!/bin/bash
# Guard Dog Nightly Cron Scanner
# Scans all package.json files in the workspace
#
# Legacy/manual wrapper. The supported scheduler command is:
#   myos-guard-dog updates enable --workspace "/your/workspace" --time 02:30
#
# Change WORKSPACE below to the directory you want to scan.

export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
GUARD_DOG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Fallback only: explicit config.scanRoots (myos-guard-dog setup) win over this.
WORKSPACE="${GUARDOG_WORKSPACE:-$HOME}"
LOG_DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Overseer status file, written on every exit (crash, timeout cap or clean run),
# in the same {status,last_run} shape as the other ~/.myos/state/overseer jobs.
# The detailed receipt stays at ~/.guardog/data/last-nightly.json.
OVERSEER_STATUS="${GUARD_DOG_OVERSEER_STATUS:-$HOME/.myos/state/overseer/guard-dog-nightly.json}"
RUN_STARTED_EPOCH=$(date +%s)
write_overseer_status() {
  local code=$?
  local receipt="${GUARDOG_HOME:-$HOME/.guardog}/data/last-nightly.json"
  local detail=""
  if [ -f "$receipt" ] && [ "$(stat -f %m "$receipt" 2>/dev/null || echo 0)" -ge "$RUN_STARTED_EPOCH" ]; then
    detail=$(/usr/bin/python3 -c 'import json,sys
r=json.load(open(sys.argv[1]))
print("receipt status=%s dangerous=%s suspicious=%s deps=%s projects=%s" % (r.get("status"), r.get("dangerousCount"), r.get("suspiciousCount"), r.get("dependencyCount"), r.get("projectsScanned")))' "$receipt" 2>/dev/null || true)
  else
    detail="no receipt written this run"
  fi
  local reason
  case "$code" in
    0) reason="scan complete or partial (rotation deferral)" ;;
    1) reason="dangerous dependency findings" ;;
    2) reason="incomplete or suspicious scan" ;;
    124|137) reason="hit the ${CAP_SECONDS:-3900}s hard cap" ;;
    *) reason="scanner exited $code" ;;
  esac
  [ -n "$detail" ] && reason="$reason; $detail"
  local status="error"; [ "$code" -eq 0 ] && status="ok"
  mkdir -p "$(dirname "$OVERSEER_STATUS")" 2>/dev/null || true
  /usr/bin/python3 -c 'import json,sys,os
path,status,code,reason=sys.argv[1],sys.argv[2],int(sys.argv[3]),sys.argv[4]
from datetime import datetime,timezone
tmp=path+".%d.tmp"%os.getpid()
json.dump({"status":status,"last_run":datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),"exit_code":code,"reason":reason,"taskClass":"security_scan"},open(tmp,"w"))
os.replace(tmp,path)' "$OVERSEER_STATUS" "$status" "$code" "$reason" 2>/dev/null || true
  exit "$code"
}
trap write_overseer_status EXIT

echo "===== Guard Dog Nightly Scan: $LOG_DATE ====="

# Dead-man switch for spending reconciliation. It sends an alert when Scrooge
# has not written a valid reconciliation state for 26 hours, then scan proceeds.
node "$GUARD_DOG_DIR/bin/check-scrooge-freshness.cjs" || true

# Dead-man switch for the daily Stripe/Gumroad revenue pull (Revenue Pulse).
# Redundant with its own 8:30am check; this catches the case where that job
# itself failed to fire.
node "$HOME/.myos/workspace/agents/revenue-pulse/bin/check-revenue-pulse-freshness.cjs" || true

# Delegate dependency discovery and stopping conditions to the released nightly
# runner. It uses the cross-process VirusTotal daily budget and stops the run as
# soon as that budget is exhausted, unlike the historical per-manifest loop.
# Guard Dog pins Node 24 (.nvmrc, engines, src/node-version.js). Homebrew's
# default `node` is 26 on the Studio, which made every nightly run exit 1 with
# ERR_UNSUPPORTED_NODE_VERSION. Prefer a Node 24 binary when one is installed.
GUARD_DOG_NODE="${GUARD_DOG_NODE:-}"
if [ -z "$GUARD_DOG_NODE" ]; then
  for candidate in /opt/homebrew/opt/node@24/bin/node /usr/local/opt/node@24/bin/node; do
    if [ -x "$candidate" ]; then GUARD_DOG_NODE="$candidate"; break; fi
  done
fi
GUARD_DOG_NODE="${GUARD_DOG_NODE:-node}"
# Hard external cap: nightly-scan has a 1h internal budget; never let it hold
# the slot past that (TERM at 65 min, KILL 60s later). Exit 124/137 = capped.
CAP_SECONDS="${GUARD_DOG_NIGHTLY_CAP_SECONDS:-3900}"
TIMEOUT_BIN="$(command -v timeout || command -v gtimeout || true)"
if [ -n "$TIMEOUT_BIN" ]; then
  GUARDOG_WORKSPACE="$WORKSPACE" "$TIMEOUT_BIN" -k 60 "$CAP_SECONDS" "$GUARD_DOG_NODE" "$GUARD_DOG_DIR/bin/nightly-scan.js"
else
  GUARDOG_WORKSPACE="$WORKSPACE" "$GUARD_DOG_NODE" "$GUARD_DOG_DIR/bin/nightly-scan.js"
fi
