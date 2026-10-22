# Learning

Record verified scan-policy improvements, false-positive patterns, and reusable guardrails here.

## 2026-08-14 MISTAKE LOGGED: guard-dog should validate against the active wave snapshot

Failure: The Guard Dog test read the stale primary-tree registry snapshot while the active Autonomizer wave was tracking versions in the worktree registry.
Cause: I assumed the nested repo parent tree was the authoritative version source for this rollout.
Correction: When validating Guard Dog version drift during an Autonomizer wave, point the test at the active worktree registry snapshot so the contract, registry, and package version are checked against the same release.
Guard: Do not mix primary-tree and worktree registry snapshots in the same version check.

## 2026-10-22 MISTAKE LOGGED: runtime blind spot

Failure: Node.js shipped four HIGH CVEs on 2026-10-21 (Brotli decoder out-of-bounds write reachable through fetch(), TLS hostname bypasses, dns.resolve NUL truncation). Every Node on the Mac Studio (Homebrew 26.12.0, 24.22.0, 22.23.3 and the All Sorted runtime at 22.23.2) was vulnerable, and Guard Dog reported clean nights.
Cause: Guard Dog only audited packages. The interpreter that runs every package was never inventoried, and Homebrew lagged the official fix by more than a day, so "brew is up to date" was not evidence either.
Correction: 5.2.0 adds `myos-guard-dog runtime`, wired into nightly and doctor. A newer same-major release with `security: true` in nodejs.org/dist/index.json is the source of truth. Replaced binaries do not protect processes started earlier: report restart needed by inode.
Guard: Any "everything is clean" claim covers packages, workspace files and the runtimes that execute them. When a scanner checks one layer, name the layers it does not check.
