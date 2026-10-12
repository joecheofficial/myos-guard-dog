# Changelog

## 4.1.0 (release candidate)

- Add keyless, exact-version npm artifact inspection with verified registry digest or local `.tgz` input. Parse archive bytes in memory with bounded size and entry limits; report lifecycle scripts and correlated source indicators without executing or extracting package code.
- Gate guarded npm installs on that bounded artifact inspection in addition to existing OSV, registry and VirusTotal checks. High-risk, review and incomplete artifact findings block the guarded install with a file and rule to examine.
- Make failed pattern checks reach the actual install verdict, and make suspicious project-audit results visible with a nonzero exit status.
- Fold in the unreleased 4.0.4 candidate fixes below.

- Resolve Windows helpers by absolute system path, reject project-local npm entry points, and keep Guard Dog credentials out of helper and npm child environments.
- Treat non-registry and unproven dependency origins, lock and install mismatches, and installed-only packages as incomplete inventory coverage.
- Block UNCONFIRMED installs, distinguish unsupported repository hosts, scope trusted names to their ecosystem, and use canonical GitHub repository names after redirects.
- Make batch and command failures visible in exit codes; recover abandoned quota locks, fail closed on corrupt ledgers, and write quota records atomically.
- Require the exact PyPI distribution hash for multi-file releases and state the metadata-only scope of pattern checks in output and docs.
- Bound package-batch analysis to four concurrent packages while preserving order and VirusTotal API-key pacing.
- Detect legacy `# guarddog-nightly` cron entries and preserve customized schedules.
- Make scan-root regression coverage portable across Windows, macOS and Linux.

## 4.0.3

- Declare POSIX installer and installed-hook tests unsupported on Windows, matching the product behavior, so cross-platform CI tests the supported surface without attempting to launch unavailable Bash commands.

## 4.0.2

- Make the Git hook scan staged dependency metadata, including lockfile-only, overrides and workspace resolution changes, while skipping scripts-only manifest edits.
- Distinguish confirmed danger from incomplete coverage and keep changed dependencies fail-closed.
- Preserve customized scheduler entries during enable, repair and disable, while repairing the owned runner independently.
- Add bounded install and nightly resilience cycles with repair readback, recurrence tracking and privacy-safe next actions.
- Standardize the public repository, package and command identity as `josephtandle/myos-guard-dog` and `myos-guard-dog`.
- Pin development, CI, installation and runtime support to Node 24 LTS. The shell installer rejects other majors before npm runs, and every shipped executable rejects them before Guard Dog operates.

## 4.0.1

- Add a persisted cross-process VirusTotal daily request budget of 400 calls, preserving 100 calls of public-API headroom for manual checks.
- Treat VirusTotal quota responses as a hard stop, with no retry after a 429 response.
- Stop nightly scans once VirusTotal quota coverage is exhausted, and route the legacy macOS launcher through the same protected nightly runner.

## 4.0.0

- Rename the public package and command to `myos-guard-dog` to avoid collisions with unrelated GuardDog and Guardog tools. Fresh installs no longer expose ambiguous command aliases.

## 3.0.1

- Mark local and workspace-linked npm dependencies as incomplete audit coverage instead of treating them as verified registry packages.
- Build the approved dependency tree in project-local staging and promote it only after a successful `npm ci`, preserving the live manifest, lockfile and dependency tree when staging fails.

## 3.0.0

- Audit exact installed and locked npm versions, including transitive dependencies.
- Keep registry and OSV failures distinct from completed clean checks.
- Use package creation dates for new-package signals and reduce unverified complaint noise.
- Block confirmed malware independently of reputation allowlists.
- Gate npm installation on exact-version artifact identity, integrity and completed checks.
- Disable lifecycle scripts during dependency resolution and installation.
- Distinguish fresh VirusTotal reports, unknown hashes, stale reports and failed checks.
- Add verified cross-platform scheduling, explicit scan roots and bounded self-repair.
- Record daily repairs, coverage gaps and scan findings without claiming empty scans succeeded.
- Preserve malformed settings, hide terminal key entry and report incomplete setup honestly.
- Add participant install instructions, command aliases and cross-platform CI.

Guard Dog is package-workflow protection, not a replacement for OS antivirus.
Supported guarded installation and project inventory are npm-only in this release.

## 2.0.0 (2026-08-25)

Security capability and fail-safe behavior update based on external security audit, 2026-08-25:

- Fix 1: Deferred optional Telegram shared module require inside sendDangerAlert to prevent startup crashes.
- Fix 2: Updated guardedInstall spawnSync to handle Windows .cmd execution safely and catch spawn errors explicitly.
- Fix 3: Normalized CVE severity vocabulary (alias moderate to medium) and added warning fallback for unmapped severities.
- Fix 4: Raised SECURITY_COMPLAINTS reputation weight to reach WHINE threshold on its own, and rendered SILENT decisions with reasons as UNCONFIRMED with an informational icon instead of a green checkmark.
- Fix 5: Short-circuited missing registry packages to WHINE/NOT_FOUND verdict instead of scoring as low-threat safe packages.
- Fix 6: Derived VirusTotal target hash automatically from package tarball or PyPI metadata, polled URL analyses until completion, and failed 0-engine scans.
- Fix 7: Restricted trusted-provider allowlist to skip only reputation heuristics while still running objective VT, CVE, and pattern checks.
- Fix 8: Split decision notes from risk reasons so trusted provider notifications do not trigger UNCONFIRMED threat state on safe packages.
- Fix 9: Removed dead, unpatched duplicate module tree in src/alerts, src/core, and src/scanners.
- Fix 10: Discriminated GitHub API lookup failures to emit GITHUB_CHECK_FAILED and score 25 (UNCONFIRMED) instead of treating API rate limiting or errors as clean repository signals (found during verification of audit wave).
