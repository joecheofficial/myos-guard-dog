# Runtime advisories review fixes: 5.2.1

- fnm under `~/Library/Application Support/fnm` (and nvm, volta, asdf, mise, pnpm, n trees) is classified as a version manager before vendor rules, so its vulnerable versions are HIGH instead of vendor-managed.
- Cron-safe tools: `lsof`, `ps` and `brew` resolve through `/usr/sbin`, `/sbin`, `/opt/homebrew/bin` and `/usr/local/bin` even with `PATH=/usr/bin:/bin`. A failed process listing or `lsof` read now makes the result incomplete instead of silently complete.
- Windows probes `node.exe` on PATH plus the running executable and skips the process scan with a note that does not mark the run incomplete.
- Runtime status is settled before the optional Vercel step. Vercel requests time out after 15 seconds within a 45-second budget, paginate, and keep team results when the personal scope fails. The nightly retries once with `--no-vercel` if the first attempt dies.
- A missing release schedule makes the result incomplete, and the nightly records runtime issues whatever the status.
- Manager-installed versions that are not running, not on PATH and not the manager default are reported as medium "installed, inactive" with an uninstall command. An unresolved default is treated as active. Manager fix commands now install, set the default and uninstall the old version.
- Fix plans: each binary fix is one `set -euo pipefail` subshell, so a failed GPG signature or checksum stops before anything is installed. Signatures are checked with `gpgv` against the nodejs/release-keys keyring. Every interpolated value is shell-quoted and release versions must match `vX.Y.Z`.
- Unpatched Homebrew kegs are never overwritten: the verified build goes to `~/.local/node-vX.Y.Z` to be placed first on PATH, and `brew upgrade` restores the normal path when it ships. Other replaced binaries are backed up to `~/.guardog/runtime-backups`, not next to the binary.
- Discovery adds `/usr/local/bin/node`, mise, pnpm env, `~/bin` and the running executable. Version-manager shims (Volta, asdf, mise, nodenv, proto) are labelled as shims instead of broken binaries.
- A failed advisory fetch falls back to the last good copy from the past 30 days, reported as a note. Process command lines are redacted for Stripe/GitHub/Slack tokens, `--token`/`--key`/`--password` values, URL credentials and `*_TOKEN=`/`*_KEY=` assignments.
- Install documentation points at `github:joecheofficial/myos-guard-dog`; old URLs redirect.

# Runtime advisories: 5.2.0

- Add `myos-guard-dog runtime [--json] [--fix-plan] [--no-cache]`. It checks the Node.js runtimes themselves, not only packages: every `node` on PATH, Homebrew kegs and opt links, nvm, fnm, volta, asdf, n, the All Sorted runtime (`~/.local/allsorted-node`) and the executables of running node processes. Runtimes are deduplicated by real path plus device and inode. A binary that cannot run `-v` is reported as unknown and never stops the check.
- Compare each version with `nodejs.org/dist/index.json`: a newer release on the same major with `security: true` makes the runtime vulnerable, and the newest such release is reported as `fixedIn`. End-of-life majors come from the Node release schedule. CVE ids are added from the Node security-wg core database when it lists them; the verdict works from the release index alone. Sources are cached privately for six hours and requests are paced.
- Report running processes whose executable file was replaced after start (lsof inode differs from the current file) as "restart needed" with pid and redacted command. Runtimes bundled inside applications (for example `/Applications/*.app`, `~/Library/Application Support`, Codex runtimes) are vendor-managed: reported, never given a replacement command.
- Binaries are never modified. `--fix-plan` prints exact commands only: `brew upgrade` when Homebrew has shipped the fix, otherwise the official nodejs.org tarball with SHASUMS256.txt, its GPG signature, a backup of the old binary and a version readback.
- The nightly scan runs the runtime check first. A vulnerable or end-of-life runtime is a HIGH issue, marks the receipt dangerous and exits 1, and `doctor` repeats it from the last receipt. Set `runtimeAdvisories: false` in the user config to opt out.
- With `VERCEL_TOKEN` set, also list Vercel projects (personal and teams) and flag Node versions on an end-of-life major. Report only.

# Incremental advisory-first scans: 5.1.0

- Run a four-worker advisory sweep across all discovered projects before VirusTotal or GitHub enrichment. Share exact-version OSV evidence only within the current nightly run; every new run checks for newly published advisories.
- Reuse local rule results by actual file bytes, path and scanner/ruleset version for up to 24 hours. Re-read/hash ignored and untracked files too. Preserve cached findings and all existing scope/resource limits. `workspace --no-cache` forces rule evaluation.
- Add private, bounded, authenticated evidence caching: successful reputation and verified artifact-hash mappings for one hour; VirusTotal hash reports only while their original analysis remains fresh. Failed checks never certify coverage. Install gates remain uncached.
- Deduplicate shared GitHub repositories, pace GitHub and VirusTotal across audit processes, and keep the existing daily VT quota guard. Work runs in local deterministic workers with no model API costs.
- Preserve out-of-order worker checkpoints, prevent overlapping writes to a manifest cursor, and retry unfinished rows after interruption.
- Include package names, exact versions, project paths and advisory IDs in nightly findings. Report advisory and enrichment coverage separately; retain advisories when enrichment is deferred or killed.
- Share remaining enrichment time fairly between projects. Configure total budget with `GUARDOG_NIGHTLY_TIMEOUT_MS` or `nightlyTimeoutMs`; retain `GUARDOG_MANIFEST_TIMEOUT_MS` as a per-project cap. Explicit `scan --advisories-only` runs the fast phase without enrichment.

# Resumable nightly scans: 5.0.3

- Checkpoint dependency progress after every completed analysis. Nightly scans stop starting new checks before the per-project deadline and resume at the next dependency on the next run.
- Recover current-run findings if the child process still reaches its hard timeout. Known danger stays exit 1 even when other coverage is incomplete.
- Add `scan --budget-ms N` and the helper equivalent for bounded manual audits. A cursor carries position only; previous verdicts never count as fresh evidence. Changed inventory resets the cursor.
- Report checked and deferred dependency counts, budget stops, hard timeouts and runner failures in local receipts. Incomplete audits remain exit 2.
- Stop repeated rate-limit waits after the local daily quota guard refuses a request; allow a fresh quota check after UTC rollover.
- Stop spawning further scans when the Node executable is missing or cannot run, with a concrete repair instruction.

# Student setup and naming corrections: 5.0.2

- Use MyOS Guard Dog consistently in current product documentation. Keep third-party names and existing code identifiers distinct.
- Explain why `.guardog` and `GUARDOG_HOME` remain unchanged for existing settings, credentials and schedules.
- Fix the shell installer and student setup instructions to accept both supported Node versions, 22 and 24. Unsupported majors still stop before npm runs.
- Include the local workspace scan in student setup instructions and distinguish it from the dependency audit.
- Document `myos-guard-dog-scan` as the bundled helper; keep `myos-guard-dog` as the main command.

# Customer report security fixes: 5.0.1

These three fixes come from an All Sorted customer report.

- VirusTotal requests refuse HTTP redirects, so the x-apikey header can never be forwarded to another host.
- GitHub issue search uses the repository's canonical name (renamed repositories), validated as a plain owner/repo before it enters the search query. Legacy owners ending in a hyphen are accepted.
- Guarded install accepts exactly two reviewed override shapes that All Sorted ships (Mission Control's postcss pin, the WhatsApp server's Baileys/qs pins). Every locked package is still origin-, integrity- and scan-checked; every other override is refused, including a null or empty one.

# Workspace scanner: 5.0.0

- Adds an offline workspace command with 28 original rules for secrets, suspicious source patterns, development configuration, CI and agent permissions.
- Adds bounded no-follow file traversal, explicit incomplete coverage, JSON/SARIF output and non-suppressing baselines. Reports do not contain matched credential values.
- Adds opt-in workspace scanning to existing nightly jobs and reports local coverage separately from dependency protection.
- Adds an explicit adapter for a separately installed ClamAV engine. Missing, stale or failed engines remain incomplete; GuardDog never installs or updates that engine automatically.
- Preserves both the local nightly quota/rotation improvements and public 4.1 package-artifact inspection.
- Expands CI to Node 22/24 on macOS, Linux and Windows; adds an isolated Linux ClamAV release probe with harmless fixtures.

Native rules are heuristic checks, not semantic SAST or endpoint antivirus. Evidence and deployment boundaries are recorded in WORKSPACE-SECURITY.md.

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
