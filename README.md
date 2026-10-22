# MyOS Guard Dog 5.2.0

VirusTotal requests are paced within each process, including retries and refreshes.
Separate processes or other software sharing the same API key can still exhaust its
quota. Rate limits leave coverage incomplete; they never turn into a clean result.

MyOS Guard Dog checks software packages before installation and rechecks your projects against current security information. Its main command is `myos-guard-dog`; `myos-guard-dog-scan` is the bundled dependency-audit helper. It is not affiliated with DataDog GuardDog or other similarly named packages. The official source is [josephtandle/myos-guard-dog](https://github.com/josephtandle/myos-guard-dog).

## Local workspace scanner

The workspace scanner adds `myos-guard-dog workspace "/your/project" --json` for local files. It checks 28 native patterns across secrets, source code, CI, containers, TLS and coding-agent configuration. Rules carry severity, confidence and a concrete next action. They are text heuristics, not full semantic analysis.

```sh
myos-guard-dog workspace "/your/project"
myos-guard-dog workspace "/your/project" --sarif --output workspace.sarif
myos-guard-dog workspace "/your/project" --write-baseline workspace-baseline.json
myos-guard-dog workspace "/your/project" --baseline workspace-baseline.json --json
myos-guard-dog workspace "/your/project" --clamav /absolute/path/to/clamscan --json
myos-guard-dog updates enable --workspace "/your/project" --time 02:30 --files
```

The local scan makes no network requests and executes no project code. It includes hidden coding configuration and UTF-8/UTF-16 text, rejects symlinks and special files, and records skipped or unreadable files. Default limits are 20,000 files, 50,000 entries, 1 MiB per file, 128 MiB total, depth 30, 60 seconds and 2,000 findings. `--include-dependencies` includes node_modules and vendor; otherwise dependencies, build output and Git internals are explicitly outside the native scan scope. Binary content receives only the native antivirus test-marker check. Use a stable checkout: this is an on-demand scanner, not a security boundary against concurrent hostile filesystem mutation.

JSON and SARIF contain locations, fingerprints and remediation, never matching credential values or raw engine output. Treat report paths and metadata as private. Baselines annotate known findings without hiding them or allowing them through a security gate. Moving identical evidence keeps its identity; changing a detected credential produces a new identity. Reports and baselines use new filenames and mode 0600; existing destinations are never overwritten.

`--fail-on high` is the default. Critical/high findings exit 1 even with incomplete coverage. Lower findings remain visible; `--fail-on medium` or `low` makes them fail CI too. Missing coverage without a failing finding exits 2. Exit 0 means the requested checks completed within the declared scope without findings at the chosen threshold, not that the project is safe.

ClamAV is optional and must already be installed from a trusted source. Supply its absolute executable path outside the scanned tree. Guard Dog does not install the engine, download signatures, quarantine files or delete findings. The adapter checks database age and reports stale, missing, failed or bounded coverage as incomplete. ClamAV and its databases retain their separate licenses. `--files` nightly scanning runs native checks before package audits; it does not enable ClamAV automatically.

The native scanner passed Node 22/24 CI on macOS, Windows and Linux. The optional ClamAV adapter passed ten live probes on Linux with ClamAV 1.5.4; live macOS and Windows ClamAV validation is not claimed. See `WORKSPACE-SECURITY.md` for evidence, supported coverage and distribution requirements. All Sorted uses its own module release and installed-runtime verification.

## Install with your AI assistant

Use the [installation prompt](GUARD_DOG_PROMPT.md). It guides your assistant through setup, a first audit, VirusTotal verification, scheduling, repairs, and a completion report.

For a terminal installation on macOS, Windows, or Linux, use Node 22 or Node 24 LTS. Other major versions are rejected so local installs, CI and support all exercise the same runtime:

```sh
npm install -g --ignore-scripts github:josephtandle/myos-guard-dog#v5.2.0
myos-guard-dog setup
myos-guard-dog test
myos-guard-dog scan "/your/project"
myos-guard-dog doctor --repair
```

On Windows, substitute a quoted Windows folder such as `"C:\Users\You\Projects"`. All Sorted users should use the matching module installer instead of creating a second installation.

State lives in `~/.guardog` or `%USERPROFILE%\.guardog`, independently of the installation directory. `GUARDOG_HOME` selects another state folder. These legacy state names are intentional compatibility identifiers, not commands or product names. Do not rename them: upgrades reuse them to preserve settings, credentials and schedules.

Use the v5.2.0 GitHub tag only after verifying that it has been published and resolves to this release. Check the installed version before using it with student projects.

## A keyless first check

```sh
myos-guard-dog artifact npm:lodash@4.17.21
myos-guard-dog artifact npm:lodash@4.17.21 --json
myos-guard-dog artifact "/path/to/package.tgz"
```

The `npm:` form requires an exact version. It downloads the public npm archive, checks the registry hostname, release identity and strong registry digest, then reads archive bytes in memory. The local `.tgz` form inspects bytes without proving registry origin. Neither form extracts files, runs package scripts or requires an API key. It reports lifecycle scripts and selected source indicators, including a credential-file read plus outbound network capability in the same file. The inspection has limits on archive size, entry count and text scanned. A result with no indicators is **not** proof that a package is safe.

## Check before installing

```sh
myos-guard-dog install lodash
myos-guard-dog install npm install express@5.1.0
```

The guarded npm installer resolves the full dependency tree in temporary staging with scripts disabled. It verifies exact versions and public npm artifact hashes, runs bounded artifact inspection on those same bytes, then requires completed security checks before installing the approved lockfile. High-risk, review, or uninspectable archive findings stop the guarded install and identify the file and rule for manual review. Lifecycle scripts remain disabled after installation. Packages needing build scripts require a separate review.

Direct npm or pip commands bypass Guard Dog. Guard Dog does not intercept all terminal activity. Unsupported guarded installations, including pip, custom registries, workspaces and local/Git sources, stop with an explanation. They are not silently passed through.

## Audit existing projects

```sh
myos-guard-dog scan "/your/project"
myos-guard-dog-scan "/your/project/package.json" --json
myos-guard-dog analyze node-ipc@10.1.1 npm
myos-guard-dog analyze requests@2.32.3 pypi
```

Project and nightly audits now check advisories first with four bounded local workers. Nightly completes its advisory sweep across all discovered projects before starting slower enrichment. Shared dependencies reuse successful evidence within that run. Each new nightly run checks OSV again, even when Git is clean.

Local workspace scans re-read and hash file bytes, then reuse unchanged rule results for up to 24 hours. This also covers ignored and untracked files within the declared scope. Cached findings remain visible. Reports include `filesAnalyzed` and `filesReused`; `myos-guard-dog workspace <folder> --no-cache` forces full rule evaluation. Git cleanliness alone is never evidence of safety.

Audit enrichment reuses successful reputation and integrity-verified archive hashes for one hour. VirusTotal results remain reusable only while their original analysis is fresh (at most 24 hours); failures and stale reports never become clean evidence. Cache entries are private, integrity-authenticated and bounded to 8,192 entries of at most 256 KiB each. Cache corruption causes a fresh check. This protects against damaged cache entries, not an attacker controlling your user account. `myos-guard-dog scan <folder> --no-cache` refreshes all evidence. Guarded installs do not use audit caches.

Use `myos-guard-dog scan <folder> --advisories-only --json` for the fast advisory phase. Its enrichment coverage intentionally remains incomplete. JSON reports name affected packages and advisory IDs, and nightly reports include project paths plus separate `phases.advisories` and `phases.enrichment`. Exit 1 means danger; exit 2 still means incomplete or suspicious protection. Finishing the job does not imply every external check completed.

Project audits read exact npm lockfile versions, including transitive dependencies, and compare installed identity when present. npm lockfile versions 1, 2 and 3 and shrinkwrap files are supported. Non-registry or unproven origins, installed-only packages, and mismatches between installed metadata and the lock make coverage incomplete. Python and Ruby packages can be analyzed individually; automatic project inventory currently covers npm.

## Long scans and time budgets

VirusTotal lookups are spaced 16 seconds apart. At least one lookup per dependency means 100 dependencies can take about 26 minutes, before registry checks, retries or report refreshes. The nightly per-project hard limit remains 15 minutes; increasing it alone does not solve repeated restarts.

Nightly scans now stop starting new dependency checks after 13 minutes by default, leaving two minutes for an in-flight check. Each completed analysis writes an atomic progress receipt. The next run starts at the next dependency, and changed inventory resets the cursor. A forced timeout recovers findings from that same child run when its receipt is available.

For a bounded manual audit, use:

```sh
myos-guard-dog scan "/your/project" --budget-ms 780000 --json
```

The budget stops new checks; the current check can finish afterward. The nightly parent retains the hard timeout. Ordinary manual scans without `--budget-ms` still request a full audit. Budgeted scans share their per-project cursor, so avoid running two concurrently.

Read `scannedDependencyCount`, `deferredDependencyCount`, `budgetExhausted` and `resume` in the JSON. The cursor stores position only, not reusable clean verdicts. A large project may need several runs to visit every dependency, but those separate runs are never combined into a current complete verdict. Unchecked packages remain incomplete and exit 2. Known danger remains exit 1 even if other checks time out. Guarded installation requirements are unchanged.

Nightly receipts add `scannedDependencyCount`, `coverage.deferredDependencies`, `budgetStops`, `timeouts` and `runnerFailure` when applicable. Progress is local under `~/.guardog/data/scan-progress/`; there is no automatic student telemetry. If a Node upgrade removes the running executable, the scan stops further launches and asks for Node 22/24 verification followed by `myos-guard-dog doctor --repair`. Review recurring failures with `myos-guard-dog doctor --json` and the latest nightly receipt. Do not share `.env` or API keys.

## Node.js runtime advisories

Package scans cannot see a vulnerable Node.js itself. The October 2026 Node security releases (a Brotli decoder out-of-bounds write reachable through `fetch()`, TLS hostname bypasses and a `dns.resolve` truncation) affected every installed Node on a machine whose packages all scanned clean. The runtime check closes that gap:

```sh
myos-guard-dog runtime
myos-guard-dog runtime --json
myos-guard-dog runtime --fix-plan
```

It finds `node` on PATH, in Homebrew, nvm, fnm, volta, asdf, n, the All Sorted runtime and in running processes, and compares each version with the official Node release index. A newer security release on the same major means **vulnerable**; a major past its end-of-life date means **eol**. Both exit 1 and make the nightly receipt dangerous. Processes still running a binary that has since been replaced are listed as **restart needed**. Node bundled inside applications is **vendor-managed**: update the application, not its files.

Guard Dog never replaces binaries. `--fix-plan` prints the commands to run yourself: `brew upgrade` once Homebrew ships the fix, otherwise the official nodejs.org archive verified against `SHASUMS256.txt` and its signature, with a backup of the old binary. With `VERCEL_TOKEN` set, Vercel projects on an end-of-life Node major are reported too. Set `runtimeAdvisories: false` in `~/.guardog/config.json` to leave it out of nightly runs.

## VirusTotal and coverage

OSV vulnerability checks need no API key. VirusTotal malware checks require your own key, entered locally with `myos-guard-dog setup` or supplied through `VIRUSTOTAL_API_KEY`. GitHub metadata requests can use `GITHUB_API_TOKEN` to reduce rate limits. Never paste keys into chat or bug reports.

VirusTotal checks SHA-256 reports for the exact package artifact. Old known reports request reanalysis; that request does not count as a fresh result. Reports with no completed engine verdicts, unknown hashes, old results, authentication failures and rate limits remain incomplete. No private files are uploaded. An explicitly supplied URL checks URL reputation, not its downloaded file contents.

Guarded installs require complete OSV and VirusTotal checks and no disqualifying findings. Without a VirusTotal key you can still inspect vulnerability findings, but guarded installs remain blocked. The default freshness limit for stored VirusTotal reports is 24 hours. API usage and access depend on your VirusTotal plan; see its [official API documentation](https://docs.virustotal.com/reference/overview).

| Result | Meaning |
| --- | --- |
| BARK | Serious evidence found; installation blocked. |
| WHINE | Warning signals need review; installation blocked. |
| SILENT | The completed checks did not reach a warning threshold. Read coverage too. |
| INCOMPLETE | Required evidence is missing. It is not a safe result. |

Audit exit codes are 0 only when completed checks report SAFE, 1 for serious findings, and 2 for suspicious or incomplete coverage or operational failure. Artifact inspection uses 0 for no indicators within its bounded scan, 1 for high-risk indicators, and 2 for review or incomplete inspection. A zero from artifact inspection alone does not certify package safety. Guarded installation has the stricter approval policy.

## Daily scans and self-repair

```sh
myos-guard-dog updates enable --workspace "/your/workspace" --time "02:30"
myos-guard-dog updates status
myos-guard-dog nightly
myos-guard-dog doctor --repair
```

Choose the folders and local run time explicitly. Scheduling uses cron on Mac/Linux and Task Scheduler on Windows, with registration readback. A scan receipt records the last run, project and dependency counts, danger and coverage gaps. An empty run is not reported as successful protection.

Each daily run checks its health first. Safe repairs restore missing state directories, restrict credential-file permissions on POSIX systems, and restore an owned runner or previously enabled missing schedule. Unknown files and jobs are preserved. Overlap and run-time limits prevent endless repair loops. Service retries are bounded. Credentials, unsupported inventories and persistent service outages remain visible for action. Repairs never weaken checks or alter project dependencies.

Setup and nightly runs also maintain `data/resilience-state.json`. This local receipt tracks verified cycles, successful repair counts, healthy streaks and recurring issue categories. A category that survives two cycles is escalated with a concrete next action; a verified healthy cycle clears the active recurrence. It stores categories rather than machine-specific paths or credentials. The loop never rewrites Guard Dog code, changes threat thresholds, selects scan roots, replaces customized jobs or installs project dependencies.

The computer must be available for its scheduler. Use `myos-guard-dog updates disable` to remove the owned schedule. `myos-guard-dog doctor --json` provides machine-readable health. Optional Git hooks are secondary commit checks, not pre-install protection.

## Scope and verification

Guard Dog protects package workflows and selected coding workspaces. It is not a replacement for operating-system antivirus and does not watch every file or process. Regular `analyze` and `scan` pattern checks read registry description text; `artifact` and guarded `install` now additionally read bounded npm archive source bytes. This static inspection does not execute code, perform a sandboxed behavioral analysis, or cover every obfuscation technique. The CLI queries OSV, registry metadata, GitHub metadata when linked, and optional VirusTotal reports; it does not query NVD or CISA KEV or run name-similarity detection. SILENT describes only those completed checks. No scan guarantees software is harmless. For PyPI releases with multiple distributions, provide the SHA-256 of the exact wheel or source archive to check; without one, artifact coverage is incomplete.

`npm test` runs regression and real packed-install tests. CI runs these on Windows, macOS and Linux with Node 24. Scheduler tests exercise platform command construction and readback without installing real tasks. `npm run test:live` separately exercises public services and may consume API quota. See the release verification record for actual platform results.

Report security issues through [GitHub Security Advisories](https://github.com/josephtandle/myos-guard-dog/security/advisories/new). License: MIT.

Set `GUARDOG_NIGHTLY_TIMEOUT_MS` (milliseconds, maximum 24 hours) or `nightlyTimeoutMs` in the user configuration to change the one-hour total budget. `GUARDOG_MANIFEST_TIMEOUT_MS` retains the 15-minute enrichment cap; projects share remaining time fairly. Half the available time is reserved for the advisory sweep, with unused time available to enrichment. Finite limits remain deliberate; budget stops save resumable progress. Choose explicit project roots instead of scanning an entire home directory.
