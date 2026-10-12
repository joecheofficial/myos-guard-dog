# MyOS Guard Dog 4.1 operations

Guard Dog protects supported package workflows, not the entire operating system.

## Local state

State is stored in `GUARDOG_HOME`, or `~/.guardog` by default.

- `config.json`: selected scan roots, schedule consent and local run time.
- `.env`: local VirusTotal credential, never include it in reports.
- `bin/nightly-runner.cjs`: Guard Dog-owned scheduler entry point.
- `data/last-nightly.json`: latest scan receipt, coverage and findings.
- `data/nightly.lock`: overlap protection for active nightly runs.
- `data/resilience-state.json`: privacy-safe install/nightly verification history and recurring issue categories.

## Operations

Use `myos-guard-dog doctor --repair` to inspect health and attempt bounded repairs.
Daily scans also check local health. Only previously enabled schedules can be
restored. Unknown runner files and scheduler conflicts require human attention.
Repairs must not weaken security checks or modify project dependencies.

Use `myos-guard-dog updates status` to inspect actual OS scheduling and
`myos-guard-dog nightly` to exercise a run. An empty or incomplete scan is not success.
Review the receipt's dependency count, configured roots, findings and missing
coverage. The machine must be available for its scheduler to run.

Install and nightly resilience cycles are bounded to owned local repairs, health
readback and recurrence tracking. They never self-modify code or security policy.

This release does not promise immediate external notifications, daily email
digests, monthly consolidation or automatic vulnerability remediation.
