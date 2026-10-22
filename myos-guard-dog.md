# MyOS Guard Dog skill

Use MyOS Guard Dog before installing npm dependencies and for recurring exact-version audits.
Official project: https://github.com/joecheofficial/myos-guard-dog. The main command is `myos-guard-dog`; `myos-guard-dog-scan` is its bundled dependency-audit helper.

1. Locate the installed command using the platform's command discovery, then run `myos-guard-dog --version` and `myos-guard-dog doctor`.
2. If missing or unhealthy, follow `GUARD_DOG_PROMPT.md`. Use `doctor --repair` for bounded supported repairs and verify the result.
3. For a keyless first check of an exact public npm version, use `myos-guard-dog artifact npm:<name>@<version>`. Read its findings and bounded coverage; no listed indicator is not a safety guarantee.
4. Before supported npm installs, use `myos-guard-dog install <package>`. It also inspects exact npm archive bytes. Never fall back to a direct package-manager install when the gate blocks.
5. Audit existing projects with `myos-guard-dog scan "<folder>"`. Report exact versions, suspicious findings and incomplete coverage, including transitive dependencies.
6. Check the Node.js runtimes themselves with `myos-guard-dog runtime`. Vulnerable or end-of-life runtimes exit 1; use `--fix-plan` for commands to review. Never replace binaries without the user's approval.
7. Set up opted-in daily scans with `myos-guard-dog updates enable --workspace "<folder>" --time HH:MM`, inspect registration, and run `myos-guard-dog nightly` once.

Missing VirusTotal reports, API failures, and unresolved versions are incomplete protection. Never represent them as safe. VirusTotal queries and OSV advisories do not replace operating-system antivirus. Never upload private files, erase findings, or weaken checks to make installation succeed.
