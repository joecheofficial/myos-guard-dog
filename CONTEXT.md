# MyOS Guard Dog: Project Context
> Last updated: 2026-10-03

## What It Is

A public package security scanner packaged from the internal `guard-dog` agent and published to GitHub for Mastermind students. Supported guarded npm installs use OSV advisories, registry and GitHub metadata, optional VirusTotal hash reports, and bounded static inspection of the exact npm archive. Regular analyze/scan pattern checks inspect registry description text only; `artifact` and guarded install read archive source bytes without extraction or execution.

OSV advisory checks work without an API key. VirusTotal is optional for analysis, but guarded installs require a fresh VirusTotal result for the exact artifact and remain blocked without one.

## URLs / Access

- GitHub: https://github.com/josephtandle/myos-guard-dog
- After verifying the v4.1.0 GitHub tag is published, install it with `npm install -g --ignore-scripts github:josephtandle/myos-guard-dog#v4.1.0 && myos-guard-dog setup --quick`. Verify the installed version before use.

## App Location

- Agent source (live): `~/.myos/workspace/agents/guard-dog/`
- State path for existing and new users: `~/.guardog/`
- Own git repo: yes, `josephtandle/myos-guard-dog`

## Tech Stack

- Node.js 24 LTS, pinned with `.nvmrc`, `.node-version` and `engines.node` (ESM, built-in fetch, zero runtime dependencies)
- No build step. No server. CLI tool only.
- Optional Claude Code skill: `myos-guard-dog.md`

## Environment Variables

- `VIRUSTOTAL_API_KEY`: optional, enables VirusTotal URL and file-hash results
- `GITHUB_API_TOKEN`: optional, increases GitHub API rate limits
- User configuration is loaded from `~/.guardog/.env`

## Key Endpoints / Commands

```bash
myos-guard-dog analyze <package> [npm|pypi]
myos-guard-dog batch <packages.json>
myos-guard-dog test
```

The optional `myos-guard-dog.md` Claude Code skill is included in the repository. The installer does not change Claude Code settings or skills automatically.

## Verdicts (v2.0.0)

- SILENT / SAFE (score < 50, no risk signals): no red flag in the checks that completed; package source code was not inspected
- SILENT / UNCONFIRMED (score < 50 but risk signals present): NOT an all-clear. The signals scored
  below the warning threshold, and they are printed. Renders with an info icon, never a green check.
- WHINE / SUSPICIOUS (score 50-99): suspicious
- WHINE / NOT_FOUND (short-circuit): the package does not exist in the registry, so nothing could be
  checked. Possible typosquat. Never rendered as safe.
- BARK / DANGER (score >= 100): dangerous, install blocked

Informational notes (for example "trusted provider, reputation heuristics skipped") are kept
separate from risk reasons and never trigger UNCONFIRMED.

The governing rule: "could not determine" never serializes into the same shape as "determined to be
clean". A check that fails must produce a named, scored signal, not an absence.

## Known Issues / Next Steps

- Set `GITHUB_API_TOKEN`. Unauthenticated GitHub allows only 60 requests/hour, and that quota is
  shared across every scan. Without it, GuardDog reports "GitHub could not be checked" rather than
  a clean result, but the reputation signal is genuinely unavailable. With it, 5000/hour.
- Telegram alerting was REMOVED in v1.2.0 to make the package standalone-safe. The BARK branch
  prints its banner and sends nothing.
- Anyone still on a pre-2.0.0 install should pull. A SILENT from an older version is close to
  meaningless, see the 2026-08-25 audit in CHANGELOG.md.
- Giveaway page not yet built on workshop site (next step)
- `data/` and `logs/` are gitignored, so students start with empty history
- `setup-logging-structure.sh`, `mission-control-trigger.js`, internal ops scripts excluded from public repo

## Files to Know

| File | Purpose |
|------|---------|
| `src/index.js` | Main orchestrator |
| `install.sh` | Student installer |
| `myos-guard-dog.md` | Optional Claude Code skill for manual installation |
| `bin/git-precommit-hook.sh` | Pre-commit integration |
| `config/trusted-providers.json` | Package allowlist. Skips reputation heuristics ONLY, not CVE/VT/pattern checks |
| `tests/audit-findings.test.cjs` | T1-T14, one binary regression test per audit finding |
| `CHANGELOG.md` | The 2026-08-25 audit and all ten fixes |
