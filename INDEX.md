# MyOS Guard Dog repository map

- `README.md`, `QUICKSTART.md`, `GUARD_DOG_PROMPT.md`: supported use and installation.
- `package.json`, `autonomizer.json`, `CHANGELOG.md`: release identity and history.
- `src/`: scanner, bounded npm artifact inspector, guarded installer, inventory, verdict, scheduler and quota code.
- `bin/scan-deps.js`, `bin/nightly-scan.js`, `bin/git-precommit-hook.sh`: shipped command helpers.
- `config/`: default configuration and ecosystem trust lists.
- `tests/`: offline regression suites.
- `.github/workflows/test.yml`: Node 24 checks on Windows, macOS and Linux.

The package's `files` field in `package.json` defines what is shipped. Other tracked operations scripts are source-tree utilities, not part of the installable package.
