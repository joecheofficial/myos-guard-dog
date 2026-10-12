# Install MyOS Guard Dog 4.1.0

Copy the prompt below into your AI assistant. It needs access to your computer's terminal.

---

Install or upgrade Guard Dog and prove the protection is working.

Use this exact project: https://github.com/josephtandle/myos-guard-dog. MyOS Guard Dog is the product name and `myos-guard-dog` is its only supported command. It is not DataDog GuardDog or any similarly named package. Do not substitute another project or invent a replacement implementation.

1. Detect my operating system, shell, Node version, existing installation, and project folder. Read the release instructions. Guard Dog requires Node 24 LTS and rejects other major versions so installs and support use the tested runtime. Preserve settings and credentials. Explain decisions in plain English.

2. After confirming the official v4.1.0 release tag and its commit actually exist, install with `npm install -g --ignore-scripts github:josephtandle/myos-guard-dog#v4.1.0`. Run `myos-guard-dog doctor --repair` immediately after installation so any previously enabled owned nightly runner is updated to this release. Verify `myos-guard-dog --version`. Existing `~/.guardog` state is preserved. Do not use `guarddog`, `guardog`, or `guard-dog`: they are ambiguous external names.

3. Run `myos-guard-dog setup --quick`, then help me configure VirusTotal locally using `myos-guard-dog setup`. Never ask for an API key in chat, print it, or include it in a report. Without a key, vulnerability audits still run, but malware coverage is incomplete and guarded installation stays blocked. A stored key is not proof it works: run `myos-guard-dog test` and report the actual authentication and service results.

4. Identify the project or workspace I want protected. If unclear, ask me for the folder. Run `myos-guard-dog scan "<project folder>"`. Inspect its exact-version inventory, findings, and missing checks. npm lockfiles and installed npm metadata are supported, including transitive dependencies. Unsupported inventories must be reported, never silently replaced with latest registry versions. Do not install or execute malicious demonstration packages. Explain any detected vulnerability without automatically modifying my project.

5. Configure daily scans after confirming my chosen folders and local run time. Run `myos-guard-dog updates enable --workspace "<workspace folder>" --time "02:30"`. Read back the OS registration with `myos-guard-dog updates status`. Run `myos-guard-dog nightly` once and inspect the receipt shown by `myos-guard-dog doctor`. A schedule alone, an empty scan, or a saved setting is not successful protection.

6. Use `myos-guard-dog doctor --repair` for supported repairs. It can restore its local state and a previously enabled missing schedule. Daily runs also perform these checks and record repairs or unresolved health issues in their receipt. Check the result after every repair. Stop retrying after two failed attempts, preserve diagnostic evidence, and identify the exact remaining problem. Never disable a security check, change a threat threshold, erase findings, rotate credentials, or upgrade project dependencies as a repair shortcut. If Guard Dog cannot start at all, daily self-repair cannot run: diagnose the executable or run the pinned installer again, preserving settings.

7. Demonstrate the keyless read-only check `myos-guard-dog artifact npm:lodash@4.17.21` and explain that bounded static source inspection cannot certify a package safe. Explain how to use `myos-guard-dog install <npm-package>` before future installations. This command checks the resolved dependency tree, verifies and inspects exact archive bytes, requires completed checks, and keeps lifecycle scripts disabled. Direct npm/pip commands bypass this protection. Unsupported installation types are blocked with an explanation. A Git hook runs after dependencies may already be installed and is not a replacement for the install gate.

8. Leave a short completion report: installed version and path, scan roots, number of exact versions checked, findings, missing coverage, VirusTotal authentication and report freshness, OS schedule and time, last completed run, repairs performed, and anything I need to do. If a step failed, say setup is incomplete and give the next specific action.

Guard Dog protects the package workflow. It is not operating-system antivirus, does not watch every file, and cannot guarantee software is harmless. VirusTotal file-hash lookups retrieve current stored intelligence; old known reports can request a rescan, which remains incomplete until fresh results exist. Do not upload private files. SILENT means no warning threshold was reached, so always read coverage too.
