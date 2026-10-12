# GuardDog protection evaluation (2026-10-03)

This review targets a student who wants to inspect a public npm package before installing it and to audit an existing project without being told that missing evidence is safe. It compares design ideas from maintained projects; no external scanner code was copied into this repository.

| Project | Useful design evidence | GuardDog decision |
| --- | --- | --- |
| [DataDog GuardDog](https://github.com/DataDog/guarddog) | Downloads package artifacts, combines metadata with source indicators, and uses a sandbox for extraction and analysis. | Add a narrow, bounded, no-extraction npm artifact inspection path. Do not claim YARA parity, behavioral coverage, or sandbox equivalence. |
| [OSV-Scanner](https://github.com/google/osv-scanner) | Scans many lockfile types, supports offline databases and offers guided remediation with a warning about running package managers on untrusted projects. | Keep exact-version OSV queries. Multi-ecosystem project inventory and offline OSV data remain future work. Do not auto-run remediation in student projects. |
| [pip-audit](https://github.com/pypa/pip-audit) | Audits Python environments and pinned requirements, reports skipped coverage, and documents its security assumptions. | Keep guarded pip installs unsupported. An optional, clearly attributed pip-audit adapter is preferable to treating a single PyPI package check as a full Python project audit. |
| [OpenSSF package-analysis](https://github.com/ossf/package-analysis) | Collects static and dynamic package behavior using isolated workers. | Do not execute downloaded package code in this cross-platform CLI. Dynamic analysis needs an actual sandbox and separate operational controls. |
| [OpenSSF Scorecard](https://github.com/ossf/scorecard) | Assesses repository practices such as token permissions and vulnerability handling. | Treat repository health as context, never as proof that the published artifact is safe. |

## Implemented in the v4.1.0 release candidate

- `myos-guard-dog artifact npm:<name>@<exact-version>` checks the npm registry hostname, release identity and strong digest before a bounded static read of the archive. A local `.tgz` can also be inspected without a registry trust claim. No API key is needed.
- Guarded npm installs inspect the same exact artifact bytes already bound to registry metadata and integrity. High-risk, review, or incomplete static findings stop the install before `npm ci`; lifecycle scripts stay disabled.
- Failed metadata-pattern analysis now reaches the actual install decision as incomplete. Project audits now count suspicious verdicts and exit nonzero, instead of reporting a completed warning as success.
- The student instructions state how to run a keyless first check and distinguish a bounded static result from full protection.

## What remains and why it matters

- The new source rules catch selected combinations, not arbitrary malicious code. Binary payloads, split-file behavior, novel obfuscation and runtime behavior remain outside the check. The archive parser itself adds attack surface, so independent review and cross-platform tests are release gates.
- A VirusTotal key and fresh exact-file report are still required for a GuardDog-guarded install. The keyless `artifact` command gives students useful evidence but does not replace that gate.
- Project inventory is npm-only. Python students should use a dedicated Python dependency auditor; GuardDog's single PyPI analysis is not a full environment audit.
- Large dependency scans are bounded to four concurrent packages, but shared VirusTotal rate limits can dominate total time. No end-to-end speedup is promised for a 453-package project.
- A source archive can have no listed indicators while still be malicious. GuardDog must keep reporting the evidence actually checked and cannot certify safety.

## Release verification evidence

- Offline fixture tests cover safe, high-risk and incomplete archives; exact registry identity, host and digest rejection; and blocking a guarded install before project mutation.
- Public package smoke checks used exact releases of lodash 4.17.21, axios 1.7.9 and esbuild 0.25.0. They exercised 1,048, 69 and 3 source files respectively without a high-risk finding; lifecycle scripts appeared as informational signals where present. These packages are a false-positive check, not a safety benchmark.
- The proposed commit passed the packed-install test and independent read-only review. That review found four scanner gaps, which were fixed and regression tested. Windows, macOS and Linux Node 24 CI passed for commit `6c4e692027b54abd401030e37c3dd5f20b8cb644`; release-wording changes were verified separately on the final commit.
