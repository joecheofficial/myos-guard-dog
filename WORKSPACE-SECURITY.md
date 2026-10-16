# Workspace protection contract

## Threat model

Inspect a user-selected, stable coding checkout without executing its scripts, importing plugins, uploading files or validating discovered credentials against services. Native rules identify security hotspots, known credential formats and suspicious combinations. False positives and false negatives remain possible. This is not a sandbox for a hostile concurrent filesystem writer.

## Coverage

- Native: 28 original rules, supported text encodings, hidden development config, explicit scope and bounded read-only scanning.
- Dependencies: existing exact npm inventory and external OSV/VirusTotal workflow, separate from local source findings.
- Malware: native EICAR test marker only; optional separately installed ClamAV adds signature/archive scanning, subject to its version, database, format and resource limits.
- Excluded: semantic/dataflow SAST, live process/memory/kernel monitoring, all historic Git objects, unselected roots, automatic remediation and quarantine.

No root privilege, new service, telemetry or automatic engine download is introduced. Existing scheduler registration remains opt-in. Customer upgrades must retain their state and customized jobs.

## Release and distribution requirements

1. Offline regression suite, seeded corpus and false-positive corpus with counts and declared unsupported examples.
2. Actual pinned ClamAV installation tested with benign files, EICAR, nested directories, oversized/archive limits, stale database, failure and missing engine. Mock adapter tests are not this evidence.
3. Supported Node 22/24 and macOS/Windows/Linux installation matrix, read-only scanning, report outputs and cleanup/uninstall verification.
4. Security review fixes closed with regression tests, immutable source/version and artifact hash, install from that artifact and rollback exercise.
5. All Sorted factory privacy gate, regenerated module allowlist, release manifest/index agreement and installed customer-root scan receipt.
6. Clear support/contact and vulnerability-disclosure process, dependency/license inventory and release notes. Performance numbers use stated hardware and corpus, never unspecified protection claims.

## Verified source evidence

- Core behavior: 209 offline tests pass locally on macOS. CI run 38269189999 passed all six Node 22/24 jobs on macOS, Windows and Ubuntu, including packed installation. Windows retains five platform-specific skips for Unix-only checks.
- Live engine: CI run 38268868972 used ClamAV 1.5.4, distribution package 1.5.4+dfsg-0ubuntu0.24.04.1, engine SHA-256 `3c9a2ab59a256988dac497bbb7c5e3dd98180cef846b32088a304dc604d2a3ee`. Ten harmless probes passed with the network namespace disabled during scanning. They covered benign input, plain and gzip EICAR, depth and size limits, simulated stale time, missing engine, timeout, symlink refusal and file preservation. Live ClamAV validation covers Linux only.
- Review: independent source and CI review found no outstanding P1/P2 issues in the reviewed scope. Review is not a formal security certification.
- Packaging: Node 22/24 installed-command checks and 4.1.0 upgrade, removal and rollback preserved custom state. Stable distribution artifacts must be checked again after version finalization.
- Detection corpus: 28 seeded positive cases and 28 benign cases pass. Four of eight additional syntax/coverage probes detect; aliases, bracket-access dataflow, binary secrets and arbitrary reverse shells remain outside demonstrated coverage. This small known regression corpus is not a production efficacy benchmark.

Source release: 5.0.2. All Sorted distribution remains a separate owner-controlled gate requiring its privacy/build/index checks and an installed runtime receipt. A source release alone is not proof of that deployment.
