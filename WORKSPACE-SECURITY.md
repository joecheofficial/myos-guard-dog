# Workspace protection contract

## Threat model

Inspect a user-selected, stable coding checkout without executing its scripts, importing plugins, uploading files or validating discovered credentials against services. Native rules identify security hotspots, known credential formats and suspicious combinations. False positives and false negatives remain possible. This is not a sandbox for a hostile concurrent filesystem writer.

## Coverage

- Native: 28 original rules, supported text encodings, hidden development config, explicit scope and bounded read-only scanning.
- Dependencies: existing exact npm inventory and external OSV/VirusTotal workflow, separate from local source findings.
- Malware: native EICAR test marker only; optional separately installed ClamAV adds signature/archive scanning, subject to its version, database, format and resource limits.
- Excluded: semantic/dataflow SAST, live process/memory/kernel monitoring, all historic Git objects, unselected roots, automatic remediation and quarantine.

No root privilege, new service, telemetry or automatic engine download is introduced. Existing scheduler registration remains opt-in. Customer upgrades must retain their state and customized jobs.

## Evidence required before commercial release

1. Offline regression suite, seeded corpus and false-positive corpus with counts and declared unsupported examples.
2. Actual pinned ClamAV installation tested with benign files, EICAR, nested directories, oversized/archive limits, stale database, failure and missing engine. Mock adapter tests are not this evidence.
3. Supported Node 22/24 and macOS/Windows/Linux installation matrix, read-only scanning, report outputs and cleanup/uninstall verification.
4. Security review fixes closed with regression tests, immutable source/version and artifact hash, install from that artifact and rollback exercise.
5. All Sorted factory privacy gate, regenerated module allowlist, release manifest/index agreement and installed customer-root scan receipt.
6. Clear support/contact and vulnerability-disclosure process, dependency/license inventory and release notes. Performance numbers use stated hardware and corpus, never unspecified protection claims.

Current release state: candidate only. Immutable source integration, cross-platform CI, live engine validation and All Sorted deployment evidence remain required.
