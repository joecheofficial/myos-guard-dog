# Security Policy

## Reporting a Vulnerability

Please report suspected vulnerabilities privately instead of opening a public
issue with exploit details.

Send the affected package name, version, reproduction steps, and any relevant
logs or scan output to the repository owner through GitHub Security Advisories:

https://github.com/josephtandle/myos-guard-dog/security/advisories/new

If GitHub Security Advisories are unavailable, open a minimal public issue that
requests a private security contact without including exploit details.

## Supported Versions

MyOS Guard Dog 4.x is the supported release line for this code. Security fixes land on the
default branch first, then ship from the latest tagged version.

## Handling Secrets

Do not include API keys, tokens, `.env` files, scan cache contents, or runtime
logs in vulnerability reports unless they have been redacted.

## Artifact Inspection Limits

The `artifact` command parses npm tarball bytes in memory and never extracts or executes package files. It caps compressed and expanded size, archive entries, and source text inspected. It reports selected static indicators and lifecycle scripts. A result with no indicators is not a malware clearance; dynamic behavior, encoded variants, binaries, and source beyond the limits are outside this check. Guarded installs still require their existing completed checks, including a fresh VirusTotal file report.
