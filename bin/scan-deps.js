#!/usr/bin/env node
/** Audit exact installed/locked npm dependencies. Exit 0 complete, 1 danger, 2 incomplete. */
import { resolve } from 'node:path';
import { collectDependencies } from '../src/dependency-inventory.js';
import { summarizeDependencyScan } from '../src/scan-summary.js';
import { assertSupportedNodeVersion } from '../src/node-version.js';

assertSupportedNodeVersion();

const args = process.argv.slice(2);
const json = args.includes('--json');
const manifest = args[0];
const log = console.log.bind(console);
const errorLog = console.error.bind(console);
async function main() {
  if (!manifest || manifest.startsWith('--')) throw new Error('Usage: myos-guard-dog-scan <package.json> [--json]');
  const inventory = collectDependencies(resolve(manifest));
  // Manifest changes can alter transitive resolution, so legacy changed-only callers
  // receive a full resolved inventory audit rather than skipping vulnerable leaves.
  if (!json && args.includes('--changed-only')) log('Auditing the full resolved dependency inventory, including transitive changes.');
  let results = [];
  if (inventory.packages.length > 0) {
    if (json) { console.log = () => {}; console.error = () => {}; console.warn = () => {}; }
    const { GuardDog } = await import('../src/index.js');
    results = await new GuardDog().batchAnalyze(inventory.packages);
  }
  const summary = summarizeDependencyScan(inventory, results);
  if (json) log(JSON.stringify(summary));
  else {
    log(`Guard Dog: ${summary.dependencyCount} exact dependency versions audited; ${summary.status}; coverage ${summary.coverage} (${summary.incompleteCount} incomplete, ${summary.suspiciousCount} suspicious package checks).`);
    summary.issues.forEach(issue => errorLog(`Incomplete coverage: ${issue}`));
  }
  process.exitCode = summary.dangerousCount ? 1 : summary.coverage === 'incomplete' || summary.suspiciousCount ? 2 : 0;
}
main().catch(error => {
  if (json) log(JSON.stringify({ status: 'incomplete', coverage: 'incomplete', dependencyCount: 0, dangerousCount: 0, suspiciousCount: 0, incompleteCount: 0, issues: [error.message] }));
  else errorLog(error.message);
  process.exitCode = 2;
});
