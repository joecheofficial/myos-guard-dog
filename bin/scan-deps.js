#!/usr/bin/env node
/** Audit exact installed/locked npm dependencies. Exit 0 complete, 1 danger, 2 incomplete. */
import { resolve } from 'node:path';
import { collectDependencies } from '../src/dependency-inventory.js';
import { summarizeDependencyScan } from '../src/scan-summary.js';
import { scanWithProgress } from '../src/scan-progress.js';
import { guardogDataDir } from '../src/paths.js';
import { assertSupportedNodeVersion } from '../src/node-version.js';

assertSupportedNodeVersion();

const args = process.argv.slice(2);
const json = args.includes('--json');
const manifest = args[0];
const log = console.log.bind(console);
const errorLog = console.error.bind(console);
async function main() {
  if (!manifest || manifest.startsWith('--')) throw new Error('Usage: myos-guard-dog-scan <package.json> [--json] [--budget-ms N]');
  const inventory = collectDependencies(resolve(manifest));
  // Manifest changes can alter transitive resolution, so legacy changed-only callers
  // receive a full resolved inventory audit rather than skipping vulnerable leaves.
  if (!json && args.includes('--changed-only')) log('Auditing the full resolved dependency inventory, including transitive changes.');
  const budgetIndex = args.indexOf('--budget-ms');
  const budgetMs = budgetIndex < 0 ? null : Number(args[budgetIndex + 1]);
  if (budgetMs !== null && (!Number.isFinite(budgetMs) || budgetMs <= 0)) throw new Error('--budget-ms requires a positive number.');
  const runIndex = args.indexOf('--run-id');
  let results = [];
  let summary;
  if (inventory.packages.length > 0) {
    if (json) { console.log = () => {}; console.error = () => {}; console.warn = () => {}; }
    const { GuardDog } = await import('../src/index.js');
    const guardDog = new GuardDog();
    if (budgetMs !== null) {
      summary = await scanWithProgress(inventory, {
        manifest: resolve(manifest), stateDir: guardogDataDir(), budgetMs,
        ...(runIndex >= 0 ? {runId: args[runIndex + 1]} : {}),
        analyze: pkg => guardDog.analyze(pkg.name, pkg.ecosystem, pkg.target, pkg.version)
      });
    } else results = await guardDog.batchAnalyze(inventory.packages);
  }
  summary ||= summarizeDependencyScan(inventory, results);
  if (json) log(JSON.stringify(summary));
  else {
    log(`Guard Dog: ${summary.scannedDependencyCount ?? results.length}/${summary.dependencyCount} exact dependency versions audited; ${summary.status}; coverage ${summary.coverage} (${summary.incompleteCount} incomplete, ${summary.suspiciousCount} suspicious package checks).`);
    summary.issues.forEach(issue => errorLog(`Incomplete coverage: ${issue}`));
  }
  process.exitCode = summary.dangerousCount ? 1 : summary.coverage === 'incomplete' || summary.suspiciousCount ? 2 : 0;
}
main().catch(error => {
  if (json) log(JSON.stringify({ status: 'incomplete', coverage: 'incomplete', dependencyCount: 0, dangerousCount: 0, suspiciousCount: 0, incompleteCount: 0, issues: [error.message] }));
  else errorLog(error.message);
  process.exitCode = 2;
});
