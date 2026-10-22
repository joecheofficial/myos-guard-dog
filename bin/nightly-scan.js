#!/usr/bin/env node
import { existsSync, readdirSync, realpathSync, statSync, writeFileSync, renameSync, readFileSync, openSync, closeSync, unlinkSync } from 'node:fs';
import { join, resolve, sep } from 'node:path';
import { homedir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
import { collectDependencies } from '../src/dependency-inventory.js';
import { mergeAuditPhases } from '../src/scan-summary.js';
import { readScanProgress } from '../src/scan-progress.js';
import { spawnSync } from 'node:child_process';
import { ensureGuardogHome, guardogHome, packageRoot } from '../src/paths.js';
import { loadUserConfig } from '../src/setup.js';
import { checkHealth } from '../src/health.js';
import { recordResilienceCycle } from '../src/resilience-loop.js';
import { scanWorkspace, within } from '../src/workspace-scan.js';
import { assertSupportedNodeVersion } from '../src/node-version.js';
import { runRuntimeCheckSync } from '../src/runtime-advisories.js';

assertSupportedNodeVersion();

const skipDirs = new Set(['node_modules', '.git', '.next', 'dist', 'build', 'coverage', '.venv', 'venv']);
// Child-scan messages that mean "nothing to verify here", not "the scan broke".
const COVERAGE_GAP = /^(No npm lockfile or installed dependency inventory is available|No exact installed or locked version for |scan coverage incomplete)/i;
// Skipped only when they sit directly under the user's home directory.
const homeOnlySkipDirs = new Set(['Library', 'Applications', 'Movies', 'Music', 'Pictures']);
function realPathOrNull(target) {
  try { return realpathSync(target); } catch { return null; }
}

function validateCurrentInventory(summary,manifest) {
  if(!summary.inventoryFingerprint)return summary; // Legacy callers have no current-run snapshot to reuse.
  const inventory=collectDependencies(manifest);
  const fingerprint=createHash('sha256').update(JSON.stringify(inventory)).digest('hex');
  if(fingerprint===summary.inventoryFingerprint)return summary;
  return {...summary,inventoryComplete:inventory.complete,dependencyCount:inventory.packages.length,advisoryCheckedCount:0,enrichmentCheckedCount:0,coverage:'incomplete',status:summary.dangerousCount?'dangerous':'incomplete',inventoryChanged:true,
    findings:(summary.findings||[]).map(f=>({...f,inventoryChanged:true})),
    issues:[...summary.issues,'Dependency inventory changed during the scan; recorded findings apply to the earlier snapshot and current coverage is incomplete.']};
}

export function runNightly(options = {}) {
  ensureGuardogHome();
  const lockPath = join(guardogHome(), 'data', 'nightly.lock');
  const token = JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString() });
  try {
    if (existsSync(lockPath)) {
      const original = readFileSync(lockPath, 'utf8');
      const { pid } = JSON.parse(original);
      if (Number.isInteger(pid) && pid > 0) {
        try { process.kill(pid, 0); }
        catch (error) { if (error.code === 'ESRCH' && readFileSync(lockPath, 'utf8') === original) unlinkSync(lockPath); }
      }
    }
    const descriptor = openSync(lockPath, 'wx', 0o600);
    try { writeFileSync(descriptor, token); } finally { closeSync(descriptor); }
  } catch {
    return { taskClass: 'security_scan', status: 'incomplete', exitCode: 2, dependencyCount: 0, dangerousCount: 0, issues: ['Another nightly run owns the lock, or the lock cannot be verified. No overlapping scan was started.'] };
  }
  try { return performNightly(options); }
  finally { if (existsSync(lockPath) && readFileSync(lockPath, 'utf8') === token) unlinkSync(lockPath); }
}

function performNightly(options) {
  const config = options.config || loadUserConfig();
  const totalBudget=Number(options.timeoutMs ?? process.env.GUARDOG_NIGHTLY_TIMEOUT_MS ?? config.nightlyTimeoutMs ?? 3600000);
  if(!Number.isSafeInteger(totalBudget)||totalBudget<0||totalBudget>24*3600000)throw Error('Nightly budget must be 0 to 86400000 milliseconds.');
  const deadline = Date.now() + totalBudget;
  // Explicit scan roots in config win. GUARDOG_WORKSPACE is the fallback for an
  // install that never chose roots (the legacy cron wrapper passes $HOME).
  const roots = options.roots || (config.scanRoots?.length ? config.scanRoots : process.env.GUARDOG_WORKSPACE ? [resolve(process.env.GUARDOG_WORKSPACE)] : []);
  const run = options.run || spawnSync;
  let preflight;
  try {
    const health = checkHealth({ ...options.healthOptions, repair: true, checkLastRun: false });
    // Do not nest the preceding run's receipt: history must not grow recursively.
    preflight = { checkedAt: new Date().toISOString(), ok: health.ok, schedule: health.schedule, runner: health.runner, repairs: health.repairs, issues: health.issues };
  } catch (error) {
    preflight = { checkedAt: new Date().toISOString(), ok: false, repairs: [], issues: ['Health preflight failed: ' + error.message] };
  }
  const receipt = { taskClass: 'security_scan', startedAt: new Date().toISOString(), status: 'incomplete', roots, projectsScanned: 0, dependencyCount: 0, dangerousCount: 0, suspiciousCount: 0, preflight, issues: preflight.issues.map(issue => 'Health: ' + issue), boundaries: { depthLimited: 0, unreadable: 0, samples: [] }, coverage: { projectsWithoutInventory: 0, samples: [] } };
  // Runtime advisories: the Node binaries themselves, not only packages. Library callers
  // opt in with options.runtimeCheck; the CLI enables it unless config.runtimeAdvisories is false.
  if (typeof options.runtimeCheck === 'function' && config.runtimeAdvisories !== false) {
    let runtime;
    try { runtime = options.runtimeCheck({ timeoutMs: Math.max(1, Math.min(120000, deadline - Date.now())) }); }
    catch (error) { runtime = { status: 'incomplete', findings: [], highCount: 0, issues: ['Runtime advisory check failed: ' + error.message] }; }
    receipt.runtime = runtime;
    receipt.runtimeHighCount = (runtime.findings || []).filter(f => f.severity === 'high').length;
    for (const finding of (runtime.findings || []).filter(f => f.severity === 'high')) receipt.issues.push(`HIGH runtime: ${finding.path} ${finding.version} is ${finding.kind === 'runtime_eol' ? 'end of life' : 'vulnerable, fixed in ' + finding.fixedIn}. ${finding.action}`);
    if (runtime.status === 'incomplete') receipt.issues.push(...(runtime.issues || ['Runtime advisory check incomplete.']).map(issue => 'Runtime: ' + issue));
  }
  // Opted-in local pass runs before network-dependent package audits.
  if (config.workspaceScan === true) {
    receipt.workspace = { enabled: true, findings: [], rootsScanned: 0, coverage: { complete: true, filesScanned: 0 }, issues: [] };
    const uniqueRoots = [];
    for (const root of roots) {
      const identity = typeof root === 'string' ? realPathOrNull(root) : null;
      if (!identity) { receipt.workspace.coverage.complete = false; receipt.workspace.issues.push({ code: 'root_unavailable' }); continue; }
      if (uniqueRoots.some(parent => within(parent, identity))) continue;
      for (let i = uniqueRoots.length - 1; i >= 0; i--) if (within(identity, uniqueRoots[i])) uniqueRoots.splice(i, 1);
      uniqueRoots.push(identity);
    }
    receipt.workspace.roots = uniqueRoots;
    for (const root of uniqueRoots) {
      const remaining = deadline - Date.now();
      if (remaining <= 0 || receipt.workspace.rootsScanned >= 50) { receipt.workspace.coverage.complete = false; receipt.workspace.issues.push({ code: 'nightly_workspace_budget' }); break; }
      const report = scanWorkspace(root, { timeoutMs: Math.min(60000, remaining), maxFindings: 200 });
      receipt.workspace.rootsScanned++;
      receipt.workspace.coverage.filesScanned += report.coverage.filesScanned;
      receipt.workspace.coverage.complete &&= report.coverage.complete;
      receipt.workspace.findings.push(...report.findings.map(finding => ({ ...finding, rootIndex: receipt.workspace.rootsScanned - 1 })));
      receipt.workspace.issues.push(...report.issues.slice(0, 20));
      receipt.workspace.scope = report.scope;
      if (report.exitCode === 1) receipt.dangerousCount += report.findings.filter(f => ['critical', 'high'].includes(f.severity)).length;
    }
    if (!receipt.workspace.rootsScanned) receipt.workspace.coverage.complete = false;
    if (!receipt.workspace.coverage.complete) receipt.issues.push('Local workspace scan coverage is incomplete; inspect workspace receipt.');
  }
  const manifests = new Set();
  const visited = new Set();
  // Opt-in (config.scanExcludes): path fragments to skip, for vendored or scratch trees.
  const excludes = Array.isArray(config.scanExcludes) ? config.scanExcludes.filter(item => typeof item === 'string' && item) : [];
  // Opt-in (config.partialNightlyOk): VirusTotal pacing (4 lookups/min) cannot cover a
  // large workspace in one budget. Stopping on budget or quota then rotates to the
  // next manifests tomorrow and records the deferral instead of failing every night.
  const partialOk = config.partialNightlyOk === true;
  const deferred = [];
  const incompleteOnly = [];
  let completeManifests = 0;
  const maxDepth = Number(process.env.GUARDOG_MAX_DEPTH || 4);
  const homeIdentity = realPathOrNull(options.homeDirectory || homedir());
  function discover(dir, depth = 0) {
    if (Date.now() >= deadline) { receipt.issues.push('Nightly discovery time budget exhausted.'); return; }
    // Reaching the depth limit is a boundary of the scan, not a failure: count it
    // so the receipt says how much was left unexplored, and stay "complete".
    if (depth > maxDepth) { noteBoundary('depthLimited', dir); return; }
    try {
      const identity = realpathSync(dir);
      if (identity === realpathSync(guardogHome()) || visited.has(identity)) return;
      visited.add(identity);
      const atHome = identity === homeIdentity;
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const full = join(dir, entry.name);
        if (!entry.isDirectory()) { if (entry.isFile() && entry.name === 'package.json') manifests.add(full); continue; }
        if (skipDirs.has(entry.name) || entry.name.startsWith('.')) continue;
        if (excludes.some(fragment => full.split(sep).join('/').includes(fragment.split(sep).join('/')))) continue;
        // ~/Library is app data (caches, containers, mail), not code. Walking it
        // costs minutes and trips macOS privacy guards (EPERM) on every run.
        if (atHome && homeOnlySkipDirs.has(entry.name)) continue;
        discover(full, depth + 1);
      }
    } catch (error) {
      // A folder the user cannot read (macOS privacy guards, another account's
      // data) is a boundary too, unless it is a scan root, which stays an issue.
      if (depth === 0) receipt.issues.push('Cannot read ' + dir + ': ' + (error.code || error.message));
      else noteBoundary('unreadable', dir + ': ' + (error.code || error.message));
    }
  }
  function noteBoundary(kind, detail) {
    receipt.boundaries[kind] += 1;
    if (receipt.boundaries.samples.length < 20) receipt.boundaries.samples.push(kind + ': ' + detail);
  }
  if (!Number.isInteger(maxDepth) || maxDepth < 0 || maxDepth > 30) receipt.issues.push('GUARDOG_MAX_DEPTH must be an integer from 0 to 30.');
  else for (const root of roots) {
    if (typeof root !== 'string' || !existsSync(root) || !statSync(root).isDirectory()) receipt.issues.push('Scan root is unavailable: ' + root);
    else discover(root);
  }
  if (roots.length === 0) receipt.issues.push('No scan roots configured. Run myos-guard-dog setup or set GUARDOG_WORKSPACE.');
  // One large manifest throttled by VirusTotal pacing (4 lookups/min) used to
  // consume the whole nightly budget. Cap each manifest so a slow or stuck
  // project is skipped with a logged issue and the rest still get scanned.
  const manifestTimeoutMs = Number(options.manifestTimeoutMs ?? process.env.GUARDOG_MANIFEST_TIMEOUT_MS ?? 900000);
  const cursorPath = join(guardogHome(), 'data', 'nightly-cursor.json');
  let ordered = [...manifests].sort();
  if (partialOk) {
    try {
      const { last } = JSON.parse(readFileSync(cursorPath, 'utf8'));
      const start = ordered.findIndex(item => item > last);
      if (start > 0) ordered = ordered.slice(start).concat(ordered.slice(0, start));
    } catch { /* no cursor yet: start at the beginning */ }
  }
  const auditRunId=randomUUID(), advisorySummaries=new Map(), enriched=new Set();
  receipt.findings=[]; receipt.inventoryComplete=true; receipt.advisoryCheckedCount=0; receipt.enrichmentCheckedCount=0;
  if(options.advisoryFirst!==false) {
    // Complete the fast advisory sweep across ALL projects before any VT enrichment.
    const advisoryDeadline=Date.now()+Math.max(1,(deadline-Date.now())/2);
    for(const [index,manifest] of ordered.entries()) {
      const remaining=advisoryDeadline-Date.now();
      if(remaining<=0){receipt.issues.push('Advisory sweep time budget exhausted.');break;}
      const timeout=Math.max(1,Math.floor(remaining/(ordered.length-index)));
      const result=run(process.execPath,[join(packageRoot(),'bin','scan-deps.js'),manifest,'--json','--advisories-only','--audit-run-id',auditRunId,'--budget-ms',String(Math.max(1,timeout-Math.min(15000,timeout/2)))],{encoding:'utf8',timeout,killSignal:'SIGKILL',maxBuffer:8*1024*1024,windowsHide:true});
      try {
        const summary=result.error||result.signal?readScanProgress(manifest+'.advisories',join(guardogHome(),'data'),auditRunId):JSON.parse(result.stdout);
        if(!summary||!Number.isInteger(summary.dependencyCount)||summary.dependencyCount<0||!Number.isInteger(summary.advisoryCheckedCount))throw Error('Missing advisory receipt');
        advisorySummaries.set(manifest,summary);
        if(summary.advisoryCheckedCount<summary.dependencyCount)receipt.issues.push('Incomplete advisory sweep: '+manifest);
      } catch {receipt.issues.push('Advisory sweep failed: '+manifest);}
      if(['ENOENT','EACCES','ENOEXEC'].includes(result.error?.code)){receipt.runnerFailure=result.error.code;receipt.issues.push('Node scan runner unavailable. Run myos-guard-dog doctor --repair.');break;}
    }
  }
  let lastDone = null;
  for (const [index, manifest] of ordered.entries()) {
    if(receipt.runnerFailure)break;
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      if (partialOk) { deferred.push(...ordered.slice(index)); } else receipt.issues.push('Nightly scan time budget exhausted.');
      break;
    }
    const timeout = Number.isFinite(manifestTimeoutMs) && manifestTimeoutMs > 0 ? Math.min(remaining, manifestTimeoutMs, Math.max(1,Math.floor(remaining/(ordered.length-index)))) : remaining;
    const runId = randomUUID();
    // Leave room for an in-flight registry/VT/OSV check to finish and checkpoint.
    const budgetMs = Math.max(1, timeout - Math.min(120000, timeout / 2));
    const result = run(process.execPath, [join(packageRoot(), 'bin', 'scan-deps.js'), manifest, '--json', '--budget-ms', String(budgetMs), '--run-id', runId, '--enrichment-only', '--audit-run-id', auditRunId], { encoding: 'utf8', timeout, killSignal: 'SIGKILL', maxBuffer: 8 * 1024 * 1024, windowsHide: true });
    receipt.projectsScanned++;
    if (['ENOENT', 'EACCES', 'ENOEXEC'].includes(result.error?.code)) {
      receipt.runnerFailure = result.error.code;
      receipt.issues.push('Node scan runner is unavailable (' + result.error.code + '). Remaining project scans stopped. Verify Node 22 or 24, then run myos-guard-dog doctor --repair and retry.');
      receipt.coverage.deferredManifests = ordered.length - index;
      break;
    }
    const timedOut = result.error?.code === 'ETIMEDOUT' || (result.status === null && result.signal);
    const recovered = timedOut ? readScanProgress(manifest, join(guardogHome(), 'data'), runId) : null;
    if (timedOut) {
      receipt.timeouts = (receipt.timeouts || 0) + 1;
      receipt.issues.push('Scan timed out after ' + timeout + 'ms and was skipped: ' + manifest + (recovered ? '; completed checks recovered; next run resumes.' : '; no current progress receipt.'));
      if (!recovered) { if (partialOk) { deferred.push(manifest); lastDone = manifest; } continue; }
    }
    try {
      const summary = validateCurrentInventory(mergeAuditPhases(advisorySummaries.get(manifest), recovered || JSON.parse(result.stdout)),manifest);
      if (!Number.isInteger(summary.dependencyCount) || summary.dependencyCount < 0 || !['complete', 'dangerous', 'suspicious', 'incomplete'].includes(summary.status)) throw new Error('invalid scan summary');
      enriched.add(manifest);
      receipt.inventoryComplete &&= summary.inventoryComplete!==false;
      receipt.advisoryCheckedCount+=summary.advisoryCheckedCount||0;
      receipt.enrichmentCheckedCount+=summary.enrichmentCheckedCount||0;
      receipt.findings.push(...(summary.findings||[]).map(f=>({...f,project:manifest})));
      receipt.dependencyCount += summary.dependencyCount;
      receipt.scannedDependencyCount = (receipt.scannedDependencyCount || 0) + (summary.scannedDependencyCount ?? summary.dependencyCount);
      if (summary.deferredDependencyCount > 0) receipt.coverage.deferredDependencies = (receipt.coverage.deferredDependencies || 0) + summary.deferredDependencyCount;
      if (summary.budgetExhausted) receipt.budgetStops = (receipt.budgetStops || 0) + 1;
      receipt.dangerousCount += Number(summary.dangerousCount) || 0;
      receipt.suspiciousCount += Number(summary.suspiciousCount) || 0;
      if (summary.status === 'dangerous' && !summary.dangerousCount) receipt.dangerousCount++;
      if (summary.status === 'suspicious' && !summary.suspiciousCount) receipt.suspiciousCount++;
      const expectedExit = { complete: 0, dangerous: 1, suspicious: 2, incomplete: 2 }[summary.status];
      const issueTexts = (summary.issues || []).map((issue) => (typeof issue === 'string' ? issue : JSON.stringify(issue)));
      // A project with no lockfile or installed inventory (a scratch folder, a
      // checkout never installed) is a coverage gap, not a failed night. Record
      // it under coverage and keep the receipt complete.
      // A manifest that already found danger is never deferred: its findings count tonight.
      const foundDanger = ['dangerous', 'suspicious'].includes(summary.status) || (Number(summary.dangerousCount) || 0) > 0 || (Number(summary.suspiciousCount) || 0) > 0;
      if (partialOk && summary.quotaExhausted === true && !foundDanger) {
        if(!advisorySummaries.has(manifest))receipt.dependencyCount -= summary.dependencyCount;
        deferred.push(...ordered.slice(index));
        break;
      }
      // partialNightlyOk: a manifest whose only problem is incomplete lookups (stale or missing
      // VirusTotal report, registry timeout) is a coverage note, not a failed night. Danger still
      // exits 1, and if no manifest at all scanned complete the night is still incomplete.
      if (partialOk && summary.status === 'incomplete' && result.status === expectedExit && !foundDanger && issueTexts.length > 0) {
        receipt.coverage.incompleteManifests = (receipt.coverage.incompleteManifests || 0) + 1;
        incompleteOnly.push(manifest);
        lastDone = manifest;
        continue;
      }
      const coverageOnly = summary.status === 'incomplete' && result.status === expectedExit && !foundDanger && issueTexts.length > 0 && issueTexts.every((text) => COVERAGE_GAP.test(text));
      if (coverageOnly) {
        receipt.coverage.projectsWithoutInventory += 1;
        if (receipt.coverage.samples.length < 20) receipt.coverage.samples.push(manifest + ': ' + issueTexts[0]);
      } else {
        if (summary.status === 'incomplete' || result.status !== expectedExit) receipt.issues.push('Incomplete or inconsistent scan: ' + manifest);
        for (const text of issueTexts) receipt.issues.push(manifest + ': ' + text);
      }
      lastDone = manifest;
      if (['complete', 'dangerous', 'suspicious'].includes(summary.status)) completeManifests++;
      if (summary.quotaExhausted === true) {
        receipt.issues.push('VirusTotal daily quota exhausted. Stopped remaining project scans to preserve the next UTC-day allowance.');
        break;
      }
    } catch { receipt.issues.push('Scan failed for ' + manifest + ': ' + (result.error?.message || result.stderr || 'missing scan summary')); }
  }
  for(const [manifest,savedSummary] of advisorySummaries) {
    if(enriched.has(manifest))continue;
    const summary=validateCurrentInventory(savedSummary,manifest);
    if(summary.inventoryChanged)receipt.issues.push(manifest+': dependency inventory changed after advisory sweep.');
    receipt.inventoryComplete &&= summary.inventoryComplete!==false;
    receipt.dependencyCount+=summary.dependencyCount;
    receipt.advisoryCheckedCount+=summary.advisoryCheckedCount;
    receipt.dangerousCount+=summary.dangerousCount||0;
    receipt.suspiciousCount+=summary.suspiciousCount||0;
    receipt.findings.push(...(summary.findings||[]).map(f=>({...f,project:manifest})));
    receipt.issues.push('Enrichment deferred; advisory findings retained: '+manifest);
  }
  receipt.phases={advisories:receipt.inventoryComplete&&receipt.advisoryCheckedCount===receipt.dependencyCount&&receipt.dependencyCount>0?'complete':'incomplete',enrichment:receipt.inventoryComplete&&receipt.enrichmentCheckedCount===receipt.dependencyCount&&receipt.dependencyCount>0?'complete':'incomplete'};
  if (partialOk && incompleteOnly.length && completeManifests === 0) {
    receipt.issues.push('No manifest scanned completely this run (' + incompleteOnly.length + ' incomplete); treating as a failed night.');
  }
  if (partialOk) {
    // Resume after the last finished manifest; a full pass wraps back to the start.
    try { writeFileSync(cursorPath, JSON.stringify({ last: deferred.length ? lastDone : null, updatedAt: new Date().toISOString() }), { mode: 0o600 }); } catch { /* cursor is best effort */ }
    if (deferred.length) receipt.coverage.deferredManifests = deferred.length;
  }
  if (receipt.dependencyCount === 0 && !(partialOk && deferred.length)) receipt.issues.push('No installed dependencies were scanned.');
  const workspaceDanger = receipt.workspace?.findings.some(f => ['critical', 'high'].includes(f.severity));
  const runtimeDanger = receipt.runtimeHighCount > 0;
  receipt.status = workspaceDanger || runtimeDanger || receipt.dangerousCount > 0 ? 'dangerous' : receipt.issues.length ? 'incomplete' : receipt.suspiciousCount > 0 ? 'suspicious' : deferred.length ? 'partial' : 'complete';
  receipt.executionStatus=receipt.runnerFailure||receipt.timeouts?'interrupted':receipt.budgetStops?'budget_exhausted':'finished';
  receipt.finishedAt = new Date().toISOString();
  receipt.exitCode = receipt.status === 'incomplete' || receipt.status === 'suspicious' ? 2 : receipt.status === 'dangerous' ? 1 : 0; // 'partial' (opt-in) exits 0
  const receiptPath = join(guardogHome(), 'data', 'last-nightly.json');
  const temporary = receiptPath + '.' + process.pid + '.tmp';
  writeFileSync(temporary, JSON.stringify(receipt, null, 2), { mode: 0o600 });
  renameSync(temporary, receiptPath);
  try {
    const health = checkHealth({ ...options.healthOptions, repair: false });
    receipt.resilience = recordResilienceCycle({ phase: 'nightly', health, receipt });
  } catch (error) {
    receipt.issues.push('Resilience verification failed: ' + error.message);
    receipt.status = workspaceDanger || runtimeDanger || receipt.dangerousCount > 0 ? 'dangerous' : 'incomplete';
    receipt.exitCode = receipt.status === 'dangerous' ? 1 : 2;
  }
  writeFileSync(temporary, JSON.stringify(receipt, null, 2), { mode: 0o600 });
  renameSync(temporary, receiptPath);
  return receipt;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const receipt = runNightly({ runtimeCheck: ({ timeoutMs }) => runRuntimeCheckSync({ timeoutMs, script: join(packageRoot(), 'src', 'index.js') }) });
    console.log(JSON.stringify(receipt, null, 2));
    process.exitCode = receipt.exitCode;
  } catch (error) {
    console.error('MyOS Guard Dog nightly scan incomplete: ' + error.message);
    process.exitCode = 2;
  }
}
