#!/usr/bin/env node
import { existsSync, readdirSync, realpathSync, statSync, writeFileSync, renameSync, readFileSync, openSync, closeSync, unlinkSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { homedir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';
import { ensureGuardogHome, guardogHome, packageRoot } from '../src/paths.js';
import { loadUserConfig } from '../src/setup.js';
import { checkHealth } from '../src/health.js';
import { recordResilienceCycle } from '../src/resilience-loop.js';
import { assertSupportedNodeVersion } from '../src/node-version.js';

assertSupportedNodeVersion();

const skipDirs = new Set(['node_modules', '.git', '.next', 'dist', 'build', 'coverage', '.venv', 'venv']);
// Child-scan messages that mean "nothing to verify here", not "the scan broke".
const COVERAGE_GAP = /^(No npm lockfile or installed dependency inventory is available|No exact installed or locked version for |scan coverage incomplete)/i;
// Skipped only when they sit directly under the user's home directory.
const homeOnlySkipDirs = new Set(['Library', 'Applications', 'Movies', 'Music', 'Pictures']);
function realPathOrNull(target) {
  try { return realpathSync(target); } catch { return null; }
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
  const deadline = Date.now() + (options.timeoutMs ?? 3600000);
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
  const receipt = { taskClass: 'security_scan', startedAt: new Date().toISOString(), status: 'incomplete', roots, projectsScanned: 0, dependencyCount: 0, dangerousCount: 0, preflight, issues: preflight.issues.map(issue => 'Health: ' + issue), boundaries: { depthLimited: 0, unreadable: 0, samples: [] }, coverage: { projectsWithoutInventory: 0, samples: [] } };
  const manifests = new Set();
  const visited = new Set();
  // Opt-in (config.scanExcludes): path fragments to skip, for vendored or scratch trees.
  const excludes = Array.isArray(config.scanExcludes) ? config.scanExcludes.filter(item => typeof item === 'string' && item) : [];
  // Opt-in (config.partialNightlyOk): VirusTotal pacing (4 lookups/min) cannot cover a
  // large workspace in one budget. Stopping on budget or quota then rotates to the
  // next manifests tomorrow and records the deferral instead of failing every night.
  const partialOk = config.partialNightlyOk === true;
  const deferred = [];
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
        if (excludes.some(fragment => full.includes(fragment))) continue;
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
  let lastDone = null;
  for (const [index, manifest] of ordered.entries()) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      if (partialOk) { deferred.push(...ordered.slice(index)); } else receipt.issues.push('Nightly scan time budget exhausted.');
      break;
    }
    const timeout = Number.isFinite(manifestTimeoutMs) && manifestTimeoutMs > 0 ? Math.min(remaining, manifestTimeoutMs) : remaining;
    const result = run(process.execPath, [join(packageRoot(), 'bin', 'scan-deps.js'), manifest, '--json'], { encoding: 'utf8', timeout, killSignal: 'SIGKILL', maxBuffer: 8 * 1024 * 1024, windowsHide: true });
    receipt.projectsScanned++;
    if (result.error?.code === 'ETIMEDOUT' || (result.status === null && result.signal)) {
      if (partialOk) { deferred.push(manifest); lastDone = manifest; continue; }
      receipt.issues.push('Scan timed out after ' + timeout + 'ms and was skipped: ' + manifest);
      continue;
    }
    try {
      const summary = JSON.parse(result.stdout);
      if (!Number.isInteger(summary.dependencyCount) || summary.dependencyCount < 0 || !['complete', 'dangerous', 'incomplete'].includes(summary.status)) throw new Error('invalid scan summary');
      receipt.dependencyCount += summary.dependencyCount;
      receipt.dangerousCount += Number(summary.dangerousCount) || 0;
      if (summary.status === 'dangerous' && !summary.dangerousCount) receipt.dangerousCount++;
      const expectedExit = { complete: 0, dangerous: 1, incomplete: 2 }[summary.status];
      const issueTexts = (summary.issues || []).map((issue) => (typeof issue === 'string' ? issue : JSON.stringify(issue)));
      // A project with no lockfile or installed inventory (a scratch folder, a
      // checkout never installed) is a coverage gap, not a failed night. Record
      // it under coverage and keep the receipt complete.
      if (partialOk && summary.quotaExhausted === true) {
        receipt.dependencyCount -= summary.dependencyCount;
        receipt.dangerousCount -= Number(summary.dangerousCount) || 0;
        if (summary.status === 'dangerous' && !summary.dangerousCount) receipt.dangerousCount--;
        deferred.push(...ordered.slice(index));
        break;
      }
      const coverageOnly = summary.status === 'incomplete' && result.status === expectedExit && !summary.dangerousCount && issueTexts.length > 0 && issueTexts.every((text) => COVERAGE_GAP.test(text));
      if (coverageOnly) {
        receipt.coverage.projectsWithoutInventory += 1;
        if (receipt.coverage.samples.length < 20) receipt.coverage.samples.push(manifest + ': ' + issueTexts[0]);
      } else {
        if (summary.status === 'incomplete' || result.status !== expectedExit) receipt.issues.push('Incomplete or inconsistent scan: ' + manifest);
        for (const text of issueTexts) receipt.issues.push(manifest + ': ' + text);
      }
      lastDone = manifest;
      if (summary.quotaExhausted === true) {
        receipt.issues.push('VirusTotal daily quota exhausted. Stopped remaining project scans to preserve the next UTC-day allowance.');
        break;
      }
    } catch { receipt.issues.push('Scan failed for ' + manifest + ': ' + (result.error?.message || result.stderr || 'missing scan summary')); }
  }
  if (partialOk) {
    // Resume after the last finished manifest; a full pass wraps back to the start.
    try { writeFileSync(cursorPath, JSON.stringify({ last: deferred.length ? lastDone : null, updatedAt: new Date().toISOString() }), { mode: 0o600 }); } catch { /* cursor is best effort */ }
    if (deferred.length) receipt.coverage.deferredManifests = deferred.length;
  }
  if (receipt.dependencyCount === 0 && !(partialOk && deferred.length)) receipt.issues.push('No installed dependencies were scanned.');
  receipt.status = receipt.issues.length ? 'incomplete' : receipt.dangerousCount > 0 ? 'dangerous' : deferred.length ? 'partial' : 'complete';
  receipt.finishedAt = new Date().toISOString();
  receipt.exitCode = receipt.status === 'incomplete' ? 2 : receipt.status === 'dangerous' ? 1 : 0; // 'partial' (opt-in) exits 0
  const receiptPath = join(guardogHome(), 'data', 'last-nightly.json');
  const temporary = receiptPath + '.' + process.pid + '.tmp';
  writeFileSync(temporary, JSON.stringify(receipt, null, 2), { mode: 0o600 });
  renameSync(temporary, receiptPath);
  try {
    const health = checkHealth({ ...options.healthOptions, repair: false });
    receipt.resilience = recordResilienceCycle({ phase: 'nightly', health, receipt });
  } catch (error) {
    receipt.issues.push('Resilience verification failed: ' + error.message);
    receipt.status = 'incomplete';
    receipt.exitCode = 2;
  }
  writeFileSync(temporary, JSON.stringify(receipt, null, 2), { mode: 0o600 });
  renameSync(temporary, receiptPath);
  return receipt;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const receipt = runNightly();
    console.log(JSON.stringify(receipt, null, 2));
    process.exitCode = receipt.exitCode;
  } catch (error) {
    console.error('MyOS Guard Dog nightly scan incomplete: ' + error.message);
    process.exitCode = 2;
  }
}
