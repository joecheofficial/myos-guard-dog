import { acquireScanLease } from './scan-lease.js';
import { createHash, randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, renameSync, unlinkSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { summarizeDependencyScan, mergeAuditPhases } from './scan-summary.js';

const digest = value => createHash('sha256').update(value).digest('hex');
const progressPath = (manifest, stateDir) => join(stateDir, 'scan-progress', digest(resolve(manifest)) + '.json');

/** A nonce binds recovery to this child run, never a previous clean receipt. */
export function readScanProgress(manifest, stateDir, runId, inventory = null) {
  try {
    const saved = JSON.parse(readFileSync(progressPath(manifest, stateDir), 'utf8'));
    return saved.schema === 1 && saved.runId === runId && (!inventory || saved.fingerprint === digest(JSON.stringify(inventory))) ? saved.summary : null;
  } catch { return null; }
}

/** Resume position only. Past verdicts are never reused as current evidence. */
export async function scanWithProgress(inventory, options) {
  const release=acquireScanLease(progressPath(options.manifest,options.stateDir)+'.lock');
  try {return await runProgress(inventory,options);}finally{release();}
}

async function runProgress(inventory, { manifest, stateDir, budgetMs, analyze, priorSummary = null, concurrency = 1, now = Date.now, runId = randomUUID() }) {
  if(!Number.isInteger(concurrency)||concurrency<1||concurrency>4)throw Error('Concurrency must be an integer from 1 to 4.');
  if (!Number.isFinite(budgetMs) || budgetMs <= 0) throw new Error('Scan budget must be a positive number of milliseconds.');
  const deadline = now() + budgetMs;
  const path = progressPath(manifest, stateDir);
  const fingerprint = digest(JSON.stringify(inventory));
  const count = inventory.packages.length;
  let start = 0;
  try {
    const saved = JSON.parse(readFileSync(path, 'utf8'));
    if (saved.schema === 1 && saved.fingerprint === fingerprint && Number.isInteger(saved.nextIndex) && saved.nextIndex >= 0 && saved.nextIndex < count) start = saved.nextIndex;
  } catch { /* Missing or damaged cursor restarts coverage, never certifies it. */ }
  mkdirSync(join(stateDir, 'scan-progress'), { recursive: true, mode: 0o700 });
  const ordered = inventory.packages.slice(start).concat(inventory.packages.slice(0, start));
  const rows = new Array(count);
  let stopReason = null;
  function checkpoint() {
    const results=rows.filter(Boolean);
    const completedPackages=ordered.filter((_,i)=>rows[i]);
    const summary = mergeAuditPhases(priorSummary, {...summarizeDependencyScan({ ...inventory, packages: completedPackages.concat(ordered.filter((_,i)=>!rows[i])) }, results),inventoryFingerprint:fingerprint});
    const firstUnfinished=rows.findIndex(row=>!row);
    summary.scannedDependencyCount = results.length;
    summary.deferredDependencyCount = count - results.length;
    summary.budgetExhausted = stopReason === 'time_budget';
    summary.resume = { nextIndex: count ? (start + (firstUnfinished<0?count:firstUnfinished)) % count : 0, reason: stopReason, historicalResultsReused: false };
    if (stopReason) summary.issues.push(`Scan paused: ${stopReason}; ${results.length}/${count} dependencies checked this run. Next budgeted run resumes at dependency ${summary.resume.nextIndex + 1}.`);
    const temporary = path + '.' + randomUUID() + '.tmp';
    try {
      writeFileSync(temporary, JSON.stringify({ schema: 1, fingerprint, runId, nextIndex: summary.resume.nextIndex, updatedAt: new Date().toISOString(), summary }), { mode: 0o600, flag: 'wx' });
      renameSync(temporary, path);
    } catch (error) {
      try { unlinkSync(temporary); } catch { /* Only this run's temporary file. */ }
      summary.progressError = 'Cannot save scan checkpoint (' + (error.code || 'write failure') + '); resume position was not saved.';
      summary.issues.push(summary.progressError);
      summary.coverage = 'incomplete';
      summary.status = summary.dangerousCount ? 'dangerous' : 'incomplete';
    }
    return summary;
  }
  // Replace the previous run's snapshot before starting any external requests.
  const initial = checkpoint();
  if (initial.progressError) return initial;
  let next=0, failure=null, writeFailure=null;
  async function worker() {
    while(next<count && !stopReason && !failure && !writeFailure) {
      if(now()>=deadline){stopReason='time_budget';break;}
      const index=next++;
      try {rows[index]=await analyze(ordered[index]);}
      catch(error){failure=error;break;}
      const saved=checkpoint();
      if(saved.progressError)writeFailure=saved;
      if(rows[index]?.scanResults?.status==='rate_limited')stopReason='quota_exhausted';
    }
  }
  await Promise.all(Array.from({length:Math.min(concurrency,count)},worker));
  if(failure)throw failure;
  if(writeFailure)return writeFailure;
  return checkpoint();
}
