import { createHash, randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, renameSync, unlinkSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { summarizeDependencyScan } from './scan-summary.js';

const digest = value => createHash('sha256').update(value).digest('hex');
const progressPath = (manifest, stateDir) => join(stateDir, 'scan-progress', digest(resolve(manifest)) + '.json');

/** A nonce binds recovery to this child run, never a previous clean receipt. */
export function readScanProgress(manifest, stateDir, runId) {
  try {
    const saved = JSON.parse(readFileSync(progressPath(manifest, stateDir), 'utf8'));
    return saved.schema === 1 && saved.runId === runId ? saved.summary : null;
  } catch { return null; }
}

/** Resume position only. Past verdicts are never reused as current evidence. */
export async function scanWithProgress(inventory, { manifest, stateDir, budgetMs, analyze, now = Date.now, runId = randomUUID() }) {
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
  const results = [];
  let stopReason = null;
  function checkpoint() {
    const summary = summarizeDependencyScan({ ...inventory, packages: ordered }, results);
    summary.scannedDependencyCount = results.length;
    summary.deferredDependencyCount = count - results.length;
    summary.budgetExhausted = stopReason === 'time_budget';
    summary.resume = { nextIndex: count ? (start + results.length) % count : 0, reason: stopReason, historicalResultsReused: false };
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
  for (const pkg of ordered) {
    if (now() >= deadline) { stopReason = 'time_budget'; break; }
    results.push(await analyze(pkg));
    const saved = checkpoint();
    if (saved.progressError) return saved;
    if (results.at(-1).scanResults?.status === 'rate_limited') { stopReason = 'quota_exhausted'; break; }
  }
  return checkpoint();
}
