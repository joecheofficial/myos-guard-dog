import { existsSync, openSync, readFileSync, closeSync, unlinkSync, writeFileSync, statSync, renameSync, fsyncSync, mkdirSync, rmdirSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { ensureGuardogHome, guardogDataDir } from './paths.js';

const utcDay = now => new Date(now).toISOString().slice(0, 10);
const LOCK_STALE_MS = 60_000;
const LEGACY_LOCK_STALE_MS = 300_000;

function recoverAbandonedLock(path) {
  // A separate exclusive gate serializes stale-lock removal. If recovery itself
  // crashes, reservations fail closed until the recovery gate is inspected.
  const recoveryGate = path + '.recover';
  try { mkdirSync(recoveryGate, { mode: 0o700 }); }
  catch (error) { if (error.code === 'EEXIST') return false; throw error; }
  try {
  let before;
  try { before = statSync(path); } catch (error) { return error.code === 'ENOENT'; }
  let owner;
  try { owner = JSON.parse(readFileSync(path, 'utf8')); } catch { owner = null; }
  const age = Date.now() - before.mtimeMs;
  if (age < (Number.isInteger(owner?.pid) ? LOCK_STALE_MS : LEGACY_LOCK_STALE_MS)) return false;
  if (Number.isInteger(owner?.pid)) {
    try { process.kill(owner.pid, 0); return false; }
    catch (error) { if (error.code !== 'ESRCH') return false; }
  }
  try {
    const current = statSync(path);
    if (current.ino !== before.ino || current.mtimeMs !== before.mtimeMs) return false;
    unlinkSync(path);
    return true;
  } catch (error) { return error.code === 'ENOENT'; }
  } finally { rmdirSync(recoveryGate); }
}

/** Persist a small, cross-process daily request allowance for the public VT API. */
export class VirusTotalQuota {
  constructor({ limit, now = () => Date.now(), path = join(guardogDataDir(), 'virustotal-quota.json') }) {
    this.limit = limit;
    this.now = now;
    this.path = path;
    this.lockPath = path + '.lock';
  }

  reserve() {
    if (!Number.isInteger(this.limit) || this.limit < 1) return { allowed: true, unlimited: true };
    ensureGuardogHome();
    let descriptor;
    for (let attempt = 0; attempt < 50; attempt++) {
      try { descriptor = openSync(this.lockPath, 'wx', 0o600); break; }
      catch (error) {
        if (error.code !== 'EEXIST') throw error;
        if (recoverAbandonedLock(this.lockPath)) continue;
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
      }
    }
    if (descriptor === undefined) throw new Error('VirusTotal quota ledger is busy; no request was sent.');
    try {
      writeFileSync(descriptor, JSON.stringify({ pid: process.pid, startedAt: Date.now() }) + '\n');
      const day = utcDay(this.now());
      let state = { day, used: 0 };
      if (existsSync(this.path)) {
        let parsed;
        try { parsed = JSON.parse(readFileSync(this.path, 'utf8')); }
        catch { throw new Error('VirusTotal quota ledger is unreadable or corrupt; no request was sent.'); }
        if (typeof parsed?.day !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(parsed.day) || !Number.isInteger(parsed.used) || parsed.used < 0) {
          throw new Error('VirusTotal quota ledger is invalid; no request was sent.');
        }
        if (parsed.day === day) state = parsed;
      }
      if (state.used >= this.limit) return { allowed: false, used: state.used, limit: this.limit, day };
      state.used++;
      const temporary = this.path + '.' + randomUUID() + '.tmp';
      try {
        const output = openSync(temporary, 'wx', 0o600);
        try {
          writeFileSync(output, JSON.stringify({ day, used: state.used, limit: this.limit, updatedAt: new Date(this.now()).toISOString() }) + '\n');
          fsyncSync(output);
        } finally { closeSync(output); }
        renameSync(temporary, this.path);
      } finally { if (existsSync(temporary)) unlinkSync(temporary); }
      return { allowed: true, used: state.used, limit: this.limit, day };
    } finally {
      closeSync(descriptor);
      unlinkSync(this.lockPath);
    }
  }
}
