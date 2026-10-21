const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

test('partialNightlyOk: quota stop is deferred (exit 0), excludes are skipped, next run resumes after the cursor', async () => {
  const { runNightly } = await import('../bin/nightly-scan.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-partial-'));
  const previous = process.env.GUARDOG_HOME;
  process.env.GUARDOG_HOME = path.join(root, 'state');
  fs.mkdirSync(process.env.GUARDOG_HOME);
  const config = { nightlyUpdates: false, scanRoots: [root], partialNightlyOk: true, scanExcludes: ['/vendored'] };
  for (const name of ['a', 'b', 'c', 'vendored']) {
    fs.mkdirSync(path.join(root, name));
    fs.writeFileSync(path.join(root, name, 'package.json'), '{}');
  }
  fs.writeFileSync(path.join(process.env.GUARDOG_HOME, 'config.json'), JSON.stringify(config));
  const health = { platform: 'linux', run: () => ({ status: 0, stdout: '' }) };
  const ok = { status: 0, stdout: JSON.stringify({ status: 'complete', dependencyCount: 2, dangerousCount: 0, issues: [] }) };
  const quota = { status: 2, stdout: JSON.stringify({ status: 'incomplete', dependencyCount: 1, dangerousCount: 0, quotaExhausted: true, issues: ['x: scan coverage incomplete; VirusTotal quota'] }) };
  try {
    const first = [];
    let receipt = runNightly({ advisoryFirst: false, config, roots: [root], healthOptions: health, run: (_, args) => { first.push(path.basename(path.dirname(args[1]))); return path.basename(path.dirname(args[1])) === 'b' ? quota : ok; } });
    assert.deepEqual(first, ['a', 'b'], 'excluded tree is never scanned; scan stops at the quota');
    assert.deepEqual(receipt.issues, []);
    assert.equal(receipt.status, 'partial');
    assert.equal(receipt.exitCode, 0);
    assert.equal(receipt.dependencyCount, 2);
    assert.equal(receipt.coverage.deferredManifests, 2);
    const second = [];
    receipt = runNightly({ advisoryFirst: false, config, roots: [root], healthOptions: health, run: (_, args) => { second.push(path.basename(path.dirname(args[1]))); return ok; } });
    assert.deepEqual(second, ['b', 'c', 'a'], 'resumes after the last finished manifest and wraps');
    assert.equal(receipt.status, 'complete');
  } finally {
    if (previous === undefined) delete process.env.GUARDOG_HOME; else process.env.GUARDOG_HOME = previous;
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('partialNightlyOk: incomplete-only manifests are coverage notes, but an all-incomplete night still fails', async () => {
  const { runNightly } = await import('../bin/nightly-scan.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-partial-inc-'));
  const previous = process.env.GUARDOG_HOME;
  process.env.GUARDOG_HOME = path.join(root, 'state');
  fs.mkdirSync(process.env.GUARDOG_HOME);
  const config = { nightlyUpdates: false, scanRoots: [root], partialNightlyOk: true };
  fs.writeFileSync(path.join(process.env.GUARDOG_HOME, 'config.json'), JSON.stringify(config));
  for (const name of ['a', 'b']) {
    fs.mkdirSync(path.join(root, name));
    fs.writeFileSync(path.join(root, name, 'package.json'), '{}');
  }
  const health = { platform: 'linux', run: () => ({ status: 0, stdout: '' }) };
  const ok = { status: 0, stdout: JSON.stringify({ status: 'complete', dependencyCount: 2, dangerousCount: 0, issues: [] }) };
  const stale = { status: 2, stdout: JSON.stringify({ status: 'incomplete', dependencyCount: 1, dangerousCount: 0, issues: ['x@1.0.0: scan coverage incomplete'] }) };
  try {
    let receipt = runNightly({ advisoryFirst: false, config, roots: [root], healthOptions: health, run: (_, args) => (path.basename(path.dirname(args[1])) === 'a' ? ok : stale) });
    assert.deepEqual(receipt.issues, []);
    assert.equal(receipt.exitCode, 0);
    assert.equal(receipt.coverage.incompleteManifests, 1);
    fs.rmSync(path.join(process.env.GUARDOG_HOME, 'data', 'nightly-cursor.json'), { force: true });
    receipt = runNightly({ advisoryFirst: false, config, roots: [root], healthOptions: health, run: () => stale });
    assert.equal(receipt.exitCode, 2, 'nothing scanned completely is a failed night');
  } finally {
    if (previous === undefined) delete process.env.GUARDOG_HOME; else process.env.GUARDOG_HOME = previous;
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('partialNightlyOk: a quota stop on a manifest that found danger keeps the danger and is not deferred', async () => {
  const { runNightly } = await import('../bin/nightly-scan.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-partial-danger-'));
  const previous = process.env.GUARDOG_HOME;
  process.env.GUARDOG_HOME = path.join(root, 'state');
  fs.mkdirSync(process.env.GUARDOG_HOME);
  const config = { nightlyUpdates: false, scanRoots: [root], partialNightlyOk: true };
  for (const name of ['a', 'b']) {
    fs.mkdirSync(path.join(root, name));
    fs.writeFileSync(path.join(root, name, 'package.json'), '{}');
  }
  fs.writeFileSync(path.join(process.env.GUARDOG_HOME, 'config.json'), JSON.stringify(config));
  const health = { platform: 'linux', run: () => ({ status: 0, stdout: '' }) };
  const dangerQuota = { status: 1, stdout: JSON.stringify({ status: 'dangerous', dependencyCount: 3, dangerousCount: 1, quotaExhausted: true, issues: [] }) };
  try {
    const receipt = runNightly({ advisoryFirst: false, config, roots: [root], healthOptions: health, run: () => dangerQuota });
    assert.equal(receipt.dangerousCount, 1, 'found danger is never discarded by a quota deferral');
    assert.notEqual(receipt.status, 'partial');
    assert.notEqual(receipt.exitCode, 0);
  } finally {
    if (previous === undefined) delete process.env.GUARDOG_HOME; else process.env.GUARDOG_HOME = previous;
    fs.rmSync(root, { recursive: true, force: true });
  }
});
