const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

test('a manifest that times out is skipped with a logged issue and later manifests still scan', async () => {
  const { runNightly } = await import('../bin/nightly-scan.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-manifest-timeout-'));
  const previous = process.env.GUARDOG_HOME;
  process.env.GUARDOG_HOME = path.join(root, 'state');
  fs.mkdirSync(process.env.GUARDOG_HOME);
  fs.writeFileSync(path.join(process.env.GUARDOG_HOME, 'config.json'), JSON.stringify({ nightlyUpdates: false, scanRoots: [root] }));
  for (const name of ['a-slow', 'b-ok']) {
    fs.mkdirSync(path.join(root, name));
    fs.writeFileSync(path.join(root, name, 'package.json'), '{}');
  }
  const calls = [];
  const scanner = (_, args, options) => {
    calls.push({ manifest: args[1], timeout: options.timeout });
    if (args[1].includes('a-slow')) {
      const error = new Error('spawnSync node ETIMEDOUT'); error.code = 'ETIMEDOUT';
      return { status: null, signal: 'SIGKILL', error, stdout: '' };
    }
    return { status: 0, stdout: JSON.stringify({ status: 'complete', dependencyCount: 3, dangerousCount: 0, issues: [] }) };
  };
  try {
    const receipt = runNightly({ advisoryFirst: false, roots: [root], run: scanner, manifestTimeoutMs: 1234, healthOptions: { platform: 'linux', run: () => ({ status: 0, stdout: '' }) } });
    assert.equal(calls.length, 2, 'the scan must continue past the timed-out manifest');
    for (const call of calls) assert.ok(call.timeout <= 1234, 'each manifest gets the per-manifest cap, not the whole budget');
    assert.equal(receipt.dependencyCount, 3);
    assert.ok(receipt.issues.some((issue) => /timed out after 1234ms and was skipped: .*a-slow/.test(issue)));
    assert.equal(receipt.status, 'incomplete');
  } finally {
    if (previous === undefined) delete process.env.GUARDOG_HOME; else process.env.GUARDOG_HOME = previous;
    fs.rmSync(root, { recursive: true, force: true });
  }
});


test('hard child timeout recovers current findings and danger outranks incomplete coverage', async () => {
  const {runNightly} = await import('../bin/nightly-scan.js');
  const {createHash} = require('node:crypto');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-dog-recover-'));
  const previous = process.env.GUARDOG_HOME;
  process.env.GUARDOG_HOME = path.join(root, 'state');
  fs.mkdirSync(process.env.GUARDOG_HOME);
  fs.writeFileSync(path.join(root, 'package.json'), '{}');
  fs.writeFileSync(path.join(process.env.GUARDOG_HOME, 'config.json'), JSON.stringify({nightlyUpdates: false}));
  try {
    const receipt = runNightly({ advisoryFirst: false,roots: [root], manifestTimeoutMs: 1000, healthOptions: {platform: 'linux', run: () => ({status: 0, stdout: ''})}, run: (_, args) => {
      const runId = args[args.indexOf('--run-id') + 1];
      assert.ok(runId);
      assert.equal(Number(args[args.indexOf('--budget-ms') + 1]), 500);
      const directory = path.join(process.env.GUARDOG_HOME, 'data', 'scan-progress');
      fs.mkdirSync(directory, {recursive: true});
      const file = createHash('sha256').update(args[1]).digest('hex') + '.json';
      fs.writeFileSync(path.join(directory, file), JSON.stringify({schema: 1, runId, summary: {status: 'dangerous', coverage: 'incomplete', dependencyCount: 5, scannedDependencyCount: 2, deferredDependencyCount: 3, dangerousCount: 1, issues: ['3 checks unfinished']}}));
      return {status: null, signal: 'SIGKILL', error: Object.assign(new Error('timeout'), {code: 'ETIMEDOUT'}), stdout: ''};
    }});
    assert.equal(receipt.status, 'dangerous');
    assert.equal(receipt.exitCode, 1);
    assert.equal(receipt.dangerousCount, 1);
    assert.equal(receipt.scannedDependencyCount, 2);
    assert.equal(receipt.coverage.deferredDependencies, 3);
    assert.equal(receipt.timeouts, 1);
    assert.ok(receipt.issues.some(issue => issue.includes('completed checks recovered')));
  } finally {
    if (previous === undefined) delete process.env.GUARDOG_HOME; else process.env.GUARDOG_HOME = previous;
    fs.rmSync(root, {recursive: true, force: true});
  }
});


test('missing Node executable stops the manifest loop with one actionable failure', async () => {
  const {runNightly} = await import('../bin/nightly-scan.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-dog-node-missing-'));
  const previous = process.env.GUARDOG_HOME;
  process.env.GUARDOG_HOME = path.join(root, 'state');
  fs.mkdirSync(process.env.GUARDOG_HOME);
  fs.writeFileSync(path.join(process.env.GUARDOG_HOME, 'config.json'), JSON.stringify({nightlyUpdates: false}));
  for (const name of ['a', 'b', 'c']) { fs.mkdirSync(path.join(root, name)); fs.writeFileSync(path.join(root, name, 'package.json'), '{}'); }
  let calls = 0;
  try {
    const receipt = runNightly({ advisoryFirst: false,roots: [root], healthOptions: {platform: 'linux', run: () => ({status: 0, stdout: ''})}, run: () => {calls++; return {error: Object.assign(new Error('spawn node ENOENT'), {code: 'ENOENT'}), status: null};}});
    assert.equal(calls, 1);
    assert.equal(receipt.status, 'incomplete');
    assert.equal(receipt.exitCode, 2);
    assert.equal(receipt.runnerFailure, 'ENOENT');
    assert.ok(receipt.issues.some(issue => issue.includes('doctor --repair')));
  } finally {
    if (previous === undefined) delete process.env.GUARDOG_HOME; else process.env.GUARDOG_HOME = previous;
    fs.rmSync(root, {recursive: true, force: true});
  }
});
