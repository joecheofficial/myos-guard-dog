const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const inventory = { complete: true, issues: [], packages: Array.from({length: 5}, (_, i) => ({ name: `pkg-${i}`, version: '1.0.0', ecosystem: 'npm' })) };
const good = name => ({ packageName: name, version: '1.0.0', decision: {action: 'SILENT', coverage: 'complete', threat: 'SAFE'}, cveResults: {status: 'complete'} });

async function fixture(fn) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-dog-progress-'));
  try { await fn(root, await import('../src/scan-progress.js')); }
  finally { fs.rmSync(root, { recursive: true, force: true }); }
}

test('budgeted scan checkpoints each dependency and resumes without certifying old results', () => fixture(async (root, {scanWithProgress, readScanProgress}) => {
  let now = 0; const seen = [];
  const options = {manifest: path.join(root, 'package.json'), stateDir: root, budgetMs: 2, now: () => now, analyze: async pkg => { seen.push(pkg.name); now++; return good(pkg.name); }};
  const first = await scanWithProgress(inventory, {...options, runId: 'first'});
  assert.equal(first.status, 'incomplete');
  assert.equal(first.scannedDependencyCount, 2);
  assert.equal(first.deferredDependencyCount, 3);
  assert.equal(first.budgetExhausted, true);
  assert.equal(readScanProgress(options.manifest, root, 'old'), null);
  assert.equal(readScanProgress(options.manifest, root, 'first').scannedDependencyCount, 2);
  const second = await scanWithProgress(inventory, {...options, runId: 'second'});
  assert.deepEqual(seen, ['pkg-0', 'pkg-1', 'pkg-2', 'pkg-3']);
  assert.equal(second.scannedDependencyCount, 2, 'previous results must never count as current verification');
  assert.equal(second.coverage, 'incomplete');
}));

test('inventory change resets cursor; complete pass must recheck every package', () => fixture(async (root, {scanWithProgress}) => {
  let now = 0;
  const options = {manifest: path.join(root, 'package.json'), stateDir: root, budgetMs: 1, now: () => now, analyze: async pkg => {now++; return good(pkg.name);}};
  await scanWithProgress(inventory, options);
  const changed = structuredClone(inventory); changed.packages[0].version = '2.0.0';
  const seen = [];
  const result = await scanWithProgress(changed, {...options, budgetMs: 100, analyze: async pkg => {seen.push(pkg.name); return good(pkg.name);}});
  assert.deepEqual(seen, changed.packages.map(p => p.name));
  assert.equal(result.status, 'complete');
  assert.equal(result.deferredDependencyCount, 0);
}));

test('hard interruption preserves earlier findings and retries the unfinished dependency', () => fixture(async (root, {scanWithProgress, readScanProgress}) => {
  const options = {manifest: path.join(root, 'package.json'), stateDir: root, budgetMs: 100, runId: 'interrupted'};
  await assert.rejects(scanWithProgress(inventory, {...options, analyze: async pkg => {
    if(pkg.name === 'pkg-1') throw new Error('simulated process interruption');
    return {...good(pkg.name), decision: {action: 'BARK', coverage: 'complete'}};
  }}), /interruption/);
  const saved = readScanProgress(options.manifest, root, 'interrupted');
  assert.equal(saved.dangerousCount, 1);
  assert.equal(saved.scannedDependencyCount, 1);
  const seen = [];
  await scanWithProgress(inventory, {...options, analyze: async pkg => {seen.push(pkg.name); return good(pkg.name);}});
  assert.equal(seen[0], 'pkg-1');
}));

test('quota exhaustion stops remaining network work and keeps coverage incomplete', () => fixture(async (root, {scanWithProgress}) => {
  let calls = 0;
  const result = await scanWithProgress(inventory, {manifest: path.join(root, 'package.json'), stateDir: root, budgetMs: 100, analyze: async pkg => {calls++; return {...good(pkg.name), decision: {coverage: 'incomplete'}, scanResults: {status: 'rate_limited', error: 'quota exhausted'}};}});
  assert.equal(calls, 1);
  assert.equal(result.quotaExhausted, true);
  assert.equal(result.status, 'incomplete');
}));


test('real CLI child returns before its budget and continues at the next dependency', () => fixture(async (root) => {
  const {spawnSync} = require('node:child_process');
  const {pathToFileURL} = require('node:url');
  const manifest = path.join(root, 'package.json');
  fs.writeFileSync(manifest, '{}');
  fs.writeFileSync(path.join(root, 'package-lock.json'), JSON.stringify({lockfileVersion: 3, packages: Object.fromEntries(inventory.packages.map(p => [`node_modules/${p.name}`, {version: p.version, resolved: `https://registry.npmjs.org/${p.name}/-/${p.name}-1.0.0.tgz`}]))}));
  const preload = path.join(root, 'preload.mjs');
  const source = pathToFileURL(path.resolve(__dirname, '../src/index.js')).href;
  fs.writeFileSync(preload, `import {GuardDog} from ${JSON.stringify(source)};
    let clock = Date.now(); Date.now = () => clock;
    GuardDog.prototype.analyze = async function(name) {
      clock += 60;
      return {packageName: name, version: '1.0.0', decision: {action: 'SILENT', coverage: 'complete', threat: 'SAFE'}, cveResults: {status: 'complete'}};
    };`);
  const args = ['--import', pathToFileURL(preload).href, path.resolve(__dirname, '../bin/scan-deps.js'), manifest, '--json', '--budget-ms', '100'];
  const env = {...process.env, GUARDOG_HOME: path.join(root, 'state')};
  const first = spawnSync(process.execPath, args, {env, encoding: 'utf8', timeout: 5000});
  assert.equal(first.status, 2, first.stderr);
  const one = JSON.parse(first.stdout);
  assert.equal(one.scannedDependencyCount, 2);
  assert.equal(one.resume.nextIndex, 2);
  assert.equal(one.budgetExhausted, true);
  const second = spawnSync(process.execPath, args, {env, encoding: 'utf8', timeout: 5000});
  assert.equal(second.status, 2, second.stderr);
  assert.equal(JSON.parse(second.stdout).resume.nextIndex, 4);
}));


test('real killed child leaves a recoverable current snapshot', () => fixture(async root => {
  const {spawnSync} = require('node:child_process');
  const {pathToFileURL} = require('node:url');
  const {runNightly} = await import('../bin/nightly-scan.js');
  const manifest = path.join(root, 'package.json');
  fs.writeFileSync(manifest, '{}');
  fs.writeFileSync(path.join(root, 'package-lock.json'), JSON.stringify({lockfileVersion: 3, packages: Object.fromEntries(inventory.packages.map(p => [`node_modules/${p.name}`, {version: p.version, resolved: `https://registry.npmjs.org/${p.name}/-/${p.name}-1.0.0.tgz`}]))}));
  const preload = path.join(root, 'preload.mjs');
  fs.writeFileSync(preload, `import {GuardDog} from ${JSON.stringify(pathToFileURL(path.resolve(__dirname, '../src/index.js')).href)};
    GuardDog.prototype.analyze = async function(name) {
      if (name === 'pkg-1') await new Promise(resolve => setTimeout(resolve, 10000));
      return {packageName: name, version: '1.0.0', decision: {action: 'BARK', coverage: 'complete'}, cveResults: {status: 'complete'}};
    };`);
  const previous = process.env.GUARDOG_HOME;
  process.env.GUARDOG_HOME = path.join(root, 'state');
  fs.mkdirSync(process.env.GUARDOG_HOME);
  fs.writeFileSync(path.join(process.env.GUARDOG_HOME, 'config.json'), JSON.stringify({nightlyUpdates: false}));
  try {
    const receipt = runNightly({roots: [root], manifestTimeoutMs: 2000, healthOptions: {platform: 'linux', run: () => ({status: 0, stdout: ''})}, run: (command, args, options) => spawnSync(command, ['--import', pathToFileURL(preload).href, ...args], options)});
    assert.equal(receipt.timeouts, 1);
    assert.equal(receipt.scannedDependencyCount, 1);
    assert.equal(receipt.dangerousCount, 1);
    assert.equal(receipt.status, 'dangerous');
    assert.equal(receipt.exitCode, 1);
  } finally {if(previous === undefined) delete process.env.GUARDOG_HOME; else process.env.GUARDOG_HOME = previous;}
}));


test('checkpoint write failure retains detected danger in the returned summary', () => fixture(async (root, {scanWithProgress}) => {
  const summary = await scanWithProgress(inventory, {manifest: path.join(root, 'package.json'), stateDir: root, budgetMs: 100, analyze: async pkg => {
    const directory = path.join(root, 'scan-progress');
    const file = path.join(directory, fs.readdirSync(directory).find(name => name.endsWith('.json')));
    fs.unlinkSync(file); fs.mkdirSync(file); // Force atomic rename to fail after a finding.
    return {...good(pkg.name), decision: {action: 'BARK', coverage: 'complete'}};
  }});
  assert.equal(summary.status, 'dangerous');
  assert.equal(summary.coverage, 'incomplete');
  assert.equal(summary.dangerousCount, 1);
  assert.match(summary.progressError, /checkpoint/i);
  assert.equal(summary.scannedDependencyCount, 1);
}));
