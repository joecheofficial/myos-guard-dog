const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

function withState(fn) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-discovery-'));
  const previous = { home: process.env.GUARDOG_HOME, depth: process.env.GUARDOG_MAX_DEPTH };
  process.env.GUARDOG_HOME = path.join(root, 'state');
  fs.mkdirSync(process.env.GUARDOG_HOME);
  fs.writeFileSync(path.join(process.env.GUARDOG_HOME, 'config.json'), JSON.stringify({ nightlyUpdates: false, scanRoots: [root] }));
  const ok = () => ({ status: 0, stdout: JSON.stringify({ status: 'complete', dependencyCount: 1, dangerousCount: 0, issues: [] }) });
  return fn(root, ok).finally(() => {
    if (previous.home === undefined) delete process.env.GUARDOG_HOME; else process.env.GUARDOG_HOME = previous.home;
    if (previous.depth === undefined) delete process.env.GUARDOG_MAX_DEPTH; else process.env.GUARDOG_MAX_DEPTH = previous.depth;
    fs.rmSync(root, { recursive: true, force: true });
  });
}

test('Library directly under the home directory is skipped; a project Library folder elsewhere is not', () => withState(async (root, ok) => {
  const { runNightly } = await import('../bin/nightly-scan.js');
  fs.mkdirSync(path.join(root, 'Library', 'Caches', 'tool'), { recursive: true });
  fs.writeFileSync(path.join(root, 'Library', 'Caches', 'tool', 'package.json'), '{}');
  fs.mkdirSync(path.join(root, 'project', 'Library'), { recursive: true });
  fs.writeFileSync(path.join(root, 'project', 'Library', 'package.json'), '{}');
  const scanned = [];
  const run = (_, args) => { scanned.push(args[1]); return ok(); };
  const health = { platform: 'linux', run: () => ({ status: 0, stdout: '' }) };
  const receipt = runNightly({ roots: [root], run, homeDirectory: root, healthOptions: health });
  assert.ok(scanned.every((m) => !m.includes(path.join('Library', 'Caches'))), 'home Library must not be walked');
  assert.ok(scanned.some((m) => m.includes(path.join('project', 'Library'))), 'a Library folder inside a project still scans');
  assert.equal(receipt.status, 'complete');
}));

test('reaching the depth limit and unreadable folders are counted as boundaries, not failures', () => withState(async (root, ok) => {
  const { runNightly } = await import('../bin/nightly-scan.js');
  process.env.GUARDOG_MAX_DEPTH = '1';
  fs.mkdirSync(path.join(root, 'shallow'));
  fs.writeFileSync(path.join(root, 'shallow', 'package.json'), '{}');
  fs.mkdirSync(path.join(root, 'a', 'b', 'c'), { recursive: true });
  fs.writeFileSync(path.join(root, 'a', 'b', 'c', 'package.json'), '{}');
  const locked = path.join(root, 'locked');
  fs.mkdirSync(locked);
  fs.chmodSync(locked, 0o000);
  const health = { platform: 'linux', run: () => ({ status: 0, stdout: '' }) };
  try {
    const receipt = runNightly({ roots: [root], run: () => ok(), healthOptions: health });
    assert.ok(receipt.boundaries.depthLimited >= 1, 'depth boundary counted');
    assert.ok(receipt.issues.every((issue) => !/depth exceeded/i.test(issue)), 'depth limit is not an issue');
    if (process.getuid && process.getuid() !== 0) {
      assert.ok(receipt.boundaries.unreadable >= 1, 'unreadable folder counted');
      assert.ok(receipt.issues.every((issue) => !issue.startsWith('Cannot read')), 'unreadable folder below the root is not an issue');
    }
    assert.equal(receipt.status, 'complete');
    assert.ok(receipt.boundaries.samples.length >= 1);
  } finally { fs.chmodSync(locked, 0o755); }
}));

test('a non-directory scan root is reported unavailable', () => withState(async (root, ok) => {
  const { runNightly } = await import('../bin/nightly-scan.js');
  const other = path.join(os.tmpdir(), `guardog-nondirectory-${Date.now()}-${Math.random()}`);
  fs.writeFileSync(other, 'not a directory');
  fs.mkdirSync(path.join(root, 'p')); fs.writeFileSync(path.join(root, 'p', 'package.json'), '{}');
  const health = { platform: 'linux', run: () => ({ status: 0, stdout: '' }) };
  try {
    const receipt = runNightly({ roots: [root, other], run: () => ok(), healthOptions: health });
    assert.ok(receipt.issues.some((issue) => issue === 'Scan root is unavailable: ' + other));
    assert.equal(receipt.status, 'incomplete');
  } finally { fs.rmSync(other, { force: true }); }
}));

test('config scanRoots win over GUARDOG_WORKSPACE, which stays the fallback', () => withState(async (root, ok) => {
  const { runNightly } = await import('../bin/nightly-scan.js');
  const chosen = path.join(root, 'chosen'); fs.mkdirSync(chosen);
  fs.writeFileSync(path.join(chosen, 'package.json'), '{}');
  const elsewhere = path.join(root, 'elsewhere'); fs.mkdirSync(elsewhere);
  fs.writeFileSync(path.join(elsewhere, 'package.json'), '{}');
  const previous = process.env.GUARDOG_WORKSPACE;
  process.env.GUARDOG_WORKSPACE = elsewhere;
  const scanned = [];
  const run = (_, args) => { scanned.push(args[1]); return ok(); };
  const health = { platform: 'linux', run: () => ({ status: 0, stdout: '' }) };
  try {
    let receipt = runNightly({ config: { nightlyUpdates: false, scanRoots: [chosen] }, run, healthOptions: health });
    assert.deepEqual(receipt.roots, [chosen]);
    assert.ok(scanned.every((m) => m.startsWith(chosen)));
    scanned.length = 0;
    receipt = runNightly({ config: { nightlyUpdates: false, scanRoots: [] }, run, healthOptions: health });
    assert.deepEqual(receipt.roots, [elsewhere]);
  } finally {
    if (previous === undefined) delete process.env.GUARDOG_WORKSPACE; else process.env.GUARDOG_WORKSPACE = previous;
  }
}));

test('a project with no lockfile is a coverage gap, not an incomplete night', () => withState(async (root) => {
  const { runNightly } = await import('../bin/nightly-scan.js');
  for (const name of ['scratch', 'real']) { fs.mkdirSync(path.join(root, name)); fs.writeFileSync(path.join(root, name, 'package.json'), '{}'); }
  const run = (_, args) => {
    if (args[1].includes('scratch')) return { status: 2, stdout: JSON.stringify({ status: 'incomplete', dependencyCount: 0, dangerousCount: 0, issues: ['No npm lockfile or installed dependency inventory is available', 'No exact installed or locked version for left-pad'] }) };
    return { status: 0, stdout: JSON.stringify({ status: 'complete', dependencyCount: 4, dangerousCount: 0, issues: [] }) };
  };
  const health = { platform: 'linux', run: () => ({ status: 0, stdout: '' }) };
  const receipt = runNightly({ roots: [root], run, healthOptions: health });
  assert.equal(receipt.coverage.projectsWithoutInventory, 1);
  assert.ok(receipt.coverage.samples[0].includes('scratch'));
  assert.ok(receipt.issues.every((issue) => !/lockfile|Incomplete or inconsistent/.test(issue)), receipt.issues.join('\n'));
  assert.equal(receipt.status, 'complete');
  assert.equal(receipt.dependencyCount, 4);
}));

test('an incomplete child scan with a real problem still fails the night', () => withState(async (root) => {
  const { runNightly } = await import('../bin/nightly-scan.js');
  fs.mkdirSync(path.join(root, 'p')); fs.writeFileSync(path.join(root, 'p', 'package.json'), '{}');
  const run = () => ({ status: 2, stdout: JSON.stringify({ status: 'incomplete', dependencyCount: 3, dangerousCount: 0, issues: ['No npm lockfile or installed dependency inventory is available', 'VirusTotal lookup failed for left-pad'] }) });
  const health = { platform: 'linux', run: () => ({ status: 0, stdout: '' }) };
  const receipt = runNightly({ roots: [root], run, healthOptions: health });
  assert.equal(receipt.status, 'incomplete');
  assert.ok(receipt.issues.some((issue) => /VirusTotal lookup failed/.test(issue)));
}));
