const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

function runHook({ initial = { private: true }, staged, working = staged, packagePath = 'package.json', rootManifest, initialLock, stagedLock, workingLock = stagedLock, transformHook, env = process.env }) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'myos-guard-dog-hook-'));
  const bin = path.join(root, 'bin');
  const repo = path.join(root, 'repo');
  fs.mkdirSync(bin);
  fs.mkdirSync(repo);
  const sourceHook = fs.readFileSync(path.resolve(__dirname, '../bin/git-precommit-hook.sh'), 'utf8');
  fs.writeFileSync(path.join(bin, 'git-precommit-hook.sh'), transformHook ? transformHook(sourceHook, root) : sourceHook);
  fs.writeFileSync(path.join(bin, 'scan-deps.js'), `
    const fs = require('node:fs');
    const manifest = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
    const lockPath = require('node:path').join(require('node:path').dirname(process.argv[2]), 'package-lock.json');
    const lock = fs.existsSync(lockPath) ? fs.readFileSync(lockPath, 'utf8') : '';
    const names = [...Object.keys(manifest.dependencies || {}), ...Object.keys(manifest.overrides || {})];
    if (lock.includes('bad-package')) names.push('bad-package');
    process.exit(names.includes('bad-package') ? 1 : names.includes('incomplete-package') ? 2 : 0);
  `);
  spawnSync('git', ['init', '-q'], { cwd: repo });
  spawnSync('git', ['config', 'user.email', 'test@example.com'], { cwd: repo });
  spawnSync('git', ['config', 'user.name', 'Test'], { cwd: repo });
  fs.mkdirSync(path.dirname(path.join(repo, packagePath)), { recursive: true });
  fs.writeFileSync(path.join(repo, packagePath), JSON.stringify(initial));
  if (rootManifest) fs.writeFileSync(path.join(repo, 'package.json'), JSON.stringify(rootManifest));
  const lockPath = path.join(path.dirname(path.join(repo, packagePath)), 'package-lock.json');
  if (initialLock) fs.writeFileSync(lockPath, JSON.stringify(initialLock));
  spawnSync('git', ['add', packagePath], { cwd: repo });
  if (rootManifest) spawnSync('git', ['add', 'package.json'], { cwd: repo });
  if (initialLock) spawnSync('git', ['add', path.relative(repo, lockPath)], { cwd: repo });
  spawnSync('git', ['commit', '-qm', 'initial'], { cwd: repo });
  fs.writeFileSync(path.join(repo, packagePath), JSON.stringify(staged));
  spawnSync('git', ['add', packagePath], { cwd: repo });
  fs.writeFileSync(path.join(repo, packagePath), JSON.stringify(working));
  if (stagedLock) {
    fs.writeFileSync(lockPath, JSON.stringify(stagedLock));
    spawnSync('git', ['add', path.relative(repo, lockPath)], { cwd: repo });
    fs.writeFileSync(lockPath, JSON.stringify(workingLock));
  }
  const result = spawnSync('bash', [path.join(bin, 'git-precommit-hook.sh')], {
    cwd: repo,
    encoding: 'utf8',
    env,
  });
  fs.rmSync(root, { recursive: true, force: true });
  return { ...result, output: `${result.stdout}${result.stderr}` };
}

test('pre-commit hook skips a scripts-only manifest edit without a lockfile', () => {
  const result = runHook({ staged: { private: true, scripts: { test: 'node test.js' } } });
  assert.equal(result.status, 0, result.output);
});

test('pre-commit hook describes incomplete changed-dependency coverage without calling it danger', () => {
  const result = runHook({ staged: { private: true, dependencies: { 'incomplete-package': '1.0.0' } } });
  assert.equal(result.status, 1, result.output);
});

test('pre-commit hook scans the staged manifest instead of a benign working-tree replacement', () => {
  const result = runHook({
    staged: { private: true, dependencies: { 'bad-package': '1.0.0' } },
    working: { private: true },
  });
  assert.equal(result.status, 1, result.output);
});

test('pre-commit hook handles package paths containing spaces', () => {
  const result = runHook({
    packagePath: 'apps/with space/package.json',
    staged: { private: true, scripts: { test: 'node test.js' } },
  });
  assert.equal(result.status, 0, result.output);
});

test('pre-commit hook audits resolution changes made through overrides', () => {
  const result = runHook({ staged: { private: true, overrides: { 'bad-package': '1.0.0' } } });
  assert.equal(result.status, 1, result.output);
});

test('pre-commit hook audits staged lockfile-only changes', () => {
  const initialLock = { lockfileVersion: 3, packages: { '': { name: 'app' } } };
  const stagedLock = { lockfileVersion: 3, packages: { '': { name: 'app' }, 'node_modules/bad-package': { version: '1.0.0' } } };
  const result = runHook({ staged: { private: true }, initialLock, stagedLock, workingLock: initialLock });
  assert.equal(result.status, 1, result.output);
});

test('installed hook uses its pinned Node executable outside the installer PATH', { skip: process.platform === 'win32' }, async () => {
  const { renderGitHook } = await import('../src/setup.js');
  const result = runHook({
    staged: { private: true, overrides: { 'bad-package': '1.0.0' } },
    transformHook: (source, root) => renderGitHook(source, { root, node: process.execPath }),
    env: { ...process.env, PATH: '/usr/bin:/bin' },
  });
  assert.equal(result.status, 1, result.output);
});

test('pre-commit hook fails closed when a staged root workspace definition changes', () => {
  const result = runHook({ staged: { private: true, workspaces: ['packages/*'] }, working: { private: true } });
  assert.equal(result.status, 1, result.output);
});

test('pre-commit hook fails closed for a workspace member even when only scripts changed', () => {
  const result = runHook({
    packagePath: 'packages/member/package.json',
    rootManifest: { private: true, workspaces: ['packages/*'] },
    staged: { name: 'member', version: '1.0.0', scripts: { test: 'node test.js' } },
  });
  assert.equal(result.status, 1, result.output);
});
