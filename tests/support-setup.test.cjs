'use strict';

// Regressions from All Sorted support report e8bc2c56 (install e634ff0f):
// "setup <anything>" started the wizard, quick setup always asked for a
// VirusTotal key, and expected large files made every workspace scan incomplete.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const CLI = path.join(__dirname, '..', 'src', 'index.js');

function home(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gd-support-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function cli(args, env) {
  const clean = { ...process.env, ...env };
  if (!('VIRUSTOTAL_API_KEY' in env)) delete clean.VIRUSTOTAL_API_KEY;
  return spawnSync(process.execPath, [CLI, ...args], { env: clean, encoding: 'utf8', input: '', timeout: 60000 });
}

test('setup with an unknown argument prints usage and never starts the wizard', (t) => {
  const dir = home(t);
  for (const arg of ['--help', 'status']) {
    const result = cli(['setup', arg], { GUARDOG_HOME: dir, HOME: dir });
    assert.match(result.stdout, /Usage: myos-guard-dog setup/, arg);
    assert.doesNotMatch(result.stdout, /VirusTotal API key|Enter/i, arg);
    assert.equal(result.status, arg === '--help' ? 0 : 2, arg);
  }
});

test('quick setup does not ask for a VirusTotal key that is already configured', (t) => {
  const dir = home(t);
  fs.writeFileSync(path.join(dir, '.env'), 'VIRUSTOTAL_API_KEY=fixture-not-a-real-key\n', { mode: 0o600 });
  const configured = cli(['setup', '--quick'], { GUARDOG_HOME: dir, HOME: dir });
  assert.match(configured.stdout, /VirusTotal key: configured/);
  assert.doesNotMatch(configured.stdout, /Add a VirusTotal key/);
  assert.doesNotMatch(configured.stdout + configured.stderr, /fixture-not-a-real-key/);
  const bare = home(t);
  assert.match(cli(['setup', '--quick'], { GUARDOG_HOME: bare, HOME: bare }).stdout, /Add a VirusTotal key/);
});

test('owner-listed expected skips keep the workspace scan complete; other skips still count', async (t) => {
  const { scanWorkspace, expectedSkipMatcher } = await import('../src/workspace-scan.js');
  const root = home(t);
  fs.mkdirSync(path.join(root, 'media'));
  fs.writeFileSync(path.join(root, 'media', 'clip.mov'), Buffer.alloc(2048, 1));
  fs.writeFileSync(path.join(root, 'notes.txt'), 'hello\n');
  const limits = { maxFileBytes: 1024, cache: false };
  const plain = scanWorkspace(root, limits);
  assert.equal(plain.coverage.complete, false);
  assert.ok(plain.issues.some((i) => i.code === 'file_size_limit'));
  const listed = scanWorkspace(root, { ...limits, expectedSkips: ['media/**'] });
  assert.equal(listed.coverage.complete, true, JSON.stringify(listed.issues));
  assert.equal(listed.coverage.expectedSkips, 1);
  fs.writeFileSync(path.join(root, 'big.bin'), Buffer.alloc(2048, 2));
  assert.equal(scanWorkspace(root, { ...limits, expectedSkips: ['media/**'] }).coverage.complete, false);
  const match = expectedSkipMatcher(['*.mov', 'assets']);
  assert.ok(match('clip.mov') && match('assets/a/b.png') && !match('media/clip.mov') && !match('assetsx/a'));
  assert.throws(() => expectedSkipMatcher(['../x']));
  assert.throws(() => expectedSkipMatcher(['/abs']));
});
