const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

function runInstaller(nodeMajor) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'myos-guard-dog-installer-'));
  const fakeBin = path.join(root, 'bin');
  const marker = path.join(root, 'npm-called');
  fs.mkdirSync(fakeBin);
  fs.writeFileSync(path.join(fakeBin, 'node'), `#!/bin/sh\nif [ "$1" = "--version" ]; then echo v${nodeMajor}.0.0; exit 0; fi\nexit 0\n`, { mode: 0o755 });
  fs.writeFileSync(path.join(fakeBin, 'npm'), `#!/bin/sh\ntouch "${marker}"\nexit 0\n`, { mode: 0o755 });
  const result = spawnSync('bash', [path.resolve(__dirname, '../install.sh')], {
    encoding: 'utf8',
    env: { ...process.env, PATH: `${fakeBin}:/usr/bin:/bin` },
  });
  const npmCalled = fs.existsSync(marker);
  fs.rmSync(root, { recursive: true, force: true });
  return { result, npmCalled };
}

test('installer rejects Node 20 before invoking npm', { skip: process.platform === 'win32' }, () => {
  const { result, npmCalled } = runInstaller(20);
  assert.equal(result.status, 1);
  assert.equal(npmCalled, false);
});

test('installer accepts Node 24 and reaches npm', { skip: process.platform === 'win32' }, () => {
  const { result, npmCalled } = runInstaller(24);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.equal(npmCalled, true);
});

test('installer rejects newer unverified Node majors before invoking npm', { skip: process.platform === 'win32' }, () => {
  const { result, npmCalled } = runInstaller(26);
  assert.equal(result.status, 1);
  assert.equal(npmCalled, false);
});

test('installer accepts Node 22 and reaches npm', { skip: process.platform === 'win32' }, () => {
  const { result, npmCalled } = runInstaller(22);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.equal(npmCalled, true);
});
