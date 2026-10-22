const assert = require('node:assert/strict');
const { chmodSync, mkdirSync, readFileSync, writeFileSync } = require('node:fs');
const { join, resolve } = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const wrapper = resolve(__dirname, '../bin/cron-nightly-scan.sh');

function runWrapper(t, scannerExitCode, receipt = {}) {
  const temp = require('node:fs').mkdtempSync(join(require('node:os').tmpdir(), 'guard-dog-cron-'));
  t.after(() => require('node:fs').rmSync(temp, { recursive: true, force: true }));

  const guardogHome = join(temp, 'guardog');
  const statusPath = join(temp, 'overseer-status.json');
  const fakeNode = join(temp, 'fake-node');
  mkdirSync(join(guardogHome, 'data'), { recursive: true });
  writeFileSync(fakeNode, `#!/bin/bash
printf '%s\n' "$FAKE_RECEIPT_JSON" > "$GUARDOG_HOME/data/last-nightly.json"
exit "$FAKE_SCANNER_EXIT"
`);
  chmodSync(fakeNode, 0o755);

  const result = spawnSync('/bin/bash', [wrapper], {
    encoding: 'utf8',
    env: {
      ...process.env,
      GUARD_DOG_SKIP_DEADMAN_CHECKS: '1',
      GUARD_DOG_NODE: fakeNode,
      GUARD_DOG_OVERSEER_STATUS: statusPath,
      GUARDOG_HOME: guardogHome,
      GUARDOG_WORKSPACE: temp,
      FAKE_SCANNER_EXIT: String(scannerExitCode),
      FAKE_RECEIPT_JSON: JSON.stringify({
        status: scannerExitCode === 1 ? 'dangerous' : 'incomplete',
        exitCode: scannerExitCode,
        dangerousCount: scannerExitCode === 1 ? 3 : 0,
        suspiciousCount: 1,
        dependencyCount: 20,
        projectsScanned: 2,
        ...receipt,
      }),
    },
  });

  return { result, status: JSON.parse(readFileSync(statusPath, 'utf8')) };
}

test('danger verdict is healthy for scheduling while preserving scanner exit 1', (t) => {
  const { result, status } = runWrapper(t, 1);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.equal(status.status, 'ok');
  assert.equal(status.exit_code, 1);
  assert.match(status.reason, /dangerous dependency findings/);
});

test('operational scanner failure remains failed for launchd and Overseer', (t) => {
  const { result, status } = runWrapper(t, 2);
  assert.equal(result.status, 2, result.stderr || result.stdout);
  assert.equal(status.status, 'error');
  assert.equal(status.exit_code, 2);
});

test('exit 1 without a fresh matching danger receipt remains failed', (t) => {
  const { result, status } = runWrapper(t, 1, { status: 'incomplete', exitCode: 2, dangerousCount: 0 });
  assert.equal(result.status, 1, result.stderr || result.stdout);
  assert.equal(status.status, 'error');
  assert.match(status.reason, /without a matching dangerous receipt/);
});
