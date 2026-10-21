const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

test('the nightly API repairs a missing opted-in schedule and records the repair', async () => {
  const { runNightly } = await import('../bin/nightly-scan.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-preflight-'));
  const previous = process.env.GUARDOG_HOME;
  process.env.GUARDOG_HOME = path.join(root, 'state');
  fs.mkdirSync(process.env.GUARDOG_HOME);
  fs.writeFileSync(path.join(process.env.GUARDOG_HOME, 'config.json'), JSON.stringify({ nightlyUpdates: true, scanRoots: [root] }));
  fs.writeFileSync(path.join(root, 'package.json'), '{}');
  let cron = '10 8 * * * existing-backup\n';
  let writes = 0;
  const scheduler = (_, args, options) => {
    if (args[0] === '-l') return { status: 0, stdout: cron };
    cron = options.input; writes++; return { status: 0, stdout: '' };
  };
  const scanner = () => ({ status: 0, stdout: JSON.stringify({ status: 'complete', dependencyCount: 2, dangerousCount: 0, issues: [] }) });
  try {
    const receipt = runNightly({ advisoryFirst: false, roots: [root], run: scanner, healthOptions: { platform: 'linux', run: scheduler } });
    assert.equal(writes, 1, 'daily API must restore the opted-in missing job');
    assert.equal(receipt.status, 'complete');
    assert.equal(receipt.preflight.schedule.registered, true);
    assert.match(receipt.preflight.repairs.join(' '), /previously enabled/);
    assert.match(cron, /existing-backup/);
    const saved = JSON.parse(fs.readFileSync(path.join(process.env.GUARDOG_HOME, 'data', 'last-nightly.json')));
    assert.deepEqual(saved.preflight, receipt.preflight);
    assert.equal(receipt.resilience.lastPhase, 'nightly');
    assert.equal(receipt.resilience.healthyStreak, 1);
    assert.equal(JSON.parse(fs.readFileSync(path.join(process.env.GUARDOG_HOME, 'data', 'resilience-state.json'))).cycles, 1);
    const second = runNightly({ advisoryFirst: false, roots: [root], run: scanner, healthOptions: { platform: 'linux', run: scheduler } });
    assert.equal(second.status, 'complete');
    assert.equal(writes, 1, 'daily repair must be idempotent');
  } finally { if (previous === undefined) delete process.env.GUARDOG_HOME; else process.env.GUARDOG_HOME = previous; }
});

test('unresolved schedule health survives a clean scan; a later healthy scan recovers', async () => {
  const { runNightly } = await import('../bin/nightly-scan.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-recovery-'));
  const previous = process.env.GUARDOG_HOME;
  process.env.GUARDOG_HOME = path.join(root, 'state');
  fs.mkdirSync(process.env.GUARDOG_HOME);
  fs.writeFileSync(path.join(process.env.GUARDOG_HOME, 'config.json'), JSON.stringify({ nightlyUpdates: true, scanRoots: [root] }));
  fs.writeFileSync(path.join(root, 'package.json'), '{}');
  const scanner = () => ({ status: 0, stdout: JSON.stringify({ status: 'complete', dependencyCount: 2, dangerousCount: 0, issues: [] }) });
  let cron = '';
  const scheduler = (_, args, options) => {
    if (args[0] === '-l') return { status: 0, stdout: cron };
    cron = options.input; return { status: 0, stdout: '' };
  };
  try {
    let receipt = runNightly({ advisoryFirst: false, roots: [root], run: scanner, healthOptions: { platform: 'linux', run: () => ({ status: 1, stderr: 'permission denied' }) } });
    assert.equal(receipt.status, 'incomplete');
    assert.equal(receipt.preflight.ok, false);
    assert.match(receipt.issues.join(' '), /permission denied/);
    receipt = runNightly({ advisoryFirst: false, roots: [root], run: scanner, healthOptions: { platform: 'linux', run: scheduler } });
    assert.equal(receipt.status, 'complete', 'the failed preceding receipt must not poison recovery');
    assert.equal(receipt.preflight.ok, true);
    assert.equal('lastRun' in receipt.preflight, false);
  } finally { if (previous === undefined) delete process.env.GUARDOG_HOME; else process.env.GUARDOG_HOME = previous; }
});

test('health rejects a previous scan of different roots, empty coverage and future receipts', async () => {
  const { checkHealth } = await import('../src/health.js');
  const { scheduleSpec, runnerSource } = await import('../src/scheduler.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-proof-'));
  const previous = process.env.GUARDOG_HOME;
  process.env.GUARDOG_HOME = path.join(root, 'state');
  fs.mkdirSync(path.join(process.env.GUARDOG_HOME, 'data'), { recursive: true });
  fs.mkdirSync(path.join(process.env.GUARDOG_HOME, 'bin'));
  const config = { nightlyUpdates: true, scanRoots: [root] };
  fs.writeFileSync(path.join(process.env.GUARDOG_HOME, 'config.json'), JSON.stringify(config));
  const spec = scheduleSpec(config, { platform: 'linux' });
  fs.writeFileSync(spec.runner, runnerSource(spec));
  const opts = { platform: 'linux', run: () => ({ status: 0, stdout: spec.line + '\n' }) };
  const baseline = { status: 'complete', roots: [root], dependencyCount: 2, finishedAt: new Date().toISOString() };
  const receiptPath = path.join(process.env.GUARDOG_HOME, 'data', 'last-nightly.json');
  try {
    for (const patch of [{ roots: [path.join(root, 'another')] }, { dependencyCount: 0 }, { finishedAt: new Date(Date.now() + 3600000).toISOString() }]) {
      fs.writeFileSync(receiptPath, JSON.stringify({ ...baseline, ...patch }));
      assert.equal(checkHealth(opts).ok, false, JSON.stringify(patch));
    }
    fs.writeFileSync(receiptPath, JSON.stringify(baseline));
    assert.equal(checkHealth(opts).ok, true);
  } finally { if (previous === undefined) delete process.env.GUARDOG_HOME; else process.env.GUARDOG_HOME = previous; }
});

test('large projects receive the remaining overall deadline instead of a five-minute cap', async () => {
  const { runNightly } = await import('../bin/nightly-scan.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-budget-'));
  const previous = process.env.GUARDOG_HOME;
  process.env.GUARDOG_HOME = path.join(root, 'state');
  fs.mkdirSync(process.env.GUARDOG_HOME);
  fs.writeFileSync(path.join(process.env.GUARDOG_HOME, 'config.json'), JSON.stringify({ nightlyUpdates: false, scanRoots: [root] }));
  fs.writeFileSync(path.join(root, 'package.json'), '{}');
  try {
    let timeout;
    const receipt = runNightly({ advisoryFirst: false, roots: [root], timeoutMs: 3600000, healthOptions: { platform: 'linux', run: () => ({ status: 0, stdout: '' }) }, run: (_, args, options) => {
      timeout = options.timeout;
      return { status: 0, stdout: JSON.stringify({ status: 'complete', dependencyCount: 100, dangerousCount: 0, issues: [] }) };
    } });
    assert.equal(receipt.status, 'complete');
    assert.ok(timeout > 300000 && timeout <= 3600000);
  } finally { if (previous === undefined) delete process.env.GUARDOG_HOME; else process.env.GUARDOG_HOME = previous; }
});

test('nightly scan stops after a child reports VirusTotal quota exhaustion', async () => {
  const { runNightly } = await import('../bin/nightly-scan.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-quota-stop-'));
  const previous = process.env.GUARDOG_HOME;
  process.env.GUARDOG_HOME = path.join(root, 'state');
  fs.mkdirSync(process.env.GUARDOG_HOME);
  fs.writeFileSync(path.join(process.env.GUARDOG_HOME, 'config.json'), JSON.stringify({ nightlyUpdates: false, scanRoots: [root] }));
  fs.writeFileSync(path.join(root, 'package.json'), '{}');
  fs.mkdirSync(path.join(root, 'nested'));
  fs.writeFileSync(path.join(root, 'nested', 'package.json'), '{}');
  let calls = 0;
  try {
    const receipt = runNightly({ advisoryFirst: false, roots: [root], healthOptions: { platform: 'linux', run: () => ({ status: 0, stdout: '' }) }, run: () => {
      calls++;
      return { status: 2, stdout: JSON.stringify({ status: 'incomplete', dependencyCount: 1, dangerousCount: 0, quotaExhausted: true, issues: ['VirusTotal daily quota exhausted.'] }) };
    } });
    assert.equal(calls, 1, 'no further project scans should run after daily quota exhaustion');
    assert.equal(receipt.projectsScanned, 1);
    assert.match(receipt.issues.join(' '), /quota exhausted/i);
  } finally { if (previous === undefined) delete process.env.GUARDOG_HOME; else process.env.GUARDOG_HOME = previous; }
});

test('Windows health rejects weekly timing and extra action arguments', async () => {
  const { inspectSchedule, scheduleSpec } = await import('../src/scheduler.js');
  const config = { nightlyTime: '03:30' };
  const options = { platform: 'win32' };
  const spec = scheduleSpec(config, options);
  const formatted = spec.xml.replaceAll('><', '>\r\n    <').replaceAll('&quot;', '"');
  assert.equal(inspectSchedule(config, { ...options, run: () => ({ status: 0, stdout: formatted }) }).registered, true, 'Windows formatted XML with a default namespace must be accepted');
  const weekly = spec.xml.replace('<ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>', '<ScheduleByWeek><WeeksInterval>1</WeeksInterval><DaysOfWeek><Sunday /></DaysOfWeek></ScheduleByWeek>');
  const extraArg = spec.xml.replace('</Arguments>', ' --other</Arguments>');
  for (const xml of [weekly, extraArg]) {
    const health = inspectSchedule(config, { ...options, run: () => ({ status: 0, stdout: xml }) });
    assert.equal(health.registered, false);
  }
});
