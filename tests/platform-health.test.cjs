const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

test('schedule installation uses injected scheduler, persists a selected root and verifies registration', async () => {
  const { installNightlySchedule } = await import('../src/setup.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-schedule-'));
  const previous = process.env.GUARDOG_HOME;
  process.env.GUARDOG_HOME = path.join(root, 'state');
  let cron = '';
  const calls = [];
  const run = (command, args, options) => {
    calls.push([command, args, options]);
    if (args[0] === '-l') return { status: 0, stdout: cron };
    cron = options.input;
    return { status: 0, stdout: '' };
  };
  try {
    // Existing code ignores dependency injection. Use a nonexistent host command to prevent mutation.
    const oldPath = process.env.PATH;
    process.env.PATH = root;
    let result;
    try { result = installNightlySchedule({ scanRoots: [root], nightlyTime: '03:15' }, { run, node: '/a space/node', platform: 'linux' }); }
    finally { process.env.PATH = oldPath; }
    assert.equal(result.ok, true, result.message);
    assert.match(cron, /15 3 \* \* \* '\/a space\/node'/);
    assert.equal(calls.filter(([, args]) => args[0] === '-').length, 1);
  } finally {
    if (previous === undefined) delete process.env.GUARDOG_HOME; else process.env.GUARDOG_HOME = previous;
  }
});

test('an empty nightly scan is incomplete and leaves an honest receipt', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-nightly-'));
  const home = path.join(root, 'state');
  const result = spawnSync(process.execPath, [path.resolve(__dirname, '../bin/nightly-scan.js')], {
    encoding: 'utf8', env: { ...process.env, GUARDOG_HOME: home, GUARDOG_WORKSPACE: root },
  });
  assert.equal(result.status, 2, result.stdout + result.stderr);
  const receipt = JSON.parse(fs.readFileSync(path.join(home, 'data', 'last-nightly.json')));
  assert.equal(receipt.status, 'incomplete');
  assert.equal(receipt.dependencyCount, 0);
});

test('Windows task XML keeps paths with spaces and ampersands outside shell parsing', async () => {
  const { scheduleSpec } = await import('../src/scheduler.js');
  const spec = scheduleSpec({ nightlyTime: '21:35' }, { platform: 'win32', node: 'C:\\Program Files\\nodejs\\node.exe', home: 'C:\\Users\\Alex & Co\\.guardog' });
  assert.match(spec.xml, /<Command>C:\\Program Files\\nodejs\\node.exe<\/Command>/);
  assert.match(spec.xml, /Alex &amp; Co/);
  assert.match(spec.xml, /T21:35:00/);
  assert.match(spec.xml, /<StartWhenAvailable>true<\/StartWhenAvailable>/);
});

test('health repair never opts users in and never overwrites unknown scheduler state', async () => {
  const { checkHealth } = await import('../src/health.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-health-'));
  const previous = process.env.GUARDOG_HOME;
  process.env.GUARDOG_HOME = root;
  fs.writeFileSync(path.join(root, 'config.json'), JSON.stringify({ nightlyUpdates: false, scanRoots: [root] }));
  let writes = 0;
  const run = (command, args) => { if (args[0] !== '-l') writes++; return { status: 0, stdout: '' }; };
  try {
    let health = checkHealth({ repair: true, run, platform: 'linux' });
    assert.equal(writes, 0);
    assert.equal(health.schedule.state, 'missing');
    fs.writeFileSync(path.join(root, 'config.json'), JSON.stringify({ nightlyUpdates: true, scanRoots: [root] }));
    health = checkHealth({ repair: true, platform: 'linux', run: () => ({ status: 1, stderr: 'access denied' }) });
    assert.equal(health.schedule.state, 'unknown');
    assert.match(health.issues.join(' '), /unknown/);
  } finally { if (previous === undefined) delete process.env.GUARDOG_HOME; else process.env.GUARDOG_HOME = previous; }
});

test('health restores only a previously enabled missing schedule and preserves other cron jobs', async () => {
  const { checkHealth } = await import('../src/health.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-repair-'));
  const previous = process.env.GUARDOG_HOME;
  process.env.GUARDOG_HOME = path.join(root, 'state');
  fs.mkdirSync(process.env.GUARDOG_HOME);
  fs.writeFileSync(path.join(process.env.GUARDOG_HOME, 'config.json'), JSON.stringify({ nightlyUpdates: true, scanRoots: [root] }));
  let cron = '10 8 * * * existing-backup\n';
  let writes = 0;
  const run = (_, args, options) => {
    if (args[0] === '-l') return { status: 0, stdout: cron };
    writes++; cron = options.input; return { status: 0, stdout: '' };
  };
  try {
    const health = checkHealth({ repair: true, platform: 'darwin', run });
    assert.equal(writes, 1);
    assert.equal(health.schedule.registered, true);
    assert.match(cron, /existing-backup/);
    assert.match(health.repairs.join(' '), /previously enabled/);
    checkHealth({ repair: true, platform: 'darwin', run });
    assert.equal(writes, 1, 'second check must not register again');
  } finally { if (previous === undefined) delete process.env.GUARDOG_HOME; else process.env.GUARDOG_HOME = previous; }
});

test('Windows registration sends XML to schtasks without a shell and checks readback', async () => {
  const { installNightlySchedule } = await import('../src/setup.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-windows-'));
  const previous = process.env.GUARDOG_HOME;
  process.env.GUARDOG_HOME = path.join(root, 'state');
  let registered = '';
  const run = (command, args, options) => {
    assert.ok(command.endsWith('\\System32\\schtasks.exe'));
    assert.equal(options.shell, false);
    assert.ok(!options.env.VIRUSTOTAL_API_KEY);
    assert.ok(!options.env.GITHUB_API_TOKEN);
    if (args[0] === '/Create') {
      registered = fs.readFileSync(args[args.indexOf('/XML') + 1], 'utf16le');
      return { status: 0, stdout: '' };
    }
    if (args.includes('/TN')) return registered ? { status: 0, stdout: registered } : { status: 1, stderr: 'not found' };
    return { status: 0, stdout: '' };
  };
  try {
    const result = installNightlySchedule({ scanRoots: [root] }, { run, platform: 'win32', node: 'C:\\Program Files\\nodejs\\node.exe' });
    assert.equal(result.ok, true, result.message);
    assert.match(registered, /<Command>C:\\Program Files\\nodejs\\node.exe<\/Command>/);
    assert.doesNotMatch(registered, /Context="Author"/);
  } finally { if (previous === undefined) delete process.env.GUARDOG_HOME; else process.env.GUARDOG_HOME = previous; }
});

test('nightly distinguishes known danger from interrupted or degraded coverage', async () => {
  const { runNightly } = await import('../bin/nightly-scan.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-result-'));
  const previous = process.env.GUARDOG_HOME;
  process.env.GUARDOG_HOME = path.join(root, 'state');
  fs.writeFileSync(path.join(root, 'package.json'), '{}');
  try {
    fs.mkdirSync(process.env.GUARDOG_HOME);
    fs.writeFileSync(path.join(process.env.GUARDOG_HOME, 'config.json'), JSON.stringify({ nightlyUpdates: false, scanRoots: [root] }));
    const healthOptions = { platform: 'linux', run: () => ({ status: 0, stdout: '' }) };
    let receipt = runNightly({ roots: [root], healthOptions, run: () => ({ status: 1, stdout: JSON.stringify({ status: 'dangerous', dependencyCount: 1, dangerousCount: 1, issues: [] }) }) });
    assert.equal(receipt.status, 'dangerous');
    assert.equal(receipt.exitCode, 1);
    receipt = runNightly({ roots: [root], healthOptions, run: () => ({ status: 2, stdout: JSON.stringify({ status: 'suspicious', dependencyCount: 1, dangerousCount: 0, suspiciousCount: 1, issues: [] }) }) });
    assert.equal(receipt.status, 'suspicious');
    assert.equal(receipt.suspiciousCount, 1);
    assert.equal(receipt.exitCode, 2);
    receipt = runNightly({ roots: [root], healthOptions, run: () => ({ status: 2, stdout: JSON.stringify({ status: 'incomplete', dependencyCount: 1, dangerousCount: 1, issues: ['OSV unavailable'] }) }) });
    assert.equal(receipt.status, 'incomplete');
    assert.equal(receipt.dangerousCount, 1);
    assert.equal(receipt.exitCode, 2);
  } finally { if (previous === undefined) delete process.env.GUARDOG_HOME; else process.env.GUARDOG_HOME = previous; }
});

test('nightly rejects contradictory subprocess exit status and summary', async () => {
  const { runNightly } = await import('../bin/nightly-scan.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-contradiction-'));
  const previous = process.env.GUARDOG_HOME;
  process.env.GUARDOG_HOME = path.join(root, 'state');
  fs.writeFileSync(path.join(root, 'package.json'), '{}');
  try {
    const receipt = runNightly({ roots: [root], run: () => ({ status: 1, stdout: JSON.stringify({ status: 'complete', dependencyCount: 1, dangerousCount: 0, issues: [] }) }) });
    assert.equal(receipt.status, 'incomplete');
  } finally { if (previous === undefined) delete process.env.GUARDOG_HOME; else process.env.GUARDOG_HOME = previous; }
});

test('health repairs a missing owned runner but preserves unknown bytes', async () => {
  const { checkHealth } = await import('../src/health.js');
  const { scheduleSpec } = await import('../src/scheduler.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-runner-'));
  const previous = process.env.GUARDOG_HOME;
  process.env.GUARDOG_HOME = path.join(root, 'state');
  fs.mkdirSync(process.env.GUARDOG_HOME);
  const config = { nightlyUpdates: true, scanRoots: [root] };
  fs.writeFileSync(path.join(process.env.GUARDOG_HOME, 'config.json'), JSON.stringify(config));
  const spec = scheduleSpec(config, { platform: 'linux' });
  const run = (_, args) => { assert.equal(args[0], '-l'); return { status: 0, stdout: spec.line + '\n' }; };
  try {
    let health = checkHealth({ repair: true, platform: 'linux', run });
    assert.equal(health.runner.ok, true);
    assert.match(health.repairs.join(' '), /owned nightly runner/);
    fs.writeFileSync(spec.runner, 'unknown user file');
    health = checkHealth({ repair: true, platform: 'linux', run });
    assert.equal(health.runner.state, 'conflict');
    assert.equal(fs.readFileSync(spec.runner, 'utf8'), 'unknown user file');
  } finally { if (previous === undefined) delete process.env.GUARDOG_HOME; else process.env.GUARDOG_HOME = previous; }
});

test('health repairs the owned runner without replacing a customized marked cron entry', async () => {
  const { checkHealth } = await import('../src/health.js');
  const { scheduleSpec } = await import('../src/scheduler.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-custom-cron-'));
  const previous = process.env.GUARDOG_HOME;
  process.env.GUARDOG_HOME = path.join(root, 'state');
  fs.mkdirSync(process.env.GUARDOG_HOME);
  const config = { nightlyUpdates: true, scanRoots: [root] };
  fs.writeFileSync(path.join(process.env.GUARDOG_HOME, 'config.json'), JSON.stringify(config));
  const customized = `30 2 * * * /custom/guard-dog-wrapper # guardog-nightly\n`;
  let cron = customized;
  let writes = 0;
  const run = (_, args, options) => {
    if (args[0] === '-l') return { status: 0, stdout: cron };
    writes++;
    cron = options.input;
    return { status: 0, stdout: '' };
  };
  try {
    const health = checkHealth({ repair: true, platform: 'linux', run, checkLastRun: false });
    const spec = scheduleSpec(config, { platform: 'linux' });
    assert.equal(writes, 0, 'repair must preserve a customized marked cron entry');
    assert.equal(cron, customized);
    assert.equal(fs.existsSync(spec.runner), true, 'owned runner should be repaired independently');
    assert.equal(health.runner.ok, true);
    assert.equal(health.schedule.state, 'stale');
  } finally { if (previous === undefined) delete process.env.GUARDOG_HOME; else process.env.GUARDOG_HOME = previous; }
});

test('enabling nightly scans refuses to overwrite a customized marked cron entry', async () => {
  const { installNightlySchedule } = await import('../src/setup.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-preserve-cron-'));
  const previous = process.env.GUARDOG_HOME;
  process.env.GUARDOG_HOME = path.join(root, 'state');
  let cron = `30 2 * * * /custom/guard-dog-wrapper # guardog-nightly\n`;
  let writes = 0;
  const run = (_, args, options) => {
    if (args[0] === '-l') return { status: 0, stdout: cron };
    writes++;
    cron = options.input;
    return { status: 0, stdout: '' };
  };
  try {
    const result = installNightlySchedule({ nightlyUpdates: true, scanRoots: [root] }, { platform: 'linux', run });
    assert.equal(result.ok, false);
    assert.match(result.message, /customized|stale|differs/i);
    assert.equal(writes, 0);
  } finally { if (previous === undefined) delete process.env.GUARDOG_HOME; else process.env.GUARDOG_HOME = previous; }
});

test('disabling nightly scans preserves a customized marked cron entry', async () => {
  const { unregisterSchedule } = await import('../src/scheduler.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-preserve-disable-'));
  const customized = `30 2 * * * /custom/guard-dog-wrapper # guardog-nightly\n`;
  let cron = customized;
  let writes = 0;
  const run = (_, args, options) => {
    if (args[0] === '-l') return { status: 0, stdout: cron };
    writes++;
    cron = options.input;
    return { status: 0, stdout: '' };
  };
  const result = unregisterSchedule({}, { platform: 'linux', home: root, run });
  assert.equal(result.ok, false);
  assert.match(result.message, /customized|stale|differs/i);
  assert.equal(writes, 0);
  assert.equal(cron, customized);
});

test('legacy guarddog marker is recognized and custom schedule is preserved', async () => {
  const { inspectSchedule } = await import('../src/scheduler.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-legacy-cron-'));
  const cron = `30 2 * * * /custom/guard-dog-wrapper # guarddog-nightly\n`;
  let writes = 0;
  const run = (_, args) => {
    if (args[0] === '-l') return { status: 0, stdout: cron };
    writes++;
    return { status: 0, stdout: '' };
  };
  const result = inspectSchedule({}, { platform: 'linux', home: root, run });
  assert.equal(result.state, 'stale');
  assert.equal(result.registered, false);
  assert.equal(writes, 0);
});

test('nightly refuses overlap and enforces a finite run budget', async () => {
  const { runNightly } = await import('../bin/nightly-scan.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-lock-'));
  const previous = process.env.GUARDOG_HOME;
  process.env.GUARDOG_HOME = path.join(root, 'state');
  fs.mkdirSync(path.join(process.env.GUARDOG_HOME, 'data'), { recursive: true });
  fs.writeFileSync(path.join(root, 'package.json'), '{}');
  const lock = path.join(process.env.GUARDOG_HOME, 'data', 'nightly.lock');
  fs.writeFileSync(lock, JSON.stringify({ pid: process.pid }));
  try {
    let calls = 0;
    const run = () => { calls++; throw new Error('must not run'); };
    let receipt = runNightly({ roots: [root], run });
    assert.equal(receipt.exitCode, 2);
    assert.match(receipt.issues.join(' '), /overlapping/);
    assert.equal(calls, 0);
    fs.unlinkSync(lock);
    receipt = runNightly({ roots: [root], run, timeoutMs: 0 });
    assert.equal(receipt.exitCode, 2);
    assert.match(receipt.issues.join(' '), /time budget/);
    assert.equal(calls, 0);
    assert.equal(fs.existsSync(lock), false);
  } finally { if (previous === undefined) delete process.env.GUARDOG_HOME; else process.env.GUARDOG_HOME = previous; }
});
