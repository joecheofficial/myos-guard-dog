const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const NOW = Date.parse('2026-10-12T12:00:00Z');
const VERSION = 'ClamAV 1.4.3/27812/Mon Oct 12 08:00:00 2026\n';
async function fixture(fn) {
  const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-engine-')));
  const root = path.join(base, 'project'); fs.mkdirSync(root);
  fs.writeFileSync(path.join(root, 'sample.js'), 'fixture only');
  try { const { scanWithClamAV } = await import('../src/workspace-engines.js'); await fn({ root, base, scanWithClamAV }); }
  finally { fs.rmSync(base, { recursive: true, force: true }); }
}
function runner(scan = { status: 0, stdout: '', stderr: '' }, version = VERSION) {
  return (_, args) => args[0] === '--version' ? { status: 0, stdout: version, stderr: '' } : scan;
}
function opts(root, run) { return { root, executable: process.execPath, now: NOW, run }; }

test('fresh offline engine yields complete result and fixed scrubbed invocations', () => fixture(async ({ root, scanWithClamAV }) => {
  const calls = [];
  const result = scanWithClamAV(opts(root, (exe, args, options) => {
    calls.push({ exe, args, options }); return runner()(exe, args);
  }));
  assert.equal(result.status, 'complete'); assert.deepEqual(result.findings, []);
  assert.equal(result.id, 'clamav'); assert.equal(result.version, '1.4.3');
  assert.equal(result.databaseUpdatedAt, '2026-10-12T08:00:00.000Z');
  assert.equal(calls.length, 2);
  const scan = calls[1]; assert.equal(scan.options.shell, false);
  assert.equal(scan.options.timeout, 120000); assert.equal(scan.options.maxBuffer, 2097152);
  assert.deepEqual(Object.keys(scan.options.env).sort(), ['LANG', 'LC_ALL', 'PATH', 'TZ']);
  assert.ok(!scan.options.env.PATH.includes(root));
  for (const arg of ['--recursive', '--infected', '--no-summary', '--follow-dir-symlinks=0', '--follow-file-symlinks=0', '--alert-exceeds-max=yes']) assert.ok(scan.args.includes(arg), arg);
  assert.ok(scan.args.some(arg => arg.startsWith('--max-filesize=')));
  assert.ok(scan.args.some(arg => arg.startsWith('--exclude-dir=')));
  const exclude = new RegExp(scan.args.find(arg => arg.startsWith('--exclude-dir=')).slice('--exclude-dir='.length));
  assert.ok(exclude.test('/code/.git/objects')); assert.ok(exclude.test('C:\\code\\.git\\objects'));
  assert.ok(!exclude.test('/code/.github/workflows'));
  assert.deepEqual(scan.args.slice(-2), ['--', fs.realpathSync(root)]);
}));

test('findings have safe paths and generic messages with no raw signature or stderr leakage', () => fixture(async ({ root, scanWithClamAV }) => {
  const secret = 'PRIVATE_SECRET_FROM_ENGINE';
  const result = scanWithClamAV(opts(root, runner({ status: 1, stdout: path.join(root, 'sample.js') + ': ' + secret + ' FOUND\n', stderr: '' })));
  assert.equal(result.status, 'complete'); assert.equal(result.findings.length, 1);
  assert.deepEqual(result.findings[0], { ruleId: 'GD-CLAMAV', path: 'sample.js', severity: 'high', confidence: 'high', category: 'malware', message: 'ClamAV detected a malware signature in this file.' });
  assert.ok(!JSON.stringify(result).includes(secret));
}));

test('missing, relative, in-target, POSIX non-executable and symlinked-to-target engines never run', () => fixture(async ({ root, base, scanWithClamAV }) => {
  const targetExe = path.join(root, 'engine'); fs.writeFileSync(targetExe, 'untrusted'); fs.chmodSync(targetExe, 0o700);
  const plain = path.join(base, 'plain'); fs.writeFileSync(plain, 'plain'); fs.chmodSync(plain, 0o600);
  const link = path.join(base, 'link'); fs.symlinkSync(targetExe, link);
  // Node X_OK is equivalent to F_OK on Windows; chmod cannot model execution denial there.
  const invalid = [undefined, 'clamscan', path.join(base, 'missing'), targetExe, link];
  if (process.platform !== 'win32') invalid.push(plain);
  for (const executable of invalid) {
    let ran = false;
    const result = scanWithClamAV({ root, executable, now: NOW, run() { ran = true; throw new Error('must not execute'); } });
    assert.equal(result.status, 'incomplete'); assert.equal(ran, false);
  }
}));

test('bad version and stale or future databases remain incomplete but preserve actual findings', () => fixture(async ({ root, scanWithClamAV }) => {
  for (const version of ['nonsense PRIVATE_SECRET', 'ClamAV 1.4.3/1/Mon Sep 01 08:00:00 2026', 'ClamAV 1.4.3/1/Mon Oct 19 08:00:00 2026']) {
    const result = scanWithClamAV(opts(root, runner({ status: 1, stdout: path.join(root, 'sample.js') + ': Example FOUND\n', stderr: '' }, version)));
    assert.equal(result.status, 'incomplete'); assert.equal(result.findings.length, 1);
    assert.ok(!JSON.stringify(result).includes('PRIVATE_SECRET'));
  }
}));

test('errors, timeout, overflow, malformed output and inconsistent exits never report complete', () => fixture(async ({ root, scanWithClamAV }) => {
  const found = path.join(root, 'sample.js') + ': Example FOUND\n';
  for (const scan of [
    { status: 0, stdout: found }, { status: 1, stdout: '' }, { status: 2, stdout: found },
    { status: null, signal: 'SIGKILL', stdout: found, error: { code: 'ETIMEDOUT' } },
    { status: null, stdout: found, error: { code: 'ENOBUFS' } },
    { status: 0, stdout: 'PRIVATE_SECRET unexpected output' },
    { status: 0, stdout: '', stderr: 'PRIVATE_SECRET warning' },
  ]) {
    const result = scanWithClamAV(opts(root, runner(scan)));
    assert.equal(result.status, 'incomplete'); assert.ok(!JSON.stringify(result).includes('PRIVATE_SECRET'));
    if (scan.stdout === found) assert.equal(result.findings.length, 1);
  }
}));

test('out-of-root and symlink paths cannot become findings', () => fixture(async ({ root, base, scanWithClamAV }) => {
  const external = path.join(base, 'external.js'); fs.writeFileSync(external, 'private');
  fs.symlinkSync(external, path.join(root, 'link.js'));
  for (const file of [external, path.join(root, '..', 'external.js'), path.join(root, 'link.js'), path.join(root, 'missing.js')]) {
    const result = scanWithClamAV(opts(root, runner({ status: 1, stdout: file + ': Example FOUND\n' })));
    assert.equal(result.status, 'incomplete'); assert.equal(result.findings.length, 0);
  }
}));

test('engine scan limits are coverage errors, not malware or clean results', () => fixture(async ({ root, scanWithClamAV }) => {
  const result = scanWithClamAV(opts(root, runner({ status: 1, stdout: path.join(root, 'sample.js') + ': Heuristics.Limits.Exceeded.MaxFileSize FOUND\n' })));
  assert.equal(result.status, 'incomplete'); assert.deepEqual(result.findings, []);
}));

test('invalid roots and invalid bounds fail without launching engine', () => fixture(async ({ root, scanWithClamAV }) => {
  for (const extra of [{ root: path.join(root, 'sample.js') }, { timeoutMs: 0 }, { maxOutputBytes: -1 }, { now: NaN }]) {
    let ran = false;
    const result = scanWithClamAV({ ...opts(root, () => { ran = true; }), ...extra });
    assert.equal(result.status, 'incomplete'); assert.equal(ran, false);
  }
}));

test('bounded stdout overflow preserves complete preceding detections', () => fixture(async ({ root, scanWithClamAV }) => {
  const first = path.join(root, 'sample.js') + ': Example FOUND\n';
  const result = scanWithClamAV({ ...opts(root, runner({ status: 1, stdout: first + 'x'.repeat(2048) })), maxOutputBytes: 512 });
  assert.equal(result.status, 'incomplete'); assert.equal(result.findings.length, 1);
}));

test('version execution failures still permit positive scan evidence, and thrown errors are redacted', () => fixture(async ({ root, scanWithClamAV }) => {
  const found = path.join(root, 'sample.js') + ': Example FOUND\n';
  const result = scanWithClamAV(opts(root, (_, args) => args[0] === '--version'
    ? { status: 2, stdout: 'PRIVATE_SECRET' } : { status: 1, stdout: found }));
  assert.equal(result.status, 'incomplete'); assert.equal(result.findings.length, 1);
  const failed = scanWithClamAV(opts(root, () => { throw new Error('PRIVATE_SECRET'); }));
  assert.equal(failed.status, 'incomplete'); assert.ok(!JSON.stringify([result, failed]).includes('PRIVATE_SECRET'));
}));

test('silent directory recursion skips are detected before a successful empty engine result', () => fixture(async ({ root, scanWithClamAV }) => {
  let nested = root;
  for (let depth = 0; depth < 31; depth++) { nested = path.join(nested, 'nested'); fs.mkdirSync(nested); }
  fs.writeFileSync(path.join(nested, 'beyond-engine-depth.js'), 'fixture');
  const result = scanWithClamAV(opts(root, runner()));
  assert.equal(result.status, 'incomplete');
  assert.equal(result.coverage.complete, false); assert.ok(result.coverage.depthLimited > 0);
  assert.ok(result.issues.some(issue => /depth/i.test(issue)));
}));

test('oversized sparse files and total inventory byte limits cannot silently pass', () => fixture(async ({ root, scanWithClamAV }) => {
  const oversized = path.join(root, 'large.bin');
  const fd = fs.openSync(oversized, 'w'); fs.ftruncateSync(fd, 26 * 1024 * 1024); fs.closeSync(fd);
  let result = scanWithClamAV(opts(root, runner()));
  assert.equal(result.status, 'incomplete'); assert.equal(result.coverage.oversizedFiles, 1);
  fs.unlinkSync(oversized);
  for (let count = 0; count < 6; count++) {
    const file = fs.openSync(path.join(root, `bulk-${count}.bin`), 'w'); fs.ftruncateSync(file, 25 * 1024 * 1024); fs.closeSync(file);
  }
  result = scanWithClamAV(opts(root, runner()));
  assert.equal(result.status, 'incomplete'); assert.ok(result.issues.some(issue => /byte/i.test(issue)));
}));

test('symlinks and empty roots are incomplete, while git exclusions are explicit scope', () => fixture(async ({ root, base, scanWithClamAV }) => {
  const outside = path.join(base, 'outside'); fs.mkdirSync(outside);
  fs.symlinkSync(outside, path.join(root, 'linked-dir'));
  let result = scanWithClamAV(opts(root, runner()));
  assert.equal(result.status, 'incomplete'); assert.equal(result.coverage.symlinksSkipped, 1);
  fs.unlinkSync(path.join(root, 'linked-dir'));
  fs.mkdirSync(path.join(root, '.git')); fs.writeFileSync(path.join(root, '.git', 'config'), 'ignored');
  result = scanWithClamAV(opts(root, runner()));
  assert.equal(result.status, 'complete'); assert.deepEqual(result.scope.excludedDirectories, ['.git']);
  assert.equal(result.coverage.excludedDirectories, 1); assert.equal(result.coverage.filesInspected, 1);
  fs.unlinkSync(path.join(root, 'sample.js'));
  result = scanWithClamAV(opts(root, runner()));
  assert.equal(result.status, 'incomplete'); assert.equal(result.coverage.filesInspected, 0);
}));

test('preflight gaps preserve verified signature detections', () => fixture(async ({ root, base, scanWithClamAV }) => {
  fs.symlinkSync(base, path.join(root, 'link'));
  const result = scanWithClamAV(opts(root, runner({ status: 1, stdout: path.join(root, 'sample.js') + ': Example FOUND\n' })));
  assert.equal(result.status, 'incomplete'); assert.equal(result.findings.length, 1);
}));

test('special files are counted without opening their contents', { skip: process.platform === 'win32' }, () => fixture(async ({ root, scanWithClamAV }) => {
  const net = require('node:net');
  const server = net.createServer();
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(path.join(root, 'ipc.sock'), resolve); });
  try {
    const result = scanWithClamAV(opts(root, runner()));
    assert.equal(result.status, 'incomplete'); assert.equal(result.coverage.specialFilesSkipped, 1);
  } finally { await new Promise(resolve => server.close(resolve)); }
}));

// Exercises actual spawn failure, including Windows where chmod has no execute-bit semantics.
test('an actual non-program engine fails closed on every platform', () => fixture(async ({ root, base, scanWithClamAV }) => {
  const executable = path.join(base, 'not-a-program.txt');
  fs.writeFileSync(executable, 'This is inert fixture data, not an executable.');
  const result = scanWithClamAV({ root, executable, now: NOW, timeoutMs: 1000 });
  assert.equal(result.status, 'incomplete');
  assert.deepEqual(result.findings, []);
  assert.ok(result.issues.length > 0);
}));
