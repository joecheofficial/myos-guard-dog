const test = require('node:test'), assert = require('node:assert/strict'), fs = require('node:fs'), os = require('node:os'), path = require('node:path');

// Real nodejs.org/dist/index.json rows around the 2026-10-21 security releases.
const INDEX = [
  { version: 'v26.12.1', date: '2026-10-21', lts: false, security: true },
  { version: 'v26.12.0', date: '2026-10-14', lts: false, security: false },
  { version: 'v26.11.1', date: '2026-10-07', lts: false, security: false },
  { version: 'v24.22.1', date: '2026-10-20', lts: 'Krypton', security: true },
  { version: 'v24.22.0', date: '2026-10-14', lts: 'Krypton', security: false },
  { version: 'v24.21.0', date: '2026-09-07', lts: 'Krypton', security: false },
  { version: 'v22.23.4', date: '2026-10-20', lts: 'Jod', security: true },
  { version: 'v22.23.3', date: '2026-09-23', lts: 'Jod', security: false },
  { version: 'v22.23.2', date: '2026-07-28', lts: 'Jod', security: true },
  { version: 'v20.20.2', date: '2026-03-24', lts: 'Iron', security: true }
];
const SCHEDULE_RAW = {
  v20: { start: '2023-04-18', lts: '2023-10-24', maintenance: '2024-10-22', end: '2026-04-30', codename: 'Iron' },
  v22: { start: '2024-04-24', lts: '2024-10-29', maintenance: '2025-10-21', end: '2027-04-30', codename: 'Jod' },
  v24: { start: '2025-05-06', lts: '2025-10-28', maintenance: '2026-10-20', end: '2028-04-30', codename: 'Krypton' },
  v26: { start: '2026-05-05', lts: '2026-10-28', maintenance: '2027-10-20', end: '2029-04-30', codename: '' }
};
const VULN_RAW = {
  '195': { cve: ['CVE-2026-111497'], vulnerable: '22.x || 24.x || 26.x', patched: '^22.23.4 || ^24.22.1 || ^26.12.1', severity: 'high' },
  '196': { cve: ['CVE-2026-105483', 'CVE-2026-106069'], vulnerable: '22.x || 24.x || 26.x', patched: '^22.23.4 || ^24.22.1 || ^26.12.1', severity: 'high' },
  'bad': { description: 'entry without ranges is ignored' }
};
const NOW = new Date('2026-10-22T12:00:00Z');
const load = () => import('../src/runtime-advisories.js');
async function data() {
  const m = await load();
  return { index: m.normalizeIndex(INDEX), schedule: m.normalizeSchedule(SCHEDULE_RAW), vulnDb: m.normalizeVulnDb(VULN_RAW), sources: { index: 'fixture' } };
}

/** files: { path: { real?, ino, dev?, version?, broken? } } */
function fakeSystem(files, { processes = [], lsof = '', psArgs = '' } = {}) {
  const calls = [];
  const byReal = p => files[p] && files[p].real ? files[p].real : p;
  const fsFake = {
    realpath: p => { if (!files[p]) throw Object.assign(Error('ENOENT'), { code: 'ENOENT' }); return byReal(p); },
    stat: p => { const f = files[byReal(p)] || files[p]; if (!f || f.deleted) throw Object.assign(Error('ENOENT'), { code: 'ENOENT' }); return { dev: f.dev || 1, ino: f.ino, isFile: () => true }; },
    readdir: () => { throw Object.assign(Error('ENOENT'), { code: 'ENOENT' }); },
    exists: p => Boolean(files[p])
  };
  const exec = (file, args) => {
    calls.push([file, ...args]);
    if (args[0] === '-v') {
      const f = files[file];
      if (!f || f.broken) return { status: null, error: Object.assign(Error('spawn EACCES'), { code: 'EACCES' }) };
      return { status: 0, stdout: f.version + '\n' };
    }
    if (file === 'ps' && args[0] === '-axo') return { status: 0, stdout: processes.map(([pid, comm]) => `${pid} ${comm}`).join('\n') };
    if (file === 'ps') return { status: 0, stdout: psArgs };
    if (file === 'lsof') return { status: 0, stdout: lsof };
    if (file === 'brew') return { status: 0, stdout: JSON.stringify({ formulae: [{ name: 'node@22', versions: { stable: '22.23.3' } }, { name: 'node', versions: { stable: '26.12.0' } }] }) };
    return { status: 1, stdout: '' };
  };
  return { fs: fsFake, exec, calls };
}
const env = dirs => ({ PATH: dirs.join(path.delimiter) });

test('2026-10-21 data: 26.12.0/24.22.0/22.23.3 vulnerable, 26.12.1/24.22.1/22.23.4 ok', async () => {
  const m = await load(), d = await data();
  for (const [v, fixed] of [['v26.12.0', 'v26.12.1'], ['v24.22.0', 'v24.22.1'], ['v22.23.3', 'v22.23.4'], ['v22.23.2', 'v22.23.4']]) {
    const a = m.assessVersion(v, { ...d, now: NOW });
    assert.equal(a.status, 'vulnerable', v);
    assert.equal(a.fixedIn, fixed);
    assert.deepEqual(a.cves.sort(), ['CVE-2026-105483', 'CVE-2026-106069', 'CVE-2026-111497']);
  }
  for (const v of ['v26.12.1', 'v24.22.1', 'v22.23.4']) {
    const a = m.assessVersion(v, { ...d, now: NOW });
    assert.equal(a.status, 'ok', v);
    assert.deepEqual(a.cves, []);
  }
});

test('core logic works from index.json alone and on 22.23.2 lists both later security releases', async () => {
  const m = await load();
  const a = m.assessVersion('v22.23.1', { index: m.normalizeIndex(INDEX), now: NOW });
  assert.equal(a.status, 'vulnerable');
  assert.deepEqual(a.securityReleases, ['v22.23.2', 'v22.23.4']);
  assert.equal(a.fixedIn, 'v22.23.4');
  assert.equal(m.assessVersion('v22.23.4', { index: m.normalizeIndex(INDEX), now: NOW }).status, 'ok');
});

test('EOL detection from the release schedule', async () => {
  const m = await load(), d = await data();
  const a = m.assessVersion('v20.20.2', { ...d, now: NOW });
  assert.equal(a.status, 'eol');
  assert.equal(a.eolDate, '2026-04-30');
  assert.match(m.recommendedAction({ ...a, version: 'v20.20.2', path: '/x/node', source: 'path' }), /end of life/);
});

test('tolerates an unexpected vuln-db shape and only requires index.json', async () => {
  const m = await load();
  const responses = { [m.INDEX_URL]: INDEX, [m.SCHEDULE_URL]: SCHEDULE_RAW, [m.VULN_DB_URL]: 'not an object' };
  const fetchImpl = async url => ({ ok: true, json: async () => responses[url] });
  const result = await m.loadAdvisoryData({ fetchImpl, cache: null, pace: (_, fn) => fn() });
  assert.equal(result.index.length, INDEX.length);
  assert.deepEqual(result.vulnDb, []);
  const failing = async url => url === m.INDEX_URL ? { ok: true, json: async () => INDEX } : { ok: false, status: 404 };
  const partial = await m.loadAdvisoryData({ fetchImpl: failing, cache: null, pace: (_, fn) => fn() });
  assert.equal(partial.schedule, null);
  assert.equal(partial.sources.vulnDb, 'unavailable');
  await assert.rejects(m.loadAdvisoryData({ fetchImpl: async () => ({ ok: false, status: 503 }), cache: null, pace: (_, fn) => fn() }), /Cannot load/);
});

test('dedupes runtimes by realpath and inode', async () => {
  const m = await load();
  const cellar = '/opt/homebrew/Cellar/node@22/22.23.3_3/bin/node';
  const sys = fakeSystem({
    '/opt/homebrew/bin/node': { real: cellar },
    '/opt/homebrew/opt/node@22/bin/node': { real: cellar },
    [cellar]: { ino: 42, version: 'v22.23.4' },
    '/usr/local/bin/node': { ino: 42, version: 'v22.23.4' } // hard link to the same inode
  });
  const report = await m.checkRuntimes({ ...sys, env: env(['/opt/homebrew/bin', '/opt/homebrew/opt/node@22/bin', '/usr/local/bin']), home: '/nohome', now: NOW, advisoryData: await data(), processes: [], vercel: false });
  assert.equal(report.runtimes.length, 1);
  assert.equal(report.runtimes[0].status, 'ok');
  assert.equal(report.runtimes[0].aliases.length, 3);
  assert.equal(sys.calls.filter(c => c[1] === '-v').length, 1);
  assert.equal(report.exitCode, 0);
});

test('a broken binary is reported unknown and does not crash the check', async () => {
  const m = await load();
  const sys = fakeSystem({ '/a/node': { ino: 1, broken: true }, '/b/node': { ino: 2, version: 'v24.22.0' } });
  const report = await m.checkRuntimes({ ...sys, env: env(['/a', '/b']), home: '/nohome', now: NOW, advisoryData: await data(), processes: [], vercel: false });
  const broken = report.runtimes.find(r => r.path === '/a/node');
  assert.equal(broken.status, 'unknown');
  assert.match(broken.reason, /EACCES/);
  const vuln = report.runtimes.find(r => r.path === '/b/node');
  assert.equal(vuln.status, 'vulnerable');
  assert.equal(vuln.fixedIn, 'v24.22.1');
  assert.equal(report.status, 'dangerous');
  assert.equal(report.exitCode, 1);
  assert.equal(report.findings.filter(f => f.severity === 'high').length, 1);
});

test('stale process: running inode differs from the file now at that path', async () => {
  const m = await load();
  const bin = '/Users/x/.local/allsorted-node/bin/node';
  const sys = fakeSystem({ [bin]: { ino: 408800643, version: 'v22.23.4' } }, {
    processes: [[3019, 'node'], [3020, bin], [3021, 'zsh']],
    lsof: ['p3019', 'ftxt', 'i67715826', 'n' + bin, 'ftxt', 'i99', 'n/usr/lib/dyld', 'p3020', 'ftxt', 'i408800643', 'n' + bin].join('\n'),
    psArgs: `3019 node server.js --token=abc123\n3020 ${bin} other.js`
  });
  const report = await m.checkRuntimes({ ...sys, env: env([]), home: '/Users/x', now: NOW, advisoryData: await data(), vercel: false });
  assert.equal(report.staleProcesses.length, 1);
  assert.equal(report.staleProcesses[0].pid, 3019);
  assert.equal(report.staleProcesses[0].runningInode, 67715826);
  assert.equal(report.staleProcesses[0].currentInode, 408800643);
  assert.doesNotMatch(report.staleProcesses[0].command, /abc123/);
  const runtime = report.runtimes.find(r => r.path === bin);
  assert.equal(runtime.source, 'allsorted');
  assert.deepEqual(runtime.pids, [3020]);
  assert.equal(report.restartNeededCount, 1);
  assert.equal(report.findings.find(f => f.kind === 'restart_needed').severity, 'medium');
  assert.equal(report.exitCode, 0);
});

test('vendor-bundled runtime in a running app is vendor-managed with no fix action', async () => {
  const m = await load();
  const bin = '/Applications/ChatGPT.app/Contents/Resources/cua_node/bin/node';
  const sys = fakeSystem({ [bin]: { ino: 385843608, version: 'v24.21.0' } }, { processes: [[3016, 'node']], lsof: `p3016\nftxt\ni385843608\nn${bin}\n` });
  const report = await m.checkRuntimes({ ...sys, env: env([]), home: '/nohome', now: NOW, advisoryData: await data(), vercel: false });
  const r = report.runtimes[0];
  assert.equal(r.status, 'vendor-managed');
  assert.equal(r.versionStatus, 'vulnerable');
  assert.match(r.action, /Vendor-managed/);
  assert.equal(report.highCount, 0);
  assert.equal(report.exitCode, 0);
  assert.doesNotMatch(m.buildFixPlan(report), /ChatGPT/);
});

test('fix plan prints exact commands and never executes anything', async () => {
  const m = await load();
  const sys = fakeSystem({
    '/opt/homebrew/Cellar/node@22/22.23.3_3/bin/node': { ino: 1, version: 'v22.23.3' },
    '/Users/x/.local/allsorted-node/bin/node': { ino: 2, version: 'v22.23.2' }
  });
  const report = await m.checkRuntimes({ ...sys, env: env(['/opt/homebrew/Cellar/node@22/22.23.3_3/bin']), home: '/Users/x', now: NOW, advisoryData: await data(), processes: [], vercel: false, platform: 'darwin', arch: 'arm64' });
  const before = sys.calls.length;
  assert.ok(sys.calls.every(c => c[1] === '-v' || c[0] === 'brew'), 'only version probes and brew info ran');
  assert.ok(sys.calls.filter(c => c[0] === 'brew').every(c => c[1] === 'info'));
  const plan = m.buildFixPlan(report, { platform: 'darwin', arch: 'arm64' });
  assert.equal(sys.calls.length, before, 'building the plan executes nothing');
  assert.match(plan, /nothing has been executed/);
  assert.match(plan, /curl -fsSLO 'https:\/\/nodejs.org\/dist\/v22.23.4\/node-v22.23.4-darwin-arm64.tar.gz'/);
  assert.match(plan, /gpgv --keyring "\$PWD\/node-release-keys.kbx" SHASUMS256.txt.sig SHASUMS256.txt/);
  assert.match(plan, /shasum -a 256 -c -/);
  assert.match(plan, /install -m 0755 'node-v22.23.4-darwin-arm64\/bin\/node' '\/Users\/x\/.local\/allsorted-node\/bin\/node'/);
  const brew = report.runtimes.find(r => r.source === 'homebrew');
  assert.match(brew.action, /has not shipped v22.23.4/); // Homebrew stable 22.23.3 < fix
  const shipped = m.recommendedAction(brew, { brewStable: { 'node@22': '22.23.4' } });
  assert.equal(shipped, 'brew update && brew upgrade node@22');
  const logs = [];
  const exit = await m.runtimeCommand(['--fix-plan'], { ...sys, env: env([]), home: '/Users/x', now: NOW, advisoryData: await data(), processes: [], vercel: false, log: line => logs.push(line) });
  assert.equal(exit, 1);
  assert.match(logs.join('\n'), /set -euo pipefail/);
});

test('vercel check flags EOL node majors, report only', async () => {
  const m = await load(), d = await data();
  const fetchImpl = async url => ({ ok: true, json: async () => url.includes('/v2/teams') ? { teams: [{ id: 't1', slug: 'team' }] }
    : url.includes('teamId=t1') ? { projects: [{ name: 'old', nodeVersion: '20.x' }] } : { projects: [{ name: 'fine', nodeVersion: '24.x' }] } });
  const v = await m.checkVercelProjects({ token: 'test', schedule: d.schedule, fetchImpl, now: NOW });
  assert.equal(v.oldestSupportedMajor, 22);
  assert.deepEqual(v.projects.map(p => [p.scope, p.name, p.flagged]), [['personal', 'fine', false], ['team', 'old', true]]);
});

test('nightly marks a vulnerable runtime as HIGH and exits non-zero; doctor reports it', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gd-runtime-nightly-')); const previous = process.env.GUARDOG_HOME;
  try {
    process.env.GUARDOG_HOME = path.join(root, 'state'); fs.mkdirSync(process.env.GUARDOG_HOME);
    fs.writeFileSync(path.join(process.env.GUARDOG_HOME, 'config.json'), JSON.stringify({ nightlyUpdates: false }));
    const scanRoot = path.join(root, 'empty'); fs.mkdirSync(scanRoot);
    const m = await load();
    const sys = fakeSystem({ '/b/node': { ino: 2, version: 'v24.22.0' } });
    const report = await m.checkRuntimes({ ...sys, env: env(['/b']), home: '/nohome', now: NOW, advisoryData: await data(), processes: [], vercel: false });
    const { runNightly } = await import('../bin/nightly-scan.js');
    const healthOptions = { platform: 'linux', run: () => ({ status: 0, stdout: '' }) };
    const receipt = runNightly({ roots: [scanRoot], healthOptions, run: () => { throw Error('no project scans expected'); }, runtimeCheck: () => report });
    assert.equal(receipt.status, 'dangerous');
    assert.equal(receipt.exitCode, 1);
    assert.equal(receipt.runtimeHighCount, 1);
    assert.ok(receipt.issues.some(i => /^HIGH runtime: \/b\/node v24.22.0 is vulnerable, fixed in v24.22.1/.test(i)));
    const { checkHealth } = await import('../src/health.js');
    const health = checkHealth(healthOptions);
    assert.ok(health.issues.some(i => /^HIGH: Node runtime \/b\/node v24.22.0/.test(i)));
    // Without an injected check (library callers, other tests), nightly stays unchanged.
    const plain = runNightly({ roots: [scanRoot], healthOptions, run: () => { throw Error('none'); } });
    assert.equal(plain.runtime, undefined);
    assert.notEqual(plain.status, 'dangerous');
  } finally { if (previous === undefined) delete process.env.GUARDOG_HOME; else process.env.GUARDOG_HOME = previous; fs.rmSync(root, { recursive: true, force: true }); }
});

test('semver ranges used by the security-wg database', async () => {
  const { satisfies } = await load();
  assert.ok(satisfies('v24.22.0', '22.x || 24.x'));
  assert.ok(!satisfies('v24.22.1', '<24.22.1'));
  assert.ok(satisfies('v24.22.1', '^22.23.4 || ^24.22.1'));
  assert.ok(!satisfies('v24.22.0', '^22.23.4 || ^24.22.1'));
  assert.ok(satisfies('20.1.0', '>=20.0.0 <20.20.2'));
});

// ---------- 5.2.1 review regressions ----------

test('P1-1: fnm under ~/Library/Application Support is a version manager, not vendor, and stays HIGH', async () => {
  const m = await load();
  const bin = '/Users/x/Library/Application Support/fnm/node-versions/v22.23.3/installation/bin/node';
  const sys = fakeSystem({ [bin]: { ino: 7, version: 'v22.23.3' } }, { processes: [[50, 'node']], lsof: `p50\nftxt\ni7\nn${bin}\n` });
  const report = await m.checkRuntimes({ ...sys, env: env([]), home: '/Users/x', now: NOW, advisoryData: await data(), execPath: null, vercel: false });
  const r = report.runtimes[0];
  assert.equal(r.source, 'fnm');
  assert.equal(r.status, 'vulnerable');
  assert.equal(report.highCount, 1);
  assert.equal(m.isVendor(bin), false);
  assert.equal(m.isVendor('/Users/x/Library/Application Support/Codex/runtime/bin/node'), true);
  assert.match(r.action, /fnm install 22.23.4 && fnm default 22.23.4 && fnm uninstall 22.23.3/);
});

test('P1-2: cron PATH still finds lsof/brew; a failed lsof makes the result incomplete', async () => {
  const m = await load();
  const exists = p => ['/usr/sbin/lsof', '/opt/homebrew/bin/brew'].includes(p);
  assert.equal(m.resolveTool('lsof', { env: { PATH: '/usr/bin:/bin' }, exists }), '/usr/sbin/lsof');
  assert.equal(m.resolveTool('brew', { env: { PATH: '/usr/bin:/bin' }, exists }), '/opt/homebrew/bin/brew');
  const sys = fakeSystem({ '/b/node': { ino: 2, version: 'v24.22.1' } }, { processes: [[60, 'node']], lsof: '' });
  const report = await m.checkRuntimes({ ...sys, env: env(['/b']), home: '/nohome', now: NOW, advisoryData: await data(), execPath: null, vercel: false });
  assert.equal(report.status, 'incomplete');
  assert.equal(report.exitCode, 2);
  assert.ok(report.issues.some(i => /lsof/.test(i)));
  const psFail = { ...sys, exec: (f, a) => f === 'ps' ? { status: null, error: Object.assign(Error('ENOENT'), { code: 'ENOENT' }) } : sys.exec(f, a) };
  const r2 = await m.checkRuntimes({ ...psFail, env: env(['/b']), home: '/nohome', now: NOW, advisoryData: await data(), execPath: null, vercel: false });
  assert.equal(r2.status, 'incomplete');
});

test('P1-3: Windows probes node.exe, skips the process scan with a note, and can be complete', async () => {
  const m = await load();
  const exe = 'C:\\Program Files\\nodejs\\node.exe';
  const sys = fakeSystem({ [exe]: { ino: 3, version: 'v24.22.1' }, 'C:\\gd\\node.exe': { ino: 4, version: 'v22.23.4' } });
  const report = await m.checkRuntimes({ ...sys, platform: 'win32', env: { Path: 'C:\\Program Files\\nodejs\;C:\\Windows' }, home: 'C:\\Users\\x', now: NOW, advisoryData: await data(), execPath: 'C:\\gd\\node.exe', vercel: false });
  assert.deepEqual(report.runtimes.map(r => r.path).sort(), ['C:\\Program Files\\nodejs\\node.exe', 'C:\\gd\\node.exe'].sort());
  assert.ok(!sys.calls.some(c => c[0] === 'ps' || c[0] === 'lsof'));
  assert.ok(report.notes.some(n => /not supported on this platform/.test(n)));
  assert.equal(report.status, 'complete');
  assert.equal(report.exitCode, 0);
});

test('P2-4: a stalled Vercel API times out and never masks a HIGH runtime', async () => {
  const m = await load();
  const stall = (url, opts) => new Promise((_, reject) => opts.signal?.addEventListener('abort', () => reject(Error('aborted'))));
  const sys = fakeSystem({ '/b/node': { ino: 2, version: 'v24.22.0' } });
  const report = await m.checkRuntimes({ ...sys, env: { ...env(['/b']), VERCEL_TOKEN: 'test' }, home: '/nohome', now: NOW, advisoryData: await data(), processes: [], execPath: null, fetchImpl: stall, vercelTimeoutMs: 20, vercelBudgetMs: 200 });
  assert.equal(report.status, 'dangerous');
  assert.equal(report.highCount, 1);
  assert.equal(report.vercel.flaggedCount ?? 0, 0);
  assert.ok(['partial', 'unavailable'].includes(report.vercel.status));
  const never = () => new Promise(() => {});
  const r2 = await m.checkRuntimes({ ...sys, env: { ...env(['/b']), VERCEL_TOKEN: 'test' }, home: '/nohome', now: NOW, advisoryData: await data(), processes: [], execPath: null, fetchImpl: never, vercelTimeoutMs: 60000, vercelBudgetMs: 30 });
  assert.equal(r2.vercel.status, 'unavailable');
  assert.equal(r2.exitCode, 1);
  let calls = 0;
  const run = (_, args, opts) => { calls++; return args.includes('--no-vercel') ? { status: 1, stdout: JSON.stringify({ ...report, vercel: undefined }) } : { status: null, signal: 'SIGKILL', stdout: '', error: Object.assign(Error('spawnSync ETIMEDOUT'), { code: 'ETIMEDOUT' }) }; };
  const synced = m.runRuntimeCheckSync({ run, timeoutMs: 1000, script: 'x' });
  assert.equal(calls, 2);
  assert.equal(synced.highCount, 1);
  assert.ok(synced.issues.some(i => /without the optional Vercel step/.test(i)));
});

test('P2-5: a missing release schedule is incomplete, and nightly surfaces runtime issues even when dangerous', async () => {
  const m = await load(), d = await data();
  const sys = fakeSystem({ '/b/node': { ino: 2, version: 'v24.22.1' } });
  const report = await m.checkRuntimes({ ...sys, env: env(['/b']), home: '/nohome', now: NOW, advisoryData: { ...d, schedule: null }, processes: [], execPath: null, vercel: false });
  assert.equal(report.status, 'incomplete');
  assert.ok(report.issues.some(i => /schedule unavailable/.test(i)));
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gd-runtime-p25-')); const previous = process.env.GUARDOG_HOME;
  try {
    process.env.GUARDOG_HOME = path.join(root, 'state'); fs.mkdirSync(process.env.GUARDOG_HOME);
    fs.writeFileSync(path.join(process.env.GUARDOG_HOME, 'config.json'), JSON.stringify({ nightlyUpdates: false }));
    const { runNightly } = await import('../bin/nightly-scan.js');
    const dangerous = { status: 'dangerous', findings: [{ severity: 'high', kind: 'runtime_vulnerable', path: '/b/node', version: 'v24.22.0', fixedIn: 'v24.22.1', action: 'x' }], issues: ['Release schedule unavailable; end-of-life status not checked.'] };
    const receipt = runNightly({ roots: [root], healthOptions: { platform: 'linux', run: () => ({ status: 0, stdout: '' }) }, run: () => { throw Error('none'); }, runtimeCheck: () => dangerous });
    assert.equal(receipt.exitCode, 1);
    assert.ok(receipt.issues.includes('Runtime: Release schedule unavailable; end-of-life status not checked.'));
  } finally { if (previous === undefined) delete process.env.GUARDOG_HOME; else process.env.GUARDOG_HOME = previous; fs.rmSync(root, { recursive: true, force: true }); }
});

test('P2-6: inactive manager versions are medium with an uninstall step; the default stays HIGH', async () => {
  const m = await load();
  const a = '/Users/x/.nvm/versions/node/v22.23.3/bin/node', b = '/Users/x/.nvm/versions/node/v24.22.0/bin/node';
  const sys = fakeSystem({ [a]: { ino: 11, version: 'v22.23.3' }, [b]: { ino: 12, version: 'v24.22.0' }, '/Users/x/.nvm/alias/default': { ino: 13 } });
  sys.fs.readdir = p => p === '/Users/x/.nvm/versions/node' ? ['v22.23.3', 'v24.22.0'] : (() => { throw Error('ENOENT'); })();
  sys.fs.readFile = p => { if (p === '/Users/x/.nvm/alias/default') return '24\n'; throw Error('ENOENT'); };
  const report = await m.checkRuntimes({ ...sys, env: env([]), home: '/Users/x', now: NOW, advisoryData: await data(), processes: [], execPath: null, vercel: false });
  const inactive = report.runtimes.find(r => r.path === a), active = report.runtimes.find(r => r.path === b);
  assert.equal(inactive.active, false);
  assert.equal(active.active, true);
  assert.equal(report.findings.find(f => f.path === a).severity, 'medium');
  assert.equal(report.findings.find(f => f.path === b).severity, 'high');
  assert.equal(report.highCount, 1);
  const plan = m.buildFixPlan(report);
  assert.match(plan, /nvm uninstall 22.23.3 {3}# remove the inactive vulnerable version/);
  assert.match(plan, /nvm install 24.22.1 && nvm alias default 24.22.1 && nvm uninstall 24.22.0/);
  // Unknown default (no alias file) fails safe: active, HIGH.
  sys.fs.readFile = () => { throw Error('ENOENT'); };
  const r2 = await m.checkRuntimes({ ...sys, env: env([]), home: '/Users/x', now: NOW, advisoryData: await data(), processes: [], execPath: null, vercel: false });
  assert.equal(r2.highCount, 2);
});

test('P2-7: a failed signature check stops the block before anything is installed', { skip: process.platform === 'win32' }, async () => {
  const m = await load();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gd-plan-')); const stubs = path.join(dir, 'stubs'), log = path.join(dir, 'log'); fs.mkdirSync(stubs);
  const stub = (name, body) => fs.writeFileSync(path.join(stubs, name), `#!/bin/sh\necho ${name} >> "${log}"\n${body}\n`, { mode: 0o755 });
  stub('curl', 'for a; do last="$a"; done; case "$*" in *" -o "*) : > "$last";; *) : > "$(basename "$last")";; esac');
  stub('gpgv', 'exit 1');
  for (const t of ['shasum', 'tar', 'install', 'cp', 'mv']) stub(t, 'exit 0');
  try {
    const report = { runtimes: [{ path: path.join(dir, 'bin', 'node'), version: 'v22.23.2', status: 'vulnerable', source: 'allsorted', fixedIn: 'v22.23.4', cves: [], action: 'x' }], staleProcesses: [] };
    const block = m.buildFixPlan(report, { platform: 'darwin', arch: 'arm64' }).split('\n').filter(l => !l.startsWith('#') || l.startsWith('# Node')).join('\n');
    const result = require('node:child_process').spawnSync('bash', ['-c', block], { encoding: 'utf8', env: { PATH: stubs + ':/usr/bin:/bin', HOME: dir } });
    const ran = fs.readFileSync(log, 'utf8').trim().split('\n');
    assert.notEqual(result.status, 0);
    assert.ok(ran.includes('gpgv'));
    for (const t of ['shasum', 'tar', 'install', 'cp']) assert.ok(!ran.includes(t), t + ' must not run after a failed signature');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('P2-8: discovery covers the official installer, mise, pnpm, ~/bin and process.execPath', async () => {
  const m = await load();
  const dirs = { '/Users/x/.local/share/mise/installs/node': ['22.23.4'], '/Users/x/Library/pnpm/nodejs': ['24.22.1'], '/Users/x/.local/share/pnpm/nodejs': ['26.12.1'] };
  const fsFake = { readdir: p => { if (dirs[p]) return dirs[p]; throw Error('ENOENT'); } };
  const paths = m.candidatePaths({ fs: fsFake, env: { PATH: '' }, home: '/Users/x', platform: 'darwin', execPath: '/opt/self/bin/node' }).map(c => c.path + '|' + c.source);
  for (const want of ['/usr/local/bin/node|installer', '/Users/x/.local/share/mise/installs/node/22.23.4/bin/node|mise', '/Users/x/Library/pnpm/nodejs/24.22.1/bin/node|pnpm', '/Users/x/.local/share/pnpm/nodejs/26.12.1/bin/node|pnpm', '/Users/x/bin/node|home-bin', '/opt/self/bin/node|self'])
    assert.ok(paths.includes(want), want);
});

test('P3-9: junk release versions are rejected and fix plans quote everything', async () => {
  const m = await load();
  const idx = m.normalizeIndex([{ version: 'v99.0.0;touch /tmp/pwn', security: true }, ...INDEX]);
  assert.ok(!idx.some(r => r.version.includes(';')));
  assert.throws(() => m.normalizeIndex([{ version: 'v1.2.3$(id)' }]), /no releases/);
  const plan = m.buildFixPlan({ runtimes: [{ path: "/tmp/it's here/node", version: 'v22.23.2', status: 'vulnerable', source: 'other', fixedIn: 'v22.23.4', cves: [], action: 'x' }, { path: '/x/node', version: 'v22.23.2', status: 'vulnerable', source: 'other', fixedIn: 'v99;rm -rf ~', cves: [], action: 'x' }], staleProcesses: [] }, { platform: 'darwin', arch: 'arm64' });
  assert.match(plan, /install -m 0755 'node-v22.23.4-darwin-arm64\/bin\/node' '\/tmp\/it'\\''s here\/node'/);
  assert.doesNotMatch(plan, /rm -rf ~/);
});

test('P3-10: a failed nodejs.org fetch falls back to the last good cached index, marked stale', async () => {
  const m = await load();
  const store = new Map();
  const cache = { get: (k, maxAge) => { const e = store.get(JSON.stringify(k)); return e && e.age < maxAge ? e.value : null; }, set: (k, value) => store.set(JSON.stringify(k), { value, age: 0 }) };
  const ok = async url => ({ ok: true, json: async () => url.includes('schedule') ? SCHEDULE_RAW : url.includes('vuln') ? VULN_RAW : INDEX });
  await m.loadAdvisoryData({ fetchImpl: ok, cache, pace: (_, fn) => fn() });
  for (const [k, e] of store) if (!k.includes('last-good')) e.age = 7 * 3600000; // fresh entries expire
  const down = async () => { throw Error('ENOTFOUND nodejs.org'); };
  const result = await m.loadAdvisoryData({ fetchImpl: down, cache, pace: (_, fn) => fn() });
  assert.equal(result.sources.index, 'stale-cache');
  assert.equal(result.index.length, INDEX.length);
  assert.ok(result.stale.some(s => s.name === 'index' && /ENOTFOUND/.test(s.error)));
  const sys = fakeSystem({ '/b/node': { ino: 2, version: 'v24.22.1' } });
  const report = await m.checkRuntimes({ ...sys, env: env(['/b']), home: '/nohome', now: NOW, advisoryData: result, processes: [], execPath: null, vercel: false });
  assert.equal(report.status, 'complete');
  assert.ok(report.notes.some(n => /last good index/.test(n)));
});

test('P3-11: a Volta shim is labelled as a shim, not a broken binary', async () => {
  const m = await load();
  const sys = fakeSystem({ '/Users/x/.volta/bin/node': { real: '/Users/x/.volta/bin/volta-shim' }, '/Users/x/.volta/bin/volta-shim': { ino: 9, broken: true } });
  const report = await m.checkRuntimes({ ...sys, env: env(['/Users/x/.volta/bin']), home: '/Users/x', now: NOW, advisoryData: await data(), processes: [], execPath: null, vercel: false });
  assert.equal(report.runtimes[0].status, 'shim');
  assert.ok(!sys.calls.some(c => c[1] === '-v'));
  assert.equal(report.findings.length, 0);
});

test('P3-12: process command lines are redacted before storing', async () => {
  const { redactCommand } = await load();
  const out = redactCommand('node x.js --token abc123 --password=hunter2 sk_live_51Habc rk_test_9xyz https://joe:pa55@db.example.com GITHUB_TOKEN=ghp_zzz --port 9222');
  for (const secret of ['abc123', 'hunter2', '51Habc', '9xyz', 'pa55', 'ghp_zzz']) assert.ok(!out.includes(secret), secret);
  assert.match(out, /--port 9222/);
});

test('P3-13: Vercel paginates and keeps team results when the personal scope fails', async () => {
  const m = await load(), d = await data();
  const seen = [];
  const fetchImpl = async url => {
    seen.push(url);
    if (url.includes('/v2/teams')) return { ok: true, json: async () => ({ teams: [{ id: 't1', slug: 'team' }] }) };
    if (!url.includes('teamId')) return { ok: false, status: 403 };
    if (!url.includes('until=')) return { ok: true, json: async () => ({ projects: [{ name: 'a', nodeVersion: '20.x' }], pagination: { next: 111 } }) };
    return { ok: true, json: async () => ({ projects: [{ name: 'b', nodeVersion: '24.x' }], pagination: { next: null } }) };
  };
  const v = await m.checkVercelProjects({ token: 'test', schedule: d.schedule, fetchImpl, now: NOW });
  assert.deepEqual(v.projects.map(p => p.name), ['a', 'b']);
  assert.equal(v.flaggedCount, 1);
  assert.equal(v.status, 'partial');
  assert.ok(v.errors.some(e => /personal/.test(e)));
  assert.ok(seen.some(u => u.includes('until=111')));
});

test('P3-14: an unpatched Homebrew keg is never overwritten; the build goes to its own prefix', async () => {
  const m = await load();
  const keg = '/opt/homebrew/Cellar/node@22/22.23.3_3/bin/node';
  const plan = m.buildFixPlan({ runtimes: [{ path: keg, version: 'v22.23.3', status: 'vulnerable', source: 'homebrew', fixedIn: 'v22.23.4', cves: [], action: 'Homebrew node@22 has not shipped' }], staleProcesses: [] }, { platform: 'darwin', arch: 'arm64' });
  assert.match(plan, /mv 'node-v22.23.4-darwin-arm64' "\$HOME\/.local\/node-v22.23.4"/);
  assert.match(plan, /export PATH="\$HOME\/.local\/node-v22.23.4\/bin:\$PATH"/);
  assert.doesNotMatch(plan, /install -m 0755 .*Cellar/);
  assert.doesNotMatch(plan, /cp -p .*Cellar/);
});
