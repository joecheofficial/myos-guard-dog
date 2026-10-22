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
  assert.match(plan, /curl -fsSLO https:\/\/nodejs.org\/dist\/v22.23.4\/node-v22.23.4-darwin-arm64.tar.gz/);
  assert.match(plan, /gpg --verify SHASUMS256.txt.sig SHASUMS256.txt/);
  assert.match(plan, /shasum -a 256 -c -/);
  assert.match(plan, /cp -p '\/Users\/x\/.local\/allsorted-node\/bin\/node' '\/Users\/x\/.local\/allsorted-node\/bin\/node.bak-v22.23.2'/);
  const brew = report.runtimes.find(r => r.source === 'homebrew');
  assert.match(brew.action, /has not shipped v22.23.4/); // Homebrew stable 22.23.3 < fix
  const shipped = m.recommendedAction(brew, { brewStable: { 'node@22': '22.23.4' } });
  assert.equal(shipped, 'brew update && brew upgrade node@22');
  const logs = [];
  const exit = await m.runtimeCommand(['--fix-plan'], { ...sys, env: env([]), home: '/Users/x', now: NOW, advisoryData: await data(), processes: [], vercel: false, log: line => logs.push(line) });
  assert.equal(exit, 1);
  assert.match(logs.join('\n'), /install -m 0755/);
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
