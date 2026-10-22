/**
 * Runtime advisories: checks the Node.js runtimes on this machine, not just packages.
 *
 * Discovers node binaries (PATH, Homebrew, managers, All Sorted runtime, running
 * processes), compares each version with nodejs.org/dist/index.json and the release
 * schedule, and reports vulnerable, end-of-life and stale (restart needed) runtimes.
 * It never modifies binaries; buildFixPlan() only returns commands for a human.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, realpathSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, delimiter, join } from 'node:path';
import { guardogDataDir } from './paths.js';
import { EvidenceCache } from './scan-cache.js';
import { createRequestPacer } from './request-pacer.js';

export const INDEX_URL = 'https://nodejs.org/dist/index.json';
export const SCHEDULE_URL = 'https://raw.githubusercontent.com/nodejs/Release/main/schedule.json';
export const VULN_DB_URL = 'https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json';
const CACHE_TTL_MS = 6 * 3600000;
const FETCH_TIMEOUT_MS = 20000;
const PROBE_TIMEOUT_MS = 5000;
const VENDOR_PATTERNS = [/\.app\/Contents\//, /\/Library\/Application Support\//, /\/\.cache\/codex-runtimes\//, /\/\.vscode(-server)?\//, /\/\.cursor(-server)?\//];

// ---------- versions and ranges ----------

export function parseVersion(text) {
  const m = /^v?(\d+)\.(\d+)\.(\d+)/.exec(String(text || '').trim());
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}
export function compareVersions(a, b) {
  const x = typeof a === 'string' ? parseVersion(a) : a, y = typeof b === 'string' ? parseVersion(b) : b;
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
  return 0;
}
function comparatorMatches(version, token) {
  const m = /^(<=|>=|<|>|=|\^|~)?v?(\d+|x|\*)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?$/.exec(token);
  if (!m) throw Error('Unsupported range token: ' + token);
  const [, op = '', ...parts] = m;
  const nums = parts.map(p => (p === undefined || p === 'x' || p === '*') ? null : Number(p));
  const [maj, min, pat] = nums;
  if (maj === null) return true;
  if (op === '' || op === '=') {
    if (min === null) return version[0] === maj;
    if (pat === null) return version[0] === maj && version[1] === min;
    return compareVersions(version, [maj, min, pat]) === 0;
  }
  const base = [maj, min ?? 0, pat ?? 0];
  const cmp = compareVersions(version, base);
  if (op === '^') return version[0] === maj && cmp >= 0;
  if (op === '~') return version[0] === maj && (min === null || version[1] === min) && cmp >= 0;
  if (op === '>=') return cmp >= 0;
  if (op === '<') return cmp < 0;
  if (op === '>') return min === null ? version[0] > maj : cmp > 0;
  if (op === '<=') return min === null ? version[0] <= maj : cmp <= 0;
  return false;
}
/** Minimal semver range check covering the shapes used by the Node security-wg database. */
export function satisfies(version, range) {
  const v = typeof version === 'string' ? parseVersion(version) : version;
  if (!v || typeof range !== 'string' || !range.trim()) return false;
  return range.split('||').some(set => set.trim().split(/\s+/).filter(Boolean).every(token => comparatorMatches(v, token)));
}

// ---------- advisory data ----------

/** Reduce nodejs.org/dist/index.json to the fields needed, so it fits the evidence cache. */
export function normalizeIndex(raw) {
  if (!Array.isArray(raw)) throw Error('Node release index is not an array');
  const out = raw.filter(r => r && parseVersion(r.version)).map(r => ({ version: r.version, security: r.security === true, lts: r.lts || false, date: r.date || null }));
  if (!out.length) throw Error('Node release index has no releases');
  return out;
}
export function normalizeSchedule(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw Error('Release schedule is not an object');
  const out = {};
  for (const [key, entry] of Object.entries(raw)) {
    const major = /^v(\d+)$/.exec(key)?.[1];
    if (major && entry && typeof entry.end === 'string') out[major] = { start: entry.start || null, end: entry.end, lts: entry.lts || null };
  }
  return out;
}
/** Tolerant: accepts an object or array of entries; skips anything without a CVE and ranges. */
export function normalizeVulnDb(raw) {
  const entries = Array.isArray(raw) ? raw : raw && typeof raw === 'object' ? Object.values(raw) : [];
  return entries.flatMap(entry => {
    if (!entry || typeof entry.vulnerable !== 'string') return [];
    const cve = (Array.isArray(entry.cve) ? entry.cve : [entry.cve]).filter(id => typeof id === 'string' && id);
    if (!cve.length) return [];
    return [{ cve, vulnerable: entry.vulnerable, patched: typeof entry.patched === 'string' ? entry.patched : '', severity: entry.severity || null }];
  });
}

/** Fetch advisory sources through the private evidence cache and a cross-process pacer. */
export async function loadAdvisoryData({ fetchImpl = globalThis.fetch, cache, pace, noCache = false } = {}) {
  const evidence = cache === undefined ? new EvidenceCache({ directory: join(guardogDataDir(), 'cache', 'runtime-advisories'), namespace: 'runtime-advisories' }) : cache;
  const pacer = pace || createRequestPacer('runtime-advisories');
  async function get(url, normalize, required) {
    const cached = !noCache && evidence ? evidence.get(['runtime', url], CACHE_TTL_MS) : null;
    if (cached) return { value: cached, source: 'cache' };
    try {
      const value = await pacer(1000, async () => {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
        try {
          const response = await fetchImpl(url, { signal: controller.signal, headers: { accept: 'application/json' } });
          if (!response.ok) throw Error('HTTP ' + response.status);
          return normalize(await response.json());
        } finally { clearTimeout(timer); }
      });
      evidence?.set(['runtime', url], value, CACHE_TTL_MS);
      return { value, source: 'network' };
    } catch (error) {
      if (required) throw Error(`Cannot load ${url}: ${error.message}`);
      return { value: null, source: 'unavailable', error: error.message };
    }
  }
  const index = await get(INDEX_URL, normalizeIndex, true);
  const schedule = await get(SCHEDULE_URL, normalizeSchedule, false);
  const vulns = await get(VULN_DB_URL, normalizeVulnDb, false);
  return { index: index.value, schedule: schedule.value, vulnDb: vulns.value, sources: { index: index.source, schedule: schedule.source, vulnDb: vulns.source } };
}

/** Classify one version against the release index (required) plus optional schedule and CVE db. */
export function assessVersion(version, { index, schedule = null, vulnDb = null, now = new Date() }) {
  const parsed = parseVersion(version);
  if (!parsed) return { status: 'unknown', reason: 'Version could not be read.' };
  const sameMajor = index.filter(r => parseVersion(r.version)[0] === parsed[0]);
  const latest = sameMajor.reduce((best, r) => !best || compareVersions(r.version, best.version) > 0 ? r : best, null);
  const newerSecurity = sameMajor.filter(r => r.security && compareVersions(r.version, parsed) > 0).sort((a, b) => compareVersions(a.version, b.version));
  const today = now.toISOString().slice(0, 10);
  const eolDate = schedule?.[String(parsed[0])]?.end || null;
  const eol = Boolean(eolDate && eolDate < today);
  const cves = vulnDb ? [...new Set(vulnDb.filter(e => {
    try { return satisfies(parsed, e.vulnerable) && !(e.patched && satisfies(parsed, e.patched)); } catch { return false; }
  }).flatMap(e => e.cve))] : [];
  const result = { major: parsed[0], latestOnMajor: latest?.version || null, eolDate, cves };
  if (!latest) return { ...result, status: eol ? 'eol' : 'unknown', reason: 'Major version is not in the Node release index.' };
  if (newerSecurity.length) {
    const fixedIn = newerSecurity[newerSecurity.length - 1].version;
    return { ...result, status: eol ? 'eol' : 'vulnerable', vulnerable: true, fixedIn, securityReleases: newerSecurity.map(r => r.version), reason: `Security release${newerSecurity.length > 1 ? 's' : ''} ${newerSecurity.map(r => r.version).join(', ')} published after ${version}.` };
  }
  if (eol) return { ...result, status: 'eol', vulnerable: false, fixedIn: null, reason: `Node ${parsed[0]} reached end of life on ${eolDate}; it receives no security fixes.` };
  return { ...result, status: 'ok', vulnerable: false, fixedIn: null, reason: 'No newer security release on this major.' };
}

// ---------- discovery ----------

function defaultExec(file, args, { timeout = PROBE_TIMEOUT_MS } = {}) {
  return spawnSync(file, args, { encoding: 'utf8', timeout, killSignal: 'SIGKILL', maxBuffer: 16 * 1024 * 1024, windowsHide: true, env: { ...process.env, NODE_OPTIONS: '' } });
}
const defaultFs = {
  realpath: p => realpathSync(p),
  stat: p => statSync(p),
  readdir: p => readdirSync(p),
  exists: p => existsSync(p)
};
function glob(fs, parent, childPattern, suffix) {
  try { return fs.readdir(parent).filter(name => childPattern.test(name)).map(name => join(parent, name, suffix)); } catch { return []; }
}

/** Candidate node paths with their discovery source. */
export function candidatePaths({ fs = defaultFs, env = process.env, home = homedir() } = {}) {
  const out = [];
  const add = (path, source) => out.push({ path, source });
  for (const dir of String(env.PATH || '').split(delimiter).filter(Boolean)) add(join(dir, 'node'), 'path');
  for (const prefix of ['/opt/homebrew', '/usr/local']) {
    const cellar = join(prefix, 'Cellar');
    for (const keg of glob(fs, cellar, /^node(@\d+)?$/, '')) for (const p of glob(fs, keg, /./, 'bin/node')) add(p, 'homebrew');
    for (const p of glob(fs, join(prefix, 'opt'), /^node(@\d+)?$/, 'bin/node')) add(p, 'homebrew');
  }
  add(join(home, '.local', 'allsorted-node', 'bin', 'node'), 'allsorted');
  for (const p of glob(fs, join(home, '.nvm', 'versions', 'node'), /^v\d/, 'bin/node')) add(p, 'nvm');
  for (const root of [join(home, '.fnm', 'node-versions'), join(home, '.local', 'share', 'fnm', 'node-versions'), join(home, 'Library', 'Application Support', 'fnm', 'node-versions')])
    for (const p of glob(fs, root, /^v\d/, 'installation/bin/node')) add(p, 'fnm');
  for (const p of glob(fs, join(home, '.volta', 'tools', 'image', 'node'), /^\d/, 'bin/node')) add(p, 'volta');
  for (const p of glob(fs, join(home, '.asdf', 'installs', 'nodejs'), /^\d/, 'bin/node')) add(p, 'asdf');
  for (const p of glob(fs, '/usr/local/n/versions/node', /^\d/, 'bin/node')) add(p, 'n');
  return out;
}

/** Parse `lsof -Fpfin` output into pid -> executable {path, inode}. */
export function parseLsof(text) {
  const byPid = new Map();
  let pid = null, fd = null, inode = null;
  for (const line of String(text || '').split('\n')) {
    const tag = line[0], value = line.slice(1);
    if (tag === 'p') { pid = Number(value); fd = null; inode = null; }
    else if (tag === 'f') { fd = value; inode = null; }
    else if (tag === 'i') inode = Number(value);
    else if (tag === 'n' && pid && fd === 'txt') {
      const list = byPid.get(pid) || [];
      list.push({ path: value, inode });
      byPid.set(pid, list);
    }
  }
  const result = new Map();
  for (const [p, entries] of byPid) {
    const exe = entries.find(e => basename(e.path) === 'node') || entries[0];
    if (exe) result.set(p, exe);
  }
  return result;
}

function redactCommand(command) {
  return String(command || '').replace(/((?:token|secret|password|passwd|api[-_]?key|auth)[^=\s:]*[=:\s]+)\S+/gi, '$1[redacted]').slice(0, 160);
}

/** Running node processes with their executable path and inode. */
export function runningNodeProcesses({ exec = defaultExec } = {}) {
  const ps = exec('ps', ['-axo', 'pid=,comm=']);
  if (ps.status !== 0 || typeof ps.stdout !== 'string') return { processes: [], issue: 'Could not list processes.' };
  const pids = ps.stdout.split('\n').map(line => /^\s*(\d+)\s+(.+)$/.exec(line)).filter(m => m && basename(m[2].trim()) === 'node').map(m => Number(m[1])).filter(pid => pid !== process.pid);
  if (!pids.length) return { processes: [] };
  const lsof = exec('lsof', ['-nP', '-a', '-d', 'txt', '-p', pids.join(','), '-Fpfin'], { timeout: 15000 });
  const exes = parseLsof(lsof.stdout);
  const args = exec('ps', ['-o', 'pid=,args=', '-p', pids.join(',')]);
  const commands = new Map(String(args.stdout || '').split('\n').map(line => /^\s*(\d+)\s+(.*)$/.exec(line)).filter(Boolean).map(m => [Number(m[1]), redactCommand(m[2])]));
  const processes = pids.filter(pid => exes.has(pid)).map(pid => ({ pid, path: exes.get(pid).path, inode: exes.get(pid).inode, command: commands.get(pid) || '' }));
  return { processes, issue: exes.size === 0 && pids.length ? 'Could not read process executables (lsof).' : undefined };
}

function isVendor(path) { return VENDOR_PATTERNS.some(re => re.test(path)); }
function homebrewFormula(realPath) { return /\/Cellar\/(node(?:@\d+)?)\//.exec(realPath)?.[1] || null; }
function classifySource(realPath, sources, home) {
  if (isVendor(realPath)) return 'vendor';
  if (homebrewFormula(realPath)) return 'homebrew';
  if (realPath.startsWith(join(home, '.local', 'allsorted-node') + '/')) return 'allsorted';
  for (const s of ['nvm', 'fnm', 'volta', 'asdf', 'n']) if (sources.includes(s)) return s;
  return sources.includes('process') && !sources.includes('path') ? 'other' : (sources[0] === 'path' ? 'path' : sources[0] || 'other');
}

/** Read the Homebrew stable version for each formula, without auto-update. Never fatal. */
export function homebrewStableVersions(formulas, { exec = defaultExec } = {}) {
  if (!formulas.length) return {};
  const result = exec('brew', ['info', '--json=v2', '--formula', ...formulas], { timeout: 30000 });
  try {
    if (result.status !== 0) return {};
    return Object.fromEntries(JSON.parse(result.stdout).formulae.map(f => [f.name, f.versions?.stable || null]));
  } catch { return {}; }
}

// ---------- the check ----------

/**
 * Run the runtime advisory check. All side-effecting dependencies are injectable.
 * @returns {Promise<object>} report with runtimes, staleProcesses, findings, status, exitCode
 */
export async function checkRuntimes(options = {}) {
  const { exec = defaultExec, fs = defaultFs, env = process.env, home = homedir(), now = new Date(), platform = process.platform, arch = process.arch } = options;
  const report = { taskClass: 'runtime_advisories', checkedAt: now.toISOString(), status: 'incomplete', runtimes: [], staleProcesses: [], findings: [], issues: [], sources: {} };
  let data;
  try {
    data = options.advisoryData || await loadAdvisoryData({ fetchImpl: options.fetchImpl, cache: options.cache, pace: options.pace, noCache: options.noCache });
    report.sources = data.sources || {};
    if (!data.schedule) report.issues.push('Release schedule unavailable; end-of-life status not checked.');
  } catch (error) {
    report.issues.push(error.message);
  }

  // Discover and dedupe by device+inode of the resolved file.
  const byIdentity = new Map();
  const consider = (path, source) => {
    let realPath, stat;
    try { realPath = fs.realpath(path); stat = fs.stat(realPath); } catch { return null; }
    if (typeof stat.isFile === 'function' && !stat.isFile()) return null;
    const key = `${stat.dev}:${stat.ino}`;
    let entry = byIdentity.get(key);
    if (!entry) { entry = { path: realPath, aliases: [], sources: [], inode: stat.ino, dev: stat.dev, pids: [] }; byIdentity.set(key, entry); }
    if (!entry.aliases.includes(path)) entry.aliases.push(path);
    if (!entry.sources.includes(source)) entry.sources.push(source);
    return entry;
  };
  for (const { path, source } of candidatePaths({ fs, env, home })) consider(path, source);

  const running = (options.processes ? { processes: options.processes } : runningNodeProcesses({ exec }));
  if (running.issue) report.issues.push(running.issue);
  for (const proc of running.processes) {
    let current = null;
    try { current = fs.stat(proc.path); } catch { /* deleted after exec */ }
    if (!current || (Number.isFinite(proc.inode) && current.ino !== proc.inode)) {
      report.staleProcesses.push({ pid: proc.pid, path: proc.path, runningInode: proc.inode ?? null, currentInode: current?.ino ?? null, command: proc.command || '', vendorManaged: isVendor(proc.path), action: `Restart pid ${proc.pid}: it still runs the replaced (possibly vulnerable) binary at ${proc.path}.` });
      continue;
    }
    const entry = consider(proc.path, 'process');
    if (entry && !entry.pids.includes(proc.pid)) entry.pids.push(proc.pid);
  }

  const entries = [...byIdentity.values()];
  for (const entry of entries) {
    const probe = (() => { try { return exec(entry.path, ['-v'], { timeout: PROBE_TIMEOUT_MS }); } catch (error) { return { status: null, error }; } })();
    entry.version = probe.status === 0 && parseVersion(probe.stdout) ? String(probe.stdout).trim() : null;
    if (!entry.version) entry.probeError = probe.error?.code || probe.error?.message || (probe.signal ? 'killed by ' + probe.signal : 'exit ' + probe.status);
  }
  const brewFormulas = [...new Set(entries.map(e => homebrewFormula(e.path)).filter(Boolean))];
  const brewStable = options.homebrewStable || (brewFormulas.length ? homebrewStableVersions(brewFormulas, { exec }) : {});

  for (const entry of entries) {
    const source = classifySource(entry.path, entry.sources, home);
    const runtime = { path: entry.path, aliases: entry.aliases.filter(a => a !== entry.path), source, version: entry.version, status: 'unknown', fixedIn: null, latestOnMajor: null, cves: [], pids: entry.pids.slice(0, 20), processCount: entry.pids.length };
    if (!entry.version) { runtime.reason = 'Could not run `node -v`: ' + entry.probeError; runtime.action = 'Inspect or remove this broken binary.'; }
    else if (data?.index) {
      const assessment = assessVersion(entry.version, { index: data.index, schedule: data.schedule, vulnDb: data.vulnDb, now });
      Object.assign(runtime, { status: assessment.status, fixedIn: assessment.fixedIn || null, latestOnMajor: assessment.latestOnMajor, cves: assessment.cves || [], eolDate: assessment.eolDate, reason: assessment.reason });
    } else runtime.reason = 'Release index unavailable.';
    if (source === 'vendor') { runtime.versionStatus = runtime.status; runtime.status = 'vendor-managed'; }
    runtime.action = runtime.action || recommendedAction(runtime, { brewStable, platform, arch });
    report.runtimes.push(runtime);
  }
  report.runtimes.sort((a, b) => a.path.localeCompare(b.path));

  for (const r of report.runtimes) {
    if (r.status === 'vulnerable' || r.status === 'eol') report.findings.push({ severity: 'high', kind: r.status === 'eol' ? 'runtime_eol' : 'runtime_vulnerable', path: r.path, version: r.version, fixedIn: r.fixedIn, cves: r.cves, action: r.action });
    else if (r.status === 'vendor-managed' && ['vulnerable', 'eol'].includes(r.versionStatus)) report.findings.push({ severity: 'info', kind: 'vendor_runtime_outdated', path: r.path, version: r.version, fixedIn: r.fixedIn, action: r.action });
  }
  for (const s of report.staleProcesses) report.findings.push({ severity: s.vendorManaged ? 'info' : 'medium', kind: 'restart_needed', path: s.path, pid: s.pid, action: s.action });
  if (options.vercel !== false && env.VERCEL_TOKEN && data?.schedule) {
    try { report.vercel = await checkVercelProjects({ token: env.VERCEL_TOKEN, schedule: data.schedule, fetchImpl: options.fetchImpl || globalThis.fetch, now }); }
    catch (error) { report.vercel = { status: 'unavailable', error: error.message, projects: [] }; }
  }

  report.highCount = report.findings.filter(f => f.severity === 'high').length;
  report.vulnerableCount = report.runtimes.filter(r => r.status === 'vulnerable').length;
  report.eolCount = report.runtimes.filter(r => r.status === 'eol').length;
  report.restartNeededCount = report.staleProcesses.length;
  report.status = report.highCount ? 'dangerous' : !data?.index || report.runtimes.length === 0 ? 'incomplete' : 'complete';
  if (report.runtimes.length === 0) report.issues.push('No Node runtimes found.');
  report.exitCode = report.status === 'dangerous' ? 1 : report.status === 'incomplete' ? 2 : 0;
  return report;
}

function distTarget(platform, arch) {
  const os = platform === 'darwin' ? 'darwin' : platform === 'linux' ? 'linux' : null;
  const cpu = ['arm64', 'x64'].includes(arch) ? arch : null;
  return os && cpu ? `${os}-${cpu}` : null;
}

export function recommendedAction(runtime, { brewStable = {}, platform = process.platform, arch = process.arch } = {}) {
  if (runtime.status === 'vendor-managed') return 'Vendor-managed: update the owning application; do not replace its bundled binary.';
  if (runtime.status === 'ok') return 'None.';
  if (runtime.status === 'unknown') return runtime.action || 'Verify this runtime manually.';
  const target = runtime.fixedIn || runtime.latestOnMajor;
  const major = runtime.version ? parseVersion(runtime.version)[0] : null;
  if (runtime.status === 'eol') return `Node ${major} is end of life: move to a supported LTS major and retire this binary.`;
  const formula = homebrewFormula(runtime.path);
  if (runtime.source === 'homebrew' && formula) {
    const stable = brewStable[formula];
    if (stable && parseVersion(stable) && compareVersions(stable, target) >= 0) return `brew update && brew upgrade ${formula}`;
    return `Homebrew ${formula} has not shipped ${target} yet (stable ${stable || 'unknown'}): install the verified official ${target} binary (see --fix-plan), then brew upgrade when it ships.`;
  }
  const v = target?.replace(/^v/, '');
  const managers = { nvm: `nvm install ${v}`, fnm: `fnm install ${v}`, volta: `volta install node@${v}`, asdf: `asdf install nodejs ${v}`, n: `n ${v}` };
  if (managers[runtime.source]) return managers[runtime.source];
  return distTarget(platform, arch) ? `Replace with the verified official ${target} binary (see --fix-plan).` : `Upgrade to ${target} or later.`;
}

function shellQuote(value) { return "'" + String(value).replace(/'/g, "'\\''") + "'"; }

/** Exact commands for a human to review and run. Pure: never executes anything. */
export function buildFixPlan(report, { platform = process.platform, arch = process.arch } = {}) {
  const lines = ['# MyOS Guard Dog runtime fix plan. Review before running; nothing has been executed.'];
  const target = distTarget(platform, arch);
  let steps = 0;
  for (const r of report.runtimes || []) {
    if (!['vulnerable', 'eol'].includes(r.status)) continue;
    steps++;
    lines.push('', `# ${r.path} (${r.version}, ${r.status}${r.cves?.length ? ', ' + r.cves.join(' ') : ''})`);
    if (r.status === 'eol') { lines.push(`# ${r.action}`); continue; }
    if (/^brew update && brew upgrade /.test(r.action) || ['nvm', 'fnm', 'volta', 'asdf', 'n'].includes(r.source)) { lines.push(r.action); continue; }
    if (!target) { lines.push(`# ${r.action}`); continue; }
    const v = r.fixedIn || r.latestOnMajor;
    const tarball = `node-${v}-${target}.tar.gz`;
    const bin = shellQuote(r.path);
    lines.push(
      'D="$(mktemp -d)" && cd "$D"',
      `curl -fsSLO https://nodejs.org/dist/${v}/${tarball}`,
      `curl -fsSLO https://nodejs.org/dist/${v}/SHASUMS256.txt`,
      `curl -fsSLO https://nodejs.org/dist/${v}/SHASUMS256.txt.sig`,
      '# Requires the Node.js release keys: https://github.com/nodejs/release-keys',
      'gpg --verify SHASUMS256.txt.sig SHASUMS256.txt',
      `grep ' ${tarball}$' SHASUMS256.txt | shasum -a 256 -c -`,
      `tar -xzf ${tarball}`,
      `cp -p ${bin} ${shellQuote(r.path + '.bak-' + r.version)}`,
      `install -m 0755 node-${v}-${target}/bin/node ${bin}`,
      `${bin} -v`
    );
  }
  for (const s of report.staleProcesses || []) {
    if (!steps) lines.push('');
    steps++;
    lines.push(`# Restart needed: pid ${s.pid} runs a replaced binary (${s.path})${s.command ? ': ' + s.command : ''}`);
    lines.push(`#   restart the owning app or service; or, if safe: kill -TERM ${s.pid}`);
  }
  if (!steps) lines.push('', '# No action needed.');
  return lines.join('\n');
}

/** Report-only check of Vercel project Node versions. Runs only with a VERCEL_TOKEN. */
export async function checkVercelProjects({ token, schedule, fetchImpl = globalThis.fetch, now = new Date() }) {
  const today = now.toISOString().slice(0, 10);
  const supported = Object.entries(schedule).filter(([, e]) => (!e.start || e.start <= today) && e.end >= today).map(([m]) => Number(m));
  const oldest = supported.length ? Math.min(...supported) : null;
  const call = async url => {
    const response = await fetchImpl(url, { headers: { authorization: 'Bearer ' + token } });
    if (!response.ok) throw Error('Vercel HTTP ' + response.status);
    return response.json();
  };
  const scopes = [{ id: null, name: 'personal' }];
  try { for (const t of (await call('https://api.vercel.com/v2/teams')).teams || []) scopes.push({ id: t.id, name: t.slug || t.name }); } catch { /* personal scope still checked */ }
  const projects = [];
  for (const scope of scopes) {
    const data = await call('https://api.vercel.com/v9/projects?limit=100' + (scope.id ? '&teamId=' + encodeURIComponent(scope.id) : ''));
    for (const p of data.projects || []) {
      const major = Number(/^(\d+)/.exec(String(p.nodeVersion || ''))?.[1]);
      const eol = Number.isFinite(major) && schedule[String(major)] && schedule[String(major)].end < today;
      const tooOld = Number.isFinite(major) && oldest !== null && major < oldest;
      projects.push({ scope: scope.name, name: p.name, nodeVersion: p.nodeVersion || null, flagged: Boolean(eol || tooOld), reason: eol || tooOld ? `Node ${major}.x is end of life; move to ${oldest}.x or newer.` : null });
    }
  }
  return { status: 'complete', oldestSupportedMajor: oldest, flaggedCount: projects.filter(p => p.flagged).length, projects };
}

/** Human-readable report. */
export function formatRuntimeReport(report) {
  const lines = ['MyOS Guard Dog runtime advisories', '─'.repeat(60)];
  for (const r of report.runtimes) {
    const label = r.status === 'ok' ? 'OK' : r.status.toUpperCase();
    lines.push(`${label.padEnd(15)} ${r.version || '?'}  ${r.path}${r.processCount ? `  (${r.processCount} running)` : ''}`);
    if (r.status !== 'ok') {
      if (r.fixedIn) lines.push(`                fixed in ${r.fixedIn}${r.cves.length ? '; ' + r.cves.join(', ') : ''}`);
      if (r.reason) lines.push(`                ${r.reason}`);
      lines.push(`                action: ${r.action}`);
    }
  }
  if (report.staleProcesses.length) {
    lines.push('', `Restart needed (${report.staleProcesses.length}): processes still running a replaced binary`);
    for (const s of report.staleProcesses.slice(0, 30)) lines.push(`  pid ${s.pid}  ${s.path}${s.vendorManaged ? ' (vendor)' : ''}  ${s.command}`);
  }
  if (report.vercel) {
    lines.push('', `Vercel: ${report.vercel.status}${report.vercel.flaggedCount ? `, ${report.vercel.flaggedCount} project(s) on an old Node major` : ''}`);
    for (const p of (report.vercel.projects || []).filter(p => p.flagged)) lines.push(`  ${p.scope}/${p.name}: ${p.nodeVersion}: ${p.reason}`);
  }
  for (const issue of report.issues) lines.push('Issue: ' + issue);
  lines.push('─'.repeat(60), `Result: ${report.status} (${report.highCount} high, ${report.restartNeededCount} restart needed). Binaries are never modified; use --fix-plan for commands.`);
  return lines.join('\n');
}

/** CLI entry: `myos-guard-dog runtime [--json] [--fix-plan] [--no-cache]`. */
export async function runtimeCommand(args = [], options = {}) {
  const report = await checkRuntimes({ ...options, noCache: args.includes('--no-cache') });
  const out = options.log || console.log;
  if (args.includes('--json')) out(JSON.stringify(args.includes('--fix-plan') ? { ...report, fixPlan: buildFixPlan(report) } : report));
  else if (args.includes('--fix-plan')) out(buildFixPlan(report));
  else out(formatRuntimeReport(report));
  return report.exitCode;
}

/** Spawn the runtime check as a child for synchronous callers (nightly). */
export function runRuntimeCheckSync({ run = spawnSync, timeoutMs = 120000, script } = {}) {
  const result = run(process.execPath, [script, 'runtime', '--json'], { encoding: 'utf8', timeout: timeoutMs, killSignal: 'SIGKILL', maxBuffer: 8 * 1024 * 1024, windowsHide: true });
  try {
    const report = JSON.parse(result.stdout);
    if (report.taskClass !== 'runtime_advisories') throw Error('unexpected output');
    return report;
  } catch {
    return { taskClass: 'runtime_advisories', status: 'incomplete', exitCode: 2, runtimes: [], staleProcesses: [], findings: [], highCount: 0, issues: ['Runtime advisory check failed: ' + (result.error?.message || String(result.stderr || '').slice(0, 300) || 'no report')] };
  }
}

