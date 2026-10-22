/**
 * Runtime advisories: checks the Node.js runtimes on this machine, not just packages.
 *
 * Discovers node binaries (PATH, Homebrew, version managers, All Sorted runtime,
 * official installer, running processes), compares each version with
 * nodejs.org/dist/index.json and the release schedule, and reports vulnerable,
 * end-of-life and stale (restart needed) runtimes. It never modifies binaries;
 * buildFixPlan() only returns commands for a human to review.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, join } from 'node:path';
import { guardogDataDir, guardogHome } from './paths.js';
import { EvidenceCache } from './scan-cache.js';
import { createRequestPacer } from './request-pacer.js';

export const INDEX_URL = 'https://nodejs.org/dist/index.json';
export const SCHEDULE_URL = 'https://raw.githubusercontent.com/nodejs/Release/main/schedule.json';
export const VULN_DB_URL = 'https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json';
export const RELEASE_KEYS_URL = 'https://raw.githubusercontent.com/nodejs/release-keys/HEAD/gpg-only-active-keys/pubring.kbx';
const CACHE_TTL_MS = 6 * 3600000;
const LAST_GOOD_TTL_MS = 30 * 24 * 3600000;
const FETCH_TIMEOUT_MS = 20000;
const VERCEL_TIMEOUT_MS = 15000;
const VERCEL_BUDGET_MS = 45000;
const PROBE_TIMEOUT_MS = 5000;
// Cron runs with PATH=/usr/bin:/bin; lsof lives in /usr/sbin and brew in /opt/homebrew/bin.
export const SYSTEM_TOOL_DIRS = ['/usr/sbin', '/sbin', '/usr/bin', '/bin', '/opt/homebrew/bin', '/usr/local/bin'];
const VERSION_RE = /^v\d+\.\d+\.\d+$/;

// Version-manager install trees are classified BEFORE vendor patterns, because fnm on
// macOS lives under ~/Library/Application Support/fnm.
const MANAGER_PATTERNS = [
  ['nvm', /\/\.nvm\/versions\/node\/(v[^/]+)\//],
  ['fnm', /\/fnm\/node-versions\/(v[^/]+)\/installation\//],
  ['volta', /\/\.volta\/tools\/image\/node\/([^/]+)\//],
  ['asdf', /\/\.asdf\/installs\/nodejs\/([^/]+)\//],
  ['mise', /\/mise\/installs\/node\/([^/]+)\//],
  ['pnpm', /\/pnpm\/nodejs\/([^/]+)\//],
  ['n', /\/n\/versions\/node\/([^/]+)\//]
];
const SHIM_PATTERNS = [/\/\.volta\/bin\/node$/, /\/volta-shim$/, /\/\.asdf\/shims\/node$/, /\/mise\/shims\/node$/, /\/\.nodenv\/shims\/node$/, /\/proto\/shims\/node$/];
const VENDOR_PATTERNS = [/\.app\/Contents\//, /\/Library\/Application Support\//, /\/\.cache\/codex-runtimes\//, /\/\.vscode(-server)?\//, /\/\.cursor(-server)?\//];
export function managerFor(path) {
  for (const [name, re] of MANAGER_PATTERNS) { const m = re.exec(path); if (m) return { name, version: m[1] }; }
  return null;
}
export function isShim(path, realPath = path) { return SHIM_PATTERNS.some(re => re.test(path) || re.test(realPath)); }
export function isVendor(path) { return !managerFor(path) && VENDOR_PATTERNS.some(re => re.test(path)); }

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

/** Reduce nodejs.org/dist/index.json to strict, needed fields so it fits the evidence cache. */
export function normalizeIndex(raw) {
  if (!Array.isArray(raw)) throw Error('Node release index is not an array');
  const out = raw.filter(r => r && typeof r.version === 'string' && VERSION_RE.test(r.version))
    .map(r => ({ version: r.version, security: r.security === true, lts: typeof r.lts === 'string' ? r.lts : false, date: typeof r.date === 'string' ? r.date : null }));
  if (!out.length) throw Error('Node release index has no releases');
  return out;
}
export function normalizeSchedule(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw Error('Release schedule is not an object');
  const out = {};
  for (const [key, entry] of Object.entries(raw)) {
    const major = /^v(\d+)$/.exec(key)?.[1];
    if (major && entry && typeof entry.end === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(entry.end)) out[major] = { start: entry.start || null, end: entry.end, lts: entry.lts || null };
  }
  if (!Object.keys(out).length) throw Error('Release schedule has no majors');
  return out;
}
/** Tolerant: accepts an object or array of entries; skips anything without a CVE and ranges. */
export function normalizeVulnDb(raw) {
  const entries = Array.isArray(raw) ? raw : raw && typeof raw === 'object' ? Object.values(raw) : [];
  return entries.flatMap(entry => {
    if (!entry || typeof entry.vulnerable !== 'string') return [];
    const cve = (Array.isArray(entry.cve) ? entry.cve : [entry.cve]).filter(id => typeof id === 'string' && /^CVE-\d{4}-\d+$/.test(id));
    if (!cve.length) return [];
    return [{ cve, vulnerable: entry.vulnerable, patched: typeof entry.patched === 'string' ? entry.patched : '', severity: entry.severity || null }];
  });
}

/**
 * Fetch advisory sources through the private evidence cache and a cross-process pacer.
 * If a fetch fails, the last good copy (up to 30 days old) is used and marked stale.
 */
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
      evidence?.set(['runtime-last-good', url], { value, fetchedAt: Date.now() }, LAST_GOOD_TTL_MS);
      return { value, source: 'network' };
    } catch (error) {
      const lastGood = evidence ? evidence.get(['runtime-last-good', url], LAST_GOOD_TTL_MS) : null;
      if (lastGood?.value) return { value: lastGood.value, source: 'stale-cache', fetchedAt: lastGood.fetchedAt, error: error.message };
      if (required) throw Error(`Cannot load ${url}: ${error.message}`);
      return { value: null, source: 'unavailable', error: error.message };
    }
  }
  const index = await get(INDEX_URL, normalizeIndex, true);
  const schedule = await get(SCHEDULE_URL, normalizeSchedule, false);
  const vulns = await get(VULN_DB_URL, normalizeVulnDb, false);
  const stale = Object.entries({ index, schedule, vulnDb: vulns }).filter(([, s]) => s.source === 'stale-cache').map(([name, s]) => ({ name, fetchedAt: s.fetchedAt ? new Date(s.fetchedAt).toISOString() : null, error: s.error }));
  return { index: index.value, schedule: schedule.value, vulnDb: vulns.value, sources: { index: index.source, schedule: schedule.source, vulnDb: vulns.source }, stale };
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

/** Resolve a bare tool name against PATH plus the system tool dirs (cron has a minimal PATH). */
export function resolveTool(name, { env = process.env, exists = existsSync } = {}) {
  if (name.includes('/')) return name;
  for (const dir of [...SYSTEM_TOOL_DIRS, ...String(env.PATH || '').split(':').filter(Boolean)]) {
    const candidate = join(dir, name);
    if (exists(candidate)) return candidate;
  }
  return name;
}
function augmentedPath(env = process.env) {
  return [...new Set([...String(env.PATH || '').split(':').filter(Boolean), ...SYSTEM_TOOL_DIRS])].join(':');
}
function defaultExec(file, args, { timeout = PROBE_TIMEOUT_MS } = {}) {
  const env = { ...process.env, NODE_OPTIONS: '', HOMEBREW_NO_AUTO_UPDATE: '1' };
  if (process.platform !== 'win32') env.PATH = augmentedPath(process.env);
  const command = process.platform === 'win32' ? file : resolveTool(file);
  return spawnSync(command, args, { encoding: 'utf8', timeout, killSignal: 'SIGKILL', maxBuffer: 16 * 1024 * 1024, windowsHide: true, env });
}
const defaultFs = {
  realpath: p => realpathSync(p),
  stat: p => statSync(p),
  readdir: p => readdirSync(p),
  exists: p => existsSync(p),
  readFile: p => readFileSync(p, 'utf8')
};
function glob(fs, parent, childPattern, suffix) {
  try { return fs.readdir(parent).filter(name => childPattern.test(name)).map(name => join(parent, name, suffix)); } catch { return []; }
}

/** Candidate node paths with their discovery source. */
export function candidatePaths({ fs = defaultFs, env = process.env, home = homedir(), platform = process.platform, execPath = process.execPath } = {}) {
  const out = [];
  const add = (path, source) => out.push({ path, source });
  const win = platform === 'win32';
  const exe = win ? 'node.exe' : 'node';
  const sep = win ? ';' : ':';
  for (const dir of String(env.PATH || env.Path || '').split(sep).filter(Boolean)) add(win ? dir.replace(/[\\/]+$/, '') + '\\' + exe : join(dir, exe), 'path');
  if (execPath) add(execPath, 'self');
  if (win) return out;
  add('/usr/local/bin/node', 'installer');
  for (const prefix of ['/opt/homebrew', '/usr/local']) {
    const cellar = join(prefix, 'Cellar');
    for (const keg of glob(fs, cellar, /^node(@\d+)?$/, '')) for (const p of glob(fs, keg, /./, 'bin/node')) add(p, 'homebrew');
    for (const p of glob(fs, join(prefix, 'opt'), /^node(@\d+)?$/, 'bin/node')) add(p, 'homebrew');
  }
  add(join(home, '.local', 'allsorted-node', 'bin', 'node'), 'allsorted');
  add(join(home, 'bin', 'node'), 'home-bin');
  for (const p of glob(fs, join(home, '.nvm', 'versions', 'node'), /^v\d/, 'bin/node')) add(p, 'nvm');
  for (const root of [join(home, '.fnm', 'node-versions'), join(home, '.local', 'share', 'fnm', 'node-versions'), join(home, 'Library', 'Application Support', 'fnm', 'node-versions')])
    for (const p of glob(fs, root, /^v\d/, 'installation/bin/node')) add(p, 'fnm');
  for (const p of glob(fs, join(home, '.volta', 'tools', 'image', 'node'), /^\d/, 'bin/node')) add(p, 'volta');
  for (const p of glob(fs, join(home, '.asdf', 'installs', 'nodejs'), /^\d/, 'bin/node')) add(p, 'asdf');
  for (const p of glob(fs, join(home, '.local', 'share', 'mise', 'installs', 'node'), /^\d/, 'bin/node')) add(p, 'mise');
  for (const root of [join(home, 'Library', 'pnpm', 'nodejs'), join(home, '.local', 'share', 'pnpm', 'nodejs')])
    for (const p of glob(fs, root, /^\d/, 'bin/node')) add(p, 'pnpm');
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

/** Remove credentials from a process command line before it is stored or printed. */
export function redactCommand(command) {
  return String(command || '')
    .replace(/\b(sk|rk|pk)_(live|test)_[A-Za-z0-9]+/g, '$1_$2_[redacted]')
    .replace(/\b(ghp|gho|ghs|github_pat|xox[abprs])[-_][A-Za-z0-9_-]+/g, '$1_[redacted]')
    .replace(/(\/\/)[^/\s:@]+:[^/\s@]+@/g, '$1[redacted]@')
    .replace(/\b([A-Za-z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD|PASSWD)[A-Za-z0-9_]*=)\S+/gi, '$1[redacted]')
    .replace(/(--?[A-Za-z0-9-]*(?:token|secret|password|passwd|api-?key|key|auth)[A-Za-z0-9-]*)(=|\s+)(?!-)\S+/gi, '$1$2[redacted]')
    .slice(0, 160);
}

/** Running node processes with their executable path and inode. `incomplete` when listing failed. */
export function runningNodeProcesses({ exec = defaultExec } = {}) {
  const ps = exec('ps', ['-axo', 'pid=,comm=']);
  if (ps.status !== 0 || typeof ps.stdout !== 'string') return { processes: [], incomplete: true, issue: 'Could not list processes (ps): restart-needed detection did not run.' };
  const pids = ps.stdout.split('\n').map(line => /^\s*(\d+)\s+(.+)$/.exec(line)).filter(m => m && basename(m[2].trim()) === 'node').map(m => Number(m[1])).filter(pid => pid !== process.pid);
  if (!pids.length) return { processes: [] };
  const lsof = exec('lsof', ['-nP', '-a', '-d', 'txt', '-p', pids.join(','), '-Fpfin'], { timeout: 15000 });
  const exes = parseLsof(lsof.stdout);
  if (exes.size === 0) return { processes: [], incomplete: true, issue: `Could not read process executables (lsof ${lsof.error?.code || 'exit ' + lsof.status}): restart-needed detection did not run.` };
  const args = exec('ps', ['-o', 'pid=,args=', '-p', pids.join(',')]);
  const commands = new Map(String(args.stdout || '').split('\n').map(line => /^\s*(\d+)\s+(.*)$/.exec(line)).filter(Boolean).map(m => [Number(m[1]), redactCommand(m[2])]));
  const processes = pids.filter(pid => exes.has(pid)).map(pid => ({ pid, path: exes.get(pid).path, inode: exes.get(pid).inode, command: commands.get(pid) || '' }));
  return { processes };
}

function homebrewFormula(realPath) { return /\/Cellar\/(node(?:@\d+)?)\//.exec(realPath)?.[1] || null; }
function classifySource(realPath, sources, home) {
  const manager = managerFor(realPath);
  if (manager) return manager.name;
  if (isVendor(realPath)) return 'vendor';
  if (homebrewFormula(realPath)) return 'homebrew';
  if (realPath.startsWith(join(home, '.local', 'allsorted-node') + '/')) return 'allsorted';
  for (const s of ['installer', 'home-bin', 'path', 'self']) if (sources.includes(s)) return s;
  return 'other';
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

/**
 * Which manager-installed version each manager selects by default. Returns a map
 * manager -> Set of version strings, or null for a manager whose default cannot be
 * resolved (callers then treat all its versions as active: fail safe).
 */
export function managerDefaults({ fs = defaultFs, home = homedir(), installed = {} } = {}) {
  const read = p => { try { return String(fs.readFile(p)).trim(); } catch { return null; } };
  const pick = (manager, spec) => {
    const versions = (installed[manager] || []).filter(v => parseVersion(v));
    if (!spec) return null;
    const clean = spec.replace(/^v/, '');
    if (/^\d+(\.\d+){0,2}$/.test(clean)) {
      const parts = clean.split('.').map(Number);
      const match = versions.filter(v => parseVersion(v).slice(0, parts.length).every((n, i) => n === parts[i])).sort(compareVersions).pop();
      return match ? new Set([match]) : new Set();
    }
    if (['node', 'stable', 'latest', 'current'].includes(clean)) { const top = versions.sort(compareVersions).pop(); return top ? new Set([top]) : new Set(); }
    return null;
  };
  const out = {};
  out.nvm = pick('nvm', read(join(home, '.nvm', 'alias', 'default')));
  try {
    const target = fs.realpath(join(home, '.local', 'share', 'fnm', 'aliases', 'default'));
    const v = managerFor(join(target, 'bin', 'node'))?.version || /node-versions\/(v[^/]+)/.exec(target)?.[1];
    out.fnm = v ? new Set([parseVersion(v) ? 'v' + parseVersion(v).join('.') : v]) : null;
  } catch {
    try {
      const target = fs.realpath(join(home, 'Library', 'Application Support', 'fnm', 'aliases', 'default'));
      const v = /node-versions\/(v[^/]+)/.exec(target)?.[1];
      out.fnm = v ? new Set([v]) : null;
    } catch { out.fnm = null; }
  }
  try { const p = JSON.parse(read(join(home, '.volta', 'tools', 'user', 'platform.json')) || 'null'); out.volta = p?.node?.runtime ? pick('volta', p.node.runtime) : null; } catch { out.volta = null; }
  const toolVersions = read(join(home, '.tool-versions'));
  const asdfSpec = toolVersions && /^nodejs\s+(\S+)/m.exec(toolVersions)?.[1];
  out.asdf = asdfSpec ? pick('asdf', asdfSpec) : null;
  out.n = new Set(); // n keeps a download cache; the active n install is copied to /usr/local/bin/node.
  return out;
}

// ---------- the check ----------

/**
 * Run the runtime advisory check. All side-effecting dependencies are injectable.
 * @returns {Promise<object>} report with runtimes, staleProcesses, findings, status, exitCode
 */
export async function checkRuntimes(options = {}) {
  const { exec = defaultExec, fs = defaultFs, env = process.env, home = homedir(), now = new Date(), platform = process.platform, arch = process.arch } = options;
  const execPath = options.execPath === undefined ? process.execPath : options.execPath;
  const report = { taskClass: 'runtime_advisories', checkedAt: now.toISOString(), status: 'incomplete', runtimes: [], staleProcesses: [], findings: [], issues: [], notes: [], sources: {} };
  let data;
  try {
    data = options.advisoryData || await loadAdvisoryData({ fetchImpl: options.fetchImpl, cache: options.cache, pace: options.pace, noCache: options.noCache });
    report.sources = data.sources || {};
    if (!data.schedule) report.issues.push('Release schedule unavailable; end-of-life status not checked.');
    for (const s of data.stale || []) report.notes.push(`Using the last good ${s.name} from ${s.fetchedAt || 'an earlier run'} (fetch failed: ${s.error}).`);
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
    if (!entry) { entry = { path: realPath, aliases: [], sources: [], inode: stat.ino, dev: stat.dev, pids: [], shim: false }; byIdentity.set(key, entry); }
    if (!entry.aliases.includes(path)) entry.aliases.push(path);
    if (!entry.sources.includes(source)) entry.sources.push(source);
    if (isShim(path, realPath)) entry.shim = true;
    return entry;
  };
  for (const { path, source } of candidatePaths({ fs, env, home, platform, execPath })) consider(path, source);

  let processScanIncomplete = false;
  if (platform === 'win32') report.notes.push('Process scan not supported on this platform; restart-needed detection skipped.');
  else {
    const running = options.processes ? { processes: options.processes } : runningNodeProcesses({ exec });
    if (running.issue) report.issues.push(running.issue);
    processScanIncomplete = running.incomplete === true;
    for (const proc of running.processes) {
      let current = null;
      try { current = fs.stat(proc.path); } catch { /* deleted after exec */ }
      if (!current || (Number.isFinite(proc.inode) && current.ino !== proc.inode)) {
        report.staleProcesses.push({ pid: proc.pid, path: proc.path, runningInode: proc.inode ?? null, currentInode: current?.ino ?? null, command: redactCommand(proc.command), vendorManaged: isVendor(proc.path), action: `Restart pid ${proc.pid}: it still runs the replaced (possibly vulnerable) binary at ${proc.path}.` });
        continue;
      }
      const entry = consider(proc.path, 'process');
      if (entry && !entry.pids.includes(proc.pid)) entry.pids.push(proc.pid);
    }
  }

  const entries = [...byIdentity.values()];
  for (const entry of entries) {
    if (entry.shim) continue; // A shim selects another binary; those are checked individually.
    const probe = (() => { try { return exec(entry.path, ['-v'], { timeout: PROBE_TIMEOUT_MS }); } catch (error) { return { status: null, error }; } })();
    const out = String(probe.stdout || '').trim();
    entry.version = probe.status === 0 && VERSION_RE.test(out) ? out : null;
    if (!entry.version) entry.probeError = probe.error?.code || probe.error?.message || (probe.signal ? 'killed by ' + probe.signal : 'exit ' + probe.status);
  }
  const brewFormulas = [...new Set(entries.map(e => homebrewFormula(e.path)).filter(Boolean))];
  const brewStable = options.homebrewStable || (brewFormulas.length ? homebrewStableVersions(brewFormulas, { exec }) : {});
  const installed = {};
  for (const e of entries) { const m = managerFor(e.path); if (m && e.version) (installed[m.name] ||= []).push(e.version); }
  const defaults = options.managerDefaults || managerDefaults({ fs, home, installed });

  for (const entry of entries) {
    const source = classifySource(entry.path, entry.sources, home);
    const runtime = { path: entry.path, aliases: entry.aliases.filter(a => a !== entry.path), source, version: entry.version || null, status: 'unknown', fixedIn: null, latestOnMajor: null, cves: [], pids: entry.pids.slice(0, 20), processCount: entry.pids.length };
    if (entry.shim) { runtime.status = 'shim'; runtime.reason = 'Version-manager shim; the versions it selects are checked individually.'; runtime.action = 'None.'; report.runtimes.push(runtime); continue; }
    if (!entry.version) { runtime.reason = 'Could not run `node -v`: ' + entry.probeError; runtime.action = 'Inspect or remove this broken binary.'; }
    else if (data?.index) {
      const assessment = assessVersion(entry.version, { index: data.index, schedule: data.schedule, vulnDb: data.vulnDb, now });
      Object.assign(runtime, { status: assessment.status, fixedIn: assessment.fixedIn || null, latestOnMajor: assessment.latestOnMajor, cves: assessment.cves || [], eolDate: assessment.eolDate, reason: assessment.reason });
    } else runtime.reason = 'Release index unavailable.';
    if (source === 'vendor') { runtime.versionStatus = runtime.status; runtime.status = 'vendor-managed'; }
    if (managerFor(entry.path) && runtime.version) {
      const selected = defaults[source];
      // Active = running, reachable on PATH, or the manager's default. Unknown default: active (fail safe).
      runtime.active = entry.pids.length > 0 || entry.sources.includes('path') || selected == null || selected.has(runtime.version);
    }
    runtime.action = runtime.action || recommendedAction(runtime, { brewStable, platform, arch });
    report.runtimes.push(runtime);
  }
  report.runtimes.sort((a, b) => a.path.localeCompare(b.path));

  for (const r of report.runtimes) {
    if (r.status === 'vulnerable' || r.status === 'eol') {
      const inactive = r.active === false;
      report.findings.push({ severity: inactive ? 'medium' : 'high', kind: (r.status === 'eol' ? 'runtime_eol' : 'runtime_vulnerable') + (inactive ? '_inactive' : ''), path: r.path, version: r.version, fixedIn: r.fixedIn, cves: r.cves, action: r.action });
    } else if (r.status === 'vendor-managed' && ['vulnerable', 'eol'].includes(r.versionStatus)) report.findings.push({ severity: 'info', kind: 'vendor_runtime_outdated', path: r.path, version: r.version, fixedIn: r.fixedIn, action: r.action });
  }
  for (const s of report.staleProcesses) report.findings.push({ severity: s.vendorManaged ? 'info' : 'medium', kind: 'restart_needed', path: s.path, pid: s.pid, action: s.action });

  // Status is settled before the optional Vercel step, so a stalled API can never mask a HIGH.
  report.highCount = report.findings.filter(f => f.severity === 'high').length;
  report.vulnerableCount = report.runtimes.filter(r => r.status === 'vulnerable').length;
  report.eolCount = report.runtimes.filter(r => r.status === 'eol').length;
  report.inactiveVulnerableCount = report.findings.filter(f => /_inactive$/.test(f.kind)).length;
  report.restartNeededCount = report.staleProcesses.length;
  if (report.runtimes.length === 0) report.issues.push('No Node runtimes found.');
  const missingEvidence = !data?.index || !data?.schedule || report.runtimes.length === 0 || processScanIncomplete;
  report.status = report.highCount ? 'dangerous' : missingEvidence ? 'incomplete' : 'complete';
  report.exitCode = report.status === 'dangerous' ? 1 : report.status === 'incomplete' ? 2 : 0;

  if (options.vercel !== false && env.VERCEL_TOKEN && data?.schedule) {
    let timer;
    try {
      report.vercel = await Promise.race([
        checkVercelProjects({ token: env.VERCEL_TOKEN, schedule: data.schedule, fetchImpl: options.fetchImpl || globalThis.fetch, now, timeoutMs: options.vercelTimeoutMs }),
        new Promise((_, reject) => { timer = setTimeout(() => reject(Error('Vercel check exceeded its time budget')), options.vercelBudgetMs ?? VERCEL_BUDGET_MS); })
      ]);
    } catch (error) { report.vercel = { status: 'unavailable', error: error.message, projects: [] }; }
    finally { clearTimeout(timer); }
  }
  return report;
}

function distTarget(platform, arch) {
  const os = platform === 'darwin' ? 'darwin' : platform === 'linux' ? 'linux' : null;
  const cpu = ['arm64', 'x64'].includes(arch) ? arch : null;
  return os && cpu ? `${os}-${cpu}` : null;
}

const MANAGER_COMMANDS = {
  nvm: (v, old) => [`nvm install ${v}`, `nvm alias default ${v}`, `nvm uninstall ${old}`],
  fnm: (v, old) => [`fnm install ${v}`, `fnm default ${v}`, `fnm uninstall ${old}`],
  volta: (v, old) => [`volta install node@${v}`, `rm -rf "$HOME/.volta/tools/image/node/${old}"`],
  asdf: (v, old) => [`asdf install nodejs ${v}`, `asdf global nodejs ${v}`, `asdf uninstall nodejs ${old}`],
  mise: (v, old) => [`mise install node@${v}`, `mise use -g node@${v}`, `mise uninstall node@${old}`],
  pnpm: (v, old) => [`pnpm env use --global ${v}`, `pnpm env remove --global ${old}`],
  n: (v, old) => [`n ${v}`, `n rm ${old}`]
};
function managerSteps(source, target, version) {
  const v = String(target).replace(/^v/, ''), old = String(version).replace(/^v/, '');
  if (!/^\d+\.\d+\.\d+$/.test(v) || !/^\d+\.\d+\.\d+$/.test(old)) return null;
  return MANAGER_COMMANDS[source]?.(v, old) || null;
}

export function recommendedAction(runtime, { brewStable = {}, platform = process.platform, arch = process.arch } = {}) {
  if (runtime.status === 'vendor-managed') return 'Vendor-managed: update the owning application; do not replace its bundled binary.';
  if (runtime.status === 'ok' || runtime.status === 'shim') return 'None.';
  if (runtime.status === 'unknown') return runtime.action || 'Verify this runtime manually.';
  const target = runtime.fixedIn || runtime.latestOnMajor;
  const major = runtime.version ? parseVersion(runtime.version)[0] : null;
  if (runtime.status === 'eol') return `Node ${major} is end of life: move to a supported LTS major and retire this binary.`;
  const formula = homebrewFormula(runtime.path);
  if (runtime.source === 'homebrew' && formula) {
    const stable = brewStable[formula];
    if (stable && parseVersion(stable) && compareVersions(stable, target) >= 0) return `brew update && brew upgrade ${formula}`;
    return `Homebrew ${formula} has not shipped ${target} yet (stable ${stable || 'unknown'}): install the verified official ${target} build to its own prefix and put it first on PATH (see --fix-plan); brew upgrade ${formula} when it ships.`;
  }
  const steps = managerSteps(runtime.source, target, runtime.version);
  if (steps) return (runtime.active === false ? `Installed but inactive: remove it with \`${steps[steps.length - 1]}\`, or upgrade: ` : '') + steps.join(' && ');
  return distTarget(platform, arch) ? `Replace with the verified official ${target} binary (see --fix-plan).` : `Upgrade to ${target} or later.`;
}

export function shellQuote(value) { return "'" + String(value).replace(/'/g, "'\\''") + "'"; }

/** Download and verify an official build inside one fail-fast block, leaving the tree in "$D". */
function verifiedDownload(v, target) {
  const tarball = `node-${v}-${target}.tar.gz`;
  const base = `https://nodejs.org/dist/${v}/`;
  return [
    'set -euo pipefail',
    'D="$(mktemp -d)"; cd "$D"',
    `curl -fsSLO ${shellQuote(base + tarball)}`,
    `curl -fsSLO ${shellQuote(base + 'SHASUMS256.txt')}`,
    `curl -fsSLO ${shellQuote(base + 'SHASUMS256.txt.sig')}`,
    '# Node.js release signing keys (nodejs/release-keys); gpgv comes with GnuPG (brew install gnupg).',
    `curl -fsSL ${shellQuote(RELEASE_KEYS_URL)} -o node-release-keys.kbx`,
    'gpgv --keyring "$PWD/node-release-keys.kbx" SHASUMS256.txt.sig SHASUMS256.txt',
    `grep ${shellQuote(' ' + tarball + '$')} SHASUMS256.txt | shasum -a 256 -c -`,
    `tar -xzf ${shellQuote(tarball)}`
  ];
}

/**
 * Exact commands for a human to review and run. Pure: never executes anything.
 * Each binary fix is one `set -euo pipefail` subshell so a failed signature or checksum
 * stops before anything is installed. Homebrew kegs are never overwritten: the verified
 * build goes to its own prefix (~/.local/node-vX.Y.Z) placed first on PATH.
 */
export function buildFixPlan(report, { platform = process.platform, arch = process.arch } = {}) {
  const lines = ['# MyOS Guard Dog runtime fix plan. Review before running; nothing has been executed.'];
  const target = distTarget(platform, arch);
  const backups = join(guardogHome(), 'runtime-backups');
  let steps = 0;
  for (const r of report.runtimes || []) {
    if (!['vulnerable', 'eol'].includes(r.status)) continue;
    steps++;
    const cves = (r.cves || []).filter(id => /^CVE-\d{4}-\d+$/.test(id));
    lines.push('', `# ${r.path.replace(/[\r\n]/g, ' ')} (${r.version}, ${r.status}${r.active === false ? ', installed but inactive' : ''}${cves.length ? ', ' + cves.join(' ') : ''})`);
    if (r.status === 'eol') { lines.push(`# ${r.action}`); continue; }
    const v = r.fixedIn || r.latestOnMajor;
    if (!VERSION_RE.test(String(v)) || !VERSION_RE.test(String(r.version))) { lines.push('# Version data is not a plain release number; fix manually.'); continue; }
    if (/^brew update && brew upgrade node(@\d+)?$/.test(r.action)) { lines.push(r.action); continue; }
    const mgr = managerSteps(r.source, v, r.version);
    if (mgr) { lines.push(r.active === false ? `${mgr[mgr.length - 1]}   # remove the inactive vulnerable version` : mgr.join(' && ')); continue; }
    if (!target) { lines.push(`# ${r.action}`); continue; }
    const tree = `node-${v}-${target}`;
    if (r.source === 'homebrew') {
      const prefix = `$HOME/.local/node-${v}`;
      lines.push('(', ...verifiedDownload(v, target),
        `rm -rf "${prefix}"; mkdir -p "$HOME/.local"; mv ${shellQuote(tree)} "${prefix}"`,
        `"${prefix}/bin/node" -v`,
        ')',
        `# Put it first on PATH (shell profile and any launchd/cron jobs): export PATH="${prefix}/bin:$PATH"`,
        `# The Homebrew keg ${r.path} stays vulnerable until \`brew upgrade\` ships ${v}; the keg is left untouched.`);
      continue;
    }
    const bin = shellQuote(r.path);
    lines.push('(', ...verifiedDownload(v, target),
      `mkdir -p ${shellQuote(backups)}`,
      `cp -p ${bin} ${shellQuote(join(backups, basename(r.path) + '-' + r.version + '-' + r.path.replace(/[^A-Za-z0-9]+/g, '_')))}`,
      `install -m 0755 ${shellQuote(tree + '/bin/node')} ${bin}`,
      `${bin} -v`,
      ')');
  }
  for (const s of report.staleProcesses || []) {
    if (!steps) lines.push('');
    steps++;
    lines.push(`# Restart needed: pid ${Number(s.pid)} runs a replaced binary (${String(s.path).replace(/[\r\n]/g, ' ')})${s.command ? ': ' + redactCommand(s.command).replace(/[\r\n]/g, ' ') : ''}`);
    lines.push(`#   restart the owning app or service; or, if safe: kill -TERM ${Number(s.pid)}`);
  }
  if (!steps) lines.push('', '# No action needed.');
  return lines.join('\n');
}

/** Report-only check of Vercel project Node versions. Runs only with a VERCEL_TOKEN. */
export async function checkVercelProjects({ token, schedule, fetchImpl = globalThis.fetch, now = new Date(), timeoutMs = VERCEL_TIMEOUT_MS }) {
  const today = now.toISOString().slice(0, 10);
  const supported = Object.entries(schedule).filter(([, e]) => (!e.start || e.start <= today) && e.end >= today).map(([m]) => Number(m));
  const oldest = supported.length ? Math.min(...supported) : null;
  const call = async url => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetchImpl(url, { headers: { authorization: 'Bearer ' + token }, signal: controller.signal });
      if (!response.ok) throw Error('Vercel HTTP ' + response.status);
      return await response.json();
    } finally { clearTimeout(timer); }
  };
  const scopes = [{ id: null, name: 'personal' }];
  const errors = [];
  try { for (const t of (await call('https://api.vercel.com/v2/teams')).teams || []) scopes.push({ id: t.id, name: t.slug || t.name }); }
  catch (error) { errors.push('teams: ' + error.message); }
  const projects = [];
  for (const scope of scopes) {
    try {
      let next = null;
      for (let page = 0; page < 20; page++) {
        const url = 'https://api.vercel.com/v9/projects?limit=100' + (scope.id ? '&teamId=' + encodeURIComponent(scope.id) : '') + (next ? '&until=' + encodeURIComponent(next) : '');
        const data = await call(url);
        for (const p of data.projects || []) {
          const major = Number(/^(\d+)/.exec(String(p.nodeVersion || ''))?.[1]);
          const eol = Number.isFinite(major) && schedule[String(major)] && schedule[String(major)].end < today;
          const tooOld = Number.isFinite(major) && oldest !== null && major < oldest;
          projects.push({ scope: scope.name, name: p.name, nodeVersion: p.nodeVersion || null, flagged: Boolean(eol || tooOld), reason: eol || tooOld ? `Node ${major}.x is end of life; move to ${oldest}.x or newer.` : null });
        }
        const following = data.pagination?.next;
        if (!following || following === next) break;
        next = following;
      }
    } catch (error) { errors.push(`${scope.name}: ${error.message}`); }
  }
  return { status: errors.length ? 'partial' : 'complete', errors, oldestSupportedMajor: oldest, flaggedCount: projects.filter(p => p.flagged).length, projects };
}

/** Human-readable report. */
export function formatRuntimeReport(report) {
  const lines = ['MyOS Guard Dog runtime advisories', '─'.repeat(60)];
  for (const r of report.runtimes) {
    const label = r.status === 'ok' ? 'OK' : r.status.toUpperCase() + (r.active === false && ['vulnerable', 'eol'].includes(r.status) ? ' (inactive)' : '');
    lines.push(`${label.padEnd(15)} ${r.version || '?'}  ${r.path}${r.processCount ? `  (${r.processCount} running)` : ''}`);
    if (!['ok', 'shim'].includes(r.status)) {
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
    for (const e of report.vercel.errors || []) lines.push(`  error: ${e}`);
  }
  for (const note of report.notes || []) lines.push('Note: ' + note);
  for (const issue of report.issues) lines.push('Issue: ' + issue);
  lines.push('─'.repeat(60), `Result: ${report.status} (${report.highCount} high, ${report.restartNeededCount} restart needed). Binaries are never modified; use --fix-plan for commands.`);
  return lines.join('\n');
}

/** CLI entry: `myos-guard-dog runtime [--json] [--fix-plan] [--no-cache] [--no-vercel]`. */
export async function runtimeCommand(args = [], options = {}) {
  const report = await checkRuntimes({ ...options, noCache: args.includes('--no-cache'), vercel: args.includes('--no-vercel') ? false : options.vercel });
  const out = options.log || console.log;
  if (args.includes('--json')) out(JSON.stringify(args.includes('--fix-plan') ? { ...report, fixPlan: buildFixPlan(report) } : report));
  else if (args.includes('--fix-plan')) out(buildFixPlan(report));
  else out(formatRuntimeReport(report));
  return report.exitCode;
}

/** Spawn the runtime check as a child for synchronous callers (nightly). Retries once without Vercel. */
export function runRuntimeCheckSync({ run = spawnSync, timeoutMs = 120000, script } = {}) {
  const attempt = (extra, timeout) => {
    const result = run(process.execPath, [script, 'runtime', '--json', ...extra], { encoding: 'utf8', timeout, killSignal: 'SIGKILL', maxBuffer: 8 * 1024 * 1024, windowsHide: true });
    try {
      const report = JSON.parse(result.stdout);
      if (report.taskClass !== 'runtime_advisories') throw Error('unexpected output');
      return { report };
    } catch { return { error: result.error?.message || String(result.stderr || '').slice(0, 300) || 'no report' }; }
  };
  const started = Date.now();
  const first = attempt([], Math.max(1, Math.floor(timeoutMs * 0.6)));
  if (first.report) return first.report;
  const second = attempt(['--no-vercel'], Math.max(1, timeoutMs - (Date.now() - started)));
  if (second.report) { second.report.issues = [...(second.report.issues || []), 'First runtime check attempt failed (' + first.error + '); reran without the optional Vercel step.']; return second.report; }
  return { taskClass: 'runtime_advisories', status: 'incomplete', exitCode: 2, runtimes: [], staleProcesses: [], findings: [], highCount: 0, issues: ['Runtime advisory check failed: ' + second.error] };
}
