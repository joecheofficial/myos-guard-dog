import { spawnSync } from 'node:child_process';
import { accessSync, constants, lstatSync, opendirSync, realpathSync } from 'node:fs';
import { join, relative, resolve, isAbsolute, sep } from 'node:path';

const DAY = 86400000;
const ENGINE_ENV = Object.freeze({ PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C', TZ: 'UTC' });
const outside = value => value === '..' || value.startsWith('..' + sep) || isAbsolute(value);
const controlCharacters = /[\u0000-\u001f\u007f]/;
const INVENTORY_LIMITS = Object.freeze({ maxDepth: 30, maxEntries: 50000, maxFiles: 20000, maxFileBytes: 25 * 1024 * 1024, maxTotalBytes: 128 * 1024 * 1024, timeoutMs: 10000 });

// clamscan can return success after silently skipping a directory at its depth
// limit. Independently account for filesystem boundaries before trusting exit 0.
function inspectEngineScope(root, coverage, issue) {
  const limits = coverage.limits;
  const started = Date.now();
  const pending = [{ directory: root, depth: 0 }];
  let stopped = false;
  const budget = () => {
    if (Date.now() - started >= limits.timeoutMs) { issue('ClamAV inventory time limit reached.'); return false; }
    if (coverage.entriesVisited >= limits.maxEntries) { issue('ClamAV inventory entry limit reached.'); return false; }
    return true;
  };
  while (pending.length && !stopped) {
    if (!budget()) break;
    const { directory, depth } = pending.pop();
    let opened;
    try {
      if (!lstatSync(directory).isDirectory() || lstatSync(directory).isSymbolicLink() || outside(relative(root, realpathSync(directory)))) throw new Error();
      opened = opendirSync(directory);
      let entry;
      while ((entry = opened.readSync())) {
        if (!budget()) { stopped = true; break; }
        coverage.entriesVisited++;
        if (controlCharacters.test(entry.name)) { issue('ClamAV inventory encountered an unsafe filename.'); continue; }
        const file = join(directory, entry.name);
        let stat;
        try { stat = lstatSync(file); } catch { coverage.unreadableEntries++; issue('ClamAV inventory contains unreadable or changing entries.'); continue; }
        if (stat.isSymbolicLink()) { coverage.symlinksSkipped++; issue('ClamAV skipped symbolic links; their targets were not scanned.'); continue; }
        if (stat.isDirectory()) {
          if (entry.name === '.git') { coverage.excludedDirectories++; continue; }
          if (depth + 1 >= limits.maxDepth) { coverage.depthLimited++; issue('ClamAV directory depth limit leaves part of the requested tree unscanned.'); continue; }
          pending.push({ directory: file, depth: depth + 1 });
          continue;
        }
        if (!stat.isFile()) { coverage.specialFilesSkipped++; issue('ClamAV skipped special files; their contents were not scanned.'); continue; }
        try { accessSync(file, constants.R_OK); } catch { coverage.unreadableEntries++; issue('ClamAV inventory contains unreadable files.'); }
        if (coverage.filesInspected >= limits.maxFiles) { issue('ClamAV inventory file limit reached.'); stopped = true; break; }
        coverage.filesInspected++;
        coverage.bytesInspected += stat.size;
        if (stat.size > limits.maxFileBytes) { coverage.oversizedFiles++; issue('ClamAV file size limit leaves oversized files incompletely scanned.'); }
        if (coverage.bytesInspected > limits.maxTotalBytes) { issue('ClamAV inventory byte limit reached.'); stopped = true; break; }
      }
    } catch { coverage.unreadableEntries++; issue('ClamAV inventory contains an unreadable or changing directory.'); }
    finally { if (opened) { try { opened.closeSync(); } catch { issue('ClamAV inventory directory could not be closed cleanly.'); } } }
  }
  if (coverage.filesInspected === 0) issue('ClamAV inventory contains no regular files to scan.');
}

function safeFindingPath(root, candidate) {
  if (!isAbsolute(candidate) || controlCharacters.test(candidate)) return null;
  const file = resolve(candidate);
  const rel = relative(root, file);
  if (!rel || outside(rel)) return null;
  let current = root;
  const segments = rel.split(sep);
  if (segments.includes('.git')) return null;
  for (let index = 0; index < segments.length; index++) {
    current = join(current, segments[index]);
    const stat = lstatSync(current);
    if (stat.isSymbolicLink() || (index === segments.length - 1 ? !stat.isFile() : !stat.isDirectory())) return null;
  }
  if (outside(relative(root, realpathSync(file)))) return null;
  return segments.join('/');
}

/** Explicit offline signature scanning. No engine discovery, downloads or project code execution. */
export function scanWithClamAV({ root, executable, timeoutMs = 120000, maxOutputBytes = 2097152, now = Date.now(), run = spawnSync } = {}) {
  const result = {
    id: 'clamav', status: 'incomplete', findings: [], issues: [],
    scope: { excludedDirectories: ['.git'], symlinks: 'never followed', network: false, databaseUpdates: 'never automatic', inventory: 'bounded preflight metadata, not a proof that every byte was analyzed' },
    coverage: { complete: true, filesInspected: 0, bytesInspected: 0, entriesVisited: 0, excludedDirectories: 0, symlinksSkipped: 0, specialFilesSkipped: 0, oversizedFiles: 0, depthLimited: 0, unreadableEntries: 0, limits: { ...INVENTORY_LIMITS } },
  };
  const issue = message => { result.coverage.complete = false; if (!result.issues.includes(message)) result.issues.push(message); };
  let scanRoot;
  let engine;
  try {
    if (typeof root !== 'string' || !root || controlCharacters.test(root) || !lstatSync(root).isDirectory()) throw new Error();
    scanRoot = realpathSync(root);
    if (typeof executable !== 'string' || !isAbsolute(executable) || controlCharacters.test(executable)) throw new Error();
    engine = realpathSync(executable);
    if (!lstatSync(engine).isFile() || !outside(relative(scanRoot, engine))) throw new Error();
    accessSync(engine, constants.X_OK);
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 3600000 || !Number.isSafeInteger(maxOutputBytes) || maxOutputBytes <= 0 || maxOutputBytes > 16777216 || !Number.isFinite(now) || typeof run !== 'function') throw new Error();
  } catch {
    issue('ClamAV requires an available scan directory, an absolute executable outside that directory, and valid bounded options.');
    return result;
  }
  inspectEngineScope(scanRoot, result.coverage, issue);
  const options = { encoding: 'utf8', shell: false, windowsHide: true, timeout: timeoutMs, maxBuffer: maxOutputBytes, killSignal: 'SIGKILL', cwd: '/', env: { ...ENGINE_ENV } };
  function invoke(args) {
    try {
      const response = run(engine, args, options);
      if (!response || typeof response !== 'object') { issue('ClamAV returned an invalid process result.'); return {}; }
      if (response.error || response.signal || response.status === null) issue('ClamAV execution failed, exceeded its time or output limit, or was interrupted.');
      if ((response.stderr || '').length) issue('ClamAV emitted diagnostics; coverage needs review.');
      if (typeof response.stdout !== 'string') {
        issue('ClamAV output was missing, malformed, or exceeded its limit.');
        return { ...response, stdout: '' };
      }
      if (Buffer.byteLength(response.stdout) > maxOutputBytes) {
        issue('ClamAV output exceeded its limit; only complete bounded detection lines were retained.');
        const bounded = Buffer.from(response.stdout).subarray(0, maxOutputBytes).toString('utf8');
        return { ...response, stdout: bounded.slice(0, bounded.lastIndexOf('\n') + 1) };
      }
      return response;
    } catch {
      issue('ClamAV could not be executed.');
      return {};
    }
  }
  const version = invoke(['--version']);
  const metadata = version.status === 0 && typeof version.stdout === 'string'
    ? version.stdout.trim().match(/^ClamAV (\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?)\/\d+\/([^\r\n]+)$/)
    : null;
  if (!metadata) issue('ClamAV engine version and signature database freshness could not be verified.');
  else {
    result.version = metadata[1].split(/[-+]/)[0];
    // The subprocess timezone is UTC, so ClamAV's timestamp has an unambiguous zone.
    const updated = Date.parse(metadata[2] + ' UTC');
    if (!Number.isFinite(updated)) issue('ClamAV signature database timestamp could not be parsed.');
    else {
      result.databaseUpdatedAt = new Date(updated).toISOString();
      if (now - updated > 7 * DAY || updated - now > DAY) issue('ClamAV signature database is older than seven days or has an invalid future timestamp.');
    }
  }
  // Preserve detections even if the version or database freshness check failed.
  const scan = invoke([
    '--recursive', '--infected', '--no-summary', '--follow-dir-symlinks=0', '--follow-file-symlinks=0',
    '--max-scansize=100M', '--max-filesize=25M', '--max-recursion=20', '--max-dir-recursion=30',
    '--max-files=10000', '--alert-exceeds-max=yes', String.raw`--exclude-dir=(^|[/\\])\.git([/\\]|$)`, '--', scanRoot,
  ]);
  const seen = new Set();
  let detectionLines = 0;
  for (const line of (scan.stdout || '').split(/\r?\n/)) {
    if (!line.trim()) continue;
    const match = line.match(/^(.*): ([^\r\n]+) FOUND$/);
    if (!match) { issue('ClamAV emitted unrecognized scan output; coverage could not be verified.'); continue; }
    detectionLines++;
    if (/^Heuristics\.Limits\.Exceeded(?:\.|$)/.test(match[2])) {
      issue('ClamAV reached a file or archive scan limit; coverage is incomplete.');
      continue;
    }
    let file;
    try { file = safeFindingPath(scanRoot, match[1]); } catch { file = null; }
    if (!file) { issue('ClamAV reported a path that could not be verified as a regular file inside the scan root.'); continue; }
    if (seen.has(file)) continue;
    seen.add(file);
    result.findings.push({ ruleId: 'GD-CLAMAV', path: file, severity: 'high', confidence: 'high', category: 'malware', message: 'ClamAV detected a malware signature in this file.' });
  }
  if (![0, 1].includes(scan.status) || (scan.status === 0 && detectionLines > 0) || (scan.status === 1 && detectionLines === 0)) issue('ClamAV exit status did not confirm a complete, consistent scan.');
  result.status = result.issues.length ? 'incomplete' : 'complete';
  return result;
}
