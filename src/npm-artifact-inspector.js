import { gunzipSync } from 'node:zlib';
import { posix } from 'node:path';

const DEFAULT_LIMITS = Object.freeze({ compressed: 50 * 1024 * 1024, expanded: 128 * 1024 * 1024, entries: 10_000, textFile: 1024 * 1024, totalText: 12 * 1024 * 1024 });
const textDecoder = new TextDecoder('utf-8', { fatal: true });
const lifecycleNames = ['preinstall', 'install', 'postinstall', 'prepublish', 'prepublishOnly', 'prepare', 'postprepare'];
const sourceFile = /\.(?:js|cjs|mjs|ts|tsx|jsx|mts|cts)$/i;
const executableFile = /\.(?:node|exe|dll|so|dylib|wasm)$/i;
const scriptFile = /\.(?:sh|bash|zsh|ps1|bat|cmd|py|rb|pl)$/i;
const passiveFile = /\.(?:md|markdown|txt|json|map)$/i;

function field(header, start, length) {
  return header.subarray(start, start + length).toString('utf8').replace(/\0.*$/s, '');
}

function octal(header, start, length) {
  const value = field(header, start, length).trim();
  if (!/^[0-7]+$/.test(value)) throw new Error('Malformed tar numeric field');
  const number = Number.parseInt(value, 8);
  if (!Number.isSafeInteger(number)) throw new Error('Tar numeric field exceeds safe limits');
  return number;
}

function verifiedHeader(header) {
  const expected = octal(header, 148, 8);
  let actual = 0;
  for (let i = 0; i < 512; i++) actual += i >= 148 && i < 156 ? 32 : header[i];
  if (actual !== expected) throw new Error('Tar header checksum mismatch');
}

function paxPath(bytes) {
  let offset = 0, path = null;
  while (offset < bytes.length) {
    const space = bytes.indexOf(32, offset);
    if (space < 0) throw new Error('Malformed PAX header');
    const length = Number(bytes.subarray(offset, space).toString('ascii'));
    if (!Number.isSafeInteger(length) || length < 4 || offset + length > bytes.length) throw new Error('Malformed PAX record length');
    const record = textDecoder.decode(bytes.subarray(space + 1, offset + length));
    if (!record.endsWith('\n')) throw new Error('Malformed PAX record');
    const equal = record.indexOf('=');
    if (equal < 0) throw new Error('Malformed PAX key');
    const key = record.slice(0, equal);
    if (key === 'path') path = record.slice(equal + 1, -1);
    if (key === 'size') throw new Error('PAX size overrides are not supported');
    offset += length;
  }
  return path;
}

function safeName(name) {
  if (!name || name.includes('\\') || name.includes('\0') || name.startsWith('/') || name.includes(':')) throw new Error('Unsafe archive entry path');
  const normalized = posix.normalize(name);
  if (!normalized.startsWith('package/') || normalized.includes('/../') || normalized.endsWith('/..')) throw new Error('Archive entry is outside package/');
  for (const segment of normalized.split('/')) {
    if (/[. ]$/.test(segment) || /^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i.test(segment)) {
      throw new Error('Archive entry has a platform-ambiguous path');
    }
  }
  return normalized;
}

function addFinding(findings, file, rule, severity) {
  findings.push({ file, rule, severity });
}

function entrypointPath(value) {
  if (typeof value !== 'string' || !value) return null;
  const path = value.replace(/^\.\//, '');
  if (path === 'package.json') return null;
  return safeName(`package/${path}`);
}

function collectEntrypoints(manifest, paths) {
  for (const value of [manifest.main, manifest.module]) {
    const path = entrypointPath(value);
    if (path) paths.add(path);
  }
  const bins = typeof manifest.bin === 'string' ? [manifest.bin] : Object.values(manifest.bin || {});
  for (const value of bins) {
    const path = entrypointPath(value);
    if (path) paths.add(path);
  }
  const walk = (value, depth = 0) => {
    if (depth > 12) throw new Error('Package exports nesting exceeds scan limit');
    if (typeof value === 'string') {
      if (value.startsWith('./')) {
        const path = entrypointPath(value);
        if (path) paths.add(path);
      }
    } else if (value && typeof value === 'object') {
      for (const child of Object.values(value)) walk(child, depth + 1);
    }
  };
  walk(manifest.exports);
}

function inspectScript(findings, name, script) {
  if (typeof script !== 'string') throw new Error(`Invalid ${name} lifecycle script`);
  addFinding(findings, 'package/package.json', `${name} lifecycle script is present; guarded installs disable scripts`, 'info');
  if (/(?:curl|wget|Invoke-WebRequest|iwr)\b[^\n|]{0,300}\|\s*(?:sh|bash|node|powershell|pwsh)\b/i.test(script)
      || /\b(?:node|powershell|pwsh)\s+-e\b[^\n]{0,300}(?:base64|fromCharCode|atob)/i.test(script)) {
    addFinding(findings, 'package/package.json', `${name} runs downloaded or encoded code`, 'high');
  }
}

function maskNonCode(text) {
  const output = [...text];
  let mode = 'code';
  for (let i = 0; i < text.length; i++) {
    const char = text[i], next = text[i + 1];
    if (mode === 'code') {
      if (char === '/' && next === '/') { mode = 'line'; output[i] = output[++i] = ' '; }
      else if (char === '/' && next === '*') { mode = 'block'; output[i] = output[++i] = ' '; }
      else if (char === "'" || char === '"' || char === '`') { mode = char; output[i] = ' '; }
    } else if (mode === 'line') {
      if (char === '\n') mode = 'code';
      else output[i] = ' ';
    } else if (mode === 'block') {
      if (char === '*' && next === '/') { output[i] = output[++i] = ' '; mode = 'code'; }
      else if (char !== '\n') output[i] = ' ';
    } else {
      output[i] = char === '\n' ? '\n' : ' ';
      if (char === '\\') { if (i + 1 < text.length) output[++i] = ' '; }
      else if (char === mode) mode = 'code';
    }
  }
  return output.join('');
}

function inspectSource(findings, name, text) {
  const code = maskNonCode(text);
  const credentialCall = /\b(?:readFileSync|readFile|openSync|createReadStream)\s*\(/gi;
  let credentialRead = false, match;
  while ((match = credentialCall.exec(code)) !== null) {
    if (/(?:\.npmrc|\.aws[\\/]credentials|\.ssh[\\/](?:id_|config))/i.test(text.slice(match.index, match.index + 180))) credentialRead = true;
  }
  const tokenVariable = /process\.env\s*\.\s*[A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD)/i.test(code);
  const outbound = /(?:\bfetch\s*\(|\bhttps?\s*\.\s*(?:request|get)\s*\(|\baxios\s*\(|\bXMLHttpRequest\b|\bWebSocket\s*\()/i.test(code);
  if (credentialRead && outbound) addFinding(findings, name, 'Credential file read and outbound network capability occur in one file', 'high');
  else if (tokenVariable && outbound) addFinding(findings, name, 'Token-like environment access and outbound network capability occur in one file', 'review');
  if (/\b(?:eval|Function)\s*\(\s*(?:Buffer\.from\s*\(|atob\s*\(|String\.fromCharCode\s*\()/i.test(code)) {
    addFinding(findings, name, 'Encoded code is passed to dynamic execution', 'high');
  }
}

/** Inspect bytes only: never extract an archive or execute package code. */
export function inspectNpmArtifact(input, limits = {}) {
  const cap = { ...DEFAULT_LIMITS, ...limits };
  const compressed = Buffer.isBuffer(input) ? input : Buffer.from(input);
  if (compressed.length > cap.compressed) throw new Error('Package archive exceeds compressed scan limit');
  let tar;
  try { tar = gunzipSync(compressed, { maxOutputLength: cap.expanded }); }
  catch (error) { throw new Error(`Cannot safely expand npm archive: ${error.message}`); }
  const findings = [];
  let offset = 0, entries = 0, textBytes = 0, sourceFiles = 0, manifest = false, pendingPath = null;
  const entrypoints = new Set();
  const seenFiles = new Set();
  const seenNames = new Map();
  let truncated = false;
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every(byte => byte === 0)) break;
    if (++entries > cap.entries) throw new Error('Package archive has too many entries');
    verifiedHeader(header);
    const size = octal(header, 124, 12);
    const start = offset + 512;
    const end = start + size;
    if (end > tar.length) throw new Error('Truncated tar entry');
    const type = field(header, 156, 1) || '0';
    const rawName = field(header, 345, 155) ? `${field(header, 345, 155)}/${field(header, 0, 100)}` : field(header, 0, 100);
    if (type === 'x') {
      pendingPath = paxPath(tar.subarray(start, end));
    } else {
      const name = safeName(pendingPath || rawName);
      pendingPath = null;
      const collisionKey = name.normalize('NFKC').toLowerCase();
      if (seenNames.has(collisionKey)) throw new Error(`Archive paths collide on case-insensitive filesystems: ${seenNames.get(collisionKey)} and ${name}`);
      seenNames.set(collisionKey, name);
      if (type === '0') seenFiles.add(name);
      if (type === '1' || type === '2') addFinding(findings, name, 'Archive contains a link entry that static source inspection cannot follow', 'incomplete');
      else if (type !== '0' && type !== '5') addFinding(findings, name, `Unsupported tar entry type ${type}`, 'incomplete');
      else if (type === '0' && name === 'package/package.json') {
        if (manifest || size > cap.textFile) throw new Error('Missing, repeated, or oversized package manifest');
        const parsed = JSON.parse(textDecoder.decode(tar.subarray(start, end)));
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Invalid package manifest');
        if (limits.expectName && parsed.name !== limits.expectName) throw new Error('Archive package name differs from registry identity');
        if (limits.expectVersion && parsed.version !== limits.expectVersion) throw new Error('Archive package version differs from registry identity');
        manifest = true;
        collectEntrypoints(parsed, entrypoints);
        for (const key of lifecycleNames) {
          if (Object.hasOwn(parsed.scripts || {}, key)) inspectScript(findings, key, parsed.scripts[key]);
        }
      } else if (type === '0' && sourceFile.test(name)) {
        if (size > cap.textFile || textBytes + size > cap.totalText) truncated = true;
        else {
          textBytes += size;
          sourceFiles++;
          try { inspectSource(findings, name, textDecoder.decode(tar.subarray(start, end))); }
          catch { truncated = true; }
        }
      } else if (type === '0' && executableFile.test(name)) {
        addFinding(findings, name, 'Native or WebAssembly executable is outside static text inspection', 'incomplete');
      } else if (type === '0' && (scriptFile.test(name) || tar.subarray(start, Math.min(end, start + 2)).toString('ascii') === '#!')) {
        addFinding(findings, name, 'Executable script is outside JavaScript text inspection', 'incomplete');
      }
    }
    offset = start + Math.ceil(size / 512) * 512;
  }
  if (!manifest) throw new Error('npm archive has no package/package.json');
  for (const path of entrypoints) {
    const matches = path.includes('*')
      ? [...seenFiles].filter(file => new RegExp(`^${path.split('*').map(piece => piece.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`).test(file))
      : seenFiles.has(path) ? [path] : [];
    if (matches.length === 0) addFinding(findings, path, 'Declared package entrypoint is absent from the archive', 'incomplete');
    for (const match of matches) {
      if (!sourceFile.test(match) && !(path.includes('*') && passiveFile.test(match))) {
        addFinding(findings, match, 'Declared package entrypoint is outside JavaScript text inspection', 'incomplete');
      }
    }
  }
  if (truncated) addFinding(findings, 'package/', 'Some source files exceeded bounded text scan limits', 'incomplete');
  const incomplete = findings.some(item => item.severity === 'incomplete');
  const risk = findings.some(item => item.severity === 'high') ? 'high'
    : incomplete ? 'incomplete'
      : findings.some(item => item.severity === 'review') ? 'review' : 'none';
  return { risk, sourceFiles, entries, findings, coverage: incomplete ? 'incomplete' : 'bounded_source_scan' };
}
