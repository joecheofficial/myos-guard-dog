import { chmodSync, existsSync, readFileSync, writeFileSync, statSync } from 'fs';
import { join, resolve } from 'path';
import { registerSchedule, unregisterSchedule, shellQuote } from './scheduler.js';
import { checkHealth } from './health.js';
import { recordResilienceCycle } from './resilience-loop.js';
import { spawnSync } from 'child_process';
import os from 'os';
import readline from 'readline/promises';
import { Writable } from 'node:stream';
import { stdin as input, stdout as output } from 'process';

import {
  ensureGuardogHome,
  guardogConfigPath,
  guardogEnvPath,
  guardogHome,
  packageRoot
} from './paths.js';

const DEFAULT_CONFIG = {
  nightlyUpdates: false,
  nightlyTime: '00:00',
  scanRoots: [],
  gitPreCommitHook: false,
  virustotalConfigured: false
};


function readJson(path, fallback) {
  try {
    const value = JSON.parse(readFileSync(path, 'utf-8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Expected a JSON object');
    return value;
  } catch (error) {
    if (error.code === 'ENOENT') return fallback;
    throw new Error(`Cannot read MyOS Guard Dog config at ${path}. Existing file was preserved: ${error.message}`);
  }
}

export function loadUserConfig() {
  const config = {
    ...DEFAULT_CONFIG,
    ...readJson(guardogConfigPath(), {})
  };
  delete config.guardedInstalls;
  return config;
}

export function saveUserConfig(config) {
  ensureGuardogHome();
  const nextConfig = { ...DEFAULT_CONFIG, ...config };
  delete nextConfig.guardedInstalls;
  writeFileSync(guardogConfigPath(), JSON.stringify(nextConfig, null, 2));
}

function yes(answer) {
  return /^(y|yes)$/i.test(answer.trim());
}

function hasVirusTotalKey() {
  if (process.env.VIRUSTOTAL_API_KEY) return true;
  if (!existsSync(guardogEnvPath())) return false;
  return /^VIRUSTOTAL_API_KEY=.+$/m.test(readFileSync(guardogEnvPath(), 'utf-8'));
}

export function saveVirusTotalKey(apiKey) {
  const value = apiKey.trim();
  if (!value) return false;

  ensureGuardogHome();
  const envPath = guardogEnvPath();
  const existing = existsSync(envPath) ? readFileSync(envPath, 'utf-8') : '';
  const lines = existing
    .split(/\r?\n/)
    .filter(line => line && !line.startsWith('VIRUSTOTAL_API_KEY='));
  lines.push(`VIRUSTOTAL_API_KEY=${value}`);
  writeFileSync(envPath, `${lines.join(os.EOL)}${os.EOL}`, { mode: 0o600 });
  chmodSync(envPath, 0o600);
  return true;
}

export function runQuickSetup() {
  ensureGuardogHome();
  const config = {
    ...loadUserConfig(),
    virustotalConfigured: hasVirusTotalKey()
  };
  saveUserConfig(config);
  const health = checkHealth({ repair: true, checkLastRun: false });
  const resilience = recordResilienceCycle({ phase: 'install', health });

  console.log('\nMyOS Guard Dog quick setup complete.');
  console.log('OSV needs no API key. Run myos-guard-dog test to verify connectivity.');
  console.log('No background job or global git hook was installed or changed.');
  console.log('Add a VirusTotal key with myos-guard-dog setup for malware coverage and guarded installs.');
  console.log('Use myos-guard-dog install for supported npm installs with lifecycle scripts disabled.');
  console.log('Try it: `myos-guard-dog analyze lodash npm`');
  if (!resilience.lastOperational) console.log('Setup is installed but protection is incomplete. Run myos-guard-dog doctor --json for the next action.');
  return config;
}

export function renderGitHook(source, options = {}) {
  const root = options.root || packageRoot();
  const node = options.node || process.execPath;
  return source
    .replace(/^GUARD_DOG_DIR=.*$/m, `GUARD_DOG_DIR=${shellQuote(root)}`)
    .replace(/^NODE_BIN=.*$/m, `NODE_BIN=${shellQuote(node)}`);
}

export function installGitHook() {
  const root = packageRoot();
  const hookSource = join(root, 'bin', 'git-precommit-hook.sh');
  if (process.platform === 'win32') {
    return {
      ok: false,
      message: 'Global git pre-commit hook install is skipped on Windows. Use myos-guard-dog install before dependency installs.'
    };
  }
  if (!existsSync(hookSource)) {
    return { ok: false, message: `Missing hook source: ${hookSource}` };
  }
  const hooksDir = join(guardogHome(), 'hooks');
  const hookDest = join(hooksDir, 'pre-commit');
  const existing = spawnSync('git', ['config', '--global', '--get', 'core.hooksPath'], { encoding: 'utf-8' });
  const existingPath = existing.status === 0 ? existing.stdout.trim() : '';
  if (existingPath && existingPath !== hooksDir) {
    return {
      ok: false,
      message: `Existing global git hooksPath is set to ${existingPath}. MyOS Guard Dog did not overwrite it.`
    };
  }
  const script = renderGitHook(readFileSync(hookSource, 'utf-8'), { root, node: process.execPath });
  writeFileSync(hookDest, script);
  spawnSync('chmod', ['+x', hookDest], { stdio: 'ignore' });
  const result = spawnSync('git', ['config', '--global', 'core.hooksPath', hooksDir], { encoding: 'utf-8' });
  if (result.status !== 0) {
    return { ok: false, message: result.stderr || 'git config failed' };
  }
  return { ok: true, message: `Git pre-commit hook installed at ${hookDest}` };
}

export function removeGitHook() {
  if (process.platform === 'win32') {
    return { ok: true, message: 'No Windows global git hook was installed by MyOS Guard Dog.' };
  }
  const hooksDir = join(guardogHome(), 'hooks');
  const existing = spawnSync('git', ['config', '--global', '--get', 'core.hooksPath'], { encoding: 'utf-8' });
  const existingPath = existing.status === 0 ? existing.stdout.trim() : '';
  if (existingPath !== hooksDir) {
    return { ok: true, message: 'MyOS Guard Dog is not the active global git hooksPath.' };
  }
  const result = spawnSync('git', ['config', '--global', '--unset', 'core.hooksPath'], { encoding: 'utf-8' });
  return {
    ok: result.status === 0,
    message: result.status === 0 ? 'MyOS Guard Dog global git hook disabled.' : result.stderr || 'git config unset failed'
  };
}

export function installNightlySchedule(config = loadUserConfig(), options = {}) {
  ensureGuardogHome();
  const scanRoots = config.scanRoots?.length ? config.scanRoots : process.env.GUARDOG_WORKSPACE ? [resolve(process.env.GUARDOG_WORKSPACE)] : [];
  if (!scanRoots.length) return { ok: false, message: 'Choose a scan root first: myos-guard-dog setup, or set GUARDOG_WORKSPACE.' };
  if (!Array.isArray(scanRoots) || scanRoots.some(root => {
    try { return typeof root !== 'string' || !statSync(root).isDirectory(); } catch { return true; }
  })) return { ok: false, message: 'Every scan root must be an available directory before enabling nightly scans.' };
  const next = { ...config, scanRoots };
  const result = registerSchedule(next, options);
  if (result.ok) saveUserConfig({ ...next, nightlyUpdates: true });
  return result;
}

export function removeNightlySchedule(options = {}) {
  const config = loadUserConfig();
  const result = unregisterSchedule(config, options);
  if (result.ok) saveUserConfig({ ...config, nightlyUpdates: false });
  return result;
}

export async function readHiddenKey(terminalInput = input, terminalOutput = output) {
  if (!terminalInput.isTTY || !terminalOutput.isTTY) return null;
  let muted = false;
  const hiddenOutput = new Writable({ write(chunk, encoding, callback) {
    if (!muted) terminalOutput.write(chunk, encoding);
    callback();
  } });
  const secretReader = readline.createInterface({ input: terminalInput, output: hiddenOutput, terminal: true });
  terminalOutput.write('VirusTotal API key (hidden, press Enter to skip): ');
  muted = true;
  try { return await secretReader.question(''); }
  finally {
    secretReader.close();
    terminalInput.pause();
    terminalOutput.write('\n');
  }
}

export async function runSetup(options = {}) {
  ensureGuardogHome();
  const config = loadUserConfig();
  const failures = [];

  console.log('\nMyOS Guard Dog setup');
  console.log(`State folder: ${guardogHome()}`);
  console.log('MyOS Guard Dog checks public package and security databases. It does not use AI tokens.');
  console.log('OSV works immediately with no account or key. Nothing runs in the background unless you opt in.\n');

  const vtKey = await readHiddenKey(options.input || input, options.output || output);
  if (vtKey === null) console.log(`Non-interactive input: set VIRUSTOTAL_API_KEY locally in your environment or ${guardogEnvPath()}. Do not paste keys into chat.`);
  if (vtKey?.trim()) {
    config.virustotalConfigured = saveVirusTotalKey(vtKey);
    console.log(`Saved VirusTotal key to ${guardogEnvPath()}`);
  } else {
    config.virustotalConfigured = hasVirusTotalKey();
    console.log('VirusTotal skipped. OSV and the other checks still work.');
  }

  const rl = options.question ? null : readline.createInterface({ input: options.input || input, output: options.output || output });
  const question = options.question || (prompt => rl.question(prompt));
  try {
  const advanced = await question('Set up optional nightly scans or a global git hook? [y/N] ');
  if (yes(advanced)) {
    const nightly = await question('Run MyOS Guard Dog every night at midnight? [y/N] ');
    const enableNightly = yes(nightly);
    if (enableNightly) {
      const root = await question(`Project folder to scan nightly [${process.cwd()}]: `);
      config.scanRoots = [resolve(root.trim() || process.cwd())];
    }
    const nightlyResult = enableNightly ? (options.installSchedule || installNightlySchedule)(config) : (options.removeSchedule || removeNightlySchedule)();
    if (nightlyResult.ok) config.nightlyUpdates = enableNightly;
    else failures.push(nightlyResult.message);
    console.log(nightlyResult.ok ? `OK: ${nightlyResult.message}` : `Skipped: ${nightlyResult.message}`);

    const hook = await question('Install a global git pre-commit dependency scan hook? [y/N] ');
    const enableHook = yes(hook);
    const hookResult = enableHook ? (options.installHook || installGitHook)() : (options.removeHook || removeGitHook)();
    if (hookResult.ok) config.gitPreCommitHook = enableHook;
    else failures.push(hookResult.message);
    console.log(hookResult.ok ? `OK: ${hookResult.message}` : `Skipped: ${hookResult.message}`);
  } else {
    console.log('No background job or global git hook changes were made.');
  }

  saveUserConfig(config);
  } finally { rl?.close(); }

  const health = checkHealth({ ...options.healthOptions, repair: true, checkLastRun: false });
  recordResilienceCycle({ phase: 'install', health });

  if (failures.length) {
    const error = new Error(`MyOS Guard Dog setup incomplete: ${failures.join('; ')}`);
    error.exitCode = 2;
    throw error;
  }

  console.log('\nMyOS Guard Dog setup complete.');
  console.log('Try it: `myos-guard-dog analyze lodash npm`');
  return { status: 'complete', config };
}

export function printDoctor(options = {}) {
  const health = checkHealth(options);
  const checks = [
    ['Node', process.version],
    ['Platform', `${process.platform} ${process.arch}`],
    ['State folder', guardogHome()],
    ['Config', existsSync(guardogConfigPath()) ? guardogConfigPath() : 'missing'],
    ['OSV', health.osv],
    ['VirusTotal', health.virusTotal],
    ['Nightly schedule', `${health.schedule.state}: ${health.schedule.detail}`],
    ['Scan roots', health.scanRoots.join(', ') || 'not selected'],
    ['Last nightly scan', health.lastRun ? `${health.lastRun.finishedAt}: ${health.lastRun.status}, ${health.lastRun.dependencyCount} dependencies` : 'never verified'],
    ['External notifications', 'none']
  ];
  console.log('\nMyOS Guard Dog doctor');
  for (const [label, value] of checks) {
    console.log(`${label}: ${value}`);
  }
  console.log('\nInstall checks: myos-guard-dog install <package> for supported npm installs. Unsupported installers stay blocked.');
  for (const repair of health.repairs) console.log(`Repaired: ${repair}`);
  for (const issue of health.issues) console.log(`Attention: ${issue}`);
  return health;
}
