import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { ensureGuardogHome, guardogHome, packageRoot } from './paths.js';
import { childEnvironment, windowsSystemTool } from './windows-process.js';

export const CRON_MARKER = '# guardog-nightly';
const LEGACY_CRON_MARKERS = [CRON_MARKER, '# guarddog-nightly'];
const TASK = 'GuardogNightlyScan';
const RUNNER_HEADER = '// MyOS Guard Dog owned runner. taskClass=security_scan\n';
const LEGACY_RUNNER_HEADER = '// Guardog owned runner. taskClass=security_scan\n';
const callOptions = { encoding: 'utf8', timeout: 10000, windowsHide: true, shell: false };
const commandOptions = () => ({ ...callOptions, env: childEnvironment() });
export const shellQuote = value => `'${String(value).replaceAll("'", "'\\''")}'`;
const xmlText = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&apos;');

export function runnerSource(spec) {
  return `${RUNNER_HEADER}process.env.GUARDOG_HOME = ${JSON.stringify(spec.home)};\ndelete process.env.GUARDOG_WORKSPACE;\nconst r = require('node:child_process').spawnSync(${JSON.stringify(spec.node)}, [${JSON.stringify(join(spec.root, 'bin', 'nightly-scan.js'))}], {stdio:'inherit', env:process.env, windowsHide:true, timeout:7200000});\nprocess.exit(r.status ?? 2);\n`;
}

export function inspectRunner(spec) {
  if (!existsSync(spec.runner)) return { state: 'missing', ok: false };
  try {
    const source = readFileSync(spec.runner, 'utf8');
    if (source === runnerSource(spec)) return { state: 'ready', ok: true };
    return { state: source.startsWith(RUNNER_HEADER) || source.startsWith(LEGACY_RUNNER_HEADER) ? 'stale' : 'conflict', ok: false };
  } catch { return { state: 'unknown', ok: false }; }
}

export function repairRunner(spec) {
  const observed = inspectRunner(spec);
  if (observed.ok) return { ok: true, changed: false };
  if (['conflict', 'unknown'].includes(observed.state)) return { ok: false, message: 'Runner file is not a recognized MyOS Guard Dog file; it was preserved.' };
  if (observed.state === 'stale') writeFileSync(spec.runner + '.' + Date.now() + '.backup', readFileSync(spec.runner), { flag: 'wx', mode: 0o600 });
  writeFileSync(spec.runner, runnerSource(spec), { mode: 0o600 });
  return { ok: true, changed: true };
}

export function scheduleSpec(config = {}, options = {}) {
  const platform = options.platform || process.platform;
  const home = options.home || guardogHome();
  const node = options.node || process.execPath;
  const root = options.root || packageRoot();
  const time = config.nightlyTime || '00:00';
  if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(time)) throw new Error('Nightly time must be HH:MM (local time).');
  const runner = join(home, 'bin', 'nightly-runner.cjs');
  const [hour, minute] = time.split(':').map(Number);
  const command = `${shellQuote(node)} ${shellQuote(runner)}`;
  if ([node, runner, home].some(value => /[\r\n\0]/.test(value))) throw new Error('Schedule paths cannot contain line breaks.');
  // crontab processes percent characters even inside shell quotes.
  const line = `${minute} ${hour} * * * ${command} >> ${shellQuote(join(home, 'data', 'logs', 'nightly.log'))} 2>&1 ${CRON_MARKER}`.replaceAll('%', '\\%');
  const taskCommand = `"${node}" "${runner}"`;
  const xml = `<?xml version="1.0" encoding="UTF-16"?><Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><RegistrationInfo><Description>MyOS Guard Dog nightly scan taskClass=security_scan</Description></RegistrationInfo><Triggers><CalendarTrigger><StartBoundary>2020-01-01T${time}:00</StartBoundary><Enabled>true</Enabled><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger></Triggers><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><StartWhenAvailable>true</StartWhenAvailable><ExecutionTimeLimit>PT2H</ExecutionTimeLimit></Settings><Actions><Exec><Command>${xmlText(node)}</Command><Arguments>${xmlText(`"${runner}"`)}</Arguments></Exec></Actions></Task>`;
  return { platform, home, node, root, runner, time, line, taskCommand, xml };
}

export function inspectSchedule(config = {}, options = {}) {
  const spec = scheduleSpec(config, options);
  const run = options.run || spawnSync;
  if (spec.platform === 'win32') {
    const result = run(windowsSystemTool('schtasks.exe'), ['/Query', '/TN', TASK, '/XML'], commandOptions());
    if (result.status === 0) {
      const text = result.stdout || '';
      const decode = value => value.replaceAll('&quot;', '"').replaceAll('&apos;', "'").replaceAll('&lt;', '<').replaceAll('&gt;', '>').replaceAll('&amp;', '&');
      const argument = text.match(/<Arguments>\s*([\s\S]*?)\s*<\/Arguments>/)?.[1] || '';
      const executable = text.match(/<Command>\s*([\s\S]*?)\s*<\/Command>/)?.[1] || '';
      const owned = decode(argument) === `"${spec.runner}"`;
      const triggers = text.match(/<Triggers>\s*([\s\S]*?)\s*<\/Triggers>/)?.[1] || '';
      const calendar = triggers.match(/^<CalendarTrigger(?:\s[^>]*)?>\s*([\s\S]*?)\s*<\/CalendarTrigger>$/)?.[1] || '';
      const daily = /<ScheduleByDay>\s*<DaysInterval>1<\/DaysInterval>\s*<\/ScheduleByDay>/.test(calendar) && !/<ScheduleBy(?:Week|Month)/.test(calendar);
      const oneAction = (text.match(/<Exec(?:\s[^>]*)?>/g) || []).length === 1;
      const current = owned && oneAction && decode(executable) === spec.node && daily && calendar.includes(`T${spec.time}:00`) && !/<Enabled>\s*false\s*<\/Enabled>/.test(text);
      return { state: !owned ? 'conflict' : current ? 'registered' : 'stale', registered: current, detail: !owned ? 'The task name belongs to another command.' : current ? 'Task Scheduler registration found.' : 'Task Scheduler action, time, or enabled state differs from current settings.' };
    }
    const listing = run(windowsSystemTool('schtasks.exe'), ['/Query', '/FO', 'CSV', '/NH'], commandOptions());
    if (listing.status === 0 && !(listing.stdout || '').includes(TASK)) return { state: 'missing', registered: false, detail: 'No MyOS Guard Dog scheduled task.' };
    return { state: 'unknown', registered: false, detail: result.error?.message || result.stderr || 'Cannot inspect Task Scheduler.' };
  }
  const result = run('crontab', ['-l'], commandOptions());
  if (result.status !== 0) {
    if (result.status === 1 && /no crontab for/i.test(result.stderr || '')) return { state: 'missing', registered: false, detail: 'No user crontab.' };
    return { state: 'unknown', registered: false, detail: result.error?.message || result.stderr || 'Cannot inspect crontab.' };
  }
  const lines = result.stdout.split('\n').filter(line => LEGACY_CRON_MARKERS.some(marker => line.trim().endsWith(marker)));
  if (lines.length === 0) return { state: 'missing', registered: false, detail: 'No MyOS Guard Dog cron entry.' };
  const registered = lines.length === 1 && lines[0] === spec.line;
  return { state: registered ? 'registered' : 'stale', registered, detail: registered ? `Cron registered for ${spec.time} local time.` : 'MyOS Guard Dog cron entry differs from current settings.' };
}

export function registerSchedule(config = {}, options = {}) {
  const run = options.run || spawnSync;
  const spec = scheduleSpec(config, options);
  const observed = inspectSchedule(config, options);
  if (['unknown', 'conflict'].includes(observed.state)) return { ok: false, message: observed.detail };
  if (observed.state === 'stale') {
    return { ok: false, message: 'A customized or stale Guard Dog schedule already exists and was preserved. Remove it explicitly before enabling a replacement.' };
  }
  ensureGuardogHome();
  const repaired = repairRunner(spec);
  if (!repaired.ok) return repaired;
  let result;
  if (spec.platform === 'win32') {
    const xmlPath = join(spec.home, 'bin', 'nightly-task.xml');
    writeFileSync(xmlPath, '\ufeff' + spec.xml, 'utf16le');
    result = run(windowsSystemTool('schtasks.exe'), ['/Create', '/TN', TASK, '/XML', xmlPath, '/F'], commandOptions());
  } else {
    const existing = run('crontab', ['-l'], commandOptions());
    if (existing.status !== 0 && !(existing.status === 1 && /no crontab for/i.test(existing.stderr || ''))) return { ok: false, message: 'Cannot safely read existing crontab.' };
    const lines = (existing.stdout || '').split('\n').filter(line => !line.trim().endsWith(CRON_MARKER));
    result = run('crontab', ['-'], { ...commandOptions(), input: [...lines, spec.line, ''].join('\n') });
  }
  if (result.status !== 0) return { ok: false, message: result.error?.message || result.stderr || result.stdout || 'Schedule registration failed.' };
  const checked = inspectSchedule(config, options);
  return { ok: checked.registered, message: checked.registered ? `Nightly scan registered for ${spec.time} local time.` : `Registration not verified: ${checked.detail}` };
}

export function unregisterSchedule(config = {}, options = {}) {
  const run = options.run || spawnSync;
  const spec = scheduleSpec(config, options);
  const observed = inspectSchedule(config, options);
  if (observed.state === 'missing') return { ok: true, message: 'No MyOS Guard Dog schedule exists.' };
  if (['unknown', 'conflict'].includes(observed.state)) return { ok: false, message: observed.detail };
  if (observed.state === 'stale') {
    return { ok: false, message: 'A customized or stale Guard Dog schedule was preserved. Remove it manually after reviewing the command.' };
  }
  let result;
  if (spec.platform === 'win32') result = run(windowsSystemTool('schtasks.exe'), ['/Delete', '/TN', TASK, '/F'], commandOptions());
  else {
    const existing = run('crontab', ['-l'], commandOptions());
    if (existing.status !== 0) return { ok: false, message: 'Cannot safely read existing crontab.' };
    result = run('crontab', ['-'], { ...commandOptions(), input: existing.stdout.split('\n').filter(line => !line.trim().endsWith(CRON_MARKER)).join('\n') + '\n' });
  }
  const removed = result.status === 0 && inspectSchedule(config, options).state === 'missing';
  return { ok: removed, message: removed ? 'MyOS Guard Dog nightly schedule removed.' : result.stderr || 'Schedule removal not verified.' };
}
