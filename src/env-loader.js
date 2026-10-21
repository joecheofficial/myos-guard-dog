import { readFileSync } from 'node:fs';
import { parseEnv } from 'node:util';

// Native parseEnv accepts some malformed lines by ignoring them. Reject those
// before applying any values, without including secret contents in diagnostics.
function validateEnvironment(text) {
  const lines = text.replace(/^\uFEFF/, '').split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index].trim();
    if (!line || line.startsWith('#')) continue;
    const assignment = line.match(/^(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*(.*)$/);
    if (!assignment) throw new Error(`Invalid environment assignment on line ${index + 1}`);
    let value = assignment[1];
    const quote = value[0];
    if (quote !== '"' && quote !== "'") continue;
    let end = value.indexOf(quote, 1);
    while (end === -1 && index + 1 < lines.length) {
      value += `\n${lines[++index]}`;
      end = value.indexOf(quote, 1);
    }
    if (end === -1 || !/^(?:\s*#.*)?\s*$/.test(value.slice(end + 1))) {
      throw new Error('Invalid quoted environment value');
    }
  }
}

/** Load an optional env file atomically. Errors never expose its values. */
export function loadEnvFile(path, { override = false, environment = process.env } = {}) {
  let text;
  try { text = readFileSync(path, 'utf8'); }
  catch (error) {
    if (error.code === 'ENOENT') return false;
    throw new Error(`Cannot read MyOS Guard Dog environment file ${path} (${error.code || 'read error'})`);
  }
  let parsed;
  try { validateEnvironment(text); parsed = parseEnv(text); }
  catch { throw new Error(`Invalid MyOS Guard Dog environment file ${path}; existing environment was preserved`); }
  for (const [key, value] of Object.entries(parsed)) {
    if (override || !Object.hasOwn(environment, key)) environment[key] = value;
  }
  return true;
}
