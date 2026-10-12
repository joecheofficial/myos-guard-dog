import { win32 } from 'node:path';

/** Resolve Windows system helpers without searching the caller's working directory. */
export function windowsSystemTool(name, root = process.env.SystemRoot || process.env.windir) {
  // The fallback supports platform-mocked tests; real Windows must supply its root.
  if (!root && process.platform !== 'win32') root = 'C:\\Windows';
  if (!root || !win32.isAbsolute(root) || /[\r\n\0]/.test(root)) {
    throw new Error('Cannot resolve the Windows system directory safely.');
  }
  return win32.join(root, 'System32', name);
}

/** Guard Dog credentials are never needed by npm or operating-system helpers. */
export function childEnvironment() {
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (/^(VIRUSTOTAL_API_KEY|GITHUB_API_TOKEN|GITHUB_TOKEN)$/i.test(key)) delete env[key];
  }
  return env;
}
