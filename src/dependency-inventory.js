import { existsSync, readFileSync, realpathSync, readdirSync } from 'node:fs';
import { dirname, join, relative, resolve, isAbsolute } from 'node:path';

const exactVersion = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const packageName = /^(?:@[a-z0-9_.-]+\/)?[a-z0-9_.-]+$/i;
const nonRegistrySpec = /^(?:git(?:\+[^:]+)?:|github:|file:|link:|workspace:|https?:)/i;
const registryOrigin = resolved => {
  try {
    const url = new URL(resolved);
    return url.protocol === 'https:' && url.hostname === 'registry.npmjs.org' && !url.port && !url.username && !url.password;
  } catch { return false; }
};

/** Collect exact npm identities; never turn an unresolved audit into a latest check. */
export function collectDependencies(manifestPath) {
  const root = realpathSync(dirname(resolve(manifestPath)));
  const issues = [];
  const packages = new Map();
  const safePath = value => {
    const path = resolve(root, value);
    const rel = relative(root, path);
    if (rel.startsWith('..') || isAbsolute(rel)) throw new Error(`Path outside project: ${value}`);
    if (existsSync(path)) {
      const actual = relative(root, realpathSync(path));
      if (actual.startsWith('..') || isAbsolute(actual)) throw new Error(`Link outside project: ${value}`);
    }
    return path;
  };
  const read = value => JSON.parse(readFileSync(safePath(value), 'utf8'));
  const add = (name, version, provenance, location) => {
    if (!packageName.test(name || '') || !exactVersion.test(version || '')) {
      issues.push(`Unresolved package at ${location}: ${name || 'unknown'}@${version || 'unknown'}`);
      return;
    }
    const key = `${name}@${version}`;
    if (!packages.has(key)) packages.set(key, { name, ecosystem: 'npm', version, provenance, locations: [] });
    packages.get(key).locations.push(location);
  };
  let manifest;
  try { manifest = read('package.json'); } catch (error) {
    return { packages: [], issues: [error.message], complete: false };
  }
  const direct = { ...manifest.dependencies, ...manifest.devDependencies, ...manifest.optionalDependencies };
  for (const [name, spec] of Object.entries(direct)) {
    if (typeof spec === 'string' && nonRegistrySpec.test(spec)) issues.push(`Non-registry direct dependency cannot be audited as a registry package: ${name}`);
  }
  const lockName = ['npm-shrinkwrap.json', 'package-lock.json'].find(name => existsSync(join(root, name)));
  const lockedLocations = new Set();
  const useEntry = (location, entry, inferredName) => {
    try {
      safePath(location);
      lockedLocations.add(location);
      if (entry.link) {
        safePath(entry.resolved || location);
        issues.push(`Linked or local dependency cannot be audited as a registry package: ${location}`);
        return;
      }
      if (entry.inBundle || entry.bundled || !registryOrigin(entry.resolved)) {
        issues.push(`Non-registry or unproven dependency origin: ${location}`);
        return;
      }
      const metadataPath = `${location}/package.json`;
      if (existsSync(join(root, metadataPath))) {
        const installed = read(metadataPath);
        if (installed.name !== (entry.name || inferredName) || installed.version !== entry.version) {
          issues.push(`Installed identity differs from ${lockName}: ${location}`);
        }
        add(installed.name, installed.version, 'installed', location);
      } else {
        add(entry.name || inferredName, entry.version, lockName, location);
      }
    } catch (error) { issues.push(error.message); }
  };
  if (lockName) {
    try {
      const lock = read(lockName);
      if ([2, 3].includes(lock.lockfileVersion) && lock.packages && typeof lock.packages === 'object') {
        for (const [location, entry] of Object.entries(lock.packages)) {
          if (!location || !location.includes('node_modules/')) continue;
          const name = location.slice(location.lastIndexOf('node_modules/') + 13);
          useEntry(location, entry, name);
        }
      } else if (lock.lockfileVersion === 1 && lock.dependencies) {
        const walk = (deps, prefix = '') => {
          for (const [name, entry] of Object.entries(deps)) {
            const location = `${prefix}node_modules/${name}`;
            useEntry(location, entry, name);
            if (entry.dependencies) walk(entry.dependencies, `${location}/`);
          }
        };
        walk(lock.dependencies);
      } else { issues.push(`Unsupported or malformed ${lockName}`); }
    } catch (error) { issues.push(`Cannot read ${lockName}: ${error.message}`); }
  }
  // Discover actual installed packages, including extraneous and nested dependencies.
  const visited = new Set();
  const walkInstalled = location => {
    try {
      const directory = safePath(location);
      if (!existsSync(directory)) return;
      const real = realpathSync(directory);
      if (visited.has(real)) return;
      visited.add(real);
      for (const entry of readdirSync(directory, { withFileTypes: true })) {
        if (entry.name.startsWith('.')) continue;
        const child = `${location}/${entry.name}`;
        if (entry.name.startsWith('@')) { walkInstalled(child); continue; }
        if (!entry.isDirectory() && !entry.isSymbolicLink()) continue;
        try {
          const metadata = read(`${child}/package.json`);
          if (!lockedLocations.has(child)) {
            issues.push(`Installed dependency has no proven registry lock origin: ${child}`);
            add(metadata.name, metadata.version, 'installed', child);
          }
          walkInstalled(`${child}/node_modules`);
        } catch (error) { issues.push(`Cannot inspect ${child}: ${error.message}`); }
      }
    } catch (error) { issues.push(error.message); }
  };
  walkInstalled('node_modules');
  for (const name of Object.keys(direct)) {
    if (!lockedLocations.has(`node_modules/${name}`) && !existsSync(join(root, 'node_modules', name, 'package.json'))) {
      issues.push(`No exact installed or locked version for ${name}`);
    }
  }
  if (!lockName && Object.keys(direct).length > 0 && packages.size === 0) {
    issues.push('No npm lockfile or installed dependency inventory is available');
  }
  return { packages: [...packages.values()], issues, complete: issues.length === 0 };
}
