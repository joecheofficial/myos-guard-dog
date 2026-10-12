import { createHash } from 'node:crypto';
import { inspectNpmArtifact } from './npm-artifact-inspector.js';

const packageName = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/i;
const exactVersion = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const maximumBytes = 50 * 1024 * 1024;

export function parseExactNpmSpec(spec) {
  if (!spec.startsWith('npm:')) throw new Error('Expected npm:<name>@<exact-version>');
  const value = spec.slice(4);
  const at = value.lastIndexOf('@');
  const name = value.slice(0, at);
  const version = value.slice(at + 1);
  if (at < 1 || !packageName.test(name) || !exactVersion.test(version)) throw new Error('Expected npm:<name>@<exact-version>');
  return { name, version };
}

async function readBounded(response) {
  if (!response.ok || !response.body) throw new Error(`Registry artifact unavailable (HTTP ${response.status})`);
  const chunks = [];
  let total = 0;
  for await (const chunk of response.body) {
    total += chunk.length;
    if (total > maximumBytes) throw new Error('Registry artifact exceeds the 50 MB scan limit');
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

/** Fetch an exact public npm release and verify its registry digest before static inspection. */
export async function inspectExactNpmRelease(spec, fetcher = fetch) {
  const { name, version } = parseExactNpmSpec(spec);
  const metadataUrl = `https://registry.npmjs.org/${encodeURIComponent(name)}/${encodeURIComponent(version)}`;
  const metadataResponse = await fetcher(metadataUrl, { signal: AbortSignal.timeout(30_000), redirect: 'error' });
  if (!metadataResponse.ok) throw new Error(`Exact npm release unavailable (HTTP ${metadataResponse.status})`);
  const metadata = await metadataResponse.json();
  if (metadata?.name !== name || metadata?.version !== version) throw new Error('Registry release identity mismatch');
  const tarball = new URL(metadata?.dist?.tarball);
  if (tarball.protocol !== 'https:' || tarball.hostname !== 'registry.npmjs.org' || tarball.port || tarball.username || tarball.password) {
    throw new Error('Registry artifact is not on the approved npm host');
  }
  const integrity = /^(sha512|sha256)-([A-Za-z0-9+/]+={0,2})$/.exec(metadata?.dist?.integrity || '');
  if (!integrity) throw new Error('Registry release lacks a strong single artifact digest');
  const bytes = await readBounded(await fetcher(tarball.href, { signal: AbortSignal.timeout(30_000), redirect: 'error' }));
  if (createHash(integrity[1]).update(bytes).digest('base64') !== integrity[2]) throw new Error('Registry artifact digest mismatch');
  return { source: 'verified_npm_registry', packageName: name, version,
    sha256: createHash('sha256').update(bytes).digest('hex'),
    ...inspectNpmArtifact(bytes, { expectName: name, expectVersion: version }) };
}
