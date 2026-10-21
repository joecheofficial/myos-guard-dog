// Explicit release probe, excluded from the offline *.test.cjs suite.
// Uses only harmless fixtures. The CI caller disables the network namespace.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { gzipSync } = require('node:zlib');
(async () => {
  const { scanWithClamAV } = await import('../src/workspace-engines.js');
  const executable = process.env.CLAMAV_EXECUTABLE;
  assert.ok(executable && path.isAbsolute(executable), 'Explicit installed engine is required');
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'guarddog-live-'));
  const checks = [];
  const fixture = name => { const root = path.join(base, name); fs.mkdirSync(root); return root; };
  const scan = (root, options = {}) => scanWithClamAV({ root, executable, ...options });
  const eicar = Buffer.from('X5O!P%@AP[4' + String.fromCharCode(92) + 'PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*');
  try {
    const clean = fixture('benign'); fs.writeFileSync(path.join(clean, 'readme.txt'), 'Ordinary project documentation.');
    const cleanResult = scan(clean); assert.equal(cleanResult.status, 'complete', JSON.stringify(cleanResult.issues)); assert.equal(cleanResult.findings.length, 0); checks.push('benign');
    const infected = fixture('eicar'); fs.writeFileSync(path.join(infected, 'sample.txt'), eicar);
    const detected = scan(infected); assert.equal(detected.status, 'complete', JSON.stringify(detected.issues)); assert.equal(detected.findings.length, 1); checks.push('eicar');
    const archived = fixture('archive'); fs.writeFileSync(path.join(archived, 'sample.gz'), gzipSync(eicar));
    const archiveResult = scan(archived); assert.equal(archiveResult.status, 'complete', JSON.stringify(archiveResult.issues)); assert.equal(archiveResult.findings.length, 1); checks.push('gzip-eicar');
    const nested = fixture('nested'); let deep = nested;
    for (let i = 0; i < 32; i++) { deep = path.join(deep, 'd'); fs.mkdirSync(deep); }
    fs.writeFileSync(path.join(deep, 'sample.txt'), eicar);
    assert.equal(scan(nested).status, 'incomplete'); checks.push('depth-limit');
    const oversized = fixture('oversized'); const file = path.join(oversized, 'large.bin'); fs.writeFileSync(file, ''); fs.truncateSync(file, 26 * 1024 * 1024);
    assert.equal(scan(oversized).status, 'incomplete'); checks.push('size-limit');
    const stale = scan(infected, { now: Date.now() + 9 * 86400000 });
    assert.equal(stale.status, 'incomplete'); assert.equal(stale.findings.length, 1); checks.push('stale-clock-preserves-detection');
    assert.equal(scan(clean, { executable: path.join(base, 'missing') }).status, 'incomplete'); checks.push('missing-engine');
    assert.equal(scan(clean, { timeoutMs: 1 }).status, 'incomplete'); checks.push('timeout');
    const linkRoot = fixture('symlink'); fs.symlinkSync(path.join(infected, 'sample.txt'), path.join(linkRoot, 'link.txt'));
    const links = scan(linkRoot); assert.equal(links.status, 'incomplete'); assert.equal(links.findings.length, 0); checks.push('symlink');
    assert.deepEqual(fs.readFileSync(path.join(infected, 'sample.txt')), eicar); checks.push('detection-preserves-file');
    console.log(JSON.stringify({ status: 'verified', engineVersion: cleanResult.version, databaseUpdatedAt: cleanResult.databaseUpdatedAt, platform: process.platform, node: process.version, checks }, null, 2));
  } finally { fs.rmSync(base, { recursive: true, force: true }); }
})().catch(error => { console.error(error); process.exitCode = 1; });
