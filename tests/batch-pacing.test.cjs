const test = require('node:test');
const assert = require('node:assert/strict');

test('batch leaves VirusTotal pacing to the shared request queue', async () => {
  const { GuardDog } = await import('../src/index.js');
  const delays = [];
  const original = global.setTimeout;
  global.setTimeout = (callback, delay) => { delays.push(delay); callback(); };
  try {
    await GuardDog.prototype.batchAnalyze.call({ scanner: {}, analyze: async () => ({ decision: { action: 'SILENT', coverage: 'complete', installAllowed: true } }) }, [{ name: 'fixture', version: '1.0.0' }]);
    assert.ok(delays.every(delay => delay <= 250), 'do not double-charge package and request pacing');
  } finally { global.setTimeout = original; }
});

test('batch analyzes concurrently with a bounded pool and preserves input order', async () => {
  const { GuardDog } = await import('../src/index.js');
  const packages = Array.from({ length: 9 }, (_, i) => ({ name: `fixture-${i}`, version: '1.0.0' }));
  let active = 0;
  let peak = 0;
  const delays = [];
  const original = global.setTimeout;
  global.setTimeout = (callback, delay) => { delays.push(delay); callback(); };
  try {
    const results = await GuardDog.prototype.batchAnalyze.call({ scanner: {}, analyze: async name => {
      active++;
      peak = Math.max(peak, active);
      await Promise.resolve();
      active--;
      return { name, decision: { action: 'SILENT', coverage: 'complete', installAllowed: true } };
    } }, packages);
    assert.ok(peak > 1, 'more than one package should be analyzed at a time');
    assert.ok(peak <= 4, 'concurrency must remain bounded');
    assert.deepEqual(results.map(result => result.name), packages.map(pkg => pkg.name));
    assert.ok(delays.every(delay => delay <= 250));
  } finally { global.setTimeout = original; }
});
