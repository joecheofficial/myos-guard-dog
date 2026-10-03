const assert = require('node:assert/strict');
const test = require('node:test');

test('runtime accepts Node 22 and 24, refuses others', async () => {
  const { assertSupportedNodeVersion } = await import('../src/node-version.js');
  assert.doesNotThrow(() => assertSupportedNodeVersion('24.0.0'));
  assert.doesNotThrow(() => assertSupportedNodeVersion('24.99.1'));
  assert.doesNotThrow(() => assertSupportedNodeVersion('22.22.0'));
  assert.throws(() => assertSupportedNodeVersion('26.0.0'), /Node\.js 22\.x or 24\.x is required/);
  assert.throws(() => assertSupportedNodeVersion('not-a-version'), /Node\.js 22\.x or 24\.x is required/);
});
