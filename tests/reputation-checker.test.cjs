const test = require('node:test');
const assert = require('node:assert/strict');

test('normalizes npm git protocol GitHub repositories to HTTPS', async () => {
  const { ReputationChecker } = await import('../src/reputation-checker.js');
  const checker = new ReputationChecker({ reputation: {} });

  assert.equal(
    checker.parseRepository({ type: 'git', url: 'git://github.com/motdotla/dotenv.git' }),
    'https://github.com/motdotla/dotenv'
  );
});
