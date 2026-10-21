const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

test('quota recovers an abandoned legacy lock and writes a complete ledger', async () => {
  const { VirusTotalQuota } = await import('../src/virustotal-quota.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-quota-'));
  const previous = process.env.GUARDOG_HOME;
  process.env.GUARDOG_HOME = root;
  const ledger = path.join(root, 'quota.json');
  const lock = ledger + '.lock';
  fs.writeFileSync(lock, '');
  const old = new Date(Date.now() - 10 * 60_000);
  fs.utimesSync(lock, old, old);
  try {
    const quota = new VirusTotalQuota({ limit: 1, path: ledger });
    assert.equal(quota.reserve().allowed, true);
    assert.equal(quota.reserve().allowed, false);
    assert.equal(JSON.parse(fs.readFileSync(ledger, 'utf8')).used, 1);
    assert.equal(fs.existsSync(lock), false);
    assert.equal(fs.readdirSync(root).some(name => name.endsWith('.tmp')), false);
  } finally {
    if (previous === undefined) delete process.env.GUARDOG_HOME; else process.env.GUARDOG_HOME = previous;
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('corrupt quota ledgers fail closed', async () => {
  const { VirusTotalQuota } = await import('../src/virustotal-quota.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-quota-corrupt-'));
  const previous = process.env.GUARDOG_HOME;
  process.env.GUARDOG_HOME = root;
  const ledger = path.join(root, 'quota.json');
  fs.writeFileSync(ledger, '{broken');
  try {
    const quota = new VirusTotalQuota({ limit: 1, path: ledger });
    assert.throws(() => quota.reserve(), /corrupt/);
    assert.equal(fs.readFileSync(ledger, 'utf8'), '{broken');
    assert.equal(fs.existsSync(ledger + '.lock'), false);
  } finally {
    if (previous === undefined) delete process.env.GUARDOG_HOME; else process.env.GUARDOG_HOME = previous;
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('an abandoned recovery gate leaves quota reservations closed', async () => {
  const { VirusTotalQuota } = await import('../src/virustotal-quota.js');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-quota-gate-'));
  const previous = process.env.GUARDOG_HOME;
  process.env.GUARDOG_HOME = root;
  const ledger = path.join(root, 'quota.json');
  const lock = ledger + '.lock';
  fs.writeFileSync(lock, '');
  const old = new Date(Date.now() - 10 * 60_000);
  fs.utimesSync(lock, old, old);
  fs.mkdirSync(lock + '.recover');
  try {
    const quota = new VirusTotalQuota({ limit: 1, path: ledger });
    assert.throws(() => quota.reserve(), /busy/);
    assert.equal(fs.existsSync(ledger), false);
  } finally {
    if (previous === undefined) delete process.env.GUARDOG_HOME; else process.env.GUARDOG_HOME = previous;
    fs.rmSync(root, { recursive: true, force: true });
  }
});
