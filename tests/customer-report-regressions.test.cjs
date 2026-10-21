'use strict';

// Regressions from a customer install report (All Sorted 8.39). Offline only:
// GitHub is mocked and the redirect check uses two loopback servers.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');

const listen = server => new Promise(resolve => server.listen(0, 'localhost', resolve));

test('VirusTotal requests refuse redirects so the x-apikey header cannot follow one', async () => {
  const { VirusTotalScanner } = await import('../src/virustotal-scanner.js');
  let leaked = null;
  const target = http.createServer((req, res) => { leaked = req.headers['x-apikey'] || null; res.end('{}'); });
  await listen(target);
  const origin = http.createServer((req, res) => {
    res.writeHead(302, { location: `http://localhost:${target.address().port}/collect` });
    res.end();
  });
  await listen(origin);
  try {
    // A different port is a different origin, so this redirect is cross-origin.
    const base = `http://localhost:${origin.address().port}`;
    const scanner = new VirusTotalScanner(
      { virustotal: { apiKey: 'fixture-key', baseUrl: base, timeoutMs: 3000 } },
      { wait: async () => {}, quota: { reserve: () => true } }
    );
    await assert.rejects(scanner.request(`${base}/api/v3/files/abc`, { headers: { 'x-apikey': scanner.apiKey } }));
    assert.equal(leaked, null);
  } finally {
    origin.close();
    target.close();
  }
});

async function issueQueryFor(fullName) {
  const { ReputationChecker } = await import('../src/reputation-checker.js');
  const originalFetch = global.fetch;
  let query = null;
  global.fetch = async url => {
    if (String(url).includes('/search/issues')) {
      query = new URL(url).searchParams.get('q');
      return { ok: true, json: async () => ({ total_count: 0 }) };
    }
    return { ok: true, headers: new Map(), json: async () => ({ full_name: fullName, stargazers_count: 1 }) };
  };
  try {
    const checker = new ReputationChecker({ reputation: { github: { apiUrl: 'https://api.github.invalid', timeoutMs: 1000 } } });
    return { result: await checker.checkGitHub('https://github.com/old-owner/old-name'), query };
  } finally {
    global.fetch = originalFetch;
  }
}

test('GitHub issue search uses the canonical name of a renamed repository', async () => {
  const { result, query } = await issueQueryFor('new-owner/new-name');
  assert.equal(result.ok, true);
  assert.equal(query, 'repo:new-owner/new-name is:issue is:open malware in:title');
});

test('GitHub canonical names accept legacy trailing-hyphen owners', async () => {
  const { result, query } = await issueQueryFor('legacy-/repo.js');
  assert.equal(result.ok, true);
  assert.equal(query, 'repo:legacy-/repo.js is:issue is:open malware in:title');
});

test('GitHub canonical names cannot inject search qualifiers', async () => {
  for (const fullName of ['evil/x is:closed', 'a/b\nc', 'owner/..', '-owner/repo', 'a/b/c', null]) {
    const { result, query } = await issueQueryFor(fullName);
    assert.equal(result.ok, false, String(fullName));
    assert.equal(query, null, String(fullName));
  }
});

async function installWith(manifest) {
  const { runGuardedInstall } = await import('../src/guarded-install.js');
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'guardog-override-test-'));
  fs.writeFileSync(path.join(cwd, 'package.json'), JSON.stringify({ name: 'fixture', version: '1.0.0', ...manifest }));
  let stagedManifest = null;
  const runner = (command, args, options) => {
    stagedManifest = JSON.parse(fs.readFileSync(path.join(options.cwd, 'package.json'), 'utf8'));
    return { status: 1 };
  };
  try {
    await runGuardedInstall(['left-pad@1.3.0'], class {}, { platform: 'linux', cwd, runner });
    return { error: null, stagedManifest };
  } catch (error) {
    return { error: error.message, stagedManifest };
  } finally {
    fs.rmSync(cwd, { recursive: true, force: true });
  }
}

const missionControl = { devDependencies: { postcss: '^8.5.23' }, overrides: { postcss: '$postcss' } };
const whatsAppServer = {
  dependencies: { '@whiskeysockets/baileys': '7.0.0-rc14', 'link-preview-js': '^4.0.4' },
  overrides: { '@whiskeysockets/baileys': { 'link-preview-js': '$link-preview-js' }, qs: '^6.15.4' }
};

test('the override shapes All Sorted ships reach the staged resolver unchanged', async () => {
  for (const manifest of [missionControl, whatsAppServer]) {
    const { error, stagedManifest } = await installWith(manifest);
    assert.match(error, /npm install failed/);
    assert.deepEqual(stagedManifest.overrides, manifest.overrides);
  }
});

test('every other override shape is still refused before npm runs', async () => {
  const refused = [
    { overrides: { postcss: '$postcss' } },
    { devDependencies: { postcss: '^8.5.23' }, overrides: { postcss: '8.4.0' } },
    { devDependencies: { postcss: 'https://evil.test/p.tgz' }, overrides: { postcss: '$postcss' } },
    { devDependencies: { postcss: '^8.5.23' }, overrides: { postcss: '$postcss', 'left-pad': '1.0.0' } },
    { ...whatsAppServer, overrides: { ...whatsAppServer.overrides, qs: 'npm:evil@1.0.0' } },
    { ...whatsAppServer, overrides: { ...whatsAppServer.overrides, '@whiskeysockets/baileys': { 'link-preview-js': 'npm:evil@1.0.0' } } },
    { ...whatsAppServer, dependencies: { ...whatsAppServer.dependencies, '@whiskeysockets/baileys': '7.0.0' } },
    { dependencies: { '@mnstry/atelier': '0.2.0-alpha.12' }, overrides: { '@mnstry/atelier': { 'fast-uri': '3.1.8' } } },
    { overrides: [] },
    { overrides: null }
  ];
  for (const manifest of refused) {
    const { error, stagedManifest } = await installWith(manifest);
    assert.match(error, /overrides/, JSON.stringify(manifest));
    assert.equal(stagedManifest, null, JSON.stringify(manifest));
  }
});
