const test = require('node:test');
const assert = require('node:assert/strict');

test('removed packages retain confirmed malware findings and incomplete coverage', async () => {
  const { DecisionTree } = await import('../src/decision-tree.js');
  const tree = new DecisionTree({ decisionThresholds: {} }, { trustedProviders: [], trustedNamespaces: [] });
  const result = tree.evaluate({ success: false }, { signals: ['PACKAGE_NOT_FOUND'] }, 'removed-package', {
    status: 'complete', found: true, severity: { critical: 0, high: 0, medium: 1, low: 0 },
    vulnerabilities: [{ id: 'MAL-2026-1', summary: 'Malicious package' }]
  });
  assert.equal(result.action, 'BARK');
  assert.equal(result.coverage, 'incomplete');
  assert.equal(result.installAllowed, false);
});

test('a newly published version of an established package is signaled', async () => {
  const { ReputationChecker } = await import('../src/reputation-checker.js');
  const checker = new ReputationChecker({ reputation: {} });
  const signals = checker.analyzeSignals({ registry: { createdAt: '2015-01-01', publishDate: new Date().toISOString(), repository: 'https://github.com/example/project', weeklyDownloads: 10000 } });
  assert.equal(signals.includes('NEWLY_PUBLISHED'), true);
});

test('complete but UNCONFIRMED results cannot approve an install', async () => {
  const { DecisionTree } = await import('../src/decision-tree.js');
  const tree = new DecisionTree({ decisionThresholds: {} }, { trustedProviders: [], trustedNamespaces: [] });
  const result = tree.evaluate({ success: true, found: true, maliciousVotes: 0, suspiciousVotes: 0 },
    { ecosystem: 'npm', signals: ['NO_REPOSITORY'] }, 'untrusted', { status: 'complete', found: false });
  assert.equal(result.threat, 'UNCONFIRMED');
  assert.equal(result.coverage, 'complete');
  assert.equal(result.installAllowed, false);
});

test('unsupported repository hosts remain incomplete', async () => {
  const { ReputationChecker } = await import('../src/reputation-checker.js');
  const { DecisionTree } = await import('../src/decision-tree.js');
  const checker = new ReputationChecker({ reputation: {} });
  const signals = checker.analyzeSignals({ registry: { repository: 'https://gitlab.com/example/project', weeklyDownloads: 10000 }, github: null });
  assert.ok(signals.includes('REPOSITORY_UNCHECKED'));
  const tree = new DecisionTree({ decisionThresholds: {} }, { trustedProviders: [], trustedNamespaces: [] });
  const result = tree.evaluate({ success: true, found: true, maliciousVotes: 0, suspiciousVotes: 0 },
    { ecosystem: 'npm', signals }, 'untrusted', { status: 'complete', found: false });
  assert.equal(result.coverage, 'incomplete');
  assert.equal(result.installAllowed, false);
});

test('a lookalike GitHub hostname cannot satisfy repository coverage', async () => {
  const { ReputationChecker } = await import('../src/reputation-checker.js');
  const checker = new ReputationChecker({ reputation: {} });
  assert.equal(await checker.checkGitHub('https://evilgithub.com/example/project'), null);
  assert.equal(await checker.checkGitHub('https://github.com.evil.test/example/project'), null);
  assert.equal(await checker.checkGitHub('https://github.com/example/project/extra'), null);
});

test('failed pattern check leaves install coverage incomplete', async () => {
  const { DecisionTree } = await import('../src/decision-tree.js');
  const tree = new DecisionTree({ decisionThresholds: {} }, { trustedProviders: [], trustedNamespaces: [] });
  const result = tree.evaluate({ success: true, found: true, maliciousVotes: 0, suspiciousVotes: 0 },
    { ecosystem: 'npm', signals: [] }, 'fixture', { status: 'complete', found: false }, { failed: true }, true);
  assert.equal(result.coverage, 'incomplete');
  assert.equal(result.installAllowed, false);
});

test('analyzer failure reaches the actual GuardDog install verdict', async () => {
  const { GuardDog } = await import('../src/index.js');
  const dog = Object.create(GuardDog.prototype);
  dog.scanner = { scan: async () => ({ success: true, found: true, maliciousVotes: 0, suspiciousVotes: 0 }) };
  dog.reputation = { checkReputation: async () => ({ ecosystem: 'npm', registry: { version: '1.0.0' }, signals: [] }) };
  dog.cveChecker = { checkCVEs: async () => ({ status: 'complete', found: false, severity: {}, vulnerabilities: [] }) };
  dog.patternAnalyzer = { analyzeFiles: () => { throw new Error('fixture analyzer failure'); } };
  const { DecisionTree } = await import('../src/decision-tree.js');
  dog.decisionTree = new DecisionTree({ decisionThresholds: {} }, { trustedProviders: [], trustedNamespaces: [] });
  dog.saveScanHistory = () => {};
  const log = console.log, error = console.error;
  console.log = () => {}; console.error = () => {};
  try {
    const result = await dog.analyze('fixture', 'npm', 'a'.repeat(64), '1.0.0');
    assert.equal(result.decision.coverage, 'incomplete');
    assert.equal(result.decision.installAllowed, false);
  } finally { console.log = log; console.error = error; }
});

test('trusted-provider names are scoped to their own ecosystem', async () => {
  const { DecisionTree } = await import('../src/decision-tree.js');
  const tree = new DecisionTree({ decisionThresholds: {} }, {
    trustedProviders: ['react'], trustedNamespaces: ['@types'],
    trustedScopes: { npm: ['vercel'], pypi: ['django'], rubygems: ['rails'] }
  });
  assert.equal(tree.isTrustedProvider('react', 'npm'), true);
  assert.equal(tree.isTrustedProvider('react', 'pypi'), false);
  assert.equal(tree.isTrustedProvider('rails', 'npm'), false);
  assert.equal(tree.isTrustedProvider('rails', 'rubygems'), true);
  assert.equal(tree.isTrustedProvider('django', 'pypi'), true);
});

test('description pattern matches do not claim a source-code scan', async () => {
  const { DecisionTree } = await import('../src/decision-tree.js');
  const tree = new DecisionTree({ decisionThresholds: {} }, { trustedProviders: [], trustedNamespaces: [] });
  const reasons = [];
  tree.evaluatePatterns({ suspicious: true, score: 50, scope: 'registry_description_only', severity: { critical: 1, high: 0, medium: 0, low: 0 } }, reasons);
  assert.match(reasons.join(' '), /registry description/);
  assert.doesNotMatch(reasons.join(' '), /in code/);
});

test('renamed GitHub repositories use their canonical name for issue search', async () => {
  const { ReputationChecker } = await import('../src/reputation-checker.js');
  const checker = new ReputationChecker({ reputation: { github: { apiUrl: 'https://api.github.test', timeoutMs: 1000 } } });
  const original = global.fetch;
  const calls = [];
  global.fetch = async url => {
    calls.push(url);
    return { ok: true, json: async () => url.includes('/search/issues')
      ? { total_count: 0 } : { full_name: 'new-owner/current', stargazers_count: 100, forks_count: 1, open_issues_count: 0, watchers_count: 100 } };
  };
  try {
    const result = await checker.checkGitHub('https://github.com/old-owner/old-name');
    assert.equal(result.ok, true);
    assert.match(decodeURIComponent(calls[1]), /repo:new-owner\/current/);
  } finally { global.fetch = original; }
});

test('PyPI multi-file releases require the hash of the exact distribution', async () => {
  const { ReputationChecker } = await import('../src/reputation-checker.js');
  const { selectPyPiDistribution } = await import('../src/index.js');
  const { DecisionTree } = await import('../src/decision-tree.js');
  const checker = new ReputationChecker({ reputation: { pypi: { apiUrl: 'https://pypi.test/pypi', timeoutMs: 1000 } } });
  const original = global.fetch;
  global.fetch = async () => ({ ok: true, json: async () => ({ info: { name: 'fixture', version: '1.0.0', summary: 'fixture' }, urls: [
    { filename: 'fixture-1.0.0.tar.gz', url: 'https://files.test/source', digests: { sha256: 'a'.repeat(64) } },
    { filename: 'fixture-1.0.0-win.whl', url: 'https://files.test/wheel', digests: { sha256: 'b'.repeat(64) } }
  ] }) });
  try {
    const registry = await checker.checkPyPiRegistry('fixture', '1.0.0');
    assert.equal(registry.tarball, null);
    assert.equal(selectPyPiDistribution(registry), null);
    assert.equal(selectPyPiDistribution(registry, 'c'.repeat(64)), null);
    assert.equal(selectPyPiDistribution(registry, 'b'.repeat(64)).filename, 'fixture-1.0.0-win.whl');
    const tree = new DecisionTree({ decisionThresholds: {} }, { trustedProviders: [], trustedNamespaces: [] });
    const result = tree.evaluate({ success: true, found: true, maliciousVotes: 0, suspiciousVotes: 0 },
      { ecosystem: 'pypi', registry, signals: [] }, 'fixture', { status: 'complete', found: false });
    assert.equal(result.coverage, 'incomplete');
    assert.equal(result.installAllowed, false);
  } finally { global.fetch = original; }
});

test('unverified complaints alone do not trigger a warning', async () => {
  const { DecisionTree } = await import('../src/decision-tree.js');
  const tree = new DecisionTree({ decisionThresholds: {} }, { trustedProviders: [], trustedNamespaces: [] });
  assert.ok(tree.evaluateReputation({ signals: ['SECURITY_COMPLAINTS'] }, []) < 50);
});

test('unresolved version does not query historical OSV advisories', async () => {
  const { CVEChecker } = await import('../src/cve-checker.js');
  const checker = new CVEChecker({});
  let calls = 0;
  checker.checkOSV = async () => { calls++; return { vulnerabilities: [] }; };
  const result = await checker.checkCVEs('better-auth', 'npm');
  assert.equal(calls, 0);
  assert.equal(result.status, 'unavailable');
});

test('OSV failure is incomplete, while successful empty response is complete', async () => {
  const { CVEChecker } = await import('../src/cve-checker.js');
  const checker = new CVEChecker({});
  checker.checkOSV = async () => { throw new Error('503'); };
  assert.equal((await checker.checkCVEs('x', 'npm', '1.0.0')).status, 'unavailable');
  checker.checkOSV = async () => ({ vulnerabilities: [] });
  assert.equal((await checker.checkCVEs('x', 'npm', '1.0.0')).status, 'complete');
});

test('confirmed malware blocks even an allowlisted package', async () => {
  const { DecisionTree } = await import('../src/decision-tree.js');
  const tree = new DecisionTree({ decisionThresholds: { maliciousVotes: 3 } }, { trustedProviders: ['x'], trustedNamespaces: [] });
  const decision = tree.evaluate({ success: true, found: true, maliciousVotes: 3 }, { signals: [] }, 'x', { status: 'complete', found: false }, null, true);
  assert.equal(decision.action, 'BARK');
  assert.equal(decision.installAllowed, false);
});

test('missing required coverage blocks installation without calling it malware', async () => {
  const { DecisionTree } = await import('../src/decision-tree.js');
  const tree = new DecisionTree({ decisionThresholds: {} }, { trustedProviders: [], trustedNamespaces: [] });
  const decision = tree.evaluate({ success: false, status: 'not_configured' }, { signals: [] }, 'x', { status: 'unavailable', found: false }, null, false);
  assert.equal(decision.coverage, 'incomplete');
  assert.equal(decision.installAllowed, false);
  assert.notEqual(decision.threat, 'SAFE');
  assert.notEqual(decision.threat, 'DANGER');
});
