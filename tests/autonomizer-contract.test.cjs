const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');

const root = resolve(__dirname, '..');
const contract = JSON.parse(readFileSync(resolve(root, 'autonomizer.json'), 'utf8'));
const packageManifest = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));
const expectedPrompts = [
  'How could this get even better?',
  'What else can I do?',
  'What can be more automated within our safeguards?',
  'What evidence would prove this conclusion is correct?',
  'What safe internal follow-up remains undone?'
];

assert.equal(contract.version, packageManifest.version);
assert.equal(contract.agentId, 'guard-dog');
assert.equal(typeof contract.loopBoundary, 'string');
assert.ok(contract.loopBoundary.trim());
assert.ok(!Number.isNaN(Date.parse(contract.lastAutonomizerUpdate)));
assert.deepEqual(contract.reflectionQuestions.map(({ prompt }) => prompt), expectedPrompts);
assert.equal(new Set(contract.reflectionQuestions.map(({ id }) => id)).size, 5);
assert.ok(contract.reflectionQuestions.every(({ id }) => /^guard_dog_/.test(id)));
assert.ok(contract.autonomousActions.every((action) => /read-only|drafting without enforcement|owned local/i.test(action)));
assert.ok(contract.approvalRequiredActions.every((action) => /^Approval required/i.test(action)));
assert.equal(packageManifest.version, '4.1.0');
assert.ok(packageManifest.files.includes('autonomizer.json'));
