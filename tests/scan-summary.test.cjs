const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { resolve } = require('node:path');

test('batch exit status distinguishes danger, incomplete checks and complete checks', async () => {
  const { auditExitCode } = await import('../src/scan-summary.js');
  assert.equal(auditExitCode([{ decision: { action: 'BARK', coverage: 'complete' } }]), 1);
  assert.equal(auditExitCode([{ decision: { action: 'SILENT', coverage: 'incomplete' } }]), 2);
  assert.equal(auditExitCode([{ decision: { action: 'WHINE', threat: 'SUSPICIOUS', coverage: 'complete' } }]), 2);
  assert.equal(auditExitCode([{ decision: { action: 'SILENT', threat: 'SAFE', coverage: 'complete' } }]), 0);
});

test('project audit does not report suspicious packages as passed', async () => {
  const { summarizeDependencyScan } = await import('../src/scan-summary.js');
  const result = summarizeDependencyScan({ complete: true, issues: [], packages: [{ name: 'fixture', version: '1.0.0' }] }, [
    { decision: { action: 'WHINE', threat: 'SUSPICIOUS', coverage: 'complete' }, cveResults: { status: 'complete' } }
  ]);
  assert.equal(result.status, 'suspicious');
  assert.equal(result.coverage, 'complete');
  assert.equal(result.suspiciousCount, 1);
});

test('unknown CLI commands exit nonzero', () => {
  const result = spawnSync(process.execPath, [resolve(__dirname, '../src/index.js'), 'analyse', 'fixture'], { encoding: 'utf8' });
  assert.equal(result.status, 2);
});

test('danger preserves incomplete coverage and package failure diagnostics', async () => {
  const { summarizeDependencyScan } = await import('../src/scan-summary.js');
  const inventory = {complete:true,issues:[],packages:[{name:'bad',version:'1.0.0'},{name:'unknown',version:'2.0.0'}]};
  const report = summarizeDependencyScan(inventory,[
    {packageName:'bad',version:'1.0.0',decision:{action:'BARK',coverage:'complete'},cveResults:{status:'complete'}},
    {packageName:'unknown',version:'2.0.0',decision:{action:'SILENT',coverage:'incomplete'},cveResults:{status:'unavailable',error:'OSV timeout'}}
  ]);
  assert.equal(report.status,'dangerous');
  assert.equal(report.coverage,'incomplete');
  assert.equal(report.incompleteCount,1);
  assert.equal(report.dangerousCount,1);
  assert.equal(report.dependencyCount,2);
  assert.ok(report.issues.some(issue=>issue.includes('unknown@2.0.0') && issue.includes('OSV timeout')));
});

test('missing coverage and missing result rows cannot count as complete', async () => {
  const { summarizeDependencyScan } = await import('../src/scan-summary.js');
  const inventory = {complete:true,issues:[],packages:[{name:'one',version:'1.0.0'},{name:'two',version:'2.0.0'}]};
  const report = summarizeDependencyScan(inventory,[{packageName:'one',decision:{action:'SILENT'},cveResults:{status:'complete'}}]);
  assert.equal(report.status,'incomplete');
  assert.equal(report.coverage,'incomplete');
  assert.equal(report.incompleteCount,2);
  assert.ok(report.issues.some(issue=>issue.includes('one@1.0.0') && issue.includes('not reported')));
  assert.ok(report.issues.some(issue=>issue.includes('received 1')));
});

test('completed dangerous evidence remains complete while inventory issues persist separately', async () => {
  const { summarizeDependencyScan } = await import('../src/scan-summary.js');
  const inventory = {complete:true,issues:[],packages:[{name:'one',version:'1.0.0'}]};
  const results = [{decision:{action:'BARK',coverage:'complete'},cveResults:{status:'complete'}}];
  assert.deepEqual(summarizeDependencyScan(inventory,results),{status:'dangerous',coverage:'complete',dependencyCount:1,dangerousCount:1,suspiciousCount:0,incompleteCount:0,quotaExhausted:false,issues:[]});
  const incomplete = summarizeDependencyScan({...inventory,complete:false,issues:['unresolved local dependency']},results);
  assert.equal(incomplete.coverage,'incomplete');
  assert.equal(incomplete.status,'dangerous');
  assert.deepEqual(incomplete.issues,['unresolved local dependency']);
});

test('failed check reasons appear in issues consumed by nightly receipts', async () => {
  const { summarizeDependencyScan } = await import('../src/scan-summary.js');
  const report = summarizeDependencyScan({complete:true,issues:[],packages:[{name:'one',version:'1.0.0'}]},[
    {decision:{action:'BARK',coverage:'incomplete'},cveResults:{status:'complete'},checks:{registry:{status:'unavailable',error:'lookup timed out'}},scanResults:{error:'VirusTotal quota exceeded'}}
  ]);
  assert.equal(report.status,'dangerous');
  assert.equal(report.incompleteCount,1);
  assert.ok(report.issues[0].includes('registry: unavailable: lookup timed out'));
  assert.ok(report.issues[0].includes('VirusTotal quota exceeded'));
});
