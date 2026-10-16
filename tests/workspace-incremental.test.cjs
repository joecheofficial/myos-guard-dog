const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
test('content cache retains findings and detects ignored, untracked and same-size edits', async () => {
 const root = fs.mkdtempSync(path.join(os.tmpdir(),'gd-incremental-'));
 try {
  const {scanWorkspace} = await import('../src/workspace-scan.js');
  const repo=path.join(root,'repo'); fs.mkdirSync(repo);
  const options={cacheDir:path.join(root,'state')};
  fs.writeFileSync(path.join(repo,'.gitignore'),'ignored.js\n');
  fs.writeFileSync(path.join(repo,'ignored.js'),'eval(atob("aGVsbG8="));');
  const cold=scanWorkspace(repo,options), warm=scanWorkspace(repo,options);
  assert.ok(cold.findings.length); assert.deepEqual(warm.findings,cold.findings);
  assert.equal(warm.coverage.filesReused,2); assert.equal(warm.coverage.filesAnalyzed,0);
  fs.writeFileSync(path.join(repo,'ignored.js'),'console.log("hello");');
  fs.writeFileSync(path.join(repo,'untracked.js'),'eval(atob("aGVsbG8="));');
  const changed=scanWorkspace(repo,options);
  assert.equal(changed.coverage.filesAnalyzed,2); assert.equal(changed.coverage.filesReused,1);
  assert.ok(changed.findings.some(f=>f.path==='untracked.js'));
  fs.renameSync(path.join(repo,'untracked.js'),path.join(repo,'renamed.js'));
  const renamed=scanWorkspace(repo,options); assert.equal(renamed.coverage.filesAnalyzed,1);
  const full=scanWorkspace(repo,{...options,cache:false}); assert.equal(full.coverage.filesReused,0);
 } finally {fs.rmSync(root,{recursive:true,force:true});}
});
