const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),{spawnSync}=require('node:child_process');
test('workspace CLI emits one JSON document and enforces findings',t=>{
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'gd cli '));t.after(()=>fs.rmSync(temp,{recursive:true,force:true}));
 const project=path.join(temp,'project');fs.mkdirSync(project);fs.writeFileSync(path.join(project,'key.pem'),'-----BEGIN PRIVATE KEY-----');
 const r=spawnSync(process.execPath,[path.resolve(__dirname,'../src/index.js'),'workspace',project,'--json'],{encoding:'utf8',env:{PATH:process.env.PATH,GUARDOG_HOME:path.join(temp,'state')}});
 assert.equal(r.status,1,r.stderr);
 const report=JSON.parse(r.stdout);assert.equal(report.findings[0].ruleId,'GD-SECRET-PRIVATE-KEY');assert.equal(report.coverage.complete,true);
});

test('existing output destination stays untouched and does not erase detected danger',t=>{
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'gd cli output '));t.after(()=>fs.rmSync(temp,{recursive:true,force:true}));
 const project=path.join(temp,'project');fs.mkdirSync(project);fs.writeFileSync(path.join(project,'key.pem'),'-----BEGIN PRIVATE KEY-----');
 const output=path.join(temp,'existing.json');fs.writeFileSync(output,'preserve');
 const r=spawnSync(process.execPath,[path.resolve(__dirname,'../src/index.js'),'workspace',project,'--json','--output',output],{encoding:'utf8',env:{PATH:process.env.PATH,GUARDOG_HOME:path.join(temp,'state')}});
 const report=JSON.parse(r.stdout);assert.equal(report.findings[0].ruleId,'GD-SECRET-PRIVATE-KEY');assert.equal(r.status,1);assert.equal(report.coverage.complete,false);assert.equal(fs.readFileSync(output,'utf8'),'preserve');
});
