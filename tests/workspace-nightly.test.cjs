const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
test('nightly preserves local findings even when dependency coverage fails',async t=>{
 const {runNightly}=await import('../bin/nightly-scan.js');
 const base=fs.mkdtempSync(path.join(os.tmpdir(),'gd night ')),root=path.join(base,'project');fs.mkdirSync(root);
 const previous=process.env.GUARDOG_HOME;process.env.GUARDOG_HOME=path.join(base,'state');fs.mkdirSync(process.env.GUARDOG_HOME);
 const config={nightlyUpdates:false,scanRoots:[root],workspaceScan:true};fs.writeFileSync(path.join(process.env.GUARDOG_HOME,'config.json'),JSON.stringify(config));
 fs.writeFileSync(path.join(root,'key.pem'),'-----BEGIN PRIVATE KEY-----');fs.writeFileSync(path.join(root,'package.json'),'{}');
 t.after(()=>{if(previous===undefined)delete process.env.GUARDOG_HOME;else process.env.GUARDOG_HOME=previous;fs.rmSync(base,{recursive:true,force:true});});
 const receipt=runNightly({ advisoryFirst: false,config,healthOptions:{platform:'linux',run:()=>({status:0,stdout:''})},run:()=>({status:2,stdout:JSON.stringify({status:'incomplete',dependencyCount:0,dangerousCount:0,issues:['offline']})})});
 assert.equal(receipt.workspace.findings.length,1);
 assert.equal(receipt.workspace.coverage.complete,true);
 assert.equal(receipt.exitCode,1);
 assert.equal(receipt.status,'dangerous');
 assert.equal(receipt.workspace.findings[0].ruleId,'GD-SECRET-PRIVATE-KEY');
 assert.ok(receipt.issues.length);
});
