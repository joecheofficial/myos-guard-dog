const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {spawnSync}=require('node:child_process');const {pathToFileURL}=require('node:url');
test('all 2124 dependencies across five projects get advisories before quota-limited enrichment',async()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'gd-nightly-phases-'));const previous=process.env.GUARDOG_HOME;
 try{
  process.env.GUARDOG_HOME=path.join(root,'state');fs.mkdirSync(process.env.GUARDOG_HOME);
  fs.writeFileSync(path.join(process.env.GUARDOG_HOME,'config.json'),JSON.stringify({nightlyUpdates:false}));
  let next=0;for(let project=0;project<5;project++){
   const dir=path.join(root,'project'+project);fs.mkdirSync(dir);fs.writeFileSync(path.join(dir,'package.json'),'{}');
   const packages={};for(let i=0;i<(project===4?424:425);i++){const name='pkg-'+next++;packages['node_modules/'+name]={version:'1.0.0',resolved:`https://registry.npmjs.org/${name}/-/${name}-1.0.0.tgz`};}
   fs.writeFileSync(path.join(dir,'package-lock.json'),JSON.stringify({lockfileVersion:3,packages}));
  }
  const log=path.join(root,'checks.log'),preload=path.join(root,'preload.mjs');
  fs.writeFileSync(preload,`import fs from 'node:fs';
   import {CVEChecker} from ${JSON.stringify(pathToFileURL(path.resolve(__dirname,'../src/cve-checker.js')).href)};
   import {GuardDog} from ${JSON.stringify(pathToFileURL(path.resolve(__dirname,'../src/index.js')).href)};
   CVEChecker.prototype.checkCVEs=async function(n,e,v){fs.appendFileSync(${JSON.stringify(log)},n+'\\n');const danger=n==='pkg-2123';return {status:'complete',version:v,found:danger,vulnerabilities:danger?[{id:'MAL-test-critical',severity:'critical'}]:[],severity:{critical:danger?1:0,high:0,medium:0,low:0}};};
   GuardDog.prototype.analyze=async function(n,e,t,v){if(fs.readFileSync(${JSON.stringify(log)},'utf8').trim().split('\\n').length!==2124)throw Error('Enrichment starved advisory checks');return {packageName:n,version:v,ecosystem:e,decision:{action:'SILENT',coverage:'incomplete'},cveResults:{status:'complete'},scanResults:{status:'rate_limited'}};};`);
  const {runNightly}=await import('../bin/nightly-scan.js');const calls=[];
  const result=runNightly({roots:[root],timeoutMs:120000,healthOptions:{platform:'linux',run:()=>({status:0,stdout:''})},run:(command,args,options)=>{calls.push(args.includes('--advisories-only')?'advisory':'enrichment');return spawnSync(command,['--import',pathToFileURL(preload).href,...args],options);}});
  assert.deepEqual(calls,['advisory','advisory','advisory','advisory','advisory','enrichment']);
  assert.equal(result.advisoryCheckedCount,2124);assert.equal(result.dependencyCount,2124);
  assert.equal(result.phases.advisories,'complete');assert.equal(result.phases.enrichment,'incomplete');
  assert.equal(result.dangerousCount,1);assert.equal(result.exitCode,1);
  assert.ok(result.findings.some(f=>f.packageName==='pkg-2123'&&f.project.endsWith('project4/package.json')&&f.advisoryIds.includes('MAL-test-critical')));
 }finally{if(previous===undefined)delete process.env.GUARDOG_HOME;else process.env.GUARDOG_HOME=previous;fs.rmSync(root,{recursive:true,force:true});}
});

test('a deferred project whose lock changes loses current advisory coverage',async()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'gd-nightly-change-'));const previous=process.env.GUARDOG_HOME;
 try {
  process.env.GUARDOG_HOME=path.join(root,'state');fs.mkdirSync(process.env.GUARDOG_HOME);fs.writeFileSync(path.join(process.env.GUARDOG_HOME,'config.json'),JSON.stringify({nightlyUpdates:false}));
  const write=(project,name)=>{const dir=path.join(root,project);fs.mkdirSync(dir,{recursive:true});fs.writeFileSync(path.join(dir,'package.json'),'{}');fs.writeFileSync(path.join(dir,'package-lock.json'),JSON.stringify({lockfileVersion:3,packages:{['node_modules/'+name]:{version:'1.0.0',resolved:`https://registry.npmjs.org/${name}/-/${name}-1.0.0.tgz`}}}));};write('a','old-a');write('b','old-b');
  const {collectDependencies}=await import('../src/dependency-inventory.js');const {createHash}=require('node:crypto');const {runNightly}=await import('../bin/nightly-scan.js');
  const receipt=runNightly({roots:[root],healthOptions:{platform:'linux',run:()=>({status:0,stdout:''})},run:(_,args)=>{
    const fingerprint=createHash('sha256').update(JSON.stringify(collectDependencies(args[1]))).digest('hex');
    if(!args.includes('--advisories-only'))write('b','new-b');
    return {status:2,stdout:JSON.stringify({status:'incomplete',coverage:'incomplete',dependencyCount:1,advisoryCheckedCount:1,enrichmentCheckedCount:0,dangerousCount:0,suspiciousCount:0,inventoryFingerprint:fingerprint,quotaExhausted:!args.includes('--advisories-only'),findings:[],issues:['Deferred enrichment']})};
  }});
  assert.equal(receipt.dependencyCount,2);assert.equal(receipt.advisoryCheckedCount,1);assert.equal(receipt.phases.advisories,'incomplete');assert.ok(receipt.issues.some(x=>/inventory changed/.test(x)));
 }finally{if(previous===undefined)delete process.env.GUARDOG_HOME;else process.env.GUARDOG_HOME=previous;fs.rmSync(root,{recursive:true,force:true});}
});
