const test=require('node:test'); const assert=require('node:assert/strict'); const fs=require('node:fs'); const os=require('node:os'); const path=require('node:path');
test('fresh run checks new advisories while reusing only fresh successful enrichment',async()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'gd-audit-'));
 try{
  const {createAuditAnalyzer}=await import('../src/audit-analyzer.js');
  let osv=0,rep=0,vt=0;
  const dog=()=>({config:{},dataDir:root,cveChecker:{checkCVEs:async()=>({status:'complete',version:'1.0.0',vulnerabilities:osv++?[{id:'MAL-new',severity:'critical'}]:[],severity:{critical:osv>1?1:0}})},reputation:{checkGitHub:async()=>({ok:true,securityIssues:0}),checkReputation:async()=>{rep++;return {registry:{version:'1.0.0'},signals:[]};}},scanner:{maxReportAgeMs:86400000,scan:async()=>{vt++;return {success:true,found:true,stale:false,lastAnalysisAt:new Date().toISOString()};}},decisionTree:{evaluate:(s,r,n,c)=>({action:c.vulnerabilities.length?'BARK':'SILENT',coverage:'incomplete'})},analyze:async function(n,e,t,v){return {packageName:n,version:v,cveResults:await this.cveChecker.checkCVEs(n,e,v),reputationData:await this.reputation.checkReputation(n,e,v),scanResults:await this.scanner.scan('a'.repeat(64))};}});
  const p={name:'pkg',version:'1.0.0',ecosystem:'npm'};
  const first=createAuditAnalyzer(dog(),{runId:'one',cacheDir:root}); await first.advisory(p); await first.analyze(p);
  const next=createAuditAnalyzer(dog(),{runId:'two',cacheDir:root}); const result=await next.analyze(p);
  assert.equal(osv,2); assert.equal(rep,1); assert.equal(vt,1); assert.equal(result.cveResults.vulnerabilities[0].id,'MAL-new');
 }finally{fs.rmSync(root,{recursive:true,force:true});}
});

test('failed enrichment is retried and GitHub evidence is separated by authentication',async()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'gd-cache-auth-'));const previous=process.env.GITHUB_API_TOKEN;
 try {
  const {createAuditAnalyzer}=await import('../src/audit-analyzer.js');let calls=0;
  const dog=()=>({config:{},cveChecker:{checkCVEs:async()=>({status:'unavailable'})},reputation:{checkGitHub:async()=>{calls++;return {ok:true,securityIssues:0};},checkReputation:async()=>null},analyze:async()=>null});
  process.env.GITHUB_API_TOKEN='test-auth-one';let first=dog();createAuditAnalyzer(first,{cacheDir:root});await first.reputation.checkGitHub('https://github.com/example/repo');
  let same=dog();createAuditAnalyzer(same,{cacheDir:root});await same.reputation.checkGitHub('https://github.com/example/repo.git');assert.equal(calls,1);
  process.env.GITHUB_API_TOKEN='test-auth-two';let changed=dog();createAuditAnalyzer(changed,{cacheDir:root});await changed.reputation.checkGitHub('https://github.com/example/repo');assert.equal(calls,2);
  let attempts=0;const bad=dog();bad.reputation.checkReputation=async()=>{attempts++;return {error:'timeout',registry:null};};createAuditAnalyzer(bad,{cacheDir:root});await bad.reputation.checkReputation('pkg','npm','1.0.0');await bad.reputation.checkReputation('pkg','npm','1.0.0');assert.equal(attempts,2);
 }finally{if(previous===undefined)delete process.env.GITHUB_API_TOKEN;else process.env.GITHUB_API_TOKEN=previous;fs.rmSync(root,{recursive:true,force:true});}
});
