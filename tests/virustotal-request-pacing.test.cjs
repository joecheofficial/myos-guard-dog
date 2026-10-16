const test = require('node:test');
const assert = require('node:assert/strict');

function harness(key, responses) {
  let now = 0;
  const calls = [];
  return {
    config: { virustotal: { apiKey: key, baseUrl: 'https://vt.invalid', timeoutMs: 20 } },
    runtime: {
      pace: async (_,request)=>request(), // Unit-test the in-process queue independently of persistent pacing.
      now: () => now,
      wait: async milliseconds => { now += milliseconds; },
      fetch: async (url, options) => {
        calls.push({ url, time: now, method: options.method || 'GET', aborted: options.signal.aborted });
        const response = responses.shift();
        return { ok: response.status === 200, status: response.status, headers: { get: () => '0' }, json: async () => response.body || {} };
      }
    },
    calls
  };
}
const hash = 'a'.repeat(64);
const stale = { data: { attributes: { last_analysis_date: 1, last_analysis_stats: { malicious: 0, harmless: 5 } } } };

test('artifact lookup and stale report refresh each reserve a request slot', async () => {
  const { VirusTotalScanner } = await import('../src/virustotal-scanner.js');
  const h = harness('pacing-refresh', [{ status: 200, body: stale }, { status: 200 }]);
  const result = await new VirusTotalScanner(h.config, h.runtime).scan(hash);
  assert.equal(result.refreshRequested, true);
  assert.deepEqual(h.calls.map(call => [call.method, call.time]), [['GET', 0], ['POST', 16000]]);
  assert.ok(h.calls.every(call => !call.aborted));
});

test('concurrent scanner instances sharing an API key share slots', async () => {
  const { VirusTotalScanner } = await import('../src/virustotal-scanner.js');
  const h = harness('pacing-concurrent', [{ status: 404 }, { status: 404 }, { status: 404 }]);
  const first = new VirusTotalScanner(h.config, h.runtime);
  const second = new VirusTotalScanner(h.config, h.runtime);
  await Promise.all([first.getFileReport(hash), second.getFileReport(hash), first.getFileReport(hash)]);
  assert.deepEqual(h.calls.map(call => call.time), [0, 16000, 32000]);
});

test('quota responses do not retry, and unauthorized requests never retry', async () => {
  const { VirusTotalScanner } = await import('../src/virustotal-scanner.js');
  const h = harness('pacing-retry', [{ status: 429 }, { status: 404 }]);
  await assert.rejects(() => new VirusTotalScanner(h.config, h.runtime).getFileReport(hash), /429/);
  assert.deepEqual(h.calls.map(call => call.time), [0]);
  const denied = harness('pacing-unauthorized', [{ status: 401 }]);
  const result = await new VirusTotalScanner(denied.config, denied.runtime).scan(hash);
  assert.equal(result.status, 'unauthorized');
  assert.equal(denied.calls.length, 1);
});

test('URL submission and all analysis polls reserve slots', async () => {
  const { VirusTotalScanner } = await import('../src/virustotal-scanner.js');
  const h = harness('pacing-url', [
    { status: 200, body: { data: { id: 'analysis-id' } } },
    { status: 200, body: { data: { attributes: { status: 'queued' } } } },
    { status: 200, body: { data: { attributes: { status: 'completed', stats: { harmless: 5 } } } } }
  ]);
  const result = await new VirusTotalScanner(h.config, h.runtime).scan('https://example.test/package');
  assert.equal(result.success, true);
  assert.deepEqual(h.calls.map(call => call.time), [0, 16000, 32000]);
});

test('time spent waiting for a slot does not consume the request timeout', async () => {
  const { VirusTotalScanner } = await import('../src/virustotal-scanner.js');
  const h = harness('pacing-timeout', [{ status: 404 }, { status: 404 }]);
  const advance = h.runtime.wait;
  h.runtime.wait = async milliseconds => {
    await new Promise(resolve => setTimeout(resolve, 40));
    await advance(milliseconds);
  };
  const scanner = new VirusTotalScanner(h.config, h.runtime);
  await scanner.getFileReport(hash);
  const second = await scanner.getFileReport(hash);
  assert.equal(second.status, 'not_found');
  assert.ok(h.calls.every(call => !call.aborted));
});

test('a shared daily quota guard prevents another request after capacity is reserved', async () => {
  const { VirusTotalScanner } = await import('../src/virustotal-scanner.js');
  const h = harness('pacing-daily-budget', [{ status: 404 }]);
  let remaining = 1;
  const scanner = new VirusTotalScanner(h.config, {
    ...h.runtime,
    quota: { reserve: () => remaining-- > 0 }
  });
  assert.equal((await scanner.scan(hash)).status, 'not_found');
  const capped = await scanner.scan(hash);
  assert.equal(capped.status, 'rate_limited');
  assert.match(capped.error, /daily quota guard/i);
  assert.equal(h.calls.length, 1, 'the capped request must not reach VirusTotal');
});


test('known daily quota exhaustion fails promptly until the next UTC day', async () => {
  const {VirusTotalScanner} = await import('../src/virustotal-scanner.js');
  const h = harness('quota-fast-stop', [{status: 404}, {status: 404}]);
  let remaining = 1;
  const waits = [];
  const advance = h.runtime.wait;
  h.runtime.wait = async ms => { waits.push(ms); await advance(ms); };
  const scanner = new VirusTotalScanner(h.config, {...h.runtime, quota: {reserve: () => remaining-- > 0}});
  await scanner.scan(hash);
  assert.equal((await scanner.scan(hash)).status, 'rate_limited');
  const before = waits.length;
  for (let i = 0; i < 10; i++) assert.equal((await scanner.scan(hash)).status, 'rate_limited');
  assert.equal(waits.length, before, 'do not spend 16 seconds per package after known exhaustion');
  await advance(86400000);
  remaining = 1;
  assert.equal((await scanner.scan(hash)).status, 'not_found');
  assert.equal(h.calls.length, 2);
});

test('audit pacing survives independent processes and serializes a shared key',async()=>{
 const fs=require('node:fs'),os=require('node:os'),path=require('node:path');const {spawn}=require('node:child_process');const {pathToFileURL}=require('node:url');
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'gd-pacer-'));
 try{
  const script=path.join(root,'probe.mjs'),log=path.join(root,'requests.jsonl');
  fs.writeFileSync(script,`import {createRequestPacer} from ${JSON.stringify(pathToFileURL(path.resolve(__dirname,'../src/request-pacer.js')).href)};import fs from 'node:fs';const pace=createRequestPacer('shared-key',{directory:${JSON.stringify(root)}});await pace(120,async()=>{fs.appendFileSync(${JSON.stringify(log)},Date.now()+'\\n');await new Promise(r=>setTimeout(r,40));});`);
  const launch=()=>new Promise((resolve,reject)=>{const child=spawn(process.execPath,[script]);let error='';child.stderr.on('data',d=>error+=d);child.on('error',reject);child.on('exit',code=>code===0?resolve():reject(Error(error)));});
  await Promise.all([launch(),launch()]);await launch();
  const times=fs.readFileSync(log,'utf8').trim().split('\n').map(Number);assert.equal(times.length,3);
  assert.ok(times[1]-times[0]>=110);assert.ok(times[2]-times[1]>=110);
 }finally{fs.rmSync(root,{recursive:true,force:true});}
});

test('audit and direct scanner processes share the production VT pacing ledger',async()=>{
 const fs=require('node:fs'),os=require('node:os'),path=require('node:path');const {spawnSync}=require('node:child_process');const {pathToFileURL}=require('node:url');
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'gd-vt-shared-'));
 try{
  const script=path.join(root,'probe.mjs');
  fs.writeFileSync(script,`import {VirusTotalScanner} from ${JSON.stringify(pathToFileURL(path.resolve(__dirname,'../src/virustotal-scanner.js')).href)};
   import {createAuditAnalyzer} from ${JSON.stringify(pathToFileURL(path.resolve(__dirname,'../src/audit-analyzer.js')).href)};
   let now=1000;const scanner=new VirusTotalScanner({virustotal:{apiKey:'cross-process-fixture',baseUrl:'https://vt.invalid',timeoutMs:1000}},{now:()=>now,wait:async ms=>{now+=ms;},fetch:async()=>({ok:false,status:404,headers:new Headers()})});
   if(process.argv[2]==='audit')createAuditAnalyzer({config:{},scanner,cveChecker:{checkCVEs:async()=>null},reputation:{checkGitHub:async()=>null,checkReputation:async()=>null}},{cacheDir:${JSON.stringify(path.join(root,'cache'))}});
   await scanner.scan('a'.repeat(64));console.log(now);`);
  const run=mode=>spawnSync(process.execPath,[script,mode],{env:{...process.env,GUARDOG_HOME:root},encoding:'utf8',timeout:5000});
  const first=run('audit'),second=run('direct');assert.equal(first.status,0,first.stderr);assert.equal(second.status,0,second.stderr);
  assert.equal(Number(first.stdout.trim()),1000);assert.equal(Number(second.stdout.trim()),17000);
 }finally{fs.rmSync(root,{recursive:true,force:true});}
});

test('corrupt or symlinked pacing state never permits a request',async t=>{
 const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'gd-pacer-corrupt-'));
 try {
  const {createRequestPacer}=await import('../src/request-pacer.js');const {cacheDigest}=await import('../src/scan-cache.js');
  const file=path.join(root,cacheDigest('state-test')+'.json'),pace=createRequestPacer('state-test',{directory:root});let called=false;
  fs.writeFileSync(file,'broken',{mode:0o600});await assert.rejects(pace(120,()=>{called=true;}));assert.equal(called,false);
  fs.unlinkSync(file);const target=path.join(root,'target.json');fs.writeFileSync(target,'{"next":0}',{mode:0o600});
  try{fs.symlinkSync(target,file);}catch(error){if(error.code==='EPERM'){t.diagnostic('Host does not permit file symlink fixture');return;}throw error;}
  await assert.rejects(pace(120,()=>{called=true;}),/Unsafe/);assert.equal(called,false);assert.equal(fs.readFileSync(target,'utf8'),'{"next":0}');
 }finally{fs.rmSync(root,{recursive:true,force:true});}
});
