const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
test('cache corruption, expiry, future timestamps and namespace changes never provide evidence',async()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'gd-cache-'));
 try{
  const {EvidenceCache}=await import('../src/scan-cache.js');let now=100;
  const cache=new EvidenceCache({directory:root,namespace:'one',now:()=>now});
  cache.set('key',{findings:['danger']},100);assert.deepEqual(cache.get('key',100),{findings:['danger']});
  const file=cache.shard('key').path, saved=JSON.parse(fs.readFileSync(file));
  saved.value={findings:[]};fs.writeFileSync(file,JSON.stringify(saved));assert.equal(cache.get('key',100),null);
  cache.set('key',{findings:[]},100);now=201;assert.equal(cache.get('key',100),null);
  now=50;assert.equal(cache.get('key',100),null);
  assert.equal(new EvidenceCache({directory:root,namespace:'other',now:()=>150}).get('key',100),null);
  fs.writeFileSync(file,'broken');assert.equal(cache.get('key',100),null);
 }finally{fs.rmSync(root,{recursive:true,force:true});}
});
