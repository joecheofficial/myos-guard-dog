import { lstatSync, openSync, fstatSync, readSync, closeSync, constants, writeFileSync } from 'node:fs';
import { fingerprint } from './workspace-scan.js';
const ranks={critical:4,high:3,medium:2,low:1};
export function finalizeReport(report,{engines=[],baseline,failOn='high'}={}) {
 if(!(failOn in ranks))throw Error('Invalid failure severity');
 for(const engine of engines) {
  report.engines.push(engine);
  if(engine.status!=='complete')report.coverage.complete=false;
  for(const finding of engine.findings||[])report.findings.push({...finding,line:finding.line||1,engine:engine.id,fingerprint:fingerprint(finding),baselineState:'new'});
 }
 if(baseline) {
  if(baseline.schemaVersion!==1 || baseline.rulesetVersion!==report.rulesetVersion || !Array.isArray(baseline.fingerprints) || baseline.fingerprints.length>10000 || !baseline.fingerprints.every(x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x))) throw Error('Invalid or incompatible workspace baseline');
  const known=new Set(baseline.fingerprints);
  for(const finding of report.findings)finding.baselineState=known.has(finding.fingerprint)?'unchanged':'new';
 }
 report.findings.sort((a,b)=>ranks[b.severity]-ranks[a.severity]||a.path.localeCompare(b.path)||a.line-b.line||a.ruleId.localeCompare(b.ruleId));
 report.summary={total:report.findings.length,new:report.findings.filter(f=>f.baselineState==='new').length,bySeverity:Object.fromEntries(Object.keys(ranks).map(s=>[s,report.findings.filter(f=>f.severity===s).length]))};
 report.status=report.findings.length?'findings':report.coverage.complete?'complete':'incomplete';
 // Baselines annotate known findings. They do not grant an exception to enforcement.
 report.exitCode=report.findings.some(f=>ranks[f.severity]>=ranks[failOn])?1:report.coverage.complete?0:2;
 return report;
}
export function readBaseline(file) {
 const info=lstatSync(file);
 if(!info.isFile() || info.isSymbolicLink() || info.size>1024*1024)throw Error('Invalid workspace baseline file');
 const fd=openSync(file,constants.O_RDONLY|(constants.O_NOFOLLOW||0)|(constants.O_NONBLOCK||0));
 try {
  const current=fstatSync(fd);
  if(!current.isFile()||current.dev!==info.dev||current.ino!==info.ino||current.size!==info.size)throw Error('Workspace baseline changed');
  const data=Buffer.alloc(info.size+1),n=readSync(fd,data,0,data.length,0);
  if(n!==info.size)throw Error('Workspace baseline changed');
  return JSON.parse(data.subarray(0,n).toString('utf8'));
 }finally{closeSync(fd);}
}
export function baselineFor(report) {
 if(!report.coverage.complete)throw Error('Cannot baseline an incomplete scan');
 return {schemaVersion:1,rulesetVersion:report.rulesetVersion,createdAt:new Date().toISOString(),fingerprints:[...new Set(report.findings.map(f=>f.fingerprint))]};
}
export function writeNewJson(file,value) {
 // Never replace a project file, symlink, prior report or baseline by accident.
 writeFileSync(file,JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o600});
}
export function toSarif(report) {
 const active=new Map(report.findings.map(f=>[f.ruleId,f]));
 const rules=[...active].map(([id,f])=>({id,shortDescription:{text:f.message},help:{text:f.remediation||'Review the finding with the configured scanner.'},properties:{category:f.category,confidence:f.confidence}}));
 return {$schema:'https://json.schemastore.org/sarif-2.1.0.json',version:'2.1.0',runs:[{tool:{driver:{name:'MyOS Guard Dog',rules}},invocations:[{executionSuccessful:report.coverage.complete,toolExecutionNotifications:[...(report.issues||[]).map(i=>({level:'warning',message:{text:i.code}})),...(report.engines||[]).flatMap(e=>(e.issues||[]).map(issue=>({level:'warning',message:{text:e.id+': '+(typeof issue==='string'?issue:issue.code)}})))]}],properties:{coverage:report.coverage,scope:report.scope,engines:(report.engines||[]).map(({findings,...engine})=>engine),rulesetVersion:report.rulesetVersion},results:report.findings.map(f=>({ruleId:f.ruleId,level:['critical','high'].includes(f.severity)?'error':f.severity==='medium'?'warning':'note',message:{text:f.message},locations:[{physicalLocation:{artifactLocation:{uri:f.path.split('/').map(encodeURIComponent).join('/')},region:{startLine:f.line||1}}}],partialFingerprints:{'guarddog/v1':f.fingerprint},baselineState:f.baselineState==='unchanged'?'unchanged':'new',properties:{severity:f.severity,confidence:f.confidence,category:f.category,engine:f.engine,remediation:f.remediation}}))}]};
}
function terminal(value){return String(value).replace(/[\x00-\x1f\x7f-\x9f]/g,'?');}
export function renderText(report) {
 const lines=[`Guard Dog workspace: ${report.status}; coverage ${report.coverage.complete?'complete within stated scope':'INCOMPLETE'}`,`${report.coverage.filesScanned} files; ${report.summary.total} findings (${report.summary.new} new).`];
 for(const f of report.findings)lines.push(`${f.severity.toUpperCase()} ${f.ruleId} ${terminal(f.path)}:${f.line} [${f.baselineState}] ${f.message}`);
 for(const i of report.issues)lines.push(`INCOMPLETE ${i.code}${i.path?' '+terminal(i.path):''}`);
 for(const e of report.engines)lines.push(`Engine ${e.id}: ${e.status}${e.issues?.length?' ('+e.issues.map(x=>terminal(typeof x==='string'?x:x.code)).join(', ')+')':''}`);
 lines.push('Native rules are text heuristics, not full malware, taint or runtime protection. Review scope and exclusions.');
 return lines.join('\n');
}
