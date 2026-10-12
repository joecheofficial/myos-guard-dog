import { lstatSync, realpathSync, opendirSync, openSync, readSync, fstatSync, closeSync, constants } from 'node:fs';
import { resolve, join, relative, isAbsolute } from 'node:path';
import { createHash } from 'node:crypto';
import { inspectText, isTextPath, RULESET_VERSION } from './workspace-rules.js';

const DEFAULTS = {maxFiles:20000,maxEntries:50000,maxFileBytes:1024*1024,maxTotalBytes:128*1024*1024,maxDepth:30,timeoutMs:60000,maxFindings:2000};
const CEILINGS = {maxFiles:200000,maxEntries:500000,maxFileBytes:8*1024*1024,maxTotalBytes:1024*1024*1024,maxDepth:100,timeoutMs:600000,maxFindings:10000};
const EXCLUDED = ['.git','node_modules','.venv','venv','vendor','.next','dist','build','coverage','.guardog'];
export function within(root,file) { const r=relative(root,file); return r==='' || (!r.startsWith('..'+(process.platform==='win32'?'\\':'/')) && r!=='..' && !isAbsolute(r)); }
export function fingerprint(finding) { return createHash('sha256').update([RULESET_VERSION,finding.ruleId,finding.path,finding.evidenceHash||finding.ruleId].join('\0')).digest('hex'); }

export function scanWorkspace(input, options = {}) {
  const limits={...DEFAULTS};
  for(const key of Object.keys(limits)) {
    if(options[key]!==undefined) limits[key]=options[key];
    if(!Number.isSafeInteger(limits[key]) || limits[key]<1 || limits[key]>CEILINGS[key]) throw new Error('Invalid workspace scan limit: '+key);
  }
  const started=Date.now(), findings=[], issues=[];
  const scope={excludedDirectories:EXCLUDED.filter(x=>!options.includeDependencies||!['node_modules','vendor'].includes(x)),includesHiddenConfiguration:true,symlinks:'never followed',binaryAnalysis:'native test signature only; use ClamAV for malware signatures',network:false,projectExecution:false};
  const coverage={complete:true,filesScanned:0,textFiles:0,binaryFiles:0,bytesRead:0,entriesVisited:0,excludedDirectories:0,skippedFiles:0,limits};
  const report={schemaVersion:1,rulesetVersion:RULESET_VERSION,startedAt:new Date(started).toISOString(),status:'incomplete',exitCode:2,scope,coverage,engines:[{id:'native',status:'complete'}],findings,issues};
  const issue=(code,path)=>{coverage.complete=false;if(issues.length<100)issues.push({code,...(path?{path}: {})});};
  let root;
  try {
    root=resolve(input);
    if(!lstatSync(root).isDirectory() || lstatSync(root).isSymbolicLink()) throw Error('invalid root');
    root=realpathSync(root);
  } catch { issue('root_unavailable'); return finish(); }
  const pending=[{dir:root,depth:0}], excluded=new Set(scope.excludedDirectories);
  let stopped=false;
  function budget() {
    if(Date.now()-started>=limits.timeoutMs) {issue('time_limit');return false;}
    if(coverage.entriesVisited>=limits.maxEntries) {issue('entry_limit');return false;}
    return true;
  }
  while(pending.length && !stopped) {
    const {dir,depth}=pending.pop();
    const dirName=relative(root,dir).split('\\').join('/');
    if(!budget()) break;
    let directory;
    try {
      if(lstatSync(dir).isSymbolicLink() || !within(root,realpathSync(dir))) {issue('directory_changed',dirName);continue;}
      directory=opendirSync(dir);
      let entry;
      while((entry=directory.readSync())) {
        if(!budget()) {stopped=true;break;}
        coverage.entriesVisited++;
        const file=join(dir,entry.name),name=relative(root,file).split('\\').join('/');
        if(entry.isSymbolicLink()) {coverage.skippedFiles++;issue('symlink_skipped',name);continue;}
        if(entry.isDirectory()) {
          if(excluded.has(entry.name)) {coverage.excludedDirectories++;continue;}
          if(depth>=limits.maxDepth) {issue('depth_limit',name);continue;}
          pending.push({dir:file,depth:depth+1});continue;
        }
        if(!entry.isFile()) {coverage.skippedFiles++;issue('special_file_skipped',name);continue;}
        if(coverage.filesScanned>=limits.maxFiles) {issue('file_limit');stopped=true;break;}
        let fd;
        try {
          const before=lstatSync(file);
          if(!before.isFile() || before.isSymbolicLink() || !within(root,realpathSync(file))) {issue('file_changed',name);continue;}
          if(before.size>limits.maxFileBytes) {coverage.skippedFiles++;issue('file_size_limit',name);continue;}
          if(coverage.bytesRead+before.size>limits.maxTotalBytes) {issue('byte_limit');stopped=true;break;}
          // O_NONBLOCK avoids blocking on a FIFO substituted after lstat; fstat rejects it.
          fd=openSync(file,constants.O_RDONLY | (constants.O_NOFOLLOW||0) | (constants.O_NONBLOCK||0));
          const opened=fstatSync(fd);
          if(!opened.isFile() || opened.dev!==before.dev || opened.ino!==before.ino || opened.size!==before.size) {issue('file_changed',name);continue;}
          const buffer=Buffer.alloc(before.size+1);
          let bytes=0,count;
          while(bytes<buffer.length && (count=readSync(fd,buffer,bytes,buffer.length-bytes,bytes))) bytes+=count;
          coverage.bytesRead+=bytes;
          const after=fstatSync(fd);
          if(bytes!==before.size || after.size!==before.size || after.mtimeMs!==before.mtimeMs || !within(root,realpathSync(file))) {issue('file_changed',name);continue;}
          coverage.filesScanned++;
          const content=buffer.subarray(0,bytes);
          let binary=content.includes(0),text;
          if(content[0]===255 && content[1]===254) {text=content.subarray(2).toString('utf16le');binary=false;}
          else if(content[0]===254 && content[1]===255 && content.length%2===0) {text=Buffer.from(content.subarray(2)).swap16().toString('utf16le');binary=false;}
          else if(binary)text=content.toString('latin1');
          else {try{text=new TextDecoder('utf-8',{fatal:true}).decode(content);}catch{binary=true;text=content.toString('latin1');issue('unsupported_encoding',name);}}
          if(binary) {
            coverage.binaryFiles++;
            if(isTextPath(name))issue('unsupported_text_encoding',name);
          } else coverage.textFiles++;
          const result=inspectText(text,name,{binary,deadline:started+limits.timeoutMs});
          if(result.timedOut)issue('time_limit');
          if(result.truncated) issue('file_finding_limit',name);
          for(const finding of result.findings) {
            if(findings.length>=limits.maxFindings) {issue('finding_limit');stopped=true;break;}
            const {evidenceHash,...safeFinding}=finding;
            findings.push({...safeFinding,fingerprint:fingerprint(finding),baselineState:'new'});
          }
        } catch { coverage.skippedFiles++;issue('file_unreadable',name); }
        finally {if(fd!==undefined)closeSync(fd);}
        if(stopped)break;
      }
    } catch {issue('directory_unreadable',dirName);}
    finally {if(directory)directory.closeSync();}
  }
  if(coverage.filesScanned===0) issue('no_files_scanned');
  return finish();
  function finish() {
    if(Date.now()-started>=limits.timeoutMs && !issues.some(i=>i.code==='time_limit'))issue('time_limit');
    report.engines[0].status=coverage.complete?'complete':'incomplete';
    report.finishedAt=new Date().toISOString();
    report.summary={total:findings.length,new:findings.length,bySeverity:Object.fromEntries(['critical','high','medium','low'].map(s=>[s,findings.filter(f=>f.severity===s).length]))};
    report.status=findings.length?'findings':coverage.complete?'complete':'incomplete';
    report.exitCode=findings.some(f=>['critical','high'].includes(f.severity))?1:coverage.complete?0:2;
    return report;
  }
}
