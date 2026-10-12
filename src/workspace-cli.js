import { resolve } from 'node:path';
import { scanWorkspace } from './workspace-scan.js';
import { scanWithClamAV } from './workspace-engines.js';
import { finalizeReport,readBaseline,baselineFor,writeNewJson,toSarif,renderText } from './workspace-report.js';

export function workspaceCommand(args) {
 const options={},extras={},flags=new Set();
 let root,format='text';
 const numeric={'--max-files':'maxFiles','--max-file-bytes':'maxFileBytes','--max-bytes':'maxTotalBytes','--max-depth':'maxDepth','--timeout-ms':'timeoutMs','--max-findings':'maxFindings'};
 const values=new Set([...Object.keys(numeric),'--baseline','--write-baseline','--output','--clamav','--fail-on']);
 for(let i=0;i<args.length;i++) {
  const arg=args[i];
  if(arg.startsWith('--')) {
   if(flags.has(arg))throw Error('Duplicate workspace option');flags.add(arg);
   if(arg==='--json'||arg==='--sarif') {
    if(format!=='text')throw Error('Choose one report format');format=arg.slice(2);
   } else if(arg==='--include-dependencies')options.includeDependencies=true;
   else if(values.has(arg)) {
    const value=args[++i];if(!value||value.startsWith('--'))throw Error('Workspace option requires a value');
    if(numeric[arg])options[numeric[arg]]=Number(value);else extras[arg.slice(2)]=value;
   } else throw Error('Unknown workspace option');
  } else {if(root)throw Error('Only one workspace root is accepted');root=arg;}
 }
 root=resolve(root||process.cwd());
 const baseline=extras.baseline?readBaseline(resolve(extras.baseline)):undefined;
 const native=scanWorkspace(root,options);
 const engines=extras.clamav?[scanWithClamAV({root,executable:extras.clamav})]:[];
 const report=finalizeReport(native,{engines,baseline,failOn:extras['fail-on']||'high'});
 try {
  if(extras['write-baseline'])writeNewJson(resolve(extras['write-baseline']),baselineFor(report));
  if(extras.output)writeNewJson(resolve(extras.output),format==='sarif'?toSarif(report):report);
 } catch {
  report.coverage.complete=false;
  report.issues.push({code:'report_or_baseline_write_failed'});
  finalizeReport(report,{failOn:extras['fail-on']||'high'});
 }
 const output=format==='sarif'?toSarif(report):report;
 console.log(format==='text'?renderText(report):JSON.stringify(output,null,2));
 return report.exitCode;
}
