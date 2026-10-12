const test=require('node:test'),assert=require('node:assert/strict');
test('SARIF exports safe relative URIs and redacted typed findings',async()=>{
 const {toSarif}=await import('../src/workspace-report.js');
 const finding={ruleId:'GD-SECRET-GITHUB',path:'folder with space/a#b.js',line:2,severity:'high',confidence:'high',category:'secrets',message:'Possible credential.',remediation:'Rotate it.',fingerprint:'a'.repeat(64),baselineState:'new',engine:'native'};
 const doc=toSarif({findings:[finding],coverage:{complete:true},issues:[],rulesetVersion:'1'});
 assert.equal(doc.version,'2.1.0');
 assert.equal(doc.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri,'folder%20with%20space/a%23b.js');
 assert.equal(doc.runs[0].results[0].level,'error');
});

test('baseline annotates but never removes findings or changes enforcement',async()=>{
 const {finalizeReport,baselineFor}=await import('../src/workspace-report.js');
 const report={rulesetVersion:'1',findings:[{ruleId:'x',path:'a.js',line:1,severity:'high',fingerprint:'a'.repeat(64)}],engines:[],coverage:{complete:true},issues:[]};
 const baseline=baselineFor(report);finalizeReport(report,{baseline});
 assert.equal(report.findings.length,1);assert.equal(report.findings[0].baselineState,'unchanged');assert.equal(report.exitCode,1);assert.equal(report.summary.new,0);
});
test('incomplete engine cannot become a clean scan and detections survive failure',async()=>{
 const {finalizeReport,baselineFor}=await import('../src/workspace-report.js');
 const report={rulesetVersion:'1',findings:[],engines:[],coverage:{complete:true},issues:[]};
 finalizeReport(report,{engines:[{id:'clamav',status:'incomplete',findings:[{ruleId:'GD-CLAMAV',path:'x',severity:'high'}],issues:['unavailable']}]});
 assert.equal(report.coverage.complete,false);assert.equal(report.findings.length,1);assert.equal(report.exitCode,1);assert.throws(()=>baselineFor(report));
});
test('malformed baselines fail instead of suppressing findings',async()=>{
 const {finalizeReport}=await import('../src/workspace-report.js');
 assert.throws(()=>finalizeReport({rulesetVersion:'1',findings:[],engines:[],coverage:{complete:true}},{baseline:{schemaVersion:1,rulesetVersion:'1',fingerprints:['not a hash']}}));
});

test('SARIF retains optional engine failure diagnostics',async()=>{
 const {toSarif}=await import('../src/workspace-report.js');
 const doc=toSarif({findings:[],coverage:{complete:false},issues:[],engines:[{id:'clamav',status:'incomplete',issues:['Database stale']}],scope:{network:false}});
 assert.equal(doc.runs[0].invocations[0].executionSuccessful,false);
 assert.equal(doc.runs[0].invocations[0].toolExecutionNotifications.length,1);
 assert.equal(doc.runs[0].properties.engines[0].status,'incomplete');
});
