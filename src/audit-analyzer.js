import { createRequestPacer } from './request-pacer.js';
import { randomUUID } from 'node:crypto';
import { EvidenceCache, cacheDigest } from './scan-cache.js';

const HOUR = 3600000;
/** Audit-only evidence reuse. Install gates continue to use an unwrapped GuardDog. */
export function createAuditAnalyzer(dog, { runId = randomUUID(), cacheDir, noCache = false } = {}) {
  const identity = cacheDigest([dog.config, process.env.GITHUB_API_TOKEN || process.env.GITHUB_TOKEN || '', process.env.VIRUSTOTAL_API_KEY || '']);
  const cache = new EvidenceCache({directory:cacheDir,namespace:['audit',identity]});
  const inflight = new Map();
  function memo(key, ttl, check, acceptable) {
    const id=cacheDigest(key);
    if(inflight.has(id))return inflight.get(id).then(structuredClone);
    const saved=noCache?null:cache.get(key,ttl);
    if(saved && acceptable(saved))return Promise.resolve(saved);
    const pending=Promise.resolve().then(check).then(value=>{
      if(!noCache && acceptable(value))cache.set(key,value,ttl);
      return value;
    }).finally(()=>inflight.delete(id));
    inflight.set(id,pending);
    return pending.then(structuredClone);
  }
  const osv=dog.cveChecker.checkCVEs.bind(dog.cveChecker);
  dog.cveChecker.checkCVEs=(name,ecosystem,version)=>memo(['osv',runId,name,ecosystem,version],HOUR,()=>osv(name,ecosystem,version),r=>r?.status==='complete'&&r.version===version&&Array.isArray(r.vulnerabilities));
  const github=dog.reputation.checkGitHub.bind(dog.reputation);
  const paceGitHub=createRequestPacer(['github',dog.config.reputation?.github,identity],{directory:cacheDir});
  dog.reputation.checkGitHub=url=>memo(['github',url?.replace(/\.git\/?$/,'').replace(/\/$/,'').toLowerCase()],HOUR,()=>paceGitHub((process.env.GITHUB_API_TOKEN||process.env.GITHUB_TOKEN)?2100:6100,()=>github(url)),r=>r?.ok===true&&Number.isInteger(r.securityIssues));
  const reputation=dog.reputation.checkReputation.bind(dog.reputation);
  dog.reputation.checkReputation=(name,ecosystem,version)=>memo(['reputation',name,ecosystem,version],HOUR,()=>reputation(name,ecosystem,version),r=>!!version&&r?.registry?.version===version&&!r.error&&Array.isArray(r.signals)&&!r.signals.some(s=>['GITHUB_CHECK_FAILED','REPOSITORY_UNCHECKED'].includes(s)));
  if(dog.scanner) {
    const scan=dog.scanner.scan.bind(dog.scanner);
    const maxAge=Math.min(dog.scanner.maxReportAgeMs||24*HOUR,24*HOUR);
    dog.scanner.scan=target=>memo(['vt',target],maxAge,()=>scan(target),r=>/^[a-f0-9]{64}$/i.test(target)&&r?.success===true&&r.found===true&&!r.stale&&Number.isFinite(Date.parse(r.lastAnalysisAt))&&Date.parse(r.lastAnalysisAt)<=Date.now()&&Date.now()-Date.parse(r.lastAnalysisAt)<maxAge);
  }
  dog.auditCache=noCache?null:cache;
  return {
    stats:cache.stats,
    async advisory(pkg) {
      const cveResults=await dog.cveChecker.checkCVEs(pkg.name,pkg.ecosystem,pkg.version);
      const scanResults={success:false,status:'deferred',error:'Enrichment is scheduled after advisory coverage.'};
      const decision=dog.decisionTree.evaluate(scanResults,null,pkg.name,cveResults,null,false);
      return {packageName:pkg.name,version:pkg.version,ecosystem:pkg.ecosystem,cveResults,scanResults,decision};
    },
    analyze:pkg=>dog.analyze(pkg.name,pkg.ecosystem,pkg.target,pkg.version)
  };
}
