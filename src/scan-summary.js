export function summarizeDependencyScan(inventory, results) {
  const dangerousCount = results.filter(result => result.decision?.action === 'BARK').length;
  const suspiciousCount = results.filter(result => result.decision?.action === 'WHINE' || (result.decision?.action === 'SILENT' && result.decision?.coverage === 'complete' && result.decision?.threat !== 'SAFE')).length;
  const issues = [...inventory.issues];
  let incompleteCount = 0;
  results.forEach((result, index) => {
    const failures = [];
    if (result.decision?.coverage !== 'complete') failures.push(`scan coverage ${result.decision?.coverage || 'not reported'}`);
    if (result.cveResults?.status !== 'complete') failures.push(`CVE check ${result.cveResults?.status || 'not reported'}${result.cveResults?.error ? ': ' + result.cveResults.error : ''}`);
    if (result.scanResults?.error) failures.push(`VirusTotal: ${result.scanResults.error}`);
    for (const [name, check] of Object.entries(result.checks || result.decision?.checks || {})) {
      const status = typeof check === 'string' ? check : check?.status;
      if (status && !['complete', 'ok', 'available'].includes(status)) failures.push(`${name}: ${status}${check?.error ? ': ' + check.error : ''}`);
    }
    if (failures.length === 0) return;
    incompleteCount++;
    const pkg = inventory.packages[index];
    const name = result.packageName || pkg?.name || 'unknown package';
    const version = result.version || result.resolvedVersion || pkg?.version || 'unknown version';
    issues.push(`${name}@${version}: ${failures.join('; ')}`);
  });
  if (results.length !== inventory.packages.length) {
    const missing = Math.max(0, inventory.packages.length - results.length);
    incompleteCount += missing;
    issues.push(`Expected ${inventory.packages.length} dependency results, received ${results.length}.`);
  }
  if (!inventory.complete && inventory.issues.length === 0) issues.push('Dependency inventory coverage is incomplete.');
  const incomplete = !inventory.complete || incompleteCount > 0 || issues.length > 0;
  const quotaExhausted = results.some(result => result.scanResults?.status === 'rate_limited');
  return {
    status: dangerousCount ? 'dangerous' : incomplete ? 'incomplete' : suspiciousCount ? 'suspicious' : 'complete',
    coverage: incomplete ? 'incomplete' : 'complete',
    dependencyCount: inventory.packages.length,
    inventoryComplete: inventory.complete === true,
    dangerousCount,
    suspiciousCount,
    incompleteCount,
    quotaExhausted,
    advisoryCheckedCount: results.filter(result => result.cveResults?.status === 'complete').length,
    enrichmentCheckedCount: results.filter(result => result.decision?.coverage === 'complete').length,
    findings: results.filter(result => ['BARK','WHINE'].includes(result.decision?.action) || result.cveResults?.vulnerabilities?.length).map(result => ({
      packageName: result.packageName, version: result.version, ecosystem: result.ecosystem,
      action: result.decision?.action, threat: result.decision?.threat,
      advisoryIds: (result.cveResults?.vulnerabilities || []).map(v => v.id).filter(Boolean)
    })),
    issues
  };
}

export function auditExitCode(results) {
  if (results.some(result => result.decision?.action === 'BARK')) return 1;
  if (results.some(result => result.decision?.action !== 'SILENT' || result.decision?.threat !== 'SAFE' || result.decision?.coverage !== 'complete')) return 2;
  return 0;
}

/** Keep advisory findings when enrichment stops or is killed. Never claim full coverage. */
export function mergeAuditPhases(advisories, enrichment) {
  if(!advisories)return enrichment;
  if(!advisories.inventoryFingerprint || advisories.inventoryFingerprint!==enrichment.inventoryFingerprint) {
    return {...enrichment,issues:[...enrichment.issues,'Advisory snapshot invalidated: dependency inventory changed or its identity is unavailable.']};
  }
  const byPackage=new Map();
  for(const finding of [...(advisories.findings||[]),...(enrichment.findings||[])]) {
    const key=JSON.stringify([finding.ecosystem,finding.packageName,finding.version]);
    const old=byPackage.get(key);
    byPackage.set(key,{...finding,action:old?.action==='BARK'?'BARK':finding.action,advisoryIds:[...new Set([...(old?.advisoryIds||[]),...(finding.advisoryIds||[])])]});
  }
  const findings=[...byPackage.values()];
  const dangerousCount=Math.max(advisories.dangerousCount||0,enrichment.dangerousCount||0,findings.filter(f=>f.action==='BARK').length);
  const suspiciousCount=Math.max(advisories.suspiciousCount||0,enrichment.suspiciousCount||0,findings.filter(f=>f.action==='WHINE').length);
  const advisoryCheckedCount=Math.max(advisories.advisoryCheckedCount||0,enrichment.advisoryCheckedCount||0);
  const issues=[...enrichment.issues];
  if(advisoryCheckedCount<enrichment.dependencyCount)issues.push(`Advisory coverage incomplete: ${advisoryCheckedCount}/${enrichment.dependencyCount} dependencies checked.`);
  return {...enrichment,findings,dangerousCount,suspiciousCount,advisoryCheckedCount,issues,
    status:dangerousCount?'dangerous':enrichment.coverage==='incomplete'?'incomplete':suspiciousCount?'suspicious':enrichment.status};
}
