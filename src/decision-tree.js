/**
 * Decision Tree Logic
 * Determines threat level: BARK (danger), WHINE (suspicious), or SILENT (safe)
 */

export class DecisionTree {
  constructor(config, trustedProviders) {
    this.thresholds = config.decisionThresholds;
    this.trusted = trustedProviders;
  }

  /**
   * Evaluate threat level based on scan and reputation data
   * @param {Object} scanResults - VirusTotal scan results
   * @param {Object} reputationData - Reputation check results
   * @param {string} packageName - Package name
   * @param {Object} cveResults - CVE check results
   * @param {Object} patternResults - Pattern analysis results
   * @returns {Object} Decision with action and reasoning
   */
  evaluate(scanResults, reputationData, packageName, cveResults = null, patternResults = null, vtAttempted = false) {
    const decision = {
      action: 'SILENT',
      threat: 'SAFE',
      confidence: 100,
      reasons: [],
      notes: [],
      installAllowed: false,
      details: {
        scan: scanResults,
        reputation: reputationData
      }
    };

    const isTrusted = this.isTrustedProvider(packageName, reputationData?.ecosystem || 'npm');

    if (isTrusted) {
      decision.notes.push('Trusted provider - reputation heuristics skipped');
    }
    const notFound = reputationData?.signals?.includes('PACKAGE_NOT_FOUND');

    // Evaluate VirusTotal results
    const vtScore = this.evaluateVirusTotal(scanResults, decision.reasons, vtAttempted);
    
    // Evaluate reputation signals
    const repScore = isTrusted ? 0 : this.evaluateReputation(reputationData, decision.reasons);

    // Evaluate CVE results
    const cveScore = this.evaluateCVEs(cveResults, decision.reasons);

    // Evaluate pattern analysis
    const patternScore = this.evaluatePatterns(patternResults, decision.reasons);

    // Calculate combined threat score
    const totalScore = vtScore + repScore + cveScore + patternScore;

    // Determine action based on score
    const confirmedDanger = (scanResults.maliciousVotes || 0) >= (this.thresholds.maliciousVotes || 3)
      || (cveResults?.severity?.critical || 0) > 0
      || cveResults?.vulnerabilities?.some(v => /^MAL-/.test(v.id) || /malicious package|malware/i.test(v.summary || ''));
    const incomplete = cveResults?.status !== 'complete'
      || !scanResults.success || !scanResults.found || scanResults.stale === true
      || !reputationData || Boolean(reputationData.error) || notFound
      || reputationData.signals?.includes('GITHUB_CHECK_FAILED')
      || reputationData.signals?.includes('REPOSITORY_UNCHECKED')
      || reputationData.registry?.artifactCoverage === 'incomplete'
      || patternResults?.failed === true;
    decision.coverage = incomplete ? 'incomplete' : 'complete';
    if (totalScore >= 100 || confirmedDanger) {
      decision.action = 'BARK';
      decision.threat = 'DANGER';
      decision.confidence = Math.min(totalScore, 100);
    } else if (notFound) {
      decision.action = 'WHINE';
      decision.threat = 'NOT_FOUND';
      decision.reasons.push('Package is unavailable in the registry. Installed versions may still have known advisories.');
    } else if (totalScore >= 50) {
      decision.action = 'WHINE';
      decision.threat = 'SUSPICIOUS';
      decision.confidence = totalScore;
    } else {
      decision.action = 'SILENT';
      decision.threat = decision.reasons.length > 0 ? 'UNCONFIRMED' : 'SAFE';
      decision.confidence = 100 - totalScore;
    }

    if (incomplete) {
      decision.notes.push('Protection is incomplete. Resolve missing checks with myos-guard-dog doctor --repair and myos-guard-dog test.');
      if (decision.action === 'SILENT') decision.threat = 'INCOMPLETE';
    }
    decision.installAllowed = !incomplete && decision.action === 'SILENT' && decision.threat === 'SAFE'
      && !cveResults?.found && !(scanResults.maliciousVotes > 0) && !(scanResults.suspiciousVotes > 0);

    return decision;
  }

  /**
   * Check if package is from a trusted provider
   * @param {string} packageName - Package name
   * @returns {boolean} Is trusted
   */
  isTrustedProvider(packageName, ecosystem = 'npm') {
    if (ecosystem === 'pypi') return (this.trusted.trustedScopes?.pypi || []).includes(packageName.toLowerCase());
    if (ecosystem === 'rubygems') return (this.trusted.trustedScopes?.rubygems || []).includes(packageName.toLowerCase());
    if (ecosystem !== 'npm') return false;
    // Check exact matches
    if (this.trusted.trustedProviders.includes(packageName)) {
      return true;
    }

    // Check namespaced packages
    for (const namespace of this.trusted.trustedNamespaces) {
      if (packageName.startsWith(namespace + '/')) {
        return true;
      }
    }

    // Check trusted scopes (e.g., @vercel/analytics matches scope "vercel")
    if (packageName.startsWith('@')) {
      const scope = packageName.slice(1).split('/')[0];
      const npmScopes = (this.trusted.trustedScopes?.npm || []);
      if (npmScopes.includes(scope)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Evaluate VirusTotal scan results
   * @param {Object} scanResults - Scan results
   * @param {Array} reasons - Reasons array to append to
   * @returns {number} Threat score (0-100)
   */
  evaluateVirusTotal(scanResults, reasons, vtAttempted = false) {
    let score = 0;

    if (!scanResults.success) {
      // Only penalize if VT was actually attempted (API key set + target provided)
      if (!vtAttempted) {
        return 0;
      }
      reasons.push('VirusTotal scan failed - treating as suspicious');
      return 20;
    }

    if (!scanResults.found) {
      reasons.push('No VirusTotal data available');
      return 10;
    }

    const malicious = scanResults.maliciousVotes || 0;
    const suspicious = scanResults.suspiciousVotes || 0;

    // Malicious detections
    if (malicious >= this.thresholds.maliciousVotes) {
      score += 70;
      reasons.push(`⚠️ ${malicious} engines flagged as MALICIOUS`);
    } else if (malicious > 0) {
      score += 30;
      reasons.push(`⚠️ ${malicious} engine(s) flagged as malicious`);
    }

    // Suspicious detections
    if (suspicious >= this.thresholds.suspiciousVotes) {
      score += 20;
      reasons.push(`${suspicious} engines flagged as SUSPICIOUS`);
    }

    return score;
  }

  /**
   * Evaluate reputation signals
   * @param {Object} reputationData - Reputation data
   * @param {Array} reasons - Reasons array to append to
   * @returns {number} Threat score (0-100)
   */
  evaluateReputation(reputationData, reasons) {
    let score = 0;

    if (!reputationData || reputationData.error) {
      reasons.push('Unable to verify package reputation');
      return 15;
    }

    const signals = reputationData.signals || [];

    // Critical signals (high risk)
    if (signals.includes('PACKAGE_NOT_FOUND')) {
      score += 30;
      reasons.push('❌ Package not found in registry');
    }

    if (signals.includes('SECURITY_COMPLAINTS')) {
      score += 15;
      reasons.push('Unverified open malware reports on GitHub, requires corroboration');
    }

    if (signals.includes('DISABLED_REPO')) {
      score += 35;
      reasons.push('❌ Repository disabled');
    }

    // Warning signals (medium risk)
    if (signals.includes('DEPRECATED')) {
      score += 15;
      reasons.push('⚠️ Package is deprecated');
    }

    if (signals.includes('NEWLY_PUBLISHED')) {
      score += 20;
      reasons.push('🆕 Package version recently published (< 30 days)');
    }

    if (signals.includes('NO_REPOSITORY')) {
      score += 25;
      reasons.push('❓ No source repository linked');
    }

    if (signals.includes('GITHUB_CHECK_FAILED')) {
      score += 25;
      reasons.push('❓ GitHub could not be checked - security complaints and repo status are UNKNOWN, not clear');
    }

    if (signals.includes('REPOSITORY_UNCHECKED')) {
      score += 25;
      reasons.push('❓ Linked repository is outside supported GitHub checks; repo status is UNKNOWN');
    }

    if (signals.includes('ARCHIVED_REPO')) {
      score += 10;
      reasons.push('📦 Repository is archived');
    }

    // Low-risk signals
    if (signals.includes('LOW_DOWNLOADS')) {
      score += 10;
      reasons.push('📉 Low weekly downloads (< 1,000)');
    }

    if (signals.includes('LOW_STARS')) {
      score += 5;
      reasons.push('⭐ Low GitHub stars (< 50)');
    }

    if (signals.includes('NO_MAINTAINERS')) {
      score += 10;
      reasons.push('👤 No active maintainers');
    }

    return Math.min(score, 100);
  }

  /**
   * Evaluate CVE results
   * @param {Object} cveResults - CVE check results
   * @param {Array} reasons - Reasons array to append to
   * @returns {number} Threat score (0-100)
   */
  evaluateCVEs(cveResults, reasons) {
    if (!cveResults || !cveResults.found) {
      return 0;
    }

    let score = 0;
    const severity = cveResults.severity;

    // Critical vulnerabilities
    if (severity.critical > 0) {
      score += severity.critical * 25;
      reasons.push(`🚨 ${severity.critical} CRITICAL CVE(s) found`);
    }

    // High severity
    if (severity.high > 0) {
      score += severity.high * 15;
      reasons.push(`⚠️ ${severity.high} HIGH severity CVE(s) found`);
    }

    // Medium severity
    if (severity.medium > 0) {
      score += severity.medium * 5;
      reasons.push(`⚠️ ${severity.medium} MEDIUM severity CVE(s) found`);
    }

    // Low severity
    if (severity.low > 0) {
      score += severity.low * 2;
      reasons.push(`ℹ️ ${severity.low} LOW severity CVE(s) found`);
    }

    return Math.min(score, 100);
  }

  /**
   * Evaluate pattern analysis results
   * @param {Object} patternResults - Pattern analysis results
   * @param {Array} reasons - Reasons array to append to
   * @returns {number} Threat score (0-100)
   */
  evaluatePatterns(patternResults, reasons) {
    if (!patternResults || !patternResults.suspicious) {
      return 0;
    }

    const score = patternResults.score || 0;
    const severity = patternResults.severity || patternResults.combinedSeverity;

    if (!severity) return 0;

    // Add specific pattern warnings
    const source = patternResults.scope === 'registry_description_only' ? 'registry description' : 'checked text';
    if (severity.critical > 0) {
      reasons.push(`🔴 ${severity.critical} CRITICAL pattern(s) found in ${source}`);
    }

    if (severity.high > 0) {
      reasons.push(`⚠️ ${severity.high} HIGH-risk pattern(s) found in ${source}`);
    }

    if (severity.medium > 0) {
      reasons.push(`⚠️ ${severity.medium} MEDIUM-risk pattern(s) found in ${source}`);
    }

    if (severity.low > 0 && severity.low > 5) {
      reasons.push(`ℹ️ ${severity.low} LOW-risk pattern(s) found in ${source}`);
    }

    return Math.min(score, 100);
  }

  /**
   * Format decision for display
   * @param {Object} decision - Decision object
   * @returns {string} Formatted output
   */
  formatDecision(decision) {
    const emoji = {
      BARK: '🚨',
      WHINE: '⚠️',
      SILENT: '✅'
    };

    const icon = ['UNCONFIRMED', 'INCOMPLETE'].includes(decision.threat) ? 'ℹ️' : (emoji[decision.action] || '❓');

    let output = `${icon} ${decision.action}: ${decision.threat}\n`;
    output += `Confidence: ${decision.confidence}%\n\n`;

    if (decision.reasons && decision.reasons.length > 0) {
      output += 'Reasons:\n';
      decision.reasons.forEach(reason => {
        output += `  • ${reason}\n`;
      });
      if (decision.threat === 'UNCONFIRMED') {
        output += 'Not a clean result - the signals above scored below the warning threshold.\n';
      }
    }

    if (decision.notes && decision.notes.length > 0) {
      if (decision.reasons && decision.reasons.length > 0) {
        output += '\n';
      }
      output += 'Notes:\n';
      decision.notes.forEach(note => {
        output += `  • ${note}\n`;
      });
    }

    return output;
  }
}
