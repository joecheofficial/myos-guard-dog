#!/usr/bin/env node
/**
 * Guard Dog - Package Security Scanner
 * Main orchestrator that coordinates all modules
 */

import { readFileSync, writeFileSync, existsSync, realpathSync, statSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join, resolve } from 'path';
import { spawnSync } from 'child_process';
import { createHash } from 'node:crypto';
import { loadEnvFile } from './env-loader.js';
import { assertSupportedNodeVersion } from './node-version.js';

import { VirusTotalScanner } from './virustotal-scanner.js';
import { ReputationChecker } from './reputation-checker.js';
import { CVEChecker } from './cve-checker.js';
import { PatternAnalyzer } from './pattern-analyzer.js';
import { DecisionTree } from './decision-tree.js';
import { ensureGuardogHome, guardogDataDir, guardogEnvPath, packageRoot } from './paths.js';
import { runGuardedInstall } from './guarded-install.js';
import { auditExitCode } from './scan-summary.js';
import { inspectNpmArtifact } from './npm-artifact-inspector.js';
import { inspectExactNpmRelease } from './npm-artifact-fetch.js';
import { checkHealth } from './health.js';
import {
  installGitHook,
  installNightlySchedule,
  loadUserConfig,
  printDoctor,
  removeGitHook,
  removeNightlySchedule,
  runQuickSetup,
  runSetup,
  saveUserConfig
} from './setup.js';

assertSupportedNodeVersion();

// Load environment variables
loadEnvFile(join(dirname(fileURLToPath(import.meta.url)), '../.env'));
loadEnvFile(guardogEnvPath(), { override: true });

export async function deriveVirusTotalTarget(reputationData, ecosystem) {
  const registry = reputationData?.registry;
  if (!registry || !registry.tarball) {
    return null;
  }

  if (ecosystem === 'pypi' && registry.sha256) {
    return registry.sha256;
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000);

    const response = await fetch(registry.tarball, { signal: controller.signal });
    if (!response.ok) {
      clearTimeout(timeoutId);
      return null;
    }

    const hash = createHash('sha256');
    let totalBytes = 0;
    const maxBytes = 50 * 1024 * 1024;

    for await (const chunk of response.body) {
      totalBytes += chunk.length;
      if (totalBytes > maxBytes) {
        clearTimeout(timeoutId);
        controller.abort();
        return null;
      }
      hash.update(chunk);
    }

    clearTimeout(timeoutId);
    return hash.digest('hex');
  } catch {
    return null;
  }
}

export function selectPyPiDistribution(registry, target = null) {
  const files = registry?.distributions || [];
  if (target) return files.find(file => file.sha256 && file.sha256.toLowerCase() === target.toLowerCase()) || null;
  return files.length === 1 && files[0].sha256 ? files[0] : null;
}

export class GuardDog {
  constructor() {
    const __dirname = dirname(fileURLToPath(import.meta.url));
    
    // Load configurations
    this.config = JSON.parse(
      readFileSync(join(__dirname, '../config/config.json'), 'utf-8')
    );
    
    this.trustedProviders = JSON.parse(
      readFileSync(join(__dirname, '../config/trusted-providers.json'), 'utf-8')
    );

    // Initialize modules
    try {
      this.scanner = new VirusTotalScanner(this.config);
    } catch (error) {
      console.warn('⚠️ VirusTotal scanner disabled:', error.message);
      this.scanner = null;
    }

    this.reputation = new ReputationChecker(this.config);
    this.cveChecker = new CVEChecker(this.config);
    this.patternAnalyzer = new PatternAnalyzer(this.config);
    this.decisionTree = new DecisionTree(this.config, this.trustedProviders);

    // Keep runtime state out of the installed package so global installs work
    // on macOS, Windows, Linux, and read-only npm package directories.
    ensureGuardogHome();
    this.dataDir = guardogDataDir();
  }

  /**
   * Load history from disk and repair simple malformed-array cases in place.
   * This keeps GuardDog writing durable evidence even if a previous run left
   * a trailing extra bracket in the history file.
   * @param {string} historyPath
   * @returns {Array<Object>}
   */
  loadScanHistory(historyPath) {
    if (!existsSync(historyPath)) return [];

    const raw = readFileSync(historyPath, 'utf-8').trim();
    if (!raw) return [];

    try {
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      const repairedCandidates = [
        raw.replace(/\]\s*\]+$/s, ']'),
        raw.slice(0, raw.lastIndexOf(']') + 1),
      ].filter(Boolean);

      for (const candidate of repairedCandidates) {
        try {
          const parsed = JSON.parse(candidate);
          if (Array.isArray(parsed)) {
            writeFileSync(historyPath, JSON.stringify(parsed, null, 2));
            return parsed;
          }
        } catch {
          // keep trying candidates
        }
      }

      return [];
    }
  }

  /**
   * Scan a package and determine threat level
   * @param {string} packageName - Package name
   * @param {string} ecosystem - 'npm' or 'pypi'
   * @param {string} target - Optional URL or hash to scan
   * @returns {Promise<Object>} Analysis results
   */
  async analyze(packageName, ecosystem = 'npm', target = null, version = null) {
    console.log(`\n🐕 Guard Dog analyzing: ${packageName} (${ecosystem})`);
    console.log('─'.repeat(60));

    const startTime = Date.now();
    let scanResults = { success: false, maliciousVotes: 0, suspiciousVotes: 0 };
    let reputationData = null;
    let cveResults = null;
    let patternResults = null;
    let vtAttempted = false;

    // Step 1: Reputation check
    console.log('📊 Checking reputation...');
    try {
      reputationData = await this.reputation.checkReputation(packageName, ecosystem, version);
      console.log(reputationData.error ? `Reputation unavailable: ${reputationData.error}` : `✓ Reputation check complete (${reputationData.signals.length} signals)`);
    } catch (error) {
      console.error('✗ Reputation check failed:', error.message);
    }

    // Step 2: VirusTotal scan (if available)
    let vtTarget = target;
    if (ecosystem === 'pypi' && reputationData?.registry) {
      const selected = selectPyPiDistribution(reputationData.registry, target);
      reputationData.registry.artifactCoverage = selected ? 'complete' : 'incomplete';
      reputationData.registry.selectedDistribution = selected?.filename || null;
      vtTarget = selected?.sha256 || null;
      if (selected) console.log(`PyPI artifact selected: ${selected.filename}`);
      else console.log('PyPI artifact coverage incomplete: choose the exact distribution SHA-256 for a multi-file release.');
    }
    if (this.scanner) {
      if (!vtTarget && reputationData?.registry?.tarball) {
        vtTarget = await deriveVirusTotalTarget(reputationData, ecosystem);
        if (!vtTarget) {
          console.log('⚠️  VirusTotal scan skipped (could not derive package hash)');
        }
      }

      if (vtTarget) {
        vtAttempted = true;
        console.log('🔍 Scanning with VirusTotal...');
        try {
          scanResults = await this.scanner.scan(vtTarget);
          if (scanResults.success && scanResults.found) {
            console.log(`✓ VirusTotal scan complete (${scanResults.totalEngines} engines)`);
          } else if (scanResults.success && !scanResults.found) {
            console.log('⚠️  VirusTotal has no record of this file (not a clean result)');
          } else {
            console.log(`✗ VirusTotal scan failed: ${scanResults.error || 'Unknown error'}`);
          }
        } catch (error) {
          console.error(`✗ VirusTotal scan failed: ${error.message}`);
        }
      } else if (!target && !reputationData?.registry?.tarball) {
        console.log('⚠️  VirusTotal scan skipped (no target URL/hash)');
      }
    } else {
      console.log('⚠️  VirusTotal scan skipped (no API key)');
    }

    scanResults.status = scanResults.status || (!this.scanner ? 'not_configured' : !vtTarget ? 'unavailable'
      : !scanResults.success ? 'unavailable' : !scanResults.found ? 'not_found' : 'complete');
    scanResults.target = vtTarget;
    scanResults.kind = /^https?:/.test(vtTarget || '') ? 'url_reputation' : 'artifact_hash';
    scanResults.checkedAt = new Date().toISOString();
    const resolvedVersion = version || reputationData?.registry?.version || null;
    // Step 3: CVE check
    console.log('🔐 Checking CVE databases...');
    try {
      cveResults = await this.cveChecker.checkCVEs(packageName, ecosystem, resolvedVersion);
      const cveCount = cveResults.vulnerabilities?.length || 0;
      console.log(cveResults.status === 'complete' ? `✓ CVE check complete for ${resolvedVersion} (${cveCount} vulnerabilities found)` : `CVE check INCOMPLETE: ${cveResults.error}`);
    } catch (error) {
      console.error('✗ CVE check failed:', error.message);
    }

    // Step 4: Check registry description text; package source is not inspected.
    console.log('🔎 Checking registry description patterns...');
    try {
      // Only registry metadata text is available in this scan path.
      const codeSnippets = {};
      if (reputationData?.registry?.description) {
        codeSnippets['description'] = reputationData.registry.description;
      }
      patternResults = this.patternAnalyzer.analyzeFiles(codeSnippets);
      patternResults.scope = 'registry_description_only';
      console.log(`Metadata text checks complete (score: ${patternResults.totalScore}); package source files were not scanned.`);
    } catch (error) {
      console.error('✗ Pattern analysis failed:', error.message);
      patternResults = { failed: true, scope: 'registry_description_only' };
    }

    // Step 5: Decision tree evaluation
    console.log('🎯 Evaluating threat level...');
    const decision = this.decisionTree.evaluate(
      scanResults, reputationData, packageName,
      cveResults, patternResults ? { suspicious: patternResults.suspiciousFiles > 0, score: patternResults.totalScore, severity: patternResults.combinedSeverity, scope: patternResults.scope, failed: patternResults.failed === true } : null,
      vtAttempted
    );
    if (ecosystem === 'pypi' && reputationData?.registry?.selectedDistribution) {
      decision.notes.push(`PyPI artifact verdict applies to ${reputationData.registry.selectedDistribution} only.`);
    }

    // Print results
    console.log('\n' + this.decisionTree.formatDecision(decision));

    // Suggest code-level review for flagged packages
    if (decision.action === 'BARK' || decision.action === 'WHINE') {
      console.log('\n💡 Review the exact package artifact and source before proceeding; this scan has not inspected package source files.');
    }

    const duration = Date.now() - startTime;
    console.log(`⏱️  Analysis completed in ${duration}ms`);
    console.log('─'.repeat(60));

    const result = {
      packageName,
      version: resolvedVersion,
      versionSource: version ? 'requested_exact' : 'registry_latest',
      ecosystem,
      decision,
      scanResults,
      reputationData,
      cveResults,
      patternResults,
      duration,
      timestamp: new Date().toISOString()
    };

    // Save to scan history
    this.saveScanHistory(result);

    return result;
  }

  /**
   * Save scan result to history file (keeps last 500 entries)
   * @param {Object} result - Scan result
   */
  saveScanHistory(result) {
    try {
      const historyPath = join(this.dataDir, 'scan-history.json');
      let history = this.loadScanHistory(historyPath);
      history.push({
        packageName: result.packageName,
        ecosystem: result.ecosystem,
        version: result.version,
        coverage: result.decision.coverage,
        checks: { osv: result.cveResults?.status || 'unavailable', virustotal: result.scanResults?.status || 'unavailable' },
        action: result.decision.action,
        threat: result.decision.threat,
        confidence: result.decision.confidence,
        reasons: result.decision.reasons,
        cveCount: result.cveResults?.status === 'complete' ? result.cveResults.vulnerabilities.length : null,
        patternScore: result.patternResults?.totalScore || 0,
        duration: result.duration,
        timestamp: result.timestamp
      });
      // Keep last 500 entries
      if (history.length > 500) {
        history = history.slice(-500);
      }
      writeFileSync(historyPath, JSON.stringify(history, null, 2));
    } catch (error) {
      console.error('⚠️  Failed to save scan history:', error.message);
    }
  }

  /**
   * Batch analyze multiple packages
   * @param {Array<Object>} packages - Array of {name, ecosystem, target?}
   * @returns {Promise<Array>} Results for all packages
   */
  async batchAnalyze(packages) {
    console.log(`\n🐕 Guard Dog batch analysis: ${packages.length} packages\n`);
    
    const results = new Array(packages.length);
    let next = 0;
    const worker = async () => {
      while (next < packages.length) {
        const index = next++;
        const pkg = packages[index];
        results[index] = await this.analyze(pkg.name, pkg.ecosystem, pkg.target, pkg.version);

        // VirusTotal enforces its own request-level queue, including refreshes.
        await new Promise(resolve => setTimeout(resolve, 250));
      }
    };
    await Promise.all(Array.from({ length: Math.min(4, packages.length) }, worker));

    // Summary
    const dangerous = results.filter(r => r.decision.action === 'BARK').length;
    const suspicious = results.filter(r => r.decision.action === 'WHINE').length;
    const safe = results.filter(r => r.decision.installAllowed).length;
    const incomplete = results.filter(r => r.decision.coverage !== 'complete').length;

    console.log('\n📊 BATCH ANALYSIS SUMMARY');
    console.log('─'.repeat(60));
    console.log(`🚨 Dangerous:  ${dangerous}`);
    console.log(`⚠️  Suspicious: ${suspicious}`);
    console.log(`Checks passed: ${safe}`);
    console.log(`Incomplete:   ${incomplete}`);
    console.log(`📦 Total:      ${results.length}`);
    console.log('─'.repeat(60));

    return results;
  }

  /**
   * Test Guard Dog setup
   * @returns {Promise<Object>} Test results
   */
  async test() {
    console.log('\n🐕 Guard Dog System Test\n');
    console.log('─'.repeat(60));

    const tests = {
      config: false,
      virustotal: false,
      reputation: false
    };

    // Test config
    console.log('📋 Testing configuration...');
    tests.config = !!this.config && !!this.trustedProviders;
    console.log(tests.config ? '✓ Config loaded' : '✗ Config failed');

    // Test VirusTotal
    console.log('🔍 Testing VirusTotal connection...');
    if (this.scanner) {
      try {
        const probe = await this.scanner.getFileReport('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
        tests.virustotal = probe.success === true;
        console.log(tests.virustotal ? '✓ VirusTotal authenticated lookup succeeded' : 'VirusTotal lookup incomplete');
      } catch (error) {
        console.log('✗ VirusTotal test failed:', error.message);
      }
    } else {
      console.log('⚠️  VirusTotal scanner not initialized');
    }

    // Test reputation checker
    console.log('📊 Testing reputation checker...');
    try {
      const testResult = await this.reputation.checkReputation('express', 'npm');
      tests.reputation = testResult && testResult.registry;
      console.log(tests.reputation ? '✓ Reputation checker working' : '✗ Reputation check failed');
    } catch (error) {
      console.log('✗ Reputation test failed:', error.message);
    }

    console.log('─'.repeat(60));
    const osv = await this.cveChecker.checkCVEs('lodash', 'npm', '4.17.21');
    tests.osv = osv.status === 'complete';
    const passed = Object.values(tests).filter(Boolean).length;
    console.log(`\n✅ ${passed}/${Object.keys(tests).length} tests passed\n`);

    return tests;
  }
}

function usage() {
  console.log('MyOS Guard Dog - Package Security Scanner');
  console.log('');
  console.log('Usage:');
  console.log('  myos-guard-dog --version                     - Print the installed version');
  console.log('  myos-guard-dog setup                         - Run first-time setup wizard');
  console.log('  myos-guard-dog setup --quick                 - Safe local setup with no background changes');
  console.log('  myos-guard-dog doctor [--repair] [--json]    - Check health and bounded local repairs');
  console.log('  myos-guard-dog test                          - Run system test');
  console.log('  myos-guard-dog analyze <pkg> [eco] [target]  - Analyze one package');
  console.log('  myos-guard-dog batch <json-file>             - Batch analyze packages');
  console.log('  myos-guard-dog artifact <file.tgz|npm:name@version> [--json] - Inspect exact npm archive bytes');
  console.log('  myos-guard-dog install [npm] <package>       - Gate exact npm artifacts; scripts stay disabled');
  console.log('  myos-guard-dog scan <project> [--json]       - Audit exact installed or locked npm versions');
  console.log('  myos-guard-dog nightly                       - Repair local health and scan configured roots');
  console.log('  myos-guard-dog updates enable --workspace <folder> --time HH:MM');
  console.log('  myos-guard-dog updates disable|status       - Manage and verify the daily schedule');
  console.log('  myos-guard-dog hooks enable|disable|status   - Manage git dependency hook');
}

function updatesCommand(action, args = []) {
  const config = loadUserConfig();
  if (action === 'enable') {
    const roots = args.flatMap((arg, i) => arg === '--workspace' && args[i + 1] ? [resolve(args[i + 1])] : []);
    if (roots.length) config.scanRoots = roots;
    const time = args.indexOf('--time');
    if (time !== -1) config.nightlyTime = args[time + 1];
    const result = installNightlySchedule(config);
    console.log(result.message);
    process.exitCode = result.ok ? 0 : 2;
  } else if (action === 'disable') {
    const result = removeNightlySchedule();
    console.log(result.message);
    process.exitCode = result.ok ? 0 : 2;
  } else {
    const health = printDoctor();
    process.exitCode = health.ok ? 0 : 2;
  }
}

function hooksCommand(action) {
  const config = loadUserConfig();
  if (action === 'enable') {
    const result = installGitHook();
    if (result.ok) {
      config.gitPreCommitHook = true;
      saveUserConfig(config);
    }
    console.log(result.message);
    process.exitCode = result.ok ? 0 : 2;
  } else if (action === 'disable') {
    const result = removeGitHook();
    if (result.ok) {
      config.gitPreCommitHook = false;
      saveUserConfig(config);
    }
    console.log(result.message);
    process.exitCode = result.ok ? 0 : 2;
  } else if (action === 'status') {
    console.log(`Git pre-commit hook: ${config.gitPreCommitHook ? 'enabled' : 'disabled'}`);
    console.log('Guarded installs: use `myos-guard-dog install <package>` before dependency installs.');
  } else {
    console.error(`Unknown hooks action: ${action}`);
    process.exitCode = 2;
  }
}

async function main(argv = process.argv.slice(2)) {
  const args = argv;
  const command = args[0];

  if (command === '--version' || command === '-v') {
    const manifest = JSON.parse(readFileSync(join(packageRoot(), 'package.json'), 'utf-8'));
    console.log(manifest.version);
  } else if (command === 'setup') {
    if (args[1] === '--quick') runQuickSetup();
    else await runSetup();
  } else if (command === 'doctor') {
    const health = args.includes('--json') ? checkHealth({ repair: args.includes('--repair') }) : printDoctor({ repair: args.includes('--repair') });
    if (args.includes('--json')) console.log(JSON.stringify(health));
    process.exitCode = health.ok ? 0 : 2;
  } else if (command === 'updates') {
    updatesCommand(args[1] || 'status', args.slice(2));
  } else if (command === 'hooks') {
    hooksCommand(args[1] || 'status');
  } else if (command === 'install') {
    await runGuardedInstall(args.slice(1), GuardDog);
  } else if (command === 'scan') {
    const project = resolve(args[1] || process.cwd());
    const manifest = project.endsWith('package.json') ? project : join(project, 'package.json');
    const result = spawnSync(process.execPath, [join(packageRoot(), 'bin', 'scan-deps.js'), manifest, ...args.slice(2)], { stdio: 'inherit' });
    process.exitCode = result.status ?? 2;
  } else if (command === 'nightly') {
    const result = spawnSync(process.execPath, [join(packageRoot(), 'bin', 'nightly-scan.js')], { stdio: 'inherit' });
    if (result.error) {
      console.error(`\nMyOS Guard Dog could not run nightly scan: ${result.error.message}`);
      process.exit(1);
    }
    process.exit(result.status ?? 1);
  } else if (command === 'test') {
    // Run system test
    const guardDog = new GuardDog();
    const result = await guardDog.test();
    process.exitCode = Object.values(result).every(Boolean) ? 0 : 2;
  } else if (command === 'analyze') {
    // Analyze single package
    const guardDog = new GuardDog();
    const packageName = args[1];
    const ecosystem = args[2] || 'npm';
    const target = args[3];

    if (!packageName) {
      console.error('Usage: myos-guard-dog analyze <package-name> [ecosystem] [url/hash]');
      process.exit(1);
    }

    const spec = packageName.match(/^(.+)@([^@]+)$/);
    const result = await guardDog.analyze(spec ? spec[1] : packageName, ecosystem, target, spec ? spec[2] : null);
    process.exitCode = auditExitCode([result]);
  } else if (command === 'batch') {
    // Batch analyze from JSON file
    const guardDog = new GuardDog();
    const filePath = args[1];
    if (!filePath) {
      console.error('Usage: myos-guard-dog batch <json-file>');
      process.exit(1);
    }

    const packages = JSON.parse(readFileSync(filePath, 'utf-8'));
    const results = await guardDog.batchAnalyze(packages);
    process.exitCode = auditExitCode(results);
  } else if (command === 'artifact') {
    const file = args[1];
    if (!file || file.startsWith('--')) throw new Error('Usage: myos-guard-dog artifact <file.tgz|npm:name@version> [--json]');
    let report;
    try {
      if (file.startsWith('npm:')) report = await inspectExactNpmRelease(file);
      else {
        if (statSync(file).size > 50 * 1024 * 1024) throw new Error('Package archive exceeds compressed scan limit');
        report = { source: 'local_archive', ...inspectNpmArtifact(readFileSync(file)) };
      }
    } catch (error) { error.exitCode = 2; throw error; }
    if (args.includes('--json')) console.log(JSON.stringify(report));
    else {
      console.log(`Inspected ${report.sourceFiles} source files in ${report.entries} archive entries; bounded static coverage.`);
      for (const finding of report.findings) console.log(`${finding.severity.toUpperCase()}: ${finding.file}: ${finding.rule}`);
      console.log(`Result: ${report.risk}. No static scan can certify a package is safe.`);
    }
    process.exitCode = report.risk === 'high' ? 1 : report.risk === 'none' ? 0 : 2;
  } else {
    usage();
    process.exitCode = !command || ['--help', '-h', 'help'].includes(command) ? 0 : 2;
  }
}

// CLI interface
const invokedPath = process.argv[1] ? realpathSync(resolve(process.argv[1])) : '';
if (fileURLToPath(import.meta.url) === invokedPath) {
  main().catch(error => {
    console.error(`MyOS Guard Dog could not complete the command: ${error?.message || String(error)}`);
    process.exit(error.exitCode === 2 ? 2 : 1);
  });
}
