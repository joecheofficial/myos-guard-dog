/**
 * VirusTotal Scanner Module
 * Scans packages for malicious code using VirusTotal API v3
 */

import { createRequestPacer } from './request-pacer.js';
import { VirusTotalQuota } from './virustotal-quota.js';

// Share the request budget across every scanner using the same key in this process.
const requestQueues = new Map();
const REQUEST_INTERVAL_MS = 16000;

export class VirusTotalScanner {
  constructor(config, runtime = {}) {
    this.apiKey = config.virustotal.apiKey || process.env.VIRUSTOTAL_API_KEY;
    this.baseUrl = config.virustotal.baseUrl;
    this.timeout = config.virustotal.timeoutMs;
    this.maxReportAgeMs = (config.virustotal.maxReportAgeHours || 24) * 3600000;
    this.now = runtime.now || Date.now;
    this.wait = runtime.wait || (milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds)));
    this.fetch = runtime.fetch || ((...args) => globalThis.fetch(...args));
    this.pace = runtime.pace || createRequestPacer(['vt',this.apiKey,this.baseUrl],{now:this.now,wait:this.wait});
    this.quota = runtime.quota || (Number.isInteger(config.virustotal.dailyRequestLimit)
      ? new VirusTotalQuota({ limit: config.virustotal.dailyRequestLimit })
      : null);
    
    if (!this.apiKey) {
      throw new Error('VirusTotal API key is required (VIRUSTOTAL_API_KEY)');
    }
  }

  async request(url, options = {}) {
    let queue = requestQueues.get(this.apiKey);
    if (!queue) {
      queue = { tail: Promise.resolve(), nextAt: 0 };
      requestQueues.set(this.apiKey, queue);
    }
    const pending = queue.tail.then(async () => {
      // A refused local quota cannot recover until the ledger's UTC day changes.
      // Do not charge every remaining package another rate-limit wait.
      const quotaDay = new Date(this.now()).toISOString().slice(0, 10);
      if (queue.quotaBlockedDay === quotaDay) throw new Error('VirusTotal daily quota guard stopped this request before it was sent.');
      return this.pace(REQUEST_INTERVAL_MS,async()=>{
      const delay = queue.nextAt - this.now();
      if (delay > 0) await this.wait(delay);
      queue.nextAt = this.now() + REQUEST_INTERVAL_MS;
      if (this.quota) {
        const reservation = this.quota.reserve();
        const allowed = reservation === true || reservation?.allowed === true;
        if (!allowed) {
          queue.quotaBlockedDay = new Date(this.now()).toISOString().slice(0, 10);
          throw new Error('VirusTotal daily quota guard stopped this request before it was sent.');
        }
      }
      // Waiting for a rate-limit slot must not consume the network timeout.
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeout);
      try {
        // The key travels in a custom x-apikey header, which fetch would forward
        // to any redirect target. VirusTotal's API never needs a redirect.
        const response = await this.fetch(url, { ...options, redirect: 'error', signal: controller.signal });
        // Consume the body within the same timeout, before releasing the queue.
        const data = response.ok ? await response.json() : null;
        return { response, data };
      } finally {
        clearTimeout(timeoutId);
      }
      });
    });
    queue.tail = pending.then(() => undefined, () => undefined);
    return pending;
  }

  /**
   * Scan a package URL or hash
   * @param {string} target - URL or file hash
   * @returns {Promise<Object>} Scan results
   */
  async scan(target) {
    try {
      // Check if target is a URL or hash
      const isUrl = target.startsWith('http://') || target.startsWith('https://');
      
      if (isUrl) {
        return await this.scanUrl(target);
      } else {
        const report = await this.getFileReport(target);
        if (report.success && report.found && report.stale) {
          // Ask VT to refresh an already known public hash. Never upload local files.
          try {
            const { response } = await this.request(`${this.baseUrl}/files/${encodeURIComponent(target)}/analyse`, {
              method: 'POST', headers: { 'x-apikey': this.apiKey }
            });
            report.refreshRequested = response.ok;
            report.refreshStatus = response.status;
          } catch (error) { report.refreshError = error.message; }
        }
        return report;
      }
    } catch (error) {
      return {
        success: false,
        status: /401|403/.test(error.message) ? 'unauthorized' : /429|quota/i.test(error.message) ? 'rate_limited' : 'unavailable',
        error: error.message,
        maliciousVotes: 0,
        suspiciousVotes: 0
      };
    }
  }

  /**
   * Scan a URL
   * @param {string} url - URL to scan
   * @returns {Promise<Object>} Scan results
   */
  async scanUrl(url) {
    try {
      // Submit URL for scanning
      const { response: scanResponse, data: scanData } = await this.request(`${this.baseUrl}/urls`, {
        method: 'POST',
        headers: {
          'x-apikey': this.apiKey,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: `url=${encodeURIComponent(url)}`
      });

      if (!scanResponse.ok) {
        throw new Error(`VirusTotal API error: ${scanResponse.status}`);
      }

      const analysisId = scanData.data.id;

      // Poll GET /analyses/<id> until status === 'completed'
      for (let attempt = 0; attempt < 10; attempt++) {
        const { response: resultResponse, data: resultData } = await this.request(`${this.baseUrl}/analyses/${analysisId}`, {
          headers: { 'x-apikey': this.apiKey }
        });

        if (!resultResponse.ok) {
          throw new Error(`VirusTotal API error: ${resultResponse.status}`);
        }

        if (resultData.data?.attributes?.status === 'completed') {
          return this.parseResults(resultData);
        }
      }

      return {
        success: false,
        error: 'VirusTotal analysis did not complete in time',
        maliciousVotes: 0,
        suspiciousVotes: 0
      };
    } catch (error) {
      if (error.name === 'AbortError' || error.name === 'TimeoutError') {
        return {
          success: false,
          error: 'VirusTotal analysis did not complete in time',
          maliciousVotes: 0,
          suspiciousVotes: 0
        };
      }
      throw error;
    }
  }

  /**
   * Get file report by hash
   * @param {string} hash - File hash (SHA256, SHA1, or MD5)
   * @returns {Promise<Object>} Report results
   */
  async getFileReport(hash) {
    if (!/^(?:[a-f\d]{32}|[a-f\d]{40}|[a-f\d]{64})$/i.test(hash)) throw new Error('A valid file hash is required');
    let { response, data } = await this.request(`${this.baseUrl}/files/${hash}`, {
      headers: { 'x-apikey': this.apiKey }
    });
    if (response.status >= 500) {
      const retrySeconds = Number(response.headers.get('retry-after') || 1);
      if (Number.isFinite(retrySeconds) && retrySeconds >= 0 && retrySeconds <= 5) {
        await this.wait(retrySeconds * 1000);
        ({ response, data } = await this.request(`${this.baseUrl}/files/${hash}`, {
          headers: { 'x-apikey': this.apiKey }
        }));
      }
    }

    if (response.status === 404) {
      return {
        success: true,
        status: 'not_found',
        found: false,
        maliciousVotes: 0,
        suspiciousVotes: 0
      };
    }

    if (!response.ok) {
      throw new Error(`VirusTotal API error: ${response.status}`);
    }

    return this.parseResults(data);
  }

  /**
   * Parse VirusTotal API results
   * @param {Object} data - Raw API response
   * @returns {Object} Parsed results
   */
  parseResults(data) {
    const stats = data.data?.attributes?.last_analysis_stats || 
                  data.data?.attributes?.stats || {};
    
    const maliciousVotes = stats.malicious || 0;
    const suspiciousVotes = stats.suspicious || 0;
    const undetectedVotes = stats.undetected || 0;
    const harmlessVotes = stats.harmless || 0;
    const counts = [maliciousVotes, suspiciousVotes, undetectedVotes, harmlessVotes];
    const totalEngines = counts.every(value => Number.isFinite(value) && value >= 0)
      ? counts.reduce((sum, val) => sum + val, 0) : 0;

    if (totalEngines === 0) {
      return {
        success: false,
        error: 'VirusTotal returned no engine results',
        maliciousVotes: 0,
        suspiciousVotes: 0
      };
    }

    return {
      success: true,
      found: true,
      status: 'complete',
      checkedAt: new Date().toISOString(),
      lastAnalysisAt: data.data?.attributes?.last_analysis_date ? new Date(data.data.attributes.last_analysis_date * 1000).toISOString() : null,
      stale: !data.data?.attributes?.last_analysis_date || Date.now() - data.data.attributes.last_analysis_date * 1000 > this.maxReportAgeMs,
      maliciousVotes,
      suspiciousVotes,
      undetectedVotes,
      harmlessVotes,
      totalEngines,
      details: data.data?.attributes
    };
  }
}
