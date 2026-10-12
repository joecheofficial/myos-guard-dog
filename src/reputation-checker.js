/**
 * Reputation Research Module
 * Queries npm/PyPI/GitHub for package metadata and reputation signals
 */

export class ReputationChecker {
  constructor(config) {
    this.config = config.reputation;
  }

  /**
   * Check package reputation across multiple sources
   * @param {string} packageName - Name of the package
   * @param {string} ecosystem - 'npm' or 'pypi'
   * @returns {Promise<Object>} Reputation data
   */
  async checkReputation(packageName, ecosystem = 'npm', version = null) {
    const results = {
      package: packageName,
      ecosystem,
      registry: null,
      github: null,
      signals: []
    };

    try {
      // Check package registry
      if (ecosystem === 'npm') {
        results.registry = await this.checkNpmRegistry(packageName, version);
      } else if (ecosystem === 'pypi') {
        results.registry = await this.checkPyPiRegistry(packageName, version);
      } else if (ecosystem === 'rubygems') {
        results.registry = await this.checkRubyGemsRegistry(packageName);
      }

      // Check GitHub if repository URL is available
      if (results.registry?.repository) {
        results.github = await this.checkGitHub(results.registry.repository);
      }

      // Analyze signals
      results.signals = this.analyzeSignals(results);
    } catch (error) {
      results.error = error.message;
    }

    return results;
  }

  /**
   * Check npm registry
   * @param {string} packageName - Package name
   * @returns {Promise<Object>} npm metadata
   */
  async checkNpmRegistry(packageName, version = null) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.npm.timeoutMs);

    try {
      const response = await fetch(
        `${this.config.npm.registryUrl}/${encodeURIComponent(packageName)}`,
        { signal: controller.signal }
      );

      if (!response.ok) {
        if (response.status === 404) return null;
        throw new Error(`npm registry unavailable: HTTP ${response.status}`);
      }

      const data = await response.json();
      const latestVersion = version || data['dist-tags']?.latest;
      const versionData = data.versions?.[latestVersion];
      if (!versionData) throw new Error(`Requested version could not be resolved: ${latestVersion}`);

      // Fetch weekly downloads from npm downloads API
      let weeklyDownloads = null;
      try {
        const dlController = new AbortController();
        const dlTimeoutId = setTimeout(() => dlController.abort(), this.config.npm.timeoutMs);
        const dlResponse = await fetch(
          `https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(packageName)}`,
          { signal: dlController.signal }
        );
        clearTimeout(dlTimeoutId);
        if (dlResponse.ok) {
          const dlData = await dlResponse.json();
          weeklyDownloads = dlData.downloads || null;
        }
      } catch {
        // Non-critical — leave as null
      }

      return {
        name: data.name,
        version: latestVersion,
        description: data.description,
        downloads: data.downloads?.total,
        weeklyDownloads,
        createdAt: data.time?.created || null,
        publishDate: versionData?.time || data.time?.[latestVersion],
        author: data.author?.name || versionData?.author?.name,
        maintainers: data.maintainers?.length || 0,
        repository: this.parseRepository(versionData?.repository || data.repository),
        license: versionData?.license || data.license,
        deprecated: data.deprecated || versionData?.deprecated,
        tarball: versionData?.dist?.tarball || null,
        integrity: versionData?.dist?.integrity || null,
        shasum: versionData?.dist?.shasum || null
      };
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Check PyPI registry
   * @param {string} packageName - Package name
   * @returns {Promise<Object>} PyPI metadata
   */
  async checkPyPiRegistry(packageName, version = null) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.pypi.timeoutMs);

    try {
      const response = await fetch(
        `${this.config.pypi.apiUrl}/${encodeURIComponent(packageName)}${version ? '/' + encodeURIComponent(version) : ''}/json`,
        { signal: controller.signal }
      );

      if (!response.ok) {
        if (response.status === 404) return null;
        throw new Error(`PyPI unavailable: HTTP ${response.status}`);
      }

      const data = await response.json();
      const info = data.info;
      const urls = data.urls || [];
      const distributions = urls.map(file => ({ filename: file.filename, url: file.url, sha256: file.digests?.sha256 || null }));
      const onlyFile = distributions.length === 1 ? distributions[0] : null;

      return {
        name: info.name,
        version: info.version,
        description: info.summary,
        downloads: null, // PyPI doesn't provide this in main API
        publishDate: urls[0]?.upload_time_iso_8601 || urls[0]?.upload_time || data.releases?.[info.version]?.[0]?.upload_time || null,
        author: info.author,
        repository: this.parseRepository(info.project_urls),
        license: info.license,
        deprecated: false,
        distributions,
        tarball: onlyFile?.url || null,
        sha256: onlyFile?.sha256 || null,
        artifactCoverage: 'incomplete'
      };
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Check RubyGems registry
   * @param {string} packageName - Gem name
   * @returns {Promise<Object>} RubyGems metadata
   */
  async checkRubyGemsRegistry(packageName) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.rubygems.timeoutMs);

    try {
      const response = await fetch(
        `${this.config.rubygems.apiUrl}/gems/${encodeURIComponent(packageName)}.json`,
        { signal: controller.signal }
      );

      if (!response.ok) {
        return null;
      }

      const data = await response.json();

      return {
        name: data.name,
        version: data.version,
        description: data.info,
        downloads: data.downloads,
        weeklyDownloads: null,
        publishDate: data.version_created_at,
        author: data.authors,
        maintainers: 1,
        repository: this.parseRepository(
          data.source_code_uri || data.homepage_uri || data.project_uri
        ),
        license: data.licenses?.join(', ') || null,
        deprecated: false
      };
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Check GitHub repository
   * @param {string} repoUrl - GitHub repository URL
   * @returns {Promise<Object>} GitHub metadata or error status
   */
  async checkGitHub(repoUrl) {
    if (!repoUrl) return null;

    // Only the actual GitHub host can satisfy repository coverage.
    let parsed;
    try { parsed = new URL(repoUrl.replace(/^git\+/, '')); } catch { return null; }
    if (parsed.protocol !== 'https:' || !['github.com', 'www.github.com'].includes(parsed.hostname)
        || parsed.port || parsed.username || parsed.password) return null;
    const match = /^\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/.exec(parsed.pathname);
    if (!match) return null;
    const [, owner, repoName] = match;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.github.timeoutMs);

    try {
      // Use GITHUB_API_TOKEN or GITHUB_TOKEN if available for higher rate limits (5000/hr vs 60/hr)
      const headers = {};
      const ghToken = process.env.GITHUB_API_TOKEN || process.env.GITHUB_TOKEN;
      if (ghToken) {
        headers['Authorization'] = `token ${ghToken}`;
      }

      const response = await fetch(
        `${this.config.github.apiUrl}/repos/${owner}/${repoName}`,
        { signal: controller.signal, headers }
      );

      if (!response.ok) {
        const remaining = response.headers.get('x-ratelimit-remaining');
        const reset = response.headers.get('x-ratelimit-reset');
        const isRateLimited = (response.status === 403 || response.status === 429) && remaining === '0';
        let errorMsg = `HTTP ${response.status}: ${response.statusText || 'Request failed'}`;
        if (isRateLimited) {
          errorMsg = `Rate limit exceeded (HTTP ${response.status})`;
          if (reset) {
            errorMsg += ` (resets at ${reset})`;
          }
        }
        return {
          ok: false,
          error: errorMsg,
          rateLimited: isRateLimited
        };
      }

      const data = await response.json();

      // Unverified open reports are weak evidence, not a malware verdict.
      let issuesData = { total_count: null };
      try {
        const query = `repo:${data.full_name || `${owner}/${repoName}`} is:issue is:open malware in:title`;
        const issuesResponse = await fetch(
          `${this.config.github.apiUrl}/search/issues?q=${encodeURIComponent(query)}`,
          { signal: controller.signal, headers }
        );
        if (issuesResponse.ok) {
          issuesData = await issuesResponse.json();
        }
      } catch {
        // Non-critical issue lookup failure
      }

      return {
        ok: true,
        stars: data.stargazers_count,
        forks: data.forks_count,
        openIssues: data.open_issues_count,
        watchers: data.watchers_count,
        createdAt: data.created_at,
        updatedAt: data.updated_at,
        securityIssues: issuesData.total_count,
        archived: data.archived,
        disabled: data.disabled
      };
    } catch (err) {
      return {
        ok: false,
        error: err.message || 'GitHub check failed',
        rateLimited: false
      };
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Parse repository URL from various formats
   * @param {string|Object} repo - Repository data
   * @returns {string|null} Repository URL
   */
  parseRepository(repo) {
    if (!repo) return null;
    
    if (typeof repo === 'string') {
      return repo;
    }
    
    if (repo.url) {
      return repo.url.replace(/^git\+/, '').replace(/\.git$/, '');
    }
    
    // PyPI project_urls
    if (repo.Source) return repo.Source;
    if (repo.Repository) return repo.Repository;
    if (repo.Homepage) return repo.Homepage;
    
    return null;
  }

  /**
   * Analyze reputation signals
   * @param {Object} results - Combined results
   * @returns {Array<string>} Signal flags
   */
  analyzeSignals(results) {
    const signals = [];
    const registry = results.registry;
    const github = results.github;

    if (!registry) {
      signals.push('PACKAGE_NOT_FOUND');
      return signals;
    }

    // Check deprecation
    if (registry.deprecated) {
      signals.push('DEPRECATED');
    }

    // Check recent publication (typosquatting risk)
    if (registry.publishDate || registry.createdAt) {
      const daysSincePublish = (Date.now() - new Date(registry.publishDate || registry.createdAt)) / (1000 * 60 * 60 * 24);
      if (daysSincePublish >= 0 && daysSincePublish < 30) {
        signals.push('NEWLY_PUBLISHED');
      }
    }

    // Check no repository
    if (!registry.repository) {
      signals.push('NO_REPOSITORY');
    } else if (!github) {
      signals.push('REPOSITORY_UNCHECKED');
    }

    // GitHub signals
    if (github) {
      if (github.ok === false) {
        signals.push('GITHUB_CHECK_FAILED');
      } else {
        if (github.stars < 50) {
          signals.push('LOW_STARS');
        }
        if (github.securityIssues > 0) {
          signals.push('SECURITY_COMPLAINTS');
        }
        if (github.securityIssues === null) signals.push('GITHUB_CHECK_FAILED');
        if (github.archived) {
          signals.push('ARCHIVED_REPO');
        }
        if (github.disabled) {
          signals.push('DISABLED_REPO');
        }
      }
    }

    // Check low downloads (npm only)
    if (registry.weeklyDownloads !== null && registry.weeklyDownloads < 1000) {
      signals.push('LOW_DOWNLOADS');
    }

    // Check author/maintainer
    if (registry.maintainers === 0) {
      signals.push('NO_MAINTAINERS');
    }

    return signals;
  }
}
