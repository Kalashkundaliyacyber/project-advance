/**
 * ScanWise AI — Remediation Client v2.0
 * Handles all /api/patch/* requests with:
 *   - Frontend PatchCache (5min TTL, 100 entry LRU) — eliminates repeat HTTP round-trips
 *   - In-flight deduplication (RequestDeduplicator) — concurrent same-key calls share one request
 *   - AbortController (cancel stale requests)
 *   - Queue depth awareness
 *   - Correlation ID logging for tracing
 *
 * Cache hierarchy:
 *   1. PatchCache (browser session, 5min TTL)  ← this file
 *   2. Backend deduplicated_fetch cache         ← remediation_cache.py
 *   3. AI provider call                         ← patch_generator.py
 */
const RemediationClient = (() => {
  const _BASE = '/api/patch';

  /**
   * Get patch guidance for a single service/port.
   * Checks PatchCache first, then deduplicates concurrent HTTP calls.
   */
  async function getPatchGuidance({
    service, port, version = 'unknown',
    cve_id = 'unknown', severity = 'medium',
    session_id = '', os_hint = 'ubuntu'
  }) {
    // 1. Check frontend cache
    const cached = PatchCache.get(service, port, cve_id);
    if (cached) {
      return { ...cached, from_frontend_cache: true };
    }

    const key = `patch:${service}:${port}:${cve_id}`;

    // 2. Deduplicated network fetch
    const result = await RequestDeduplicator.fetch(key, async () => {
      return ApiHelpers.apiFetch(
        `${_BASE}/guidance`,
        {
          method: 'POST',
          body: JSON.stringify({ service, port, version, cve_id, severity, session_id, os_hint }),
        },
        { tag: key, timeout: 120_000 }
      );
    });

    // 3. Store in frontend cache
    if (result && !result.error) {
      PatchCache.set(service, port, cve_id, result);
    }

    return result;
  }

  /**
   * Get patch guidance for ALL ports in a session.
   * Groups by service → reduced AI calls (one per service family).
   * Results are individually cached for subsequent single-port lookups.
   */
  async function getPatchAll(session_id, os_hint = 'ubuntu') {
    const result = await ApiHelpers.apiFetch(
      `${_BASE}/all`,
      {
        method: 'POST',
        body: JSON.stringify({ session_id, os_hint, group_by_service: true }),
      },
      { tag: 'patch:all', timeout: 300_000, retries: 1 }
    );

    // Populate frontend cache with each result so individual lookups are instant
    if (result?.results) {
      for (const r of result.results) {
        if (r.service && r.port != null) {
          const cve = r.cves?.[0]?.cve_id || 'unknown';
          PatchCache.set(r.service, r.port, cve, r);
        }
      }
    }

    return result;
  }

  /**
   * Get current AI queue and cache status.
   */
  async function getStatus() {
    return ApiHelpers.apiFetch(`${_BASE}/status`, {}, { timeout: 5_000 });
  }

  /**
   * Invalidate frontend cache entry for a specific service/port/CVE.
   * Call when user manually requests a refresh.
   */
  function invalidate(service, port, cve_id = 'unknown') {
    PatchCache.invalidate(service, port, cve_id);
  }

  /** Clear the entire frontend patch cache. */
  function clearCache() {
    PatchCache.clear();
  }

  /** Return frontend cache stats (size, TTL). */
  function cacheStats() {
    return PatchCache.stats();
  }

  return { getPatchGuidance, getPatchAll, getStatus, invalidate, clearCache, cacheStats };
})();
