/**
 * ThreatWeave — Remediation Client
 * Handles all /api/patch/* requests with:
 *   - In-flight deduplication (one request per key at a time)
 *   - Response caching (60s TTL)
 *   - AbortController (cancel stale requests)
 *   - Queue depth awareness
 */
const RemediationClient = (() => {
  const _BASE = '/api/patch';

  /**
   * Get patch guidance for a single service/port.
   * Deduplicated: concurrent calls for same key share one HTTP request.
   */
  async function getPatchGuidance({ service, port, version = 'unknown',
                                     cve_id = 'unknown', severity = 'medium',
                                     session_id = '', os_hint = 'ubuntu' }) {
    const key = `patch:${service}:${port}:${cve_id}`;
    return RequestDeduplicator.fetch(key, async () => {
      return ApiHelpers.apiFetch(
        `${_BASE}/guidance`,
        {
          method: 'POST',
          body: JSON.stringify({ service, port, version, cve_id, severity, session_id, os_hint }),
        },
        { tag: key, timeout: 120_000 }
      );
    });
  }

  /**
   * Get patch guidance for ALL ports in a session.
   * Groups by service → reduced AI calls.
   */
  async function getPatchAll(session_id, os_hint = 'ubuntu') {
    return ApiHelpers.apiFetch(
      `${_BASE}/all`,
      {
        method: 'POST',
        body: JSON.stringify({ session_id, os_hint, group_by_service: true }),
      },
      { tag: 'patch:all', timeout: 300_000, retries: 1 }
    );
  }

  /**
   * Get current AI queue status.
   */
  async function getStatus() {
    return ApiHelpers.apiFetch(`${_BASE}/status`, {}, { timeout: 5_000 });
  }

  return { getPatchGuidance, getPatchAll, getStatus };
})();
