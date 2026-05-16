/**
 * ScanWise AI — Frontend Patch Cache
 * In-memory LRU cache with TTL for patch guidance responses.
 * Prevents re-fetching identical AI results within a browser session.
 *
 * Why this matters:
 *   The /api/patch/guidance endpoint runs an AI call (30–120s).
 *   If the user clicks the same vulnerability twice, we must not fire a
 *   second AI request. The backend has its own cache too, but this
 *   client-side cache eliminates even the HTTP round-trip.
 *
 * TTL: 5 minutes (patches don't change within a session).
 * Max entries: 100 (prevents unbounded memory growth on large scans).
 */
const PatchCache = (() => {
  const _TTL_MS  = 5 * 60 * 1000;
  const _MAX     = 100;

  // Map: key → { value, ts }
  const _store   = new Map();

  function _makeKey(service, port, cveId) {
    return `${service}:${port}:${cveId || 'none'}`;
  }

  function _evict() {
    if (_store.size <= _MAX) return;
    // Evict the oldest entry
    const oldest = [..._store.entries()].sort((a, b) => a[1].ts - b[1].ts)[0];
    if (oldest) _store.delete(oldest[0]);
  }

  function get(service, port, cveId = 'unknown') {
    const key   = _makeKey(service, port, cveId);
    const entry = _store.get(key);
    if (!entry) return null;
    if (Date.now() - entry.ts > _TTL_MS) {
      _store.delete(key);
      return null;
    }
    return entry.value;
  }

  function set(service, port, cveId = 'unknown', value) {
    const key = _makeKey(service, port, cveId);
    _store.set(key, { value, ts: Date.now() });
    _evict();
  }

  function invalidate(service, port, cveId) {
    _store.delete(_makeKey(service, port, cveId));
  }

  function clear() { _store.clear(); }

  function stats() {
    return { size: _store.size, max: _MAX, ttl_ms: _TTL_MS };
  }

  return { get, set, invalidate, clear, stats };
})();
