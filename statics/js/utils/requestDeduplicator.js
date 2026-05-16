/**
 * ScanWise AI — Request Deduplicator
 * Prevents duplicate in-flight requests for the same key.
 * Multiple callers for the same key share one promise.
 */
const RequestDeduplicator = (() => {
  // key → Promise (in-flight)
  const _inFlight = new Map();
  // key → result (short-lived cache, 60s TTL)
  const _cache    = new Map();
  const CACHE_TTL = 60_000;

  /**
   * Execute fetch only if not already in-flight.
   * If the same key is pending, returns the existing promise.
   * @param {string}   key      - Unique request key
   * @param {Function} fetchFn  - async () => result
   * @param {number}   [ttl]    - Cache TTL in ms (default 60s)
   */
  async function fetch(key, fetchFn, ttl = CACHE_TTL) {
    // Cache hit
    const cached = _cache.get(key);
    if (cached && Date.now() - cached.ts < ttl) {
      return cached.data;
    }

    // In-flight dedup
    if (_inFlight.has(key)) {
      return _inFlight.get(key);
    }

    const promise = fetchFn().then(result => {
      _cache.set(key, { data: result, ts: Date.now() });
      _inFlight.delete(key);
      return result;
    }).catch(err => {
      _inFlight.delete(key);
      throw err;
    });

    _inFlight.set(key, promise);
    return promise;
  }

  function invalidate(key) {
    _cache.delete(key);
    // Note: cannot cancel in-flight; just let it complete
  }

  function invalidateAll() {
    _cache.clear();
  }

  function stats() {
    return {
      inFlight: _inFlight.size,
      cached:   _cache.size,
    };
  }

  return { fetch, invalidate, invalidateAll, stats };
})();
