/**
 * ScanWise AI — API Helpers
 * Centralized fetch wrapper with:
 *   - AbortController integration (cancel stale requests)
 *   - Timeout support
 *   - Retry on network failure
 *   - Standard error handling
 */
const ApiHelpers = (() => {
  // Track active AbortControllers by tag
  const _controllers = new Map();

  /**
   * Fetch with AbortController, timeout, and optional retry.
   * @param {string} url
   * @param {object} opts        - standard fetch options
   * @param {object} [extra]
   * @param {string} [extra.tag]      - cancel previous call with same tag
   * @param {number} [extra.timeout]  - ms before auto-abort (default 30s)
   * @param {number} [extra.retries]  - number of retries on failure (default 0)
   */
  async function apiFetch(url, opts = {}, extra = {}) {
    const { tag, timeout = 30_000, retries = 0 } = extra;

    // Cancel previous call with same tag
    if (tag && _controllers.has(tag)) {
      _controllers.get(tag).abort();
    }

    const ctrl = new AbortController();
    if (tag) _controllers.set(tag, ctrl);

    const timeoutId = setTimeout(() => ctrl.abort(), timeout);

    let lastErr;
    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        const resp = await window.fetch(url, {
          ...opts,
          signal: ctrl.signal,
          headers: {
            'Content-Type': 'application/json',
            ...(opts.headers || {}),
          },
        });
        clearTimeout(timeoutId);
        if (tag) _controllers.delete(tag);

        if (!resp.ok) {
          const text = await resp.text().catch(() => '');
          throw new Error(`HTTP ${resp.status}: ${text.slice(0, 200)}`);
        }
        return await resp.json();
      } catch (err) {
        lastErr = err;
        if (err.name === 'AbortError') throw err;  // don't retry aborts
        if (attempt < retries) {
          await _sleep(500 * (attempt + 1));  // back-off
        }
      }
    }

    clearTimeout(timeoutId);
    if (tag) _controllers.delete(tag);
    throw lastErr;
  }

  /** Cancel a tagged request if in-flight. */
  function cancel(tag) {
    if (_controllers.has(tag)) {
      _controllers.get(tag).abort();
      _controllers.delete(tag);
    }
  }

  /** Cancel all in-flight tagged requests. */
  function cancelAll() {
    for (const ctrl of _controllers.values()) ctrl.abort();
    _controllers.clear();
  }

  function _sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  return { apiFetch, cancel, cancelAll };
})();
