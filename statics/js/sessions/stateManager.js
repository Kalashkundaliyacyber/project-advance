/**
 * ScanWise AI — Session State Manager
 * Fixes: DELETE session → GET same session → 404 loops
 * Provides: race-condition protection, stale session removal, sync fixes
 *
 * This module wraps SessionManager with deletion tracking so the app
 * never tries to load a session that was just deleted.
 */
const SessionStateManager = (() => {
  // Set of session IDs explicitly deleted during this browser session
  const _deleted = new Set();
  // In-flight session load operations: sessionId → Promise
  const _loading  = new Map();

  /**
   * Mark a session as deleted. All subsequent load attempts are no-ops.
   */
  function markDeleted(sessionId) {
    _deleted.add(sessionId);
    // Cancel any in-flight load for this session
    ApiHelpers.cancel(`session:load:${sessionId}`);
  }

  /**
   * Check if a session has been deleted locally.
   */
  function isDeleted(sessionId) {
    return _deleted.has(sessionId);
  }

  /**
   * Safe session load: cancels if already deleted or in-flight.
   * Returns null (not an error) if session was deleted.
   * @param {string}   sessionId
   * @param {Function} loadFn   - async () => session data
   */
  async function safeLoad(sessionId, loadFn) {
    if (!sessionId || _deleted.has(sessionId)) {
      return null;
    }
    // Dedup in-flight loads
    if (_loading.has(sessionId)) {
      return _loading.get(sessionId);
    }

    const promise = loadFn()
      .then(data => {
        _loading.delete(sessionId);
        return data;
      })
      .catch(err => {
        _loading.delete(sessionId);
        // 404 = session deleted on server; mark locally too
        if (err && err.message && err.message.includes('404')) {
          _deleted.add(sessionId);
          return null;
        }
        throw err;
      });

    _loading.set(sessionId, promise);
    return promise;
  }

  /**
   * Delete a session safely: mark deleted BEFORE any async work
   * so subsequent calls skip it, then call the actual delete API.
   * @param {string}   sessionId
   * @param {Function} deleteFn  - async () => void
   */
  async function safeDelete(sessionId, deleteFn) {
    // Immediately mark deleted to prevent any race-condition re-fetch
    _deleted.add(sessionId);

    try {
      await deleteFn();
    } catch (err) {
      // 404 = already deleted server-side, that's fine
      if (!err.message?.includes('404')) {
        console.warn('SessionStateManager: delete failed', sessionId, err);
      }
    }
  }

  /**
   * Clear deleted set (e.g. on full page reload).
   */
  function reset() {
    _deleted.clear();
    _loading.clear();
  }

  return { markDeleted, isDeleted, safeLoad, safeDelete, reset };
})();
