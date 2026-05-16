/**
 * ScanWise AI — Polling Manager
 * Centralized management of all polling intervals.
 * Prevents: duplicate intervals, stale request accumulation, polling spam.
 *
 * Fixes:
 *  - /api/history spam
 *  - /api/project-sessions spam
 *  - duplicate setInterval registrations
 *  - cleanup on session switch/delete
 */
const PollingManager = (() => {
  // name → { intervalId, controller }
  const _active = new Map();

  /**
   * Start a named polling loop.
   * If a loop with the same name already exists, it is replaced.
   * @param {string}   name      - Unique loop name
   * @param {Function} fn        - async function called each tick
   * @param {number}   intervalMs - Polling interval in ms
   * @param {boolean}  [immediate=true] - Call fn immediately on start
   */
  function start(name, fn, intervalMs, immediate = true) {
    // Stop existing loop with same name
    stop(name);

    if (immediate) {
      fn().catch(err => _warn(name, err));
    }

    const id = setInterval(() => {
      fn().catch(err => _warn(name, err));
    }, intervalMs);

    _active.set(name, { id });
  }

  /** Stop a named polling loop. */
  function stop(name) {
    if (_active.has(name)) {
      clearInterval(_active.get(name).id);
      _active.delete(name);
    }
  }

  /** Stop ALL polling loops. */
  function stopAll() {
    for (const name of _active.keys()) stop(name);
  }

  /** Is a loop currently running? */
  function isRunning(name) {
    return _active.has(name);
  }

  function _warn(name, err) {
    if (err && err.name !== 'AbortError') {
      console.warn(`PollingManager[${name}]:`, err.message || err);
    }
  }

  return { start, stop, stopAll, isRunning };
})();
