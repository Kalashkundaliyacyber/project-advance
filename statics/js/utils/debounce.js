/**
 * ScanWise AI — Debounce Utility
 * Prevents rapid repeated function calls.
 */

/**
 * Debounce a function call.
 * @param {Function} fn  - Function to debounce
 * @param {number}   ms  - Delay in milliseconds
 * @returns {Function} debounced function with .cancel() method
 */
function debounce(fn, ms = 300) {
  let timer = null;
  function debounced(...args) {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => {
      timer = null;
      fn.apply(this, args);
    }, ms);
  }
  debounced.cancel = () => { if (timer) clearTimeout(timer); timer = null; };
  return debounced;
}

/**
 * Throttle — at most once per `ms` milliseconds.
 */
function throttle(fn, ms = 500) {
  let lastCall = 0;
  return function (...args) {
    const now = Date.now();
    if (now - lastCall >= ms) {
      lastCall = now;
      fn.apply(this, args);
    }
  };
}
