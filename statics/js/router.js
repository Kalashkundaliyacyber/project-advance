/**
 * router.js
 * ─────────────────────────────────────────────────────────────────
 * Lightweight client-side router for the SPA shell.
 * Routes: scan | dash | cmp | help
 *
 * Extend routes[] to add new pages without touching other modules.
 * ─────────────────────────────────────────────────────────────────
 */

const Router = (() => {
  /**
   * Route definitions.
   * name     — page id suffix (page-{name})
   * navIdx   — index in .nav-tab NodeList (-1 = not in nav)
   * onEnter  — optional callback when the page becomes active
   */
  const routes = [
    { name: 'scan', navIdx: 0 },
    { name: 'dash', navIdx: 1, onEnter: () => Dashboard.refreshOsintIfNeeded() },
    { name: 'hist', navIdx: -1, onEnter: () => { Dashboard.loadHistory(); Dashboard.loadTrends(); } },
    { name: 'cmp',  navIdx: 2 },
    { name: 'help', navIdx: -1 },
  ];

  const _byName = Object.fromEntries(routes.map(r => [r.name, r]));

  /** Show a page by name; e.g. showPage('scan'). */
  function showPage(name) {
    const route = _byName[name];
    if (!route) return;

    // Hide all pages
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    // Deactivate all nav tabs
    document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));

    // Activate page
    document.getElementById(`page-${name}`)?.classList.add('active');

    // Activate nav tab
    if (route.navIdx >= 0) {
      const tabs = document.querySelectorAll('.nav-tab');
      tabs[route.navIdx]?.classList.add('active');
    }

    // Run onEnter hook
    route.onEnter?.();
  }

  return { showPage };
})();
