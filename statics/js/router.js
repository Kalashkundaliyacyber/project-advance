/**
 * router.js
 * ─────────────────────────────────────────────────────────────────
 * Lightweight client-side router for the SPA shell.
 * Routes: scan | dash | hist | help
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
    { name: 'scan', onEnter: null },
    { name: 'dash', onEnter: () => Dashboard.refreshOsintIfNeeded() },
    { name: 'hist', onEnter: () => { Dashboard.loadHistory(); Dashboard.loadTrends(); } },
    { name: 'help', onEnter: null },
  ];

  const _byName = Object.fromEntries(routes.map(r => [r.name, r]));

  /** Show a page by name; e.g. showPage('scan'). */
  function showPage(name) {
    const route = _byName[name];
    if (!route) return;

    // Hide all pages
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));

    // Activate page
    document.getElementById(`page-${name}`)?.classList.add('active');

    // Show FRS toolbar on scan page; hide + close panel on other pages
    if (typeof Chatbot !== 'undefined') {
      if (name === 'scan') {
        document.getElementById('frs-toolbar')?.classList.add('frs-visible');
      } else {
        document.getElementById('frs-toolbar')?.classList.remove('frs-visible');
        Chatbot.frsClose?.();
      }
    }

    // Run onEnter hook
    route.onEnter?.();
  }

  return { showPage };
})();
