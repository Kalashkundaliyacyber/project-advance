/**
 * app.js — ThreatWeave AI
 * ─────────────────────────────────────────────────────────────────
 * SidebarManager: single source of truth for the navigation drawer.
 * App: session restore + startup token check + global state.
 */

/* ═══════════════════════════════════════════════════════════════
   SidebarManager
   ═══════════════════════════════════════════════════════════════ */
const SidebarManager = (() => {
  const LS_KEY        = 'threatweave_sidebar_v1';
  const FOCUSABLE_SEL = [
    'a[href]',
    'button:not([disabled])',
    'input:not([disabled])',
    '[tabindex]:not([tabindex="-1"])'
  ].join(',');

  let _open    = false;
  let _ready   = false;
  let _bound   = false;
  let _drawer  = null;
  let _overlay = null;

  function _save() {
    try { localStorage.setItem(LS_KEY, _open ? '1' : '0'); } catch (_) {}
  }
  function _load() {
    try { return localStorage.getItem(LS_KEY) === '1'; } catch (_) { return false; }
  }

  function _apply(animate) {
    if (!_drawer || !_overlay) return;
    const btn = document.querySelector('.hamburger');

    if (!animate) {
      _drawer.style.transition = 'none';
      requestAnimationFrame(() => { _drawer.style.transition = ''; });
    }

    if (_open) {
      _drawer.classList.add('open');
      _overlay.classList.add('open');
      _overlay.style.pointerEvents = 'auto';
      _drawer.removeAttribute('aria-hidden');
      _drawer.setAttribute('aria-modal', 'true');
      _drawer.setAttribute('role', 'dialog');
      if (btn) btn.setAttribute('aria-expanded', 'true');
      if (window.innerWidth <= 768) document.body.style.overflow = 'hidden';
      requestAnimationFrame(() => {
        const focusable = Array.from(_drawer.querySelectorAll(FOCUSABLE_SEL))
          .filter(el => el.offsetParent !== null);
        if (focusable.length) focusable[0].focus();
      });
    } else {
      _drawer.classList.remove('open');
      _overlay.classList.remove('open');
      _overlay.style.pointerEvents = 'none';
      _drawer.setAttribute('aria-hidden', 'true');
      _drawer.removeAttribute('aria-modal');
      if (btn) {
        btn.setAttribute('aria-expanded', 'false');
        if (_drawer.contains(document.activeElement)) btn.focus();
      }
      document.body.style.overflow = '';
    }
  }

  function _bind() {
    if (_bound) return;
    _bound = true;

    _overlay.addEventListener('click', (e) => {
      if (e.target === _overlay) close();
    });

    document.addEventListener('keydown', (e) => {
      if (!_open) return;
      if (e.key === 'Escape') { e.preventDefault(); close(); return; }
      if (e.key === 'Tab' && _drawer) {
        const els = Array.from(_drawer.querySelectorAll(FOCUSABLE_SEL))
          .filter(el => el.offsetParent !== null);
        if (els.length < 2) return;
        if (e.shiftKey && document.activeElement === els[0]) {
          e.preventDefault(); els[els.length - 1].focus();
        } else if (!e.shiftKey && document.activeElement === els[els.length - 1]) {
          e.preventDefault(); els[0].focus();
        }
      }
    });

    document.addEventListener('click', (e) => {
      const el = e.target.closest('[data-action]');
      if (!el) return;
      const a = el.dataset.action;
      if      (a === 'toggle-drawer') { e.stopPropagation(); toggle(); }
      else if (a === 'open-drawer')   { e.stopPropagation(); open();   }
      else if (a === 'close-drawer')  { e.stopPropagation(); close();  }
    }, true);

    window.addEventListener('resize', () => {
      if (window.innerWidth > 768) document.body.style.overflow = '';
    }, { passive: true });
  }

  function open() {
    if (!_ready) return;
    _open = true; _apply(true); _save();
    try { if (typeof Chatbot !== 'undefined') Chatbot.loadDrawer(); } catch (_) {}
  }

  function close() {
    if (!_ready) return;
    _open = false; _apply(true); _save();
  }

  function toggle() { _open ? close() : open(); }
  function isOpen() { return _open; }

  function init() {
    _drawer  = document.getElementById('drawer');
    _overlay = document.getElementById('overlay');

    if (!_drawer || !_overlay) {
      console.error('[SidebarManager] #drawer or #overlay not found. Check navbar.html loaded.');
      return;
    }

    _ready = true;
    // BUGFIX: Never restore drawer as open on page load.
    // If the drawer was open when the user last left, _load() returns true and
    // _apply() would activate the full-screen overlay (position:fixed; inset:0;
    // z-index:200; pointer-events:auto) which silently blocks ALL clicks on the
    // page — including card inputs, buttons, and the chat textarea.
    // Drawers should always start closed; the user can reopen with the hamburger.
    _open  = false;
    _save(); // clear the stale 'open' state from localStorage
    _apply(false);
    _bind();
  }

  return { init, open, close, toggle, isOpen };
})();

/* ── Global shortcuts for onclick attributes in navbar.html ───── */
window.toggleSidebar = function () { SidebarManager.toggle(); };
window.openSidebar   = function () { SidebarManager.open();   };
window.closeSidebar  = function () { SidebarManager.close();  };


/* ═══════════════════════════════════════════════════════════════
   App — session restore + global state
   ═══════════════════════════════════════════════════════════════ */
const App = (() => {
  let _currentSession = null;
  let _lastData       = null;

  function getCurrentSession() { return _currentSession; }
  function setCurrentSession(id) { _currentSession = id; }
  function getLastData()  { return _lastData; }
  function setLastData(d) { _lastData = d; }

  /* ── Restore scan + chat from already-loaded localStorage data ── */
  function _restoreFromStorage() {
    // SessionManager.loadAllFromStorage() is called BEFORE this in _init().
    // We look up the active session directly — never call active() here because
    // active() auto-creates a new session when none is set, which is exactly the bug.
    const aid = SessionManager.activeId();
    const sessions = SessionManager.list();
    const activeSess = aid ? sessions.find(s => s.session_id === aid) : null;

    // No active session in storage at all — caller will create a fresh one
    if (!activeSess) return false;

    // Restore scan panel data if present
    if (activeSess.scan_results) {
      _currentSession = activeSess.scan_session || null;
      _lastData       = activeSess.scan_results;
      try { Chatbot.renderAll(activeSess.scan_results); } catch (e) {}
      const expBtn = document.getElementById('exp-btn');
      if (expBtn) expBtn.disabled = false;
    }

    // Restore chat messages if any were saved
    const validMsgs = (activeSess.messages || []).filter(m => m && m.text && m.type);
    if (validMsgs.length > 0) {
      Chatbot.restoreChatMessages(validMsgs, SessionManager.getScrollPos(activeSess.session_id));
      const nonGreeting = validMsgs.filter(m => !m.text.startsWith('__GREETING__:'));
      if (activeSess.scan_results && nonGreeting.length === 0) _injectScanSummary(activeSess.scan_results);
      return true;
    }

    // Session has scan results but no messages — inject a compact summary
    if (activeSess.scan_results) {
      _injectScanSummary(activeSess.scan_results);
      return true;
    }

    // Session exists (even with no messages/scan) — reuse it, never create a new one.
    // This is the critical fix: showGreeting() checks project_name and shows the
    // correct UI (post-onboarding if named, onboarding card if unnamed).
    Chatbot.showGreeting();
    return true;
  }

  function _injectScanSummary(d) {
    try {
      const target   = d.target       || 'unknown';
      const scanType = d.scan_type    || 'scan';
      const duration = d.duration     || 0;
      const ai       = d.ai_analysis  || {};
      const risk     = d.risk         || {};
      const overall  = ai.overall_risk || risk.overall_risk || 'unknown';
      const summary  = ai.summary     || '';
      const hosts    = risk.hosts     || [];
      const totalPorts = hosts.reduce((n, h) => n + (h.ports || []).length, 0);
      const totalCves  = hosts.reduce((n, h) =>
        n + (h.ports || []).reduce((p, port) => p + (port.cves || []).length, 0), 0);
      let text = `✅ **Scan restored** — \`${target}\` | \`${scanType}\` | ${duration}s\n`;
      text += `**Overall Risk: ${overall.toUpperCase()}** · ${totalPorts} open ports · ${totalCves} CVEs\n`;
      if (summary) text += `\n> ${summary}\n`;
      text += `\n*Use \`/vuln\` for CVE details · \`/patch all\` for fixes · \`/report html\` to export.*`;
      Chatbot.addMsg(text, 'ai');
    } catch (e) {}
  }

  /* ── Persistence listeners (beforeunload, visibilitychange) ──── */
  function _setupPersistenceListeners() {
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'hidden') {
        if (_lastData && _currentSession) {
          const s = SessionManager.active();
          if (s && !s.scan_results) { s.scan_results = _lastData; s.scan_session = _currentSession; }
        }
        SessionManager.persistAll();
      }
    });

    window.addEventListener('beforeunload', () => {
      if (_lastData && _currentSession) {
        const s = SessionManager.active();
        if (s && !s.scan_results) { s.scan_results = _lastData; s.scan_session = _currentSession; }
      }
      const chat = document.getElementById('chat');
      if (chat && SessionManager.activeId()) {
        SessionManager.saveScrollPos(SessionManager.activeId(), chat.scrollTop);
      }
      SessionManager.persistAll();
      SessionManager.persist();
    });
  }

  /* ── Health check ────────────────────────────────────────────── */
  function _checkHealth() {
    (async () => {
      try {
        const d = await ApiService.healthCheck();
        if (d.status === 'ok') {
          const txt = document.getElementById('status-txt');
          if (txt) txt.textContent = 'Connected';
        }
      } catch (e) {
        const txt = document.getElementById('status-txt');
        if (txt) { txt.textContent = 'Offline'; txt.style.color = 'var(--red)'; }
      }
    })();
  }

  /* ── Main init ───────────────────────────────────────────────── */
  async function _init() {
    // STEP 1: Load all saved sessions into memory FIRST — before anything else.
    SessionManager.loadAllFromStorage();

    // Always start on the scan page so the FRS toolbar is visible from the start
    if (typeof Router !== 'undefined') Router.showPage('scan');

    // STEP 2: Determine if this is a fresh server start (run.sh) or a browser refresh.
    const startupState = await SessionManager.checkStartupToken();

    if (startupState === 'fresh') {
      // run.sh was re-executed — check for interrupted scan on old data BEFORE clearing.
      const interrupted = SessionManager.getInterruptedScan();
      SessionManager.clearAllSessions();
      Chatbot.loadDrawer();
      _setupPersistenceListeners();
      Utils.setStatus('idle');
      _checkHealth();
      Chatbot.showGreeting();
      if (interrupted) {
        setTimeout(() => {
          Chatbot.addMsg(
            `⚠️ **Interrupted scan detected** for \`${interrupted.target}\` (${interrupted.scanType}).\n\n` +
            `The previous scan did not complete. Use \`/scan ${interrupted.target}\` to retry.`, 'ai');
          SessionManager.clearScanState();
        }, 1500);
      }
      return;
    }

    // STEP 3: Check if URL contains a session id (?s=<scan_session_id>)
    // This enables direct linking to a session via URL, e.g.:
    //   http://localhost:3332/?s=20260625_100122_5d77ef22_10-103-181-160_full_scan
    const urlSessionId = _getUrlSessionId();
    if (urlSessionId) {
      Chatbot.loadDrawer();
      _setupPersistenceListeners();
      Utils.setStatus('idle');
      _checkHealth();
      // Delay slightly so Chatbot fully initialises before switching
      setTimeout(async () => {
        try {
          await Chatbot.viewSession(urlSessionId);
        } catch (e) {
          console.warn('[App] URL session load failed:', e);
          const restored = _restoreFromStorage();
          if (!restored) Chatbot.showGreeting();
        }
      }, 200);
      return;
    }

    // STEP 4: Browser refresh — restore the existing session, never create a new one.
    const restored = _restoreFromStorage();
    if (!restored) {
      Chatbot.showGreeting();
    }

    Chatbot.loadDrawer();
    _setupPersistenceListeners();
    Utils.setStatus('idle');
    _checkHealth();

    if (restored) {
      setTimeout(() => {
        const chat = document.getElementById('chat');
        if (chat) chat.scrollTo({ top: chat.scrollHeight, behavior: 'smooth' });
      }, 100);
      const interrupted = SessionManager.getInterruptedScan();
      if (interrupted) {
        setTimeout(() => {
          Chatbot.addMsg(
            `⚠️ **Interrupted scan detected** for \`${interrupted.target}\` (${interrupted.scanType}).\n\n` +
            `The previous scan did not complete. Use \`/scan ${interrupted.target}\` to retry.`, 'ai');
          SessionManager.clearScanState();
        }, 800);
      }
    }
  }

  /**
   * URL SESSION ROUTING
   * ─────────────────────────────────────────────────────────────────────────
   * Reads the '?s=' query parameter from the current URL.
   * Format: http://localhost:3332/?s=20260625_100122_5d77ef22_10-103-181-160_full_scan
   */
  function _getUrlSessionId() {
    try {
      const params = new URLSearchParams(window.location.search);
      return params.get('s') || null;
    } catch (_) { return null; }
  }

  /**
   * Update the browser URL to include the current scan session id.
   * Called by viewSession() so every session switch is URL-bookmarkable.
   * Uses history.replaceState so Back/Forward work naturally.
   *
   * @param {string|null} scanSessionId — the scan_session id (disk format), or null to clear
   */
  function setUrlSessionId(scanSessionId) {
    try {
      const url = new URL(window.location.href);
      if (scanSessionId) {
        url.searchParams.set('s', scanSessionId);
      } else {
        url.searchParams.delete('s');
      }
      window.history.replaceState({ sessionId: scanSessionId }, '', url.toString());
    } catch (_) {}
  }

  // Triggered by bootstrap() in index.html after ALL components are in the DOM
  document.addEventListener('app:ready', () => { _init(); });

  return { getCurrentSession, setCurrentSession, getLastData, setLastData, setUrlSessionId };


})();
