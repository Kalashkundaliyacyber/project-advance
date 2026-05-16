/**
 * utils.js
 * ─────────────────────────────────────────────────────────────────
 * Shared utility functions used across all modules.
 * No direct DOM coupling beyond helper selectors.
 * ─────────────────────────────────────────────────────────────────
 */

const Utils = (() => {

  /* ── String helpers ──────────────────────────────────────────── */

  /** Escape HTML special chars. */
  function esc(s) {
    return String(s || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  /** Render **bold** markdown to <b> tags. */
  function renderMarkdown(text) {
    return String(text).replace(/\*\*(.*?)\*\*/g, '<b>$1</b>');
  }

  /** Tooltip key-value row helper. */
  function tr(k, v) {
    if (!v && v !== 0) return '';
    return `<div style="display:flex;gap:6px;margin-top:3px">
      <span style="color:var(--text3);min-width:60px;font-size:11px">${k}</span>
      <span style="color:var(--text2);font-size:11px">${v}</span>
    </div>`;
  }

  /* ── Modal helpers ───────────────────────────────────────────── */

  function openModal(id)  { document.getElementById(id)?.classList.add('open'); }
  function closeModal(id) { document.getElementById(id)?.classList.remove('open'); }

  // Close any modal on overlay click
  document.addEventListener('click', e => {
    if (e.target.classList.contains('modal-overlay')) {
      e.target.classList.remove('open');
    }
  });

  /* ── Toast helpers ───────────────────────────────────────────── */

  function showToast(id = 'stop-toast') {
    const t = document.getElementById(id);
    if (!t) return;
    t.classList.add('show');
    setTimeout(() => hideToast(id), 8000);
  }

  function hideToast(id = 'stop-toast') {
    document.getElementById(id)?.classList.remove('show');
  }

  /* ── Status strip ────────────────────────────────────────────── */

  const STATUS_CONFIG = {
    idle:       { icon: '🟢', cls: 'state-idle',       dot: 'idle',       msg: 'System ready' },
    scanning:   { icon: '🔵', cls: 'state-scanning',   dot: 'scanning',   msg: 'Scanning' },
    processing: { icon: '🟡', cls: 'state-processing', dot: 'processing', msg: 'Analyzing results…' },
    stopped:    { icon: '🔴', cls: 'state-stopped',    dot: 'stopped',    msg: 'Scan stopped' },
    complete:   { icon: '🟢', cls: 'state-complete',   dot: 'complete',   msg: 'Scan complete' },
    error:      { icon: '🔴', cls: 'state-error',      dot: 'error',      msg: 'Error occurred' },
  };

  let _statusTimer = null;

  function setStatus(state, detail) {
    const cfg   = STATUS_CONFIG[state] || STATUS_CONFIG.idle;
    const strip = document.getElementById('status-strip');
    const icon  = document.getElementById('strip-icon');
    const msg   = document.getElementById('strip-msg');
    const spin  = document.getElementById('strip-spin');
    const dot   = document.getElementById('status-indicator');
    const txt   = document.getElementById('status-txt');

    if (!strip) return;

    strip.className = 'status-strip ' + cfg.cls;
    icon.textContent = cfg.icon;

    if (state === 'scanning' && detail) {
      msg.textContent = `Scanning ${detail}…`;
    } else if (state === 'processing') {
      msg.textContent = 'Analyzing results…';
    } else if (state === 'stopped') {
      msg.textContent = 'Scan stopped by user';
    } else if (state === 'complete' && detail) {
      msg.textContent = `Scan complete — ${detail}`;
    } else if (state === 'error' && detail) {
      msg.textContent = `Error: ${detail}`;
    } else {
      msg.textContent = cfg.msg;
    }

    spin.style.display = ['scanning', 'processing'].includes(state) ? 'flex' : 'none';
    dot.className = 'status-indicator ' + cfg.dot;
    txt.textContent = state.charAt(0).toUpperCase() + state.slice(1);

    if (_statusTimer) clearTimeout(_statusTimer);
    if (['complete', 'stopped', 'error'].includes(state)) {
      _statusTimer = setTimeout(() => setStatus('idle'), 6000);
    }
  }

  /* ── Collapsible panel toggle ────────────────────────────────── */

  function togglePanel(id, btn) {
    const p   = document.getElementById(id);
    const open = p.classList.toggle('open');
    btn.classList.toggle('open', open);
  }

  /* ── Export ─────────────────────────────────────────────────── */
  return {
    esc,
    renderMarkdown,
    tr,
    openModal,
    closeModal,
    showToast,
    hideToast,
    setStatus,
    togglePanel,
  };
})();
