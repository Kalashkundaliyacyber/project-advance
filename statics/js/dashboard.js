/**
 * dashboard.js v2.0
 * History page: 3-dot menu per session with Rename + Delete.
 * All dashboard/osint logic.
 */

const Dashboard = (() => {
  let _currentDashTab  = 'radial';
  let _openMenuId      = null;   // track which 3-dot menu is open

  function getCurrentDashTab() { return _currentDashTab; }
  function destroyCharts()     { Graphs.destroyAll(); }
  function flagOsintStale()    { Graphs.markStale(); }
  function resetOsint()        { Graphs.clearOsint(); }

  /* ════════════════════════════════════════════════════
     DASHBOARD PAGE
  ════════════════════════════════════════════════════ */

  function renderDashboard(charts, risk) {
    Graphs.renderDashboardCharts(charts, risk);
  }

  function switchDashTab(tab) {
    _currentDashTab = tab;
    document.querySelectorAll('.dash-subtab').forEach(b => b.classList.remove('active'));
    document.getElementById('subtab-' + tab)?.classList.add('active');
    document.getElementById('dash-radial').style.display = tab === 'radial' ? 'flex' : 'none';
    document.getElementById('dash-osint').style.display  = tab === 'osint'  ? 'flex' : 'none';
    if (tab === 'osint') refreshOsintIfNeeded();
  }

  function refreshOsintIfNeeded() {
    const last = App.getLastData();
    if (last && !Graphs.isBuilt()) buildOsintTree(last.risk);
  }

  function buildOsintTree(riskData) {
    Graphs.buildOsintTree(riskData);
  }

  /* ════════════════════════════════════════════════════
     HISTORY PAGE — with 3-dot rename/delete menu
  ════════════════════════════════════════════════════ */

  async function loadHistory() {
    const target   = document.getElementById('h-target')?.value || '';
    const severity = document.getElementById('h-sev')?.value    || '';
    const el       = document.getElementById('hist-list');
    try {
      const d = await ApiService.getHistory({ target, severity });
      if (!d.sessions?.length) {
        el.innerHTML = '<div class="empty">No scans found.</div>';
        return;
      }
      el.innerHTML = d.sessions.map(s => _histItem(s)).join('');
    } catch (e) {
      el.innerHTML = '<div class="empty">Could not load history.</div>';
    }
  }

  function _histItem(s) {
    const risk        = s.overall_risk || 'low';
    // Project name is the primary identifier; fall back to label then target
    const projectName = s.project_name || s.label || '';
    const target      = s.target || '';
    const displayTitle = projectName || target || 'Unnamed Project';
    const secondaryMeta = [s.scan_type, target].filter(Boolean).join(' · ');
    const menuId      = 'hmenu-' + s.session_id;
    return `
      <div class="hist-item" id="hitem-${s.session_id}">
        <div class="hist-main" onclick="Chatbot.viewSession('${s.session_id}')">
          <div class="hist-row">
            <div class="hist-title-group">
              <span class="hist-project-name">${displayTitle}</span>
              ${secondaryMeta ? `<span class="hist-target hist-target-secondary">${secondaryMeta}</span>` : ''}
            </div>
            <span class="rb rb-${risk}">${risk}</span>
          </div>
          <div class="hist-meta">${s.open_ports||0} open ports · ${s.cve_count||0} CVEs · ${s.timestamp?.slice(0,16)||''}</div>
        </div>
        <div class="hist-actions">
          <button class="hist-dot-btn" title="Options"
                  onclick="event.stopPropagation(); Dashboard.toggleHistMenu('${s.session_id}')">⋯</button>
          <div class="hist-menu" id="${menuId}" style="display:none">
            <div class="hist-menu-item" onclick="Dashboard.renameSession('${s.session_id}','${displayTitle.replace(/'/g,"\\'")}')">
              ✏️ Rename
            </div>
            <div class="hist-menu-item hist-menu-delete" onclick="Dashboard.deleteSession('${s.session_id}')">
              🗑️ Delete
            </div>
          </div>
        </div>
      </div>`;
  }

  function toggleHistMenu(sessionId) {
    const menuId = 'hmenu-' + sessionId;
    const menu   = document.getElementById(menuId);
    if (!menu) return;

    // Close any other open menu first
    if (_openMenuId && _openMenuId !== menuId) {
      const prev = document.getElementById(_openMenuId);
      if (prev) prev.style.display = 'none';
    }

    const isOpen = menu.style.display !== 'none';
    menu.style.display = isOpen ? 'none' : 'block';
    _openMenuId = isOpen ? null : menuId;

    // Close when clicking outside
    if (!isOpen) {
      setTimeout(() => {
        const handler = (e) => {
          if (!menu.contains(e.target)) {
            menu.style.display = 'none';
            _openMenuId = null;
            document.removeEventListener('click', handler);
          }
        };
        document.addEventListener('click', handler);
      }, 10);
    }
  }

  async function renameSession(sessionId, currentLabel) {
    // Close menu
    const menu = document.getElementById('hmenu-' + sessionId);
    if (menu) menu.style.display = 'none';
    _openMenuId = null;

    // Show inline rename input
    const item = document.getElementById('hitem-' + sessionId);
    if (!item) return;

    const mainEl = item.querySelector('.hist-main');
    const orig   = mainEl.innerHTML;

    mainEl.innerHTML = `
      <div class="hist-rename-row">
        <input class="hist-rename-inp" id="rename-inp-${sessionId}"
               value="${currentLabel}"
               onkeydown="if(event.key==='Enter') Dashboard._submitRename('${sessionId}');
                          if(event.key==='Escape') Dashboard._cancelRename('${sessionId}','${currentLabel.replace(/'/g,"\\'")}')"/>
        <button class="btn btn-pri" style="height:28px;padding:0 10px;font-size:11px"
                onclick="Dashboard._submitRename('${sessionId}')">Save</button>
        <button class="btn btn-sec" style="height:28px;padding:0 10px;font-size:11px"
                onclick="Dashboard._cancelRename('${sessionId}','${currentLabel.replace(/'/g,"\\'")}')">Cancel</button>
      </div>`;

    // Store original for cancel
    item._origMainHtml = orig;
    setTimeout(() => document.getElementById('rename-inp-' + sessionId)?.focus(), 50);
  }

  async function _submitRename(sessionId) {
    const inp  = document.getElementById('rename-inp-' + sessionId);
    const name = inp?.value?.trim();
    if (!name) return;

    try {
      await ApiService.renameSession(sessionId, name);
      loadHistory(); // Refresh list
    } catch (e) {
      loadHistory();
    }
  }

  function _cancelRename(sessionId, original) {
    const item   = document.getElementById('hitem-' + sessionId);
    const mainEl = item?.querySelector('.hist-main');
    if (mainEl && item._origMainHtml) mainEl.innerHTML = item._origMainHtml;
    else loadHistory();
  }

  async function deleteSession(sessionId) {
    // Close menu
    const menu = document.getElementById('hmenu-' + sessionId);
    if (menu) menu.style.display = 'none';
    _openMenuId = null;

    // Show confirmation inline
    const item = document.getElementById('hitem-' + sessionId);
    if (!item) return;
    const mainEl = item.querySelector('.hist-main');
    const orig   = mainEl.innerHTML;
    item._origMainHtml = orig;

    mainEl.innerHTML = `
      <div class="hist-confirm-row">
        <span class="hist-confirm-txt">🗑️ Delete this scan permanently?</span>
        <button class="btn" style="background:#e24b4a;color:#fff;height:28px;padding:0 12px;font-size:11px;border:none"
                onclick="Dashboard._confirmDelete('${sessionId}')">Delete</button>
        <button class="btn btn-sec" style="height:28px;padding:0 10px;font-size:11px"
                onclick="Dashboard._cancelRename('${sessionId}','')">Cancel</button>
      </div>`;
  }

  async function _confirmDelete(sessionId) {
    try {
      await ApiService.deleteSession(sessionId);
      // Remove from DOM instantly
      document.getElementById('hitem-' + sessionId)?.remove();
      // If it was the active session, clear state
      if (App.getCurrentSession() === sessionId) {
        App.setCurrentSession(null);
        App.setLastData(null);
      }
    } catch (e) {
      loadHistory();
    }
  }

  async function loadTrends() {
    try {
      const d = await ApiService.getHistoryTrends();
      Graphs.renderTrendCharts(d);
    } catch (e) { /* silent */ }
  }

  function clearHistoryFilters() {
    document.getElementById('h-target').value = '';
    document.getElementById('h-sev').value    = '';
    loadHistory();
  }

  /* ════════════════════════════════════════════════════
     COMPARE PAGE
  ════════════════════════════════════════════════════ */


  /**
   * FIX2: Full side-by-side compare render with:
   * - agreement highlights (both detected = high confidence ✅)
   * - disagreement highlights (only one detected = ⚠️ verify)
   * - confidence overlap badges
   * - metric comparison bars
   * - winner badge
   */

  /* ── Public API ─────────────────────────────────────────────── */
  return {
    getCurrentDashTab,
    destroyCharts,
    flagOsintStale,
    resetOsint,
    renderDashboard,
    switchDashTab,
    refreshOsintIfNeeded,
    buildOsintTree,
    loadHistory,
    loadTrends,
    clearHistoryFilters,
    toggleHistMenu,
    renameSession,
    _submitRename,
    _cancelRename,
    deleteSession,
    _confirmDelete,
    _setAiLabel: (label) => { _aiProviderLabel = label || 'AI Analysis'; },
  };
})();

