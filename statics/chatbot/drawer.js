/**
 * chatbot/drawer.js
 * History drawer, session 3-dot menu, report modal, export.
 */

  // FIX 1: Persist deleted session IDs so history never re-shows deleted entries.
  // Shared with restore.js (both read/write the same localStorage key).
  const _deletedSessionIds = new Set(
    (() => { try { return JSON.parse(localStorage.getItem('scanwise_deleted_ids_v1') || '[]'); } catch(_) { return []; } })()
  );
  function _persistDeletedIds() {
    try { localStorage.setItem('scanwise_deleted_ids_v1', JSON.stringify([..._deletedSessionIds].slice(-200))); } catch(_) {}
  }


  /* ── Drawer 3-dot menu ────────────────────────────────────────── */

  function _toggleDrawerMenu(sid) {
    const menuId = 'dmenu-' + sid;
    const menu   = document.getElementById(menuId);
    if (!menu) return;
    // Close any other open drawer menu
    if (_drawerMenuId && _drawerMenuId !== menuId) {
      const prev = document.getElementById(_drawerMenuId);
      if (prev) prev.style.display = 'none';
    }
    const isOpen = menu.style.display !== 'none';
    menu.style.display = isOpen ? 'none' : 'block';
    _drawerMenuId = isOpen ? null : menuId;
    if (!isOpen) {
      setTimeout(() => {
        const handler = (e) => {
          if (!menu.contains(e.target)) {
            menu.style.display = 'none';
            _drawerMenuId = null;
            document.removeEventListener('click', handler);
          }
        };
        document.addEventListener('click', handler);
      }, 10);
    }
  }

  async function _renameDrawerSession(sid, currentName) {
    const menu = document.getElementById('dmenu-' + sid);
    if (menu) menu.style.display = 'none';
    _drawerMenuId = null;

    const item   = document.getElementById('ditem-' + sid);
    const mainEl = item?.querySelector('.sb-main');
    if (!mainEl) return;
    const origHtml = mainEl.innerHTML;

    mainEl.innerHTML = `
      <div class="sb-rename-row">
        <input class="sb-rename-inp" id="dr-inp-${sid}" type="text" value="${currentName}"
               maxlength="60" placeholder="Project name…"
               onkeydown="if(event.key==='Enter') Chatbot._submitDrawerRename('${sid}');
                          if(event.key==='Escape') Chatbot._cancelDrawerRename('${sid}','${origHtml.replace(/'/g, "\\'")}')"/>
        <button class="btn btn-pri" style="height:28px;padding:0 10px;font-size:11px"
                onclick="Chatbot._submitDrawerRename('${sid}')">Save</button>
        <button class="btn btn-sec" style="height:28px;padding:0 8px;font-size:11px"
                onclick="Chatbot._cancelDrawerRename('${sid}')">✕</button>
      </div>`;

    setTimeout(() => document.getElementById(`dr-inp-${sid}`)?.focus(), 50);
  }

  async function _submitDrawerRename(sid) {
    const inp  = document.getElementById(`dr-inp-${sid}`);
    const name = inp?.value?.trim();
    if (!name) return;
    try {
      await ApiService.renameSession(sid, name);
      loadDrawer();
    } catch (e) { loadDrawer(); }
  }

  function _cancelDrawerRename(sid) { loadDrawer(); }

  async function _deleteDrawerSession(sid) {
    const menu = document.getElementById('dmenu-' + sid);
    if (menu) menu.style.display = 'none';
    _drawerMenuId = null;

    const item   = document.getElementById('ditem-' + sid);
    const mainEl = item?.querySelector('.sb-main');
    if (!mainEl) return;

    mainEl.innerHTML = `
      <div class="sb-confirm-row">
        <span class="sb-confirm-txt">🗑️ Delete permanently?</span>
        <button class="btn" style="background:#e24b4a;color:#fff;height:26px;padding:0 10px;font-size:11px;border:none"
                onclick="Chatbot._confirmDrawerDelete('${sid}')">Delete</button>
        <button class="btn btn-sec" style="height:26px;padding:0 8px;font-size:11px"
                onclick="Chatbot.loadDrawer()">Cancel</button>
      </div>`;
  }

  async function _confirmDrawerDelete(sid) {
    // FIX 1: Mark as deleted immediately so loadDrawer() won't re-show it
    // from the backend history API even before the DELETE request completes.
    _deletedSessionIds.add(sid);
    _persistDeletedIds();
    try {
      await ApiService.deleteSession(sid);
    } catch (e) {
      // Backend delete failed — may not exist on server. Continue with local cleanup.
    }
    // Always clean up locally regardless of backend result
    document.getElementById('ditem-' + sid)?.remove();
    const wasActive = SessionManager.activeId() === sid;
    SessionManager.remove(sid); // purge from memory + localStorage
    if (App.getCurrentSession() === sid) {
      App.setCurrentSession(null);
      App.setLastData(null);
    }
    // If we deleted the active session, switch to another one
    if (wasActive) {
      const remaining = SessionManager.list();
      if (remaining.length > 0) {
        const next = remaining[0];
        SessionManager.switchTo(next.session_id);
      }
    }
    // Refresh drawer so deleted entry is gone for good
    loadDrawer();
  }

  async function viewSession(id) {
    // FIX 5+7: Save scroll of current session, switch, restore scroll of target
    const scrollPos = SessionManager.getScrollPos(id);
    const mem = SessionManager.switchTo(id);

    if (mem?.scan_results) {
      App.setLastData(mem.scan_results);
      App.setCurrentSession(mem.scan_session || id);
      _currentTarget = mem.scan_results?.target || '';
      Dashboard.flagOsintStale();
      renderAll(mem.scan_results);
      const chat = document.getElementById('chat');
      chat.innerHTML = '';
      if (mem.messages?.length) {
        restoreChatMessages(mem.messages, scrollPos);  // FIX 7: restore scroll
      } else {
        // Try backend SQLite store
        try {
          const loaded = await ApiService.loadChatSession(mem.session_id);
          if (loaded?.messages?.length) {
            loaded.messages.forEach(m => SessionManager.saveMsg(m.type, m.text));
            restoreChatMessages(loaded.messages, scrollPos);
          } else if (mem.project_name) {
            _showPostOnboarding(mem.project_name);
          }
        } catch (_) {
          if (mem.project_name) _showPostOnboarding(mem.project_name);
        }
      }
      Router.showPage('scan');
      return;
    }

    // Session is in memory but has no scan results yet
    if (mem) {
      App.setCurrentSession(null);
      App.setLastData(null);
      _currentTarget = '';
      const chat = document.getElementById('chat');
      chat.innerHTML = '';
      if (mem.messages?.length) {
        restoreChatMessages(mem.messages, scrollPos);  // FIX 7
      } else {
        // Try loading messages from backend SQLite store
        try {
          const loaded = await ApiService.loadChatSession(mem.session_id);
          if (loaded?.messages?.length) {
            // Merge into session manager so future saves include them
            loaded.messages.forEach(m => SessionManager.saveMsg(m.type, m.text));
            restoreChatMessages(loaded.messages, scrollPos);
          } else if (mem.project_name) {
            _showPostOnboarding(mem.project_name);
          } else {
            showGreeting();
          }
        } catch (_) {
          if (mem.project_name) _showPostOnboarding(mem.project_name);
          else showGreeting();
        }
      }
      Router.showPage('scan');
      return;
    }

    // Not in memory at all — try to load from backend (backend session ids)
    try {
      const d = await ApiService.getScanResults(id);
      if (d.risk) {
        SessionManager.create();
        SessionManager.saveScan(d);
        App.setLastData(d);
        App.setCurrentSession(id);
        _currentTarget = d.target || '';
        Dashboard.flagOsintStale();
        renderAll(d);
        Router.showPage('scan');
      }
    } catch (e) {
      // FIX: Show a non-scary toast instead of error in chat
      Utils.showToast && Utils.showToast('session-not-found-toast');
      loadDrawer(); // refresh drawer to remove any stale entry
    }
  }

  /* ═══════════════════════════════════════════════════════
     EXPORT / REPORT
  ═══════════════════════════════════════════════════════ */

  function showReportModal() {
    const cur = App.getCurrentSession();
    if (!cur) { addMsg('Run a scan first to generate a report.', 'ai'); return; }
    Utils.openModal('report-modal');
  }

  function selectFmt(fmt) {
    _selectedFmt = fmt;
    document.querySelectorAll('.fmt-opt').forEach(el => el.classList.remove('selected'));
    document.getElementById('fmt-' + fmt)?.classList.add('selected');
  }

  async function doExportReport() {
    Utils.closeModal('report-modal');
    const goBtn = document.getElementById('export-go-btn');
    if (goBtn) goBtn.disabled = true;
    const cur = App.getCurrentSession();
    addMsg(`📄 Generating **${_selectedFmt.toUpperCase()}** report…`, 'sys');
    try {
      const d = await ApiService.generateReport(cur, _selectedFmt);
      const downloadUrl = d.download || '#';
      if (_selectedFmt === 'pdf') {
        try {
          const res = await fetch(downloadUrl);
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          const blob   = await res.blob();
          const objUrl = URL.createObjectURL(new Blob([blob], { type: 'application/pdf' }));
          const anchor = document.createElement('a');
          anchor.href = objUrl; anchor.download = `scanwise_report_${cur}.pdf`;
          document.body.appendChild(anchor); anchor.click(); document.body.removeChild(anchor);
          setTimeout(() => URL.revokeObjectURL(objUrl), 10000);
          document.getElementById('report-toast-title').textContent = '📄 PDF Report Ready';
          document.getElementById('report-toast-link').href = objUrl;
          document.getElementById('report-toast-link').download = `scanwise_report_${cur}.pdf`;
        } catch (dlErr) {
          document.getElementById('report-toast-title').textContent = '📄 PDF Report Ready';
          document.getElementById('report-toast-link').href = downloadUrl;
        }
      } else {
        document.getElementById('report-toast-title').textContent = `📄 ${_selectedFmt.toUpperCase()} Report Ready`;
        document.getElementById('report-toast-link').href = downloadUrl;
        document.getElementById('report-toast-link').setAttribute('target','_blank');
      }
      Utils.showToast('report-toast');
      addMsg(`✅ **${_selectedFmt.toUpperCase()} report ready.**`, 'ai');
    } catch (e) {
      addMsg(`Report error: ${e.message}`, 'ai');
    } finally {
      if (goBtn) goBtn.disabled = false;
    }
  }

  function suggestNext() {
    const last = App.getLastData();
    if (last?.recommendation) { const r = last.recommendation; addMsg(`💡 **${r.title}**\n${r.reason}`, 'ai'); rTab('risk'); }
    else addMsg('Run a scan first to get recommendations.', 'ai');
  }

