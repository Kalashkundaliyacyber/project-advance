/**
 * chatbot/api.js
 * Scan-selector filter helpers and Chatbot public API surface.
 * This is the last section of the IIFE — includes the return {} statement.
 */

  /* ── Public API ─────────────────────────────────────────────── */
  // Fix #11: scan selector search + category filter
  function _filterScans(uid, query) {
    const q = query.toLowerCase().trim();
    const body = document.getElementById(uid + '_body');
    if (!body) return;
    body.querySelectorAll('.scan-card').forEach(card => {
      const text = card.textContent.toLowerCase();
      card.style.display = (!q || text.includes(q)) ? '' : 'none';
    });
    body.querySelectorAll('.ss-section').forEach(sec => {
      const visible = [...sec.querySelectorAll('.scan-card')].some(c => c.style.display !== 'none');
      sec.style.display = visible ? '' : 'none';
    });
  }

  function _filterScanCat(uid, cat, btn) {
    const body = document.getElementById(uid + '_body');
    if (!body) return;
    document.getElementById(uid + '_tabs').querySelectorAll('.ss-cat-tab').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(uid + '_search').value = '';
    body.querySelectorAll('.ss-section').forEach(sec => {
      sec.style.display = (cat === 'all' || sec.dataset.cat === cat) ? '' : 'none';
    });
    body.querySelectorAll('.scan-card').forEach(c => c.style.display = '');
  }

  return {
    showGreeting, addMsg, sendChat, quickChat, restoreChatMessages,
    runScan, executeScan, confirmStop, doStop, startNewScan, newChat,
    renderAll, rTab, openDrawer, closeDrawer, filterDrawer, loadDrawer, viewSession,
    showReportModal, selectFmt, doExportReport, suggestNext,
    onChatKeyDown, onChatInput, selectAutocomplete,
    _filterVulnTable, _sortVulnTable, _filterVulnDash, _searchVulnDash,
    _filterScans, _filterScanCat,
    _sortVulnDash, _toggleVulnExpand, _copyVulnCSV,
    _togglePatchExpand, _filterPatchDash, _searchPatchDash, _copyPatchCSV,
    _promptScanIP, _submitScanIP,
    _showProjectOnboarding, _submitProjectName, _setProjectQuick,
    // Drawer 3-dot menu
    _toggleDrawerMenu, _renameDrawerSession, _submitDrawerRename,
    _cancelDrawerRename, _deleteDrawerSession, _confirmDrawerDelete,
    // Fix 8 — scroll-to-bottom
    scrollToBottom, _onChatScroll,
  };
})();
