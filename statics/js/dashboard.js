/**
 * dashboard.js v2.0
 * History page: 3-dot menu per session with Rename + Delete.
 * All other dashboard/compare/osint logic unchanged.
 */

const Dashboard = (() => {
  let _currentDashTab  = 'radial';
  let _openMenuId      = null;   // track which 3-dot menu is open
  let _aiProviderLabel = 'Gemini AI'; // set when compare runs, used in renderCompare

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

  async function runCompare() {
    const cur = App.getCurrentSession();
    if (!cur) { Chatbot.addMsg('Run a scan first.', 'ai'); return; }
    // Fetch active provider name for compare display label
    try {
      const st = await ApiService.getAIStatus();
      _aiProviderLabel = st.display_name || 'AI Analysis';
    } catch (e) { _aiProviderLabel = 'AI Analysis'; }
    Chatbot.addMsg('🤖 Running AI vs Rule-Based comparison…', 'sys');
    try {
      const d = await ApiService.runCompare(cur);
      renderCompare(d);
      Router.showPage('cmp');
      Chatbot.addMsg('✅ Comparison done. Switch to **Compare** tab.', 'ai');
    } catch (e) {
      Chatbot.addMsg(`Compare error: ${e.message}`, 'ai');
    }
  }

  /**
   * FIX2: Full side-by-side compare render with:
   * - agreement highlights (both detected = high confidence ✅)
   * - disagreement highlights (only one detected = ⚠️ verify)
   * - confidence overlap badges
   * - metric comparison bars
   * - winner badge
   */
  function renderCompare(d) {
    const el = document.getElementById('cmp-result');
    if (!el) return;
    const rb   = d.rule_based  || {};
    const ai   = d.ai_analysis || {};
    const rbs  = rb.scores || {};
    const ais  = ai.scores || {};
    const winner = d.winner || 'tie';

    // ── Overall header ──────────────────────────────────────────
    const winnerBadge = winner === 'claude-ai'
      ? `<span style="background:#7c3aed;color:#fff;padding:3px 10px;border-radius:12px;font-size:11px">🤖 AI Wins</span>`
      : winner === 'rule-based'
        ? `<span style="background:var(--blue);color:#fff;padding:3px 10px;border-radius:12px;font-size:11px">⚙️ Rules Win</span>`
        : `<span style="background:var(--bg3);color:var(--text2);padding:3px 10px;border-radius:12px;font-size:11px">🤝 Tie</span>`;

    // ── Side-by-side engine cards ───────────────────────────────
    const riskMatch = (rb.overall_risk || '').toLowerCase() === (ai.overall_risk || '').toLowerCase();
    const riskBadge = riskMatch
      ? `<span title="Both engines agree on risk level" style="color:var(--green);font-size:11px">✅ Agreement</span>`
      : `<span title="Risk levels differ — verify manually" style="color:#EF9F27;font-size:11px">⚠️ Differs</span>`;

    function _scoreBar(val, colour) {
      const pct = Math.min((val || 0) * 10, 100);
      return `<div style="height:6px;background:var(--bg3);border-radius:3px;overflow:hidden;margin-top:4px">
        <div style="width:${pct}%;height:100%;background:${colour};border-radius:3px;transition:width .5s"></div></div>`;
    }

    const engineGrid = `
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
        <div class="cmp-box" style="border-left:3px solid var(--blue)">
          <h3>⚙️ Rule-Based Engine</h3>
          <div style="font-size:12px;color:var(--text2);line-height:2">
            Overall Risk: <strong>${rb.overall_risk || '—'}</strong><br>
            Findings: <strong>${rb.findings_count || 0}</strong> &nbsp;|&nbsp; CVEs: <strong>${rb.cve_count || 0}</strong><br>
            Recommendations: <strong>${rb.rec_count || 0}</strong>
          </div>
          <div style="margin-top:10px">
            <div style="font-size:11px;color:var(--text3)">Quality Score</div>
            <div style="font-size:22px;font-weight:700;color:var(--blue)">${rbs.overall || '—'}<span style="font-size:12px;font-weight:400">/10</span></div>
            ${_scoreBar(rbs.overall, 'var(--blue)')}
          </div>
        </div>
        <div class="cmp-box" style="border-left:3px solid #7c3aed">
          <h3>🤖 ${_aiProviderLabel}</h3>
          <div style="font-size:12px;color:var(--text2);line-height:2">
            Overall Risk: <strong>${ai.overall_risk || '—'}</strong><br>
            Findings: <strong>${ai.findings_count || 0}</strong> &nbsp;|&nbsp; CVEs: <strong>${ai.cve_count || 0}</strong><br>
            Recommendations: <strong>${ai.rec_count || 0}</strong>
          </div>
          <div style="margin-top:10px">
            <div style="font-size:11px;color:var(--text3)">Quality Score</div>
            <div style="font-size:22px;font-weight:700;color:#7c3aed">${ais.overall || '—'}<span style="font-size:12px;font-weight:400">/10</span></div>
            ${_scoreBar(ais.overall, '#7c3aed')}
          </div>
        </div>
      </div>`;

    // ── Risk-level agreement row ────────────────────────────────
    const agreementRow = `
      <div class="cmp-box" style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
        <div style="flex:1;min-width:180px">
          <div style="font-size:12px;color:var(--text3);margin-bottom:4px">Risk Level Comparison</div>
          <div style="display:flex;gap:10px;align-items:center">
            <span style="background:var(--bg3);padding:4px 10px;border-radius:6px;font-size:12px">
              ⚙️ <strong>${rb.overall_risk || '—'}</strong>
            </span>
            <span style="color:var(--text3)">vs</span>
            <span style="background:var(--bg3);padding:4px 10px;border-radius:6px;font-size:12px">
              🤖 <strong>${ai.overall_risk || '—'}</strong>
            </span>
            ${riskBadge}
          </div>
        </div>
        <div>${winnerBadge}</div>
      </div>`;

    // ── Metrics bars ────────────────────────────────────────────
    const metricsHtml = (d.metrics || []).map(m => {
      const rb_v = m.rule_based || 0;
      const ai_v = m.ai || 0;
      const diff = Math.abs(rb_v - ai_v);
      // Agreement: difference < 1.5 → green border highlight
      const agree = diff < 1.5;
      const highlightStyle = agree
        ? 'border-left:3px solid var(--green)'
        : 'border-left:3px solid #EF9F27';
      const agreeTag = agree
        ? `<span title="Engines agree on this metric" style="font-size:10px;color:var(--green)">✅</span>`
        : `<span title="Engines differ — investigate" style="font-size:10px;color:#EF9F27">⚠️</span>`;
      const betterTag = m.better === 'claude-ai'
        ? `<span style="font-size:10px;color:#7c3aed">🤖 better</span>`
        : m.better === 'rule-based'
          ? `<span style="font-size:10px;color:var(--blue)">⚙️ better</span>`
          : `<span style="font-size:10px;color:var(--text3)">tied</span>`;

      return `
        <div class="metric-row" style="${highlightStyle};padding-left:8px;border-radius:4px">
          <span class="metric-lbl" style="display:flex;align-items:center;gap:4px">
            ${agreeTag} ${m.metric}
          </span>
          <div style="flex:1;display:flex;flex-direction:column;gap:5px">
            <div style="display:flex;align-items:center;gap:6px">
              <span style="width:70px;font-size:11px;color:var(--text3)">Rules</span>
              <div class="metric-bar-wrap">
                <div class="metric-bar" style="width:${rb_v*10}%;background:var(--blue)"></div>
              </div>
              <span class="metric-val" style="color:var(--blue)">${rb_v}</span>
            </div>
            <div style="display:flex;align-items:center;gap:6px">
              <span style="width:70px;font-size:11px;color:var(--text3)">AI</span>
              <div class="metric-bar-wrap">
                <div class="metric-bar" style="width:${ai_v*10}%;background:#7c3aed"></div>
              </div>
              <span class="metric-val" style="color:#7c3aed">${ai_v}</span>
            </div>
          </div>
          <div style="width:70px;text-align:right">${betterTag}</div>
        </div>`;
    }).join('');

    // ── Confidence overlap badge ────────────────────────────────
    const agreementCount = (d.metrics || []).filter(m => Math.abs((m.rule_based||0)-(m.ai||0)) < 1.5).length;
    const total = (d.metrics || []).length || 1;
    const confPct = Math.round(agreementCount / total * 100);
    const confColour = confPct >= 80 ? 'var(--green)' : confPct >= 50 ? '#EF9F27' : '#e24b4a';
    const confidenceBox = `
      <div class="cmp-box" style="display:flex;align-items:center;gap:16px;flex-wrap:wrap">
        <div>
          <div style="font-size:11px;color:var(--text3)">Metric Agreement</div>
          <div style="font-size:28px;font-weight:700;color:${confColour}">${confPct}%</div>
        </div>
        <div style="flex:1;font-size:12px;color:var(--text2)">
          ${agreementCount}/${total} metrics within ±1.5 points.
          ${confPct >= 80 ? 'High confidence — both engines strongly agree.' :
            confPct >= 50 ? 'Moderate confidence — some divergence; review flagged metrics.' :
            'Low confidence — significant divergence; manual review recommended.'}
        </div>
      </div>`;

    // ── FIX14: Side-by-side findings columns (AI vs Rule-Based) ──────────
    const rbFindings = rb.findings || [];
    const aiFindings = ai.findings || [];
    const rbCveIds   = new Set((rb.cve_insight || []).map(c => c.cve_id));
    const aiCveIds   = new Set((ai.cve_insight || []).map(c => c.cve_id));

    function _findingHtml(f, side) {
      // Determine if this finding appears in both engines
      const port = f.port || f.service || '';
      const otherFindings = side === 'ai' ? rbFindings : aiFindings;
      const inBoth = otherFindings.some(o => (o.port || o.service || '') === port);
      const cls  = inBoth ? 'both' : (side === 'ai' ? 'ai-only' : 'rb-only');
      const tag  = inBoth
        ? '<span class="cmp-agree-tag">● BOTH</span>'
        : `<span class="cmp-verify-tag">● VERIFY</span>`;
      return `<div class="cmp-finding ${cls}">${tag} Port ${port} / ${f.service || f.exposure || ''}</div>`;
    }

    const rbCol = rbFindings.length
      ? rbFindings.map(f => _findingHtml(f, 'rb')).join('')
      : '<div style="font-size:12px;color:var(--text3);padding:8px">No findings</div>';
    const aiCol = aiFindings.length
      ? aiFindings.map(f => _findingHtml(f, 'ai')).join('')
      : '<div style="font-size:12px;color:var(--text3);padding:8px">No findings</div>';

    const findingsColumns = `
      <div class="cmp-box">
        <h3 style="margin-bottom:10px">📋 Findings — Side by Side</h3>
        <div style="display:flex;gap:8px;font-size:10px;color:var(--text3);margin-bottom:10px;flex-wrap:wrap">
          <span><span class="cmp-agree-tag">■</span> Both detected = high confidence</span>
          <span><span class="cmp-verify-tag">■</span> One engine only = verify manually</span>
        </div>
        <div class="cmp-columns">
          <div>
            <div class="cmp-col-header cmp-col-rules">⚙️ Rule-Based (${rbFindings.length})</div>
            ${rbCol}
          </div>
          <div>
            <div class="cmp-col-header cmp-col-ai">🤖 AI Analysis (${aiFindings.length})</div>
            ${aiCol}
          </div>
        </div>
      </div>`;

    el.innerHTML =
      engineGrid +
      agreementRow +
      findingsColumns +
      `<div class="cmp-box"><h3>📊 Metric Comparison</h3>${metricsHtml}</div>` +
      confidenceBox +
      `<div class="verdict-box" style="margin-top:4px"><strong>Research Verdict:</strong> ${d.verdict || ''}</div>`;
  }

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
    runCompare,
    renderCompare,
    // FIX2: allow external callers (e.g. _compareDrawerSession) to set the AI label
    _setAiLabel: (label) => { _aiProviderLabel = label || 'AI Analysis'; },
  };
})();

