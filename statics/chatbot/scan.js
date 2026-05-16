/**
 * chatbot/scan.js
 * Scan-type selector, scan execution, real-time progress bar, stop.
 */

  /* ═══════════════════════════════════════════════════════
     SCAN TYPE SELECTOR
  ═══════════════════════════════════════════════════════ */

  function _showScanTypeSelector(ip) {
    _currentTarget = ip;
    const chat = document.getElementById('chat');
    const d    = document.createElement('div');
    d.className = 'msg msg-ai scan-selector-wrap';
    d.id = 'scan-selector-' + Date.now();

    const RISK_COLORS = { safe: '#22c55e', moderate: '#f59e0b', aggressive: '#ef4444', very_noisy: '#7c3aed' };
    const RISK_LABELS = { safe: '✅ Safe', moderate: '⚠️ Moderate', aggressive: '🔴 Aggressive', very_noisy: '💀 Very Noisy' };

    const CAT_ORDER = ['port_scanning', 'enumeration', 'vuln_assessment', 'discovery', 'advanced'];
    const CAT_LABELS = {
      port_scanning:   '🔌 Port Scanning',
      enumeration:     '🔎 Enumeration',
      vuln_assessment: '⚠️ Vulnerability Assessment',
      discovery:       '📡 Discovery',
      advanced:        '🚀 Advanced Pentesting',
    };

    // Homepage featured scans at top
    const featured = SCAN_TYPES.filter(s => s.recommended);
    const grouped  = {};
    CAT_ORDER.forEach(c => { grouped[c] = SCAN_TYPES.filter(s => s.category === c && !s.recommended); });

    function renderCard(s) {
      const riskColor = RISK_COLORS[s.risk] || '#888';
      const riskLabel = RISK_LABELS[s.risk] || s.risk;
      return `
        <div class="scan-card" onclick="Chatbot.executeScan('${ip}','${s.key}',this)">
          <div class="sc-top">
            <span class="sc-icon">${s.icon}</span>
            <span class="sc-duration">${s.duration}</span>
          </div>
          <div class="sc-name">${s.name}</div>
          <div class="sc-desc">${s.desc}</div>
          <div class="sc-footer">
            <span class="sc-risk" style="color:${riskColor}">${riskLabel}</span>
            <span class="sc-cmd">${s.cmd}</span>
          </div>
        </div>`;
    }

    let sectionsHtml = '';
    // Featured section
    sectionsHtml += `
      <div class="ss-section" data-cat="all">
        <div class="ss-section-title">⭐ Recommended Scans</div>
        <div class="ss-grid">${featured.map(renderCard).join('')}</div>
      </div>`;

    // Grouped sections
    CAT_ORDER.forEach(cat => {
      const scans = grouped[cat];
      if (!scans || !scans.length) return;
      sectionsHtml += `
        <div class="ss-section" data-cat="${cat}">
          <div class="ss-section-title">${CAT_LABELS[cat]}</div>
          <div class="ss-grid">${scans.map(renderCard).join('')}</div>
        </div>`;
    });

    // Fix #11: scan search + category filter
    const uid = 'ss_' + Date.now();
    d.innerHTML = `
      <div class="ss-header">
        <span class="ss-target-badge">🎯 ${ip}</span>
        <div class="ss-title">Select a Scan Mode</div>
        <div class="ss-subtitle">Click a card to execute immediately · ${SCAN_TYPES.length} scan profiles available</div>
        <div class="ss-search-row">
          <input id="${uid}_search" class="ss-search" type="text" placeholder="🔍 Search scans..." oninput="Chatbot._filterScans('${uid}', this.value)" autocomplete="off" />
          <div class="ss-cat-tabs" id="${uid}_tabs">
            <button class="ss-cat-tab active" onclick="Chatbot._filterScanCat('${uid}','all',this)">All</button>
            <button class="ss-cat-tab" onclick="Chatbot._filterScanCat('${uid}','port_scanning',this)">Port</button>
            <button class="ss-cat-tab" onclick="Chatbot._filterScanCat('${uid}','enumeration',this)">Enum</button>
            <button class="ss-cat-tab" onclick="Chatbot._filterScanCat('${uid}','discovery',this)">Discovery</button>
            <button class="ss-cat-tab" onclick="Chatbot._filterScanCat('${uid}','vuln_assessment',this)">Vuln</button>
            <button class="ss-cat-tab" onclick="Chatbot._filterScanCat('${uid}','advanced',this)">Advanced</button>
          </div>
        </div>
      </div>
      <div id="${uid}_body">${sectionsHtml}</div>`;

    d.style.opacity = '0'; d.style.transform = 'translateY(8px)';
    chat.appendChild(d);
    requestAnimationFrame(() => {
      d.style.transition = 'opacity .25s ease, transform .25s ease';
      d.style.opacity = '1'; d.style.transform = 'translateY(0)';
    });
    chat.scrollTo({ top: chat.scrollHeight, behavior: 'smooth' });
    // Persist so selector survives refresh
    _saveRichMsg('SCAN_SELECTOR', { ip });
  }

  async function executeScan(ip, scanType, cardEl) {
    if (cardEl) {
      const grid = cardEl.closest('.ss-grid');
      grid && grid.querySelectorAll('.scan-card').forEach(c => c.classList.remove('selected'));
      cardEl.classList.add('selected');
    }
    _currentTarget = ip;
    const typeMeta = SCAN_TYPES.find(s => s.key === scanType);
    addMsg(`Running **${typeMeta?.name || scanType}** on \`${ip}\`…`, 'user');
    // Render persistent running-scan widget in chat
    _renderScanRunningWidget(ip, scanType, typeMeta);
    await runScan(ip, scanType);
  }

  function _renderScanRunningWidget(ip, scanType, typeMeta) {
    const chat = document.getElementById('chat');
    const d = document.createElement('div');
    d.className = 'msg msg-sys scan-running-widget';
    d.id = 'scan-running-widget-' + Date.now();
    const name = typeMeta?.name || scanType;
    const cmd  = typeMeta?.cmd  || '';
    const risk = typeMeta?.risk || 'moderate';
    const RISK_COLORS = { safe: '#22c55e', moderate: '#f59e0b', aggressive: '#ef4444', very_noisy: '#7c3aed' };
    d.innerHTML = `
      <div class="srw-header">
        <span class="srw-icon">📡</span>
        <div class="srw-info">
          <div class="srw-title"><strong>${name}</strong> on <code>${ip}</code></div>
          <div class="srw-cmd"><code>${cmd}</code></div>
        </div>
        <span class="srw-risk" style="color:${RISK_COLORS[risk] || '#888'}">${risk}</span>
      </div>
      <div class="srw-bar-wrap">
        <div class="srw-bar-track"><div class="srw-bar-fill" id="srw-fill-${d.id}"></div></div>
        <span class="srw-bar-label" id="srw-lbl-${d.id}">Initializing…</span>
      </div>`;
    d.style.opacity = '0'; d.style.transform = 'translateY(6px)';
    chat.appendChild(d);
    requestAnimationFrame(() => {
      d.style.transition = 'opacity .25s ease, transform .25s ease';
      d.style.opacity = '1'; d.style.transform = 'translateY(0)';
    });
    chat.scrollTo({ top: chat.scrollHeight, behavior: 'smooth' });
    // Persist as rich token so it's visible on restore
    _saveRichMsg('SCAN_RUNNING', { ip, scanType, name, cmd, risk, started_at: new Date().toISOString() });
  }

  /* ═══════════════════════════════════════════════════════
     SCAN
  ═══════════════════════════════════════════════════════ */

  function _startProgressPolling() {
    if (typeof EventSource === 'undefined') {
      _progressTimer = setInterval(async () => {
        try { const d = await ApiService.getScanProgress(); _updateProgressUI(d); } catch (e) {}
      }, 1000);
      return;
    }
    const es = new EventSource('/api/scan/stream');
    _progressTimer = es;
    es.onmessage = (event) => {
      try {
        const d = JSON.parse(event.data);
        _updateProgressUI(d);
        if (!d.running && d.status !== 'running') { es.close(); _progressTimer = null; if (d.status === 'stopped') Utils.setStatus('stopped'); }
      } catch (e) {}
    };
    es.onerror = () => { es.close(); _progressTimer = null; };
  }

  function _updateProgressUI(d) {
    const pct = Math.min(d.progress || 0, 99);
    const fill = document.getElementById('prog-fill');
    const pctEl = document.getElementById('prog-pct');
    const lbl   = document.getElementById('prog-lbl');
    if (fill)  fill.style.width  = pct + '%';
    if (pctEl) pctEl.textContent = pct + '%';
    if (lbl)   lbl.textContent   = d.status === 'stopped' ? 'Stopped' : `Scanning… ${pct}%`;
  }

  function _stopProgressPolling() {
    if (_progressTimer) {
      if (typeof _progressTimer.close === 'function') _progressTimer.close();
      else clearInterval(_progressTimer);
      _progressTimer = null;
    }
  }

  function _setScanUIRunning(running) {
    const navStop = document.getElementById('nav-stop-btn');
    if (navStop) navStop.style.display = running ? 'flex' : 'none';
    if (!running) {
      const fill  = document.getElementById('prog-fill');
      const pctEl = document.getElementById('prog-pct');
      if (fill)  fill.style.width  = '0%';
      if (pctEl) pctEl.textContent = '0%';
    }
  }

  async function runScan(target, scan_type) {
    if (!target) { addMsg('Please provide a target IP or hostname.', 'ai'); return; }
    _setScanUIRunning(true);
    // FIX 6+7: Mark scan as running immediately so crash recovery knows
    SessionManager.markScanRunning(target, scan_type);
    const prog = document.getElementById('prog');
    if (prog) {
      prog.classList.add('on');
      const fill  = document.getElementById('prog-fill');
      const pctEl = document.getElementById('prog-pct');
      if (fill)  fill.style.width  = '0%';
      if (pctEl) pctEl.textContent = '0%';
    }
    Utils.setStatus('scanning', target);
    _startProgressPolling();
    const progressMsg = addMsg(`⏳ Scanning \`${target}\` — **${scan_type}**…`, 'sys');
    // Save scan-started token so even interrupted scans appear in history
    _saveRichMsg('SCAN_PROGRESS', { target, scan_type, started_at: new Date().toISOString() });
    try {
      const d = await ApiService.startScan(target, scan_type, SessionManager.getProjectName());
      const fill  = document.getElementById('prog-fill');
      const pctEl = document.getElementById('prog-pct');
      const lbl   = document.getElementById('prog-lbl');
      if (fill)  fill.style.width  = '100%';
      if (pctEl) pctEl.textContent = '100%';
      if (lbl)   lbl.textContent   = 'Scan Complete ✓';
      SessionManager.saveScan(d);
      App.setLastData(d);
      App.setCurrentSession(d.session_id);
      try { localStorage.setItem('scanwise_last_session', JSON.stringify({ sessionId: d.session_id, data: d })); } catch (e) {}
      Utils.setStatus('processing');

      // FIX2+6: Build a cumulative-merged view of ALL scans in this session for
      // renderAll() so dashboard panels show ALL findings, not just the latest scan.
      const cumulative = SessionManager.getCumulativeState();
      const dMerged = Object.assign({}, d);
      if (cumulative && cumulative.ports.length > 0) {
        dMerged.risk = d.risk ? JSON.parse(JSON.stringify(d.risk)) : { hosts: [] };
        if (!dMerged.risk.hosts || dMerged.risk.hosts.length === 0) {
          dMerged.risk.hosts = [{ ip: d.target, ports: [], risk_summary: {}, os: null }];
        }
        // Replace ports with cumulative merged list
        dMerged.risk.hosts[0].ports = cumulative.ports;
        // Recalculate severity counts from cumulative CVEs
        const allSev = { critical:0, high:0, medium:0, low:0 };
        for (const p of cumulative.ports) {
          for (const c of (p.cves || [])) {
            const sev = (c.severity || 'low').toLowerCase();
            if (sev in allSev) allSev[sev]++;
          }
        }
        dMerged.risk.hosts[0].risk_summary = Object.assign(
          {}, dMerged.risk.hosts[0].risk_summary || {},
          { counts: allSev, total_ports: cumulative.ports.length }
        );
        // Inject OS if discovered in any scan
        if (cumulative.os_fingerprints.length > 0) {
          const latestOs = cumulative.os_fingerprints[cumulative.os_fingerprints.length - 1];
          dMerged.risk.hosts[0].os = { name: latestOs.os_name, version: latestOs.os_version };
        }
      }

      renderAll(dMerged);
      loadDrawer();
      if (progressMsg) progressMsg.remove();

      // ── APPEND SCAN RESULTS TO CHAT (FIX1: never clear, always append) ──
      // The scan summary card is APPENDED to existing chat — previous scans remain visible.
      const _scanRichData = {
        target, scan_type: d.scan_type, duration: d.duration,
        summary: d.explanation?.summary || '', recommendation: d.recommendation?.reason || '',
        risk: d.risk, ai_analysis: d.ai_analysis, explanation: d.explanation,
      };
      _renderScanCompleteCard(_scanRichData);
      _saveRichMsg('SCAN_COMPLETE', _scanRichData);

      // ── APPEND CVE TABLE FOR THIS SCAN (FIX4: only NEW CVEs, never replace) ──
      // Only show a new CVE block if this scan actually found new vulnerabilities.
      // If it found none (e.g. OS discovery), show a status message that references
      // prior CVEs so the user knows their earlier results are still intact.
      const hosts   = d.risk?.hosts || [];
      const newCves = [];
      for (const h of hosts) for (const p of h.ports || []) for (const c of p.cves || [])
        newCves.push({ ...c, port: p.port, service: p.service });
      if (newCves.length > 0) {
        _renderVulnTableInChat(hosts);
        _saveRichMsg('VULN_TABLE', newCves);
      } else {
        const prevCveCount = (cumulative?.cves || []).length;
        const noNewMsg = prevCveCount > 0
          ? `✅ **${d.scan_type || 'Scan'} complete** on \`${target}\` — ${d.duration}s. No new CVEs found. (${prevCveCount} CVE(s) from earlier scans still tracked above.)`
          : `✅ **Scan complete** on \`${target}\` — ${d.duration}s. No CVEs detected.\n\n${d.explanation?.summary || ''}`;
        addMsg(noNewMsg, 'ai');
      }

      // FIX5: Cumulative summary badge after multiple scans
      if (cumulative && cumulative.scan_history.length > 1) {
        const totalPortsCum = cumulative.ports.length;
        const totalCvesCum  = cumulative.cves.length;
        const scanCount     = cumulative.scan_history.length;
        addMsg(
          `📊 **Cumulative session summary** after ${scanCount} scans: ` +
          `**${totalPortsCum}** unique open ports · **${totalCvesCum}** unique CVEs` +
          (cumulative.os_fingerprints.length > 0
            ? ` · OS: **${cumulative.os_fingerprints.map(o => o.os_name).join(', ')}**`
            : ''),
          'sys'
        );
      }

      setTimeout(() => { if (prog) prog.classList.remove('on'); if (fill) fill.style.width = '0%'; }, 2000);
    } catch (e) {
      if (progressMsg) progressMsg.remove();
      if (!e.message?.includes('stopped')) {
        addMsg(`Scan error: ${e.message}`, 'ai');
        Utils.setStatus('error', 'Scan failed');
        if (prog) prog.classList.remove('on');
      }
    } finally {
      _stopProgressPolling();
      _setScanUIRunning(false);
      SessionManager.clearScanState(); // FIX 7: clear interrupted scan flag
    }
  }

  async function confirmStop() { Utils.openModal('stop-modal'); }

  async function doStop() {
    Utils.closeModal('stop-modal');
    await ApiService.stopScan();
    _stopProgressPolling();
    _setScanUIRunning(false);
    const prog = document.getElementById('prog');
    if (prog) prog.classList.remove('on');
    Utils.setStatus('stopped', 'Scan stopped by user');
    addMsg('⏹ Scan stopped by user.', 'sys');
    Utils.showToast('stop-toast');
  }

  function startNewScan() { Utils.hideToast('stop-toast'); newChat(); }

  /* FIX 5: newChat — save scroll position before switching */
  function newChat() {
    Router.showPage('scan');
    // FIX 5+6: persist scroll + all session data before switching
    const chat = document.getElementById('chat');
    if (chat && SessionManager.activeId()) {
      SessionManager.saveScrollPos(SessionManager.activeId(), chat.scrollTop);
    }
    SessionManager.persistAll();
    SessionManager.create();           // fresh session — no project name yet
    App.setLastData(null);
    App.setCurrentSession(null);
    _currentTarget = '';
    Dashboard.resetOsint();
    ['rc-risk','rc-cve','rc-find','rc-ai'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.innerHTML = '<div class="empty"><div class="empty-icon">🛡</div>Run a scan</div>';
    });
    ['d-crit','d-high','d-med','d-low'].forEach(id => { const el = document.getElementById(id); if (el) el.textContent = '—'; });
    const gn = document.getElementById('gauge-num'); const gl = document.getElementById('gauge-lbl');
    if (gn) { gn.textContent = '—'; gn.style.color = 'var(--text3)'; }
    if (gl) gl.textContent = 'Overall Risk';
    const de = document.getElementById('dash-empty');
    if (de) de.style.display = 'block';
    Dashboard.destroyCharts();
    chat.innerHTML = '';
    showGreeting();                    // triggers project onboarding
    chat.scrollTop = 0;
    const inp = document.getElementById('chat-inp');
    if (inp) inp.focus();
  }

