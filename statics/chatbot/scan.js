/**
 * chatbot/scan.js
 * Auto-start vuln scan on IP submit. Live SSE table. No scan-type cards.
 */

  /* ═══════════════════════════════════════════════════════
     AUTO VULN SCAN — fires immediately when user gives an IP
  ═══════════════════════════════════════════════════════ */

  async function _autoStartVulnScan(ip) {
    _currentTarget = ip;
    addMsg(`🎯 Target set: \`${ip}\` — starting **Vulnerability Scan** automatically…`, 'user');
    _renderLiveVulnTable(ip);
    await runScan(ip, 'vuln_scan');
  }

  // Kept for backward compat (chat-triggered scans still use this)
  async function executeScan(ip, scanType, cardEl) {
    _currentTarget = ip;
    addMsg(`Running **${scanType}** on \`${ip}\`…`, 'user');
    _renderLiveVulnTable(ip);
    await runScan(ip, scanType);
  }

  /* ═══════════════════════════════════════════════════════
     LIVE VULN TABLE — appears instantly, rows animate in
  ═══════════════════════════════════════════════════════ */

  let _liveTableId  = null;
  let _liveCounters = { total: 0, confirmed: 0, not_vuln: 0, unconfirmed: 0 };
  let _liveTableEl  = null;

  function _renderLiveVulnTable(ip) {
    const chat = document.getElementById('chat');
    const wrap = document.createElement('div');
    _liveTableId = 'live-vuln-' + Date.now();
    wrap.id        = _liveTableId;
    wrap.className = 'msg msg-ai live-vuln-wrap';

    wrap.innerHTML = `
      <div class="lv-header">
        <div class="lv-title-row">
          <span class="lv-scan-badge scanning" id="${_liveTableId}-badge">
            <span class="lv-badge-dot"></span>⚡ SCANNING
          </span>
          <span class="lv-target"><code>${ip}</code></span>
          <span class="lv-scan-label">nmap -sV --script vuln</span>
        </div>
        <div class="lv-counters" id="${_liveTableId}-counters">
          <span class="lv-ctr lv-ctr-total"   id="${_liveTableId}-c-total">0 ports</span>
          <span class="lv-ctr lv-ctr-confirm"  id="${_liveTableId}-c-confirm">0 ✅ CONFIRMED</span>
          <span class="lv-ctr lv-ctr-notvuln"  id="${_liveTableId}-c-notvuln">0 🟢 NOT VULNERABLE</span>
          <span class="lv-ctr lv-ctr-unconf"   id="${_liveTableId}-c-unconf">0 ⚠️ UNCONFIRMED</span>
        </div>
      </div>
      <div class="lv-table-wrap">
        <table class="lv-table">
          <thead>
            <tr>
              <th>Port</th>
              <th>Protocol</th>
              <th>Service</th>
              <th>Version</th>
              <th>Vuln Status</th>
              <th>Script Used</th>
              <th>Evidence</th>
            </tr>
          </thead>
          <tbody id="${_liveTableId}-body">
            <tr class="lv-placeholder" id="${_liveTableId}-placeholder">
              <td colspan="7" class="lv-waiting">
                <span class="lv-pulse"></span>
                Waiting for nmap to discover ports…
              </td>
            </tr>
          </tbody>
        </table>
      </div>`;

    wrap.style.opacity = '0';
    wrap.style.transform = 'translateY(8px)';
    chat.appendChild(wrap);
    _liveTableEl = wrap;
    requestAnimationFrame(() => {
      wrap.style.transition = 'opacity .3s ease, transform .3s ease';
      wrap.style.opacity    = '1';
      wrap.style.transform  = 'translateY(0)';
    });
    chat.scrollTo({ top: chat.scrollHeight, behavior: 'smooth' });

    // Reset counters
    _liveCounters = { total: 0, confirmed: 0, not_vuln: 0, unconfirmed: 0 };
    _saveRichMsg('LIVE_VULN_TABLE_START', { ip, tableId: _liveTableId });
  }

  function _onPortFound(portData) {
    if (!_liveTableId) return;
    const tbody = document.getElementById(_liveTableId + '-body');
    if (!tbody) return;

    // Remove placeholder on first real port
    const ph = document.getElementById(_liveTableId + '-placeholder');
    if (ph) ph.remove();

    const vs     = portData.vuln_status || {};
    const status = vs.status || 'UNCONFIRMED';
    const script = vs.script_used || '—';
    const evid   = (vs.evidence || '').slice(0, 80) || '—';
    const ver    = [portData.product, portData.version].filter(Boolean).join(' ') || '—';

    const statusInfo = _vulnStatusBadge(status);

    _liveCounters.total++;
    if (status === 'CONFIRMED')      _liveCounters.confirmed++;
    else if (status === 'NOT_VULNERABLE') _liveCounters.not_vuln++;
    else                             _liveCounters.unconfirmed++;

    _updateLiveCounters();

    const rowId = _liveTableId + '-row-' + portData.port;
    const tr = document.createElement('tr');
    tr.id        = rowId;
    tr.className = 'lv-row lv-row-' + status.toLowerCase().replace('_', '-');
    tr.innerHTML = `
      <td class="lv-mono">${portData.port}</td>
      <td>${portData.protocol || 'tcp'}</td>
      <td><span class="lv-svc">${portData.service || '—'}</span></td>
      <td class="lv-ver">${ver}</td>
      <td class="lv-status-cell">${statusInfo.badge}</td>
      <td class="lv-script">${script !== '—' ? `<code>${script}</code>` : '—'}</td>
      <td class="lv-evid" title="${evid}">${evid}</td>`;

    tr.style.opacity   = '0';
    tr.style.transform = 'translateX(-8px)';
    tbody.appendChild(tr);

    requestAnimationFrame(() => {
      tr.style.transition = 'opacity .25s ease, transform .25s ease';
      tr.style.opacity    = '1';
      tr.style.transform  = 'translateX(0)';
    });

    const chat = document.getElementById('chat');
    if (chat && !_userScrolledUp) {
      chat.scrollTo({ top: chat.scrollHeight, behavior: 'smooth' });
    }
  }

  function _vulnStatusBadge(status) {
    switch (status) {
      case 'CONFIRMED':
        return { badge: '<span class="lv-badge lv-confirmed">✅ CONFIRMED VULNERABLE</span>' };
      case 'NOT_VULNERABLE':
        return { badge: '<span class="lv-badge lv-not-vuln">🟢 NOT VULNERABLE</span>' };
      default:
        return { badge: '<span class="lv-badge lv-unconfirmed">⚠️ UNCONFIRMED</span>' };
    }
  }

  function _updateLiveCounters() {
    const bump = (id, val, suffix) => {
      const el = document.getElementById(id);
      if (!el) return;
      el.textContent = val + suffix;
      el.classList.remove('lv-bump');
      void el.offsetWidth; // reflow to restart animation
      el.classList.add('lv-bump');
    };
    bump(_liveTableId + '-c-total',   _liveCounters.total,      ' ports');
    bump(_liveTableId + '-c-confirm', _liveCounters.confirmed,  ' ✅ CONFIRMED');
    bump(_liveTableId + '-c-notvuln', _liveCounters.not_vuln,   ' 🟢 NOT VULNERABLE');
    bump(_liveTableId + '-c-unconf',  _liveCounters.unconfirmed,' ⚠️ UNCONFIRMED');
  }

  function _completeLiveTable() {
    if (!_liveTableId) return;
    const badge = document.getElementById(_liveTableId + '-badge');
    if (badge) {
      badge.className = 'lv-scan-badge complete';
      badge.innerHTML = '✔ COMPLETE';
    }
  }

  /* ═══════════════════════════════════════════════════════
     SCAN PROGRESS POLLING / SSE
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

        // Route by event type
        if (d.type === 'port_found') {
          _onPortFound(d.port);
          return;
        }

        // Progress event
        _updateProgressUI(d);
        if (!d.running && d.status !== 'running') {
          es.close();
          _progressTimer = null;
          if (d.status === 'stopped') Utils.setStatus('stopped');
          _completeLiveTable();
        }
      } catch (e) {}
    };
    es.onerror = () => {
      es.close();
      _progressTimer = null;
      _completeLiveTable();
    };
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
    _saveRichMsg('SCAN_PROGRESS', { target, scan_type, started_at: new Date().toISOString() });
    try {
      const d = await ApiService.startScan(target, scan_type, SessionManager.getProjectName());
      const fill  = document.getElementById('prog-fill');
      const pctEl = document.getElementById('prog-pct');
      const lbl   = document.getElementById('prog-lbl');
      if (fill)  fill.style.width  = '100%';
      if (pctEl) pctEl.textContent = '100%';
      if (lbl)   lbl.textContent   = 'Scan Complete ✓';
      _completeLiveTable();
      SessionManager.saveScan(d);
      App.setLastData(d);
      App.setCurrentSession(d.session_id);
      try { localStorage.setItem('ThreatWeave_last_session', JSON.stringify({ sessionId: d.session_id, data: d })); } catch (e) {}
      Utils.setStatus('processing');

      // Cumulative merge
      const cumulative = SessionManager.getCumulativeState();
      const dMerged = Object.assign({}, d);
      if (cumulative && cumulative.ports.length > 0) {
        dMerged.risk = d.risk ? JSON.parse(JSON.stringify(d.risk)) : { hosts: [] };
        if (!dMerged.risk.hosts || dMerged.risk.hosts.length === 0) {
          dMerged.risk.hosts = [{ ip: d.target, ports: [], risk_summary: {}, os: null }];
        }
        dMerged.risk.hosts[0].ports = cumulative.ports;
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
        if (cumulative.os_fingerprints.length > 0) {
          const latestOs = cumulative.os_fingerprints[cumulative.os_fingerprints.length - 1];
          dMerged.risk.hosts[0].os = { name: latestOs.os_name, version: latestOs.os_version };
        }
      }

      renderAll(dMerged);
      loadDrawer();
      if (progressMsg) progressMsg.remove();

      // Append scan complete card
      const _scanRichData = {
        target, scan_type: d.scan_type, duration: d.duration,
        summary: d.explanation?.summary || '', recommendation: d.recommendation?.reason || '',
        risk: d.risk, ai_analysis: d.ai_analysis, explanation: d.explanation,
      };
      _renderScanCompleteCard(_scanRichData);
      _saveRichMsg('SCAN_COMPLETE', _scanRichData);

      // Append CVE table only when new CVEs found
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

      setTimeout(() => {
        if (prog) prog.classList.remove('on');
        if (fill) fill.style.width = '0%';
      }, 2000);
    } catch (e) {
      if (progressMsg) progressMsg.remove();
      _completeLiveTable();
      if (!e.message?.includes('stopped')) {
        addMsg(`Scan error: ${e.message}`, 'ai');
        Utils.setStatus('error', 'Scan failed');
        if (prog) prog.classList.remove('on');
      }
    } finally {
      _stopProgressPolling();
      _setScanUIRunning(false);
      SessionManager.clearScanState();
    }
  }

  async function confirmStop() { Utils.openModal('stop-modal'); }

  async function doStop() {
    Utils.closeModal('stop-modal');
    await ApiService.stopScan();
    _stopProgressPolling();
    _setScanUIRunning(false);
    _completeLiveTable();
    const prog = document.getElementById('prog');
    if (prog) prog.classList.remove('on');
    Utils.setStatus('stopped', 'Scan stopped by user');
    addMsg('⏹ Scan stopped by user.', 'sys');
    Utils.showToast('stop-toast');
  }

  function startNewScan() { Utils.hideToast('stop-toast'); newChat(); }

  function newChat() {
    Router.showPage('scan');
    const chat = document.getElementById('chat');
    if (chat && SessionManager.activeId()) {
      SessionManager.saveScrollPos(SessionManager.activeId(), chat.scrollTop);
    }
    SessionManager.persistAll();
    SessionManager.create();
    App.setLastData(null);
    App.setCurrentSession(null);
    _currentTarget = '';
    _liveTableId   = null;
    _liveTableEl   = null;
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
    showGreeting();
    chat.scrollTop = 0;
    const inp = document.getElementById('chat-inp');
    if (inp) inp.focus();
  }

  // Category filter helpers (kept for any remaining UI that uses them)
  function _filterScans(uid, query) {
    const q = query.toLowerCase();
    document.querySelectorAll(`#${uid}_body .scan-card`).forEach(c => {
      const text = c.textContent.toLowerCase();
      c.style.display = !q || text.includes(q) ? '' : 'none';
    });
  }

  function _filterScanCat(uid, cat, btn) {
    document.querySelectorAll(`#${uid}_tabs .ss-cat-tab`).forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');
    document.querySelectorAll(`#${uid}_body .ss-section`).forEach(sec => {
      sec.style.display = cat === 'all' || sec.dataset.cat === cat ? '' : 'none';
    });
  }
