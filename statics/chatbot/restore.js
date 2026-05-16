/**
 * chatbot/restore.js
 * Rich-token serialisation, session restore, panel render (renderAll / rTab).
 */

  // FIX 1: Reference to _deletedSessionIds defined in drawer.js (same IIFE scope).
  // loadDrawer() uses this set to filter out sessions the user has explicitly deleted.
  // Using a getter so we don't shadow drawer.js's Set — both access the same object.


  /* ═══════════════════════════════════════════════════════
     RICH TOKEN BUILDERS — reconstruct widgets from session tokens
     Called by restoreChatMessages() for each __TOKEN__ message.
  ═══════════════════════════════════════════════════════ */

  function _buildScanSummaryEl(data, container) {
    // Temporarily override chat container so _renderScanCompleteCard appends to `container`
    // We do this by creating a fake chat div, rendering into it, then moving children to container
    const fakeChat = document.createElement('div');
    fakeChat.id = '__restore_chat_tmp__';
    fakeChat.style.display = 'none';
    document.body.appendChild(fakeChat);

    const origChat = document.getElementById('chat');
    // Temporarily redirect getElementById('chat') via a wrapper
    const card = document.createElement('div');
    card.className = 'msg msg-ai scan-result-summary-card';

    const risk   = data.risk || {};
    const hosts  = risk.hosts || [];
    const rs     = hosts[0]?.risk_summary || {};
    const counts = rs.counts || {};
    const score  = rs.overall_score ?? '—';
    const level  = rs.overall ?? 'low';
    const CLR_MAP = { critical: '#e24b4a', high: '#ef9f27', medium: '#378add', low: '#1d9e75' };
    const allPorts = [];
    for (const h of hosts) for (const p of h.ports || []) allPorts.push(p);
    const allCves  = [];
    for (const h of hosts) for (const p of h.ports || []) for (const c of p.cves || []) allCves.push(c);

    card.innerHTML = `
      <div class="src-header">
        <div class="src-title-row">
          <span class="src-icon">✅</span>
          <div>
            <div class="src-title">Scan Complete — <code>${data.target || ''}</code></div>
            <div class="src-sub">${data.scan_type || ''} · ${data.duration || ''}s · restored</div>
          </div>
          <span class="rb rb-${level}" style="margin-left:auto;font-size:13px">${level.toUpperCase()} RISK</span>
        </div>
      </div>
      <div class="src-stats">
        <div class="src-stat"><span class="src-stat-num">${allPorts.length}</span><span class="src-stat-lbl">Open Ports</span></div>
        <div class="src-stat"><span class="src-stat-num" style="color:#e24b4a">${counts.critical || 0}</span><span class="src-stat-lbl">Critical</span></div>
        <div class="src-stat"><span class="src-stat-num" style="color:#ef9f27">${counts.high || 0}</span><span class="src-stat-lbl">High</span></div>
        <div class="src-stat"><span class="src-stat-num" style="color:#378add">${counts.medium || 0}</span><span class="src-stat-lbl">Medium</span></div>
        <div class="src-stat"><span class="src-stat-num" style="color:#1d9e75">${counts.low || 0}</span><span class="src-stat-lbl">Low</span></div>
        <div class="src-stat"><span class="src-stat-num">${allCves.length}</span><span class="src-stat-lbl">CVEs</span></div>
        <div class="src-stat"><span class="src-stat-num" style="color:${CLR_MAP[level]}">${score}</span><span class="src-stat-lbl">Risk Score</span></div>
      </div>
      ${data.summary ? `<div class="src-summary">${data.summary}</div>` : ''}
      ${data.recommendation ? `<div class="src-rec">💡 ${data.recommendation}</div>` : ''}
      ${allPorts.length > 0 ? `
      <div class="src-port-table">
        <div class="src-section-title">📋 Open Ports &amp; Risk Assessment</div>
        <table class="vt-table">
          <thead>
            <tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th><th>Severity</th><th>Risk Score</th><th>CVEs</th></tr>
          </thead>
          <tbody>
            ${allPorts.map(p => {
              const pvl = p.risk?.level || 'low';
              const pvs = p.risk?.score || 0;
              const cveCount = (p.cves || []).length;
              return `<tr class="vt-row">
                <td class="vt-mono">${p.port}</td>
                <td>${p.protocol || 'tcp'}</td>
                <td>${p.service || '—'}</td>
                <td><code style="font-size:11px;color:var(--purple)">${(p.product || '') + (p.version ? ' ' + p.version : '')}</code></td>
                <td><span class="rb rb-${pvl}">${pvl}</span></td>
                <td><span style="color:${CLR_MAP[pvl]};font-weight:700">${pvs}/10</span></td>
                <td>${cveCount > 0 ? `<span style="color:#e24b4a;font-weight:700">${cveCount} CVE${cveCount !== 1 ? 's' : ''}</span>` : '<span style="color:var(--text3)">—</span>'}</td>
              </tr>`;
            }).join('')}
          </tbody>
        </table>
      </div>` : ''}
      <div class="src-actions">
        <button class="post-ob-btn" style="font-size:12px;padding:6px 12px" onclick="Chatbot.quickChat('/vuln')">🔎 Full CVE Dashboard</button>
        <button class="post-ob-btn" style="font-size:12px;padding:6px 12px" onclick="Chatbot.quickChat('/patch all')">🔧 Patch Dashboard</button>
        <button class="post-ob-btn" style="font-size:12px;padding:6px 12px" onclick="Chatbot.quickChat('/report html')">📄 Generate Report</button>
      </div>`;

    fakeChat.removeChild && fakeChat.remove();
    container.appendChild(card);
  }

  function _buildVulnTableEl(allCves, container) {
    if (!allCves || !allCves.length) return;
    allCves.sort((a, b) => (b.cvss_score || 0) - (a.cvss_score || 0));
    const tableId = 'vt-restore-' + Date.now() + '-' + Math.random().toString(36).slice(2,6);
    const d = document.createElement('div');
    d.className = 'msg msg-ai vuln-table-wrap';
    d.innerHTML = `
      <div class="vt-header">
        <span class="vt-title">🔍 Vulnerability Intelligence</span>
        <span class="vt-count">${allCves.length} CVE${allCves.length !== 1 ? 's' : ''} detected</span>
        <button class="vd-export-btn" style="margin-left:auto" onclick="Chatbot.quickChat('/vuln')">Open Full Dashboard →</button>
      </div>
      <div class="vt-scroll">
        <table class="vt-table" id="${tableId}">
          <thead>
            <tr>
              <th>Port</th><th>Protocol</th><th>Service</th><th>CVE</th><th>Severity</th>
              <th>CVSS</th><th>Exploit Risk</th><th>Description</th><th>Recommendation</th>
            </tr>
          </thead>
          <tbody>
            ${allCves.map(c => {
              const sev = (c.severity || 'low').toLowerCase();
              const cvss = parseFloat(c.cvss_score || 0);
              const hasExploit = cvss >= 8.5 || sev === 'critical';
              return `<tr class="vt-row" data-port="${c.port}" data-service="${c.service||''}" data-cve_id="${c.cve_id||''}" data-severity="${sev}" data-cvss_score="${cvss}">
                <td class="vt-mono">${c.port}</td>
                <td>${c.protocol || 'tcp'}</td>
                <td>${c.service || '—'}</td>
                <td class="vt-cve-cell">
                  <a class="vt-cve-link" href="https://nvd.nist.gov/vuln/detail/${c.cve_id}" target="_blank" rel="noopener">${c.cve_id}</a>
                  <button class="vt-copy-btn" onclick="navigator.clipboard.writeText('${c.cve_id}');this.textContent='✅';setTimeout(()=>this.textContent='📋',1500)">📋</button>
                </td>
                <td><span class="rb rb-${sev}">${sev}</span></td>
                <td class="vt-cvss vt-cvss-${sev}">${cvss.toFixed(1)}</td>
                <td>${hasExploit ? '<span class="vd-exploit-yes">⚠ Known</span>' : '<span class="vd-exploit-no">— None</span>'}</td>
                <td class="vt-desc">${(c.description || '—').slice(0, 80)}…</td>
                <td><button class="vd-patch-btn" onclick="Chatbot.quickChat('/patch ${c.service} ${c.port}')">🔧 Fix</button></td>
              </tr>`;
            }).join('')}
          </tbody>
        </table>
      </div>`;
    container.appendChild(d);
  }

  function _buildVulnDashEl(allCves, container) {
    if (!allCves || !allCves.length) return;
    allCves.sort((a, b) => (b.cvss_score || 0) - (a.cvss_score || 0));
    const tableId = 'vd-restore-' + Date.now() + '-' + Math.random().toString(36).slice(2,6);
    const services = [...new Set(allCves.map(c => c.service))];
    const sevs = ['critical','high','medium','low'];
    const counts = Object.fromEntries(sevs.map(s => [s, allCves.filter(c => (c.severity||'').toLowerCase() === s).length]));
    const wrap = document.createElement('div');
    wrap.className = 'msg msg-ai vuln-dash-wrap';
    wrap.innerHTML = `
      <div class="vd-header">
        <div class="vd-title-row">
          <span class="vd-title">🔍 Vulnerability Intelligence Dashboard</span>
          <div class="vd-badges">
            ${sevs.map(s => counts[s] ? `<span class="vd-badge vd-badge-${s}" onclick="Chatbot._filterVulnDash('${tableId}','${s}')">${counts[s]} ${s}</span>` : '').join('')}
            <span class="vd-badge vd-badge-all active" id="${tableId}-all" onclick="Chatbot._filterVulnDash('${tableId}','')">All ${allCves.length}</span>
          </div>
        </div>
        <div class="vd-controls">
          <input class="vd-search" id="${tableId}-search" type="text" placeholder="Search CVE, service, description…" oninput="Chatbot._searchVulnDash('${tableId}')"/>
          <select class="vd-select" id="${tableId}-svc" onchange="Chatbot._searchVulnDash('${tableId}')">
            <option value="">All Services</option>
            ${services.map(s => `<option value="${s}">${s}</option>`).join('')}
          </select>
          <select class="vd-select" id="${tableId}-sort" onchange="Chatbot._sortVulnDash('${tableId}')">
            <option value="cvss">Sort: CVSS ↓</option>
            <option value="severity">Sort: Severity</option>
            <option value="port">Sort: Port</option>
            <option value="service">Sort: Service</option>
          </select>
        </div>
      </div>
      <div class="vd-scroll">
        <table class="vd-table" id="${tableId}">
          <thead>
            <tr>
              <th>Port</th><th>Service</th><th>CVE ID</th><th>Severity</th>
              <th>CVSS</th><th>Exploit</th><th>Description</th><th>Action</th>
            </tr>
          </thead>
          <tbody id="${tableId}-body">
            ${allCves.map((c, i) => _vulnRow(c, i, tableId)).join('')}
          </tbody>
        </table>
      </div>
      <div class="vd-footer">
        <span id="${tableId}-count">${allCves.length} vulnerabilities</span>
        <div class="vd-export-row">
          <button class="vd-export-btn" onclick="Chatbot._copyVulnCSV('${tableId}')">📋 Copy CSV</button>
        </div>
      </div>`;
    wrap.dataset.cves = JSON.stringify(allCves);
    container.appendChild(wrap);
  }

  function _buildPatchDashEl(entries, container) {
    if (!entries || !entries.length) return;
    const dashId = 'pd-restore-' + Date.now() + '-' + Math.random().toString(36).slice(2,6);
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    entries.forEach(e => counts[e.risk_level] = (counts[e.risk_level] || 0) + 1);
    const immediate = entries.filter(e => ['critical','high'].includes(e.risk_level)).length;
    const wrap = document.createElement('div');
    wrap.className = 'msg msg-ai patch-dash-wrap';
    wrap.innerHTML = `
      <div class="pd-header">
        <div class="pd-title-row">
          <span class="pd-title">🔧 Vulnerability Remediation Dashboard</span>
          <span class="pd-subtitle">${entries.length} services · ${immediate} need immediate action</span>
        </div>
        <div class="pd-stat-row">
          ${['critical','high','medium','low'].filter(s => counts[s]).map(s =>
            `<div class="pd-stat pd-stat-${s}"><span class="pd-stat-num">${counts[s]}</span><span class="pd-stat-lbl">${s}</span></div>`
          ).join('')}
        </div>
        <div class="pd-controls">
          <input class="pd-search" id="${dashId}-search" type="text" placeholder="Search port, service, CVE…"
                 oninput="Chatbot._searchPatchDash('${dashId}')"/>
          <div class="pd-filter-row">
            ${['all','critical','high','medium','low'].map(s =>
              `<button class="pd-filter-btn ${s==='all'?'active':''}" id="${dashId}-f-${s}"
                       onclick="Chatbot._filterPatchDash('${dashId}','${s==='all'?'':s}')">${s==='all'?'All':s}</button>`
            ).join('')}
          </div>
        </div>
      </div>
      <div class="pd-scroll">
        <table class="pd-table" id="${dashId}-table">
          <thead>
            <tr>
              <th>Port</th><th>Service</th><th>CVE</th><th>Severity</th>
              <th>Risk Score</th><th>Current Version</th><th>Patch Status</th><th>Priority</th><th></th>
            </tr>
          </thead>
          <tbody id="${dashId}-body">
            ${entries.map((e, i) => _patchRow(e, i, dashId)).join('')}
          </tbody>
        </table>
      </div>
      <div class="pd-footer">
        <span id="${dashId}-cnt">${entries.length} services shown</span>
        <button class="vd-export-btn" onclick="Chatbot._copyPatchCSV('${dashId}')">📋 Export CSV</button>
      </div>`;
    container.appendChild(wrap);
  }

  function _buildPatchCardEl(data, container) {
    const { ip, port, data: pd, rawText } = data || {};
    if (!ip || !port) return;
    const d = document.createElement('div');
    d.className = 'msg msg-ai patch-card-wrap';
    if (rawText) {
      d.innerHTML = `
        <div class="patch-header">
          <span class="patch-badge">🔧 Patch Guidance</span>
          <span class="patch-target">${ip}:${port}</span>
        </div>
        <div class="patch-body">${Utils.renderMarkdown(rawText)}</div>`;
    } else if (pd) {
      const sev = pd.severity || 'medium';
      d.innerHTML = `
        <div class="patch-header">
          <span class="patch-badge">🔧 Patch Guidance</span>
          <span class="patch-target">${ip}:${port}</span>
          <span class="rb rb-${sev}">${sev}</span>
        </div>
        <div class="patch-sections">
          ${pd.summary     ? `<div class="patch-section"><div class="ps-title">📋 Summary</div><div class="ps-body">${pd.summary}</div></div>` : ''}
          ${pd.upgrade_cmd ? `<div class="patch-section"><div class="ps-title">⬆️ Upgrade</div><div class="pd-cmd-row"><code class="pd-cmd">${pd.upgrade_cmd}</code><button class="vt-copy-btn" onclick="navigator.clipboard.writeText('${(pd.upgrade_cmd||'').replace(/'/g,"\\'")}');this.textContent='✅';setTimeout(()=>this.textContent='📋',1500)">📋</button></div></div>` : ''}
          ${pd.mitigation  ? `<div class="patch-section"><div class="ps-title">🛡 Mitigation</div><div class="ps-body">${pd.mitigation}</div></div>` : ''}
        </div>`;
    } else {
      return;
    }
    container.appendChild(d);
  }

  function _buildScanProgressEl(data, container) {
    const d = document.createElement('div');
    d.className = 'msg msg-sys scan-progress-record';
    d.innerHTML = `<div style="opacity:0.7;font-size:12px">📡 Scan was running on <code>${data.target || '?'}</code> — <em>${data.scan_type || ''}</em> — session record</div>`;
    container.appendChild(d);
  }

  /** Restore: full scan type selector grid — same cards, fully interactive */
  function _buildScanSelectorEl(data, container) {
    const ip = data.ip || '';
    const d  = document.createElement('div');
    d.className = 'msg msg-ai scan-selector-wrap';

    const RISK_COLORS = { safe: '#22c55e', moderate: '#f59e0b', aggressive: '#ef4444', very_noisy: '#7c3aed' };
    const RISK_LABELS = { safe: '✅ Safe', moderate: '⚠️ Moderate', aggressive: '🔴 Aggressive', very_noisy: '💀 Very Noisy' };
    const CAT_ORDER   = ['port_scanning', 'enumeration', 'vuln_assessment', 'discovery', 'advanced'];
    const CAT_LABELS  = {
      port_scanning:   '🔌 Port Scanning',
      enumeration:     '🔎 Enumeration',
      vuln_assessment: '⚠️ Vulnerability Assessment',
      discovery:       '📡 Discovery',
      advanced:        '🚀 Advanced Pentesting',
    };

    const featured = SCAN_TYPES.filter(s => s.recommended);
    const grouped  = {};
    CAT_ORDER.forEach(c => { grouped[c] = SCAN_TYPES.filter(s => s.category === c && !s.recommended); });

    function renderCard(s) {
      const riskColor = RISK_COLORS[s.risk] || '#888';
      const riskLabel = RISK_LABELS[s.risk] || s.risk;
      return `
        <div class="scan-card" onclick="Chatbot.executeScan('${ip}','${s.key}',this)">
          <div class="sc-top"><span class="sc-icon">${s.icon}</span><span class="sc-duration">${s.duration}</span></div>
          <div class="sc-name">${s.name}</div>
          <div class="sc-desc">${s.desc}</div>
          <div class="sc-footer">
            <span class="sc-risk" style="color:${riskColor}">${riskLabel}</span>
            <span class="sc-cmd">${s.cmd}</span>
          </div>
        </div>`;
    }

    let sectionsHtml = `
      <div class="ss-section" data-cat="all">
        <div class="ss-section-title">⭐ Recommended Scans</div>
        <div class="ss-grid">${featured.map(renderCard).join('')}</div>
      </div>`;
    CAT_ORDER.forEach(cat => {
      const scans = grouped[cat];
      if (!scans || !scans.length) return;
      sectionsHtml += `
        <div class="ss-section" data-cat="${cat}">
          <div class="ss-section-title">${CAT_LABELS[cat]}</div>
          <div class="ss-grid">${scans.map(renderCard).join('')}</div>
        </div>`;
    });

    const uid = 'ss_r_' + Date.now();
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
    container.appendChild(d);
  }

  /** Restore: IP prompt card — fully interactive */
  function _buildIpPromptEl(data, container) {
    const uid = 'ip-restore-' + Date.now();
    const d   = document.createElement('div');
    d.className = 'msg msg-ai';
    d.id = uid;
    d.innerHTML = `
      <div class="ip-prompt-card">
        <div class="ip-prompt-title">🎯 Enter Target IP or Hostname</div>
        <div class="ip-prompt-sub">e.g. 192.168.1.1, 10.0.0.5, scanme.nmap.org</div>
        <div class="ip-prompt-row">
          <input class="ip-prompt-inp" id="${uid}-inp" type="text"
                 placeholder="192.168.1.x or hostname…"
                 onkeydown="if(event.key==='Enter') Chatbot._submitScanIP('${uid}')"/>
          <button class="btn btn-pri" onclick="Chatbot._submitScanIP('${uid}')">Scan →</button>
        </div>
      </div>`;
    container.appendChild(d);
  }

  /** Restore: scan-running widget — shows completed or interrupted scan record */
  function _buildScanRunningEl(data, container) {
    const RISK_COLORS = { safe: '#22c55e', moderate: '#f59e0b', aggressive: '#ef4444', very_noisy: '#7c3aed' };
    const d = document.createElement('div');
    d.className = 'msg msg-sys scan-running-widget scan-running-record';
    d.innerHTML = `
      <div class="srw-header">
        <span class="srw-icon">📡</span>
        <div class="srw-info">
          <div class="srw-title"><strong>${data.name || data.scanType || 'Scan'}</strong> on <code>${data.ip || '?'}</code></div>
          <div class="srw-cmd"><code>${data.cmd || ''}</code></div>
        </div>
        <span class="srw-risk" style="color:${RISK_COLORS[data.risk] || '#888'}">${data.risk || ''}</span>
      </div>
      <div class="srw-bar-wrap">
        <div class="srw-bar-track"><div class="srw-bar-fill srw-bar-done"></div></div>
        <span class="srw-bar-label" style="color:var(--text3);font-size:11px">
          ${data.started_at ? 'Started ' + new Date(data.started_at).toLocaleTimeString() : 'Session record'}
          — <button class="srw-rescan-btn" onclick="Chatbot.quickChat('/scan ${data.ip || ''}')">↻ Re-scan</button>
        </span>
      </div>`;
    container.appendChild(d);
  }

  function renderAll(d) {
    const hosts = d.risk?.hosts || [];
    renderRisk(hosts, d.explanation);
    renderCVE(hosts);
    renderFindings(hosts);
    renderAI(d.ai_analysis);
    if (d.charts) { Dashboard.renderDashboard(d.charts, d.risk); SessionManager.saveCharts(d.charts); }
    Dashboard.flagOsintStale();
    if (Dashboard.getCurrentDashTab() === 'osint') Dashboard.buildOsintTree(d.risk);
    rTab('risk');
  }

  const CLR = { critical: '#e24b4a', high: '#ef9f27', medium: '#378add', low: '#1d9e75' };

  function renderRisk(hosts, exp) {
    const rs = hosts[0]?.risk_summary || {}; const c = rs.counts || {};
    const sumHtml = `<div class="sum-grid">
      <div class="sum-card"><div class="sum-num s-critical">${c.critical||0}</div><div class="sum-lbl">Critical</div></div>
      <div class="sum-card"><div class="sum-num s-high">${c.high||0}</div><div class="sum-lbl">High</div></div>
      <div class="sum-card"><div class="sum-num s-medium">${c.medium||0}</div><div class="sum-lbl">Medium</div></div>
      <div class="sum-card"><div class="sum-num s-low">${c.low||0}</div><div class="sum-lbl">Low</div></div>
    </div><div class="sec-title">Port Details</div>`;
    let cards = '';
    for (const h of hosts) for (const p of h.ports || []) {
      const r = p.risk || {}, lvl = r.level || 'low', sc = r.score || 0;
      cards += `<div class="port-card ${lvl}">
        <div class="ph"><span class="pnum">${p.port}/${p.protocol||'tcp'}</span><span class="psvc">${p.service}</span><span class="rb rb-${lvl}">${lvl}</span></div>
        <div class="pver">${p.product||''} ${p.version||''}</div>
        <div class="rbar"><div class="rbar-fill" style="width:${sc*10}%;background:${CLR[lvl]}"></div></div>
        <div style="display:flex;justify-content:space-between;font-size:11px;color:var(--text3);margin-bottom:4px"><span>Risk score</span><span style="color:${CLR[lvl]};font-weight:700">${sc}/10</span></div>
        <div class="pbody">${(r.reasons||[]).map(x=>'• '+x).join('<br>')}</div>
      </div>`;
    }
    const html = sumHtml + cards;
    document.getElementById('rc-risk').innerHTML = html;
    document.getElementById('risk-empty-m').style.display = 'none';
    document.getElementById('risk-body-m').innerHTML = html;
  }

  function renderCVE(hosts) {
    const all = [];
    for (const h of hosts) for (const p of h.ports||[]) for (const c of p.cves||[]) all.push({...c, port:p.port, service:p.service});
    all.sort((a,b) => b.cvss_score - a.cvss_score);
    const SC = { critical:'cs-critical', high:'cs-high', medium:'cs-medium', low:'cs-low' };
    const html = !all.length
      ? '<div class="empty"><div class="empty-icon">✅</div>No CVEs matched</div>'
      : `<div class="sec-title">${all.length} CVE(s)</div>` + all.map(c => `
          <div class="cve-card"><div class="cve-hdr">
            <span class="cve-id">${c.cve_id}</span>
            <span class="cscore ${SC[c.severity]||'cs-low'}">CVSS ${c.cvss_score}</span>
            <span style="font-size:10px;color:var(--text3);margin-left:auto">${c.service}:${c.port}</span>
          </div>
          <div class="cve-desc">${c.description}</div>
          ${c.patch ? `<div class="cve-patch">🔧 ${c.patch}</div>` : ''}</div>`).join('');
    document.getElementById('rc-cve').innerHTML = html;
    document.getElementById('cve-empty-m').style.display = 'none';
    document.getElementById('cve-body-m').innerHTML = html;
  }

  function renderFindings(hosts) {
    const VS = { latest:'var(--green)', outdated:'var(--orange)', unsupported:'var(--red)', unknown:'var(--text3)' };
    let html = '';
    for (const h of hosts) {
      html += `<div class="sec-title">${h.ip}${h.os ? ' · ' + h.os.name : ''}</div>`;
      for (const p of h.ports||[]) {
        const va = p.version_analysis||{}, r = p.risk||{};
        html += `<div class="port-card ${r.level||'low'}">
          <div class="ph"><span class="pnum">${p.port}/${p.protocol}</span><span class="psvc">${p.service}</span><span class="rb rb-${r.level||'low'}">${r.level||'low'}</span></div>
          <div class="pver" style="color:${VS[va.status]||'var(--text3)'}"> ${p.product||''} ${p.version||''} ${va.status ? '· '+va.status : ''}</div>
          <div class="pbody" style="margin-top:4px">${va.message||''}</div>
          ${(p.cves||[]).length ? `<div style="margin-top:4px">${p.cves.map(c=>`<span class="cve-tag">${c.cve_id}</span>`).join('')}</div>` : ''}
        </div>`;
      }
    }
    document.getElementById('rc-find').innerHTML = html;
  }

  function renderAI(ai) {
    if (!ai) return;
    const icon = ai.engine?.includes('claude') ? '🤖' : '⚙️';
    const lbl  = ai.engine?.includes('ollama') ? 'Ollama AI' : ai.engine?.includes('claude') ? 'Claude AI' : 'Rule-Based';
    const html = `<div class="ai-box"><h4>${icon} ${lbl}</h4>
      <div class="ai-summary">${ai.summary||''}</div>
      ${ai.overall_risk ? `<div style="margin-top:5px;font-size:12px;color:var(--purple)">Risk: <strong>${ai.overall_risk.toUpperCase()}</strong></div>` : ''}
      <div class="ai-engine">${ai.engine}</div></div>`;
    document.getElementById('rc-ai').innerHTML = html;
    document.getElementById('ai-empty-m').style.display = 'none';
    document.getElementById('ai-body-m').innerHTML = html;
  }

  function rTab(name) {
    const names = ['risk','cve','find','ai'];
    document.querySelectorAll('.r-tab').forEach((t,i) => t.classList.toggle('active', names[i] === name));
    document.querySelectorAll('.r-content').forEach(c => c.classList.remove('active'));
    document.getElementById(`rc-${name}`)?.classList.add('active');
  }

  /* ═══════════════════════════════════════════════════════
     DRAWER
  ═══════════════════════════════════════════════════════ */

  function openDrawer()  {
    // Delegate to SidebarManager — it owns all drawer state & persistence.
    // Falls back gracefully if SidebarManager not yet defined (load-order edge case).
    if (typeof SidebarManager !== 'undefined') {
      SidebarManager.open();
    } else {
      const d = document.getElementById('drawer');
      const o = document.getElementById('overlay');
      if (d) d.classList.add('open');
      if (o) o.classList.add('open');
      loadDrawer();
    }
  }
  function closeDrawer() {
    if (typeof SidebarManager !== 'undefined') {
      SidebarManager.close();
    } else {
      const d = document.getElementById('drawer');
      const o = document.getElementById('overlay');
      if (d) d.classList.remove('open');
      if (o) o.classList.remove('open');
    }
  }
  function filterDrawer() {
    const q = document.getElementById('dr-search').value.toLowerCase();
    document.querySelectorAll('#dr-list .sb-item').forEach(el => {
      const text = el.querySelector('.sb-main')?.textContent.toLowerCase() || el.textContent.toLowerCase();
      el.style.display = text.includes(q) ? '' : 'none';
    });
  }

  async function loadDrawer() {
    const el = document.getElementById('dr-list');
    if (!el) return;

    // 1. localStorage sessions — always the most current source of truth
    const memSess = SessionManager.list();
    const memFrontendIds = new Set(memSess.map(s => s.session_id));
    const memScanIds     = new Set(memSess.map(s => s.scan_session).filter(Boolean));

    // 2. Backend project sessions (named chats saved via /api/chat/save)
    let backendProjectSess = [];
    try {
      const pd = await fetch('/api/project-sessions').then(r => r.json());
      // FIX 1: skip deleted sessions; FIX 5: skip sessions with no valid name
      backendProjectSess = (pd.sessions || []).filter(s =>
        !memFrontendIds.has(s.session_id) &&
        !_deletedSessionIds.has(s.session_id) &&
        SessionManager.isValidProjectName(s.project_name)
      );
    } catch (e) {}

    // 3. Backend scan sessions (completed scans not in localStorage)
    let backendScanSess = [];
    try {
      const sd = await ApiService.getHistory();
      // FIX 1: exclude deleted; FIX 2: exclude sessions with no project name (raw IPs)
      backendScanSess = (sd.sessions || []).filter(s => {
        const label = s.label || s.project_name || '';
        return !memScanIds.has(s.session_id) &&
               !memFrontendIds.has(s.session_id) &&
               !_deletedSessionIds.has(s.session_id) &&
               SessionManager.isValidProjectName(label);
      });
    } catch (e) {}

    const activeId = SessionManager.activeId();
    const curSess  = App.getCurrentSession();
    let html = '';

    // Render localStorage sessions — skip sessions with no name and no scan
    for (const s of memSess) {
      const hasScan  = !!s.scan_results;
      const hasName  = SessionManager.isValidProjectName(s.project_name);
      if (!hasName && !hasScan) continue;
      const risk     = hasScan ? (s.scan_results?.risk?.hosts?.[0]?.risk_summary?.overall || 'low') : null;
      const target   = hasScan ? (s.scan_results?.target || '') : '';
      const stype    = hasScan ? (s.scan_results?.scan_type || '') : '';
      const ts       = s.updated_at?.slice(0,16).replace('T',' ') || '';
      const active   = s.session_id === activeId ? 'active' : '';
      html += _drawerItem(s.session_id, target, risk, stype, ts, active, s.project_name || '', hasScan);
    }

    // Render backend project sessions not in localStorage (survived run.sh restart)
    for (const s of backendProjectSess) {
      html += _drawerItem(s.session_id, '', null, '', s.updated_at?.slice(0,16) || '', '', s.project_name || '', false);
    }

    // Render backend scan sessions not in localStorage (named + not deleted only)
    for (const s of backendScanSess) {
      const sessionLabel = s.label || s.project_name || '';
      const active = s.session_id === curSess ? 'active' : '';
      html += _drawerItem(s.session_id, s.target || '', s.overall_risk || 'low', s.scan_type || '', s.timestamp?.slice(0,16) || '', active, sessionLabel, true);
    }

    el.innerHTML = html || '<div style="padding:20px 16px;font-size:12px;color:var(--text3);text-align:center">No sessions yet<br><small>Initialize a project to begin</small></div>';
  }

  function _drawerItem(sid, target, risk, stype, ts, active, projectName, hasScan) {
    // FIX 2: Never show 'Unnamed Session'. Skip entries with no name and no scan.
    const displayTitle = (projectName && projectName.trim()) || (hasScan && target) || null;
    if (!displayTitle && !hasScan) return '';
    const title = displayTitle || target || '—';
    const riskBadge = (hasScan && risk) ? `<span class="rb rb-${risk}">${risk}</span>` : `<span class="rb" style="background:rgba(96,165,250,0.12);color:var(--text3)">new</span>`;
    const meta = hasScan
      ? [stype, target].filter(Boolean).join(' · ')
      : 'No scan yet — click to open';
    const menuId = 'dmenu-' + sid;
    return `
      <div class="sb-item ${active}" id="ditem-${sid}">
        <div class="sb-main" onclick="Chatbot.viewSession('${sid}');Chatbot.closeDrawer()">
          <div class="sb-project-name">${title}${riskBadge}</div>
          <div class="sb-meta">${meta}${ts ? ' · ' + ts.slice(0,16) : ''}</div>
        </div>
        <div class="sb-actions">
          <button class="sb-dot-btn" title="Options"
                  onclick="event.stopPropagation();Chatbot._toggleDrawerMenu('${sid}')">⋯</button>
          <div class="sb-menu" id="${menuId}" style="display:none">
            <div class="sb-menu-item"
                 onclick="Chatbot._renameDrawerSession('${sid}','${title.replace(/'/g, "\\'")}')">
              ✏️ Rename
            </div>
            <div class="sb-menu-item sb-menu-delete"
                 onclick="Chatbot._deleteDrawerSession('${sid}')">
              🗑️ Delete
            </div>
          </div>
        </div>
      </div>`;
  }
