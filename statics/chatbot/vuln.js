/**
 * chatbot/vuln.js
 * /vuln CVE intelligence dashboard, scan-complete card, inline vuln table.
 */

  /* ═══════════════════════════════════════════════════════
     /vuln — FULL CVE INTELLIGENCE DASHBOARD
  ═══════════════════════════════════════════════════════ */

  async function _handleVulnCommand() {
    const data  = App.getLastData();
    const hosts = data?.risk?.hosts || [];
    const allCves = [];
    for (const h of hosts) {
      for (const p of h.ports || []) {
        for (const c of p.cves || []) {
          allCves.push({ ...c, port: p.port, service: p.service || '—', host: h.ip || '' });
        }
      }
    }

    if (!allCves.length) {
      addMsg('No CVE data found. Run a scan first (preferably **version_deep** for best CVE matching), then try `/vuln` again.', 'ai');
      return;
    }

    allCves.sort((a, b) => (b.cvss_score || 0) - (a.cvss_score || 0));
    _renderVulnDashboard(allCves);
  }

  function _renderVulnDashboard(allCves) {
    const tableId  = 'vuln-dash-' + Date.now();
    const services = [...new Set(allCves.map(c => c.service))];
    const sevs     = ['critical','high','medium','low'];
    const counts   = Object.fromEntries(sevs.map(s => [s, allCves.filter(c => (c.severity||'').toLowerCase() === s).length]));

    const chat = document.getElementById('chat');
    const wrap = document.createElement('div');
    wrap.className = 'msg msg-ai vuln-dash-wrap';

    wrap.innerHTML = `
      <div class="vd-header">
        <div class="vd-title-row">
          <span class="vd-title">🔍 Vulnerability Intelligence</span>
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
      </div>
    `;

    // Store data on element for filtering
    wrap.dataset.cves = JSON.stringify(allCves);

    wrap.style.opacity = '0'; wrap.style.transform = 'translateY(8px)';
    chat.appendChild(wrap);
    requestAnimationFrame(() => {
      wrap.style.transition = 'opacity .3s ease, transform .3s ease';
      wrap.style.opacity = '1'; wrap.style.transform = 'translateY(0)';
    });
    chat.scrollTo({ top: chat.scrollHeight, behavior: 'smooth' });
    // Persist as rich token for session restore
    _saveRichMsg('VULN_DASH', allCves);
  }

  function _vulnRow(c, i, tableId) {
    const sev       = (c.severity || 'low').toLowerCase();
    const cvss      = parseFloat(c.cvss_score || 0);
    const hasExploit = cvss >= 8.5 || sev === 'critical';
    const exploitBadge = hasExploit
      ? '<span class="vd-exploit-yes">⚠ Known</span>'
      : '<span class="vd-exploit-no">— None</span>';
    const pct = Math.min(cvss * 10, 100);
    const expandId = `${tableId}-exp-${i}`;

    return `
      <tr class="vd-row" data-sev="${sev}" data-svc="${c.service}" data-text="${(c.cve_id+' '+c.service+' '+(c.description||'')).toLowerCase()}"
          onclick="Chatbot._toggleVulnExpand('${expandId}', this)">
        <td class="vd-mono">${c.port}</td>
        <td><span class="vd-svc-tag">${c.service}</span></td>
        <td class="vd-cve-cell">
          <a class="vd-cve-link" href="https://nvd.nist.gov/vuln/detail/${c.cve_id}" target="_blank" rel="noopener" onclick="event.stopPropagation()">${c.cve_id}</a>
          <button class="vd-copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText('${c.cve_id}');this.textContent='✅';setTimeout(()=>this.textContent='📋',1500)" title="Copy">📋</button>
        </td>
        <td><span class="rb rb-${sev}">${sev}</span></td>
        <td>
          <div class="vd-cvss-wrap">
            <span class="vd-cvss-num vd-cvss-${sev}">${cvss.toFixed(1)}</span>
            <div class="vd-cvss-bar"><div class="vd-cvss-fill vd-cvss-fill-${sev}" style="width:${pct}%"></div></div>
          </div>
        </td>
        <td>${exploitBadge}</td>
        <td class="vd-desc">${(c.description || '—').slice(0, 90)}${(c.description||'').length > 90 ? '…' : ''}</td>
        <td>
          <button class="vd-patch-btn" onclick="event.stopPropagation();Chatbot.quickChat('/patch ${c.service || 'service'} ${c.port}')" title="Get patch guidance">🔧 Fix</button>
        </td>
      </tr>
      <tr class="vd-expand-row" id="${expandId}" style="display:none">
        <td colspan="8">
          <div class="vd-expand-body">
            <div class="vd-exp-grid">
              <div class="vd-exp-block">
                <div class="vd-exp-lbl">CVE ID</div>
                <div class="vd-exp-val"><code>${c.cve_id}</code></div>
              </div>
              <div class="vd-exp-block">
                <div class="vd-exp-lbl">Severity</div>
                <div class="vd-exp-val"><span class="rb rb-${sev}">${sev}</span> · CVSS ${cvss.toFixed(1)}</div>
              </div>
              <div class="vd-exp-block">
                <div class="vd-exp-lbl">Affected</div>
                <div class="vd-exp-val"><code>${c.service} (port ${c.port})</code></div>
              </div>
              <div class="vd-exp-block">
                <div class="vd-exp-lbl">Exploitability</div>
                <div class="vd-exp-val">${hasExploit ? '⚠️ Active exploits known' : '✅ No known exploit'}</div>
              </div>
            </div>
            <div class="vd-exp-desc">${c.description || 'No description available.'}</div>
            ${c.patch ? `<div class="vd-exp-patch"><span class="vd-exp-lbl">🔧 Patch:</span> ${c.patch}</div>` : ''}
            <div class="vd-exp-actions">
              <a class="vd-exp-btn" href="https://nvd.nist.gov/vuln/detail/${c.cve_id}" target="_blank" rel="noopener">🔗 NVD Advisory</a>
              <button class="vd-exp-btn" onclick="Chatbot.quickChat('/patch ${c.service} ${c.port}')">🔧 Get Full Patch Guide</button>
              <button class="vd-exp-btn" onclick="navigator.clipboard.writeText('${c.cve_id}')">📋 Copy CVE</button>
            </div>
          </div>
        </td>
      </tr>`;
  }

  function _toggleVulnExpand(expandId, row) {
    const tr = document.getElementById(expandId);
    if (!tr) return;
    const open = tr.style.display !== 'none';
    tr.style.display = open ? 'none' : 'table-row';
    row.classList.toggle('vd-row-open', !open);
  }

  function _filterVulnDash(tableId, sev) {
    // Update badge active state
    document.querySelectorAll(`[id^="${tableId}"]`).forEach(el => { if (el.classList.contains('vd-badge')) el.classList.remove('active'); });
    if (sev) document.querySelector(`.vd-badge-${sev}`)?.classList.add('active');
    else document.getElementById(`${tableId}-all`)?.classList.add('active');

    const rows = document.querySelectorAll(`#${tableId}-body .vd-row`);
    let shown = 0;
    rows.forEach(row => {
      const match = !sev || row.dataset.sev === sev;
      row.style.display = match ? '' : 'none';
      const expId = row.getAttribute('onclick')?.match(/'([^']+)'/)?.[1];
      if (expId) { const exp = document.getElementById(expId); if (exp) exp.style.display = 'none'; }
      if (match) shown++;
    });
    const cnt = document.getElementById(`${tableId}-count`);
    if (cnt) cnt.textContent = `${shown} vulnerabilities`;
  }

  function _searchVulnDash(tableId) {
    const q   = document.getElementById(`${tableId}-search`)?.value.toLowerCase() || '';
    const svc = document.getElementById(`${tableId}-svc`)?.value.toLowerCase() || '';
    const rows = document.querySelectorAll(`#${tableId}-body .vd-row`);
    let shown = 0;
    rows.forEach(row => {
      const textMatch = !q || row.dataset.text.includes(q);
      const svcMatch  = !svc || row.dataset.svc === svc;
      row.style.display = (textMatch && svcMatch) ? '' : 'none';
      if (textMatch && svcMatch) shown++;
    });
    const cnt = document.getElementById(`${tableId}-count`);
    if (cnt) cnt.textContent = `${shown} vulnerabilities`;
  }

  function _sortVulnDash(tableId) {
    const sortBy = document.getElementById(`${tableId}-sort`)?.value || 'cvss';
    const tbody  = document.getElementById(`${tableId}-body`);
    if (!tbody) return;
    const rows = Array.from(tbody.querySelectorAll('.vd-row'));
    rows.sort((a, b) => {
      if (sortBy === 'cvss')     return (parseFloat(b.querySelector('.vd-cvss-num')?.textContent)||0) - (parseFloat(a.querySelector('.vd-cvss-num')?.textContent)||0);
      if (sortBy === 'severity') { const o = ['critical','high','medium','low']; return o.indexOf(a.dataset.sev) - o.indexOf(b.dataset.sev); }
      if (sortBy === 'port')     return (parseInt(a.querySelector('.vd-mono')?.textContent)||0) - (parseInt(b.querySelector('.vd-mono')?.textContent)||0);
      if (sortBy === 'service')  return (a.dataset.svc||'').localeCompare(b.dataset.svc||'');
      return 0;
    });
    // Re-append rows + their expand rows
    rows.forEach(row => {
      tbody.appendChild(row);
      const expId = row.getAttribute('onclick')?.match(/'([^']+)'/)?.[1];
      if (expId) { const exp = document.getElementById(expId); if (exp) tbody.appendChild(exp); }
    });
  }

  function _copyVulnCSV(tableId) {
    const rows  = document.querySelectorAll(`#${tableId}-body .vd-row`);
    const lines = ['Port,Service,CVE,Severity,CVSS,Description'];
    rows.forEach(row => {
      const cells = row.querySelectorAll('td');
      const port  = cells[0]?.textContent.trim();
      const svc   = cells[1]?.textContent.trim();
      const cve   = cells[2]?.querySelector('.vd-cve-link')?.textContent.trim();
      const sev   = cells[3]?.textContent.trim();
      const cvss  = cells[4]?.querySelector('.vd-cvss-num')?.textContent.trim();
      const desc  = cells[6]?.textContent.trim().replace(/,/g, ';');
      lines.push(`${port},${svc},${cve},${sev},${cvss},"${desc}"`);
    });
    navigator.clipboard.writeText(lines.join('\n'));
  }

  /* ═══════════════════════════════════════════════════════
     SCAN COMPLETE CARD — rendered live in chat after scan
     Shows port table + risk summary + CVE count + actions.
     Also used by _buildScanSummaryEl for session restore.
  ═══════════════════════════════════════════════════════ */

  function _renderScanCompleteCard(data) {
    const chat = document.getElementById('chat');
    const d = document.createElement('div');
    d.className = 'msg msg-ai scan-result-summary-card';

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

    d.innerHTML = `
      <div class="src-header">
        <div class="src-title-row">
          <span class="src-icon">✅</span>
          <div>
            <div class="src-title">Scan Complete — <code>${data.target || ''}</code></div>
            <div class="src-sub">${data.scan_type || ''} · ${data.duration || ''}s · ${new Date().toLocaleString()}</div>
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
            <tr>
              <th>Port</th><th>Protocol</th><th>Service</th><th>Version</th>
              <th>Severity</th><th>Risk Score</th><th>CVEs</th>
            </tr>
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
                <td>${cveCount > 0
                  ? `<span style="color:#e24b4a;font-weight:700">${cveCount} CVE${cveCount !== 1 ? 's' : ''}</span>`
                  : '<span style="color:var(--text3)">—</span>'}</td>
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

    d.style.opacity = '0'; d.style.transform = 'translateY(8px)';
    chat.appendChild(d);
    requestAnimationFrame(() => {
      d.style.transition = 'opacity .3s ease, transform .3s ease';
      d.style.opacity = '1'; d.style.transform = 'translateY(0)';
    });
    chat.scrollTo({ top: chat.scrollHeight, behavior: 'smooth' });
  }

  /* ═══════════════════════════════════════════════════════
     VULNERABILITY TABLE (post-scan inline, lightweight)
  ═══════════════════════════════════════════════════════ */

  function _renderVulnTableInChat(hosts) {
    const allCves = [];
    for (const h of hosts) for (const p of h.ports || []) for (const c of p.cves || [])
      allCves.push({ ...c, port: p.port, service: p.service });
    if (!allCves.length) return;
    allCves.sort((a, b) => b.cvss_score - a.cvss_score);

    const tableId = 'vt-' + Date.now();
    const chat    = document.getElementById('chat');
    const d       = document.createElement('div');
    d.className   = 'msg msg-ai vuln-table-wrap';

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
              <th onclick="Chatbot._sortVulnTable('port','${tableId}',this)">Port <span class="sort-arrow">↕</span></th>
              <th onclick="Chatbot._sortVulnTable('service','${tableId}',this)">Service <span class="sort-arrow">↕</span></th>
              <th onclick="Chatbot._sortVulnTable('cve_id','${tableId}',this)">CVE <span class="sort-arrow">↕</span></th>
              <th onclick="Chatbot._sortVulnTable('severity','${tableId}',this)">Severity <span class="sort-arrow">↕</span></th>
              <th onclick="Chatbot._sortVulnTable('cvss_score','${tableId}',this)">CVSS <span class="sort-arrow">↕</span></th>
              <th>Description</th><th>Fix</th>
            </tr>
          </thead>
          <tbody>
            ${allCves.map(c => `
              <tr class="vt-row" data-port="${c.port}" data-service="${c.service||''}" data-cve_id="${c.cve_id||''}" data-severity="${c.severity||''}" data-cvss_score="${c.cvss_score||0}">
                <td class="vt-mono">${c.port}</td>
                <td>${c.service || '—'}</td>
                <td class="vt-cve-cell">
                  <a class="vt-cve-link" href="https://nvd.nist.gov/vuln/detail/${c.cve_id}" target="_blank" rel="noopener">${c.cve_id}</a>
                  <button class="vt-copy-btn" onclick="navigator.clipboard.writeText('${c.cve_id}');this.textContent='✅';setTimeout(()=>this.textContent='📋',1500)">📋</button>
                </td>
                <td><span class="rb rb-${c.severity}">${c.severity||'low'}</span></td>
                <td class="vt-cvss vt-cvss-${c.severity}">${c.cvss_score}</td>
                <td class="vt-desc">${(c.description||'—').slice(0,80)}…</td>
                <td><button class="vd-patch-btn" onclick="Chatbot.quickChat('/patch ${c.service} ${c.port}')">🔧</button></td>
              </tr>`).join('')}
          </tbody>
        </table>
      </div>`;

    d.style.opacity = '0'; d.style.transform = 'translateY(8px)';
    chat.appendChild(d);
    requestAnimationFrame(() => {
      d.style.transition = 'opacity .3s ease, transform .3s ease';
      d.style.opacity = '1'; d.style.transform = 'translateY(0)';
    });
    chat.scrollTo({ top: chat.scrollHeight, behavior: 'smooth' });
  }

  function _filterVulnTable(input, tableId) {
    const q = input.value.toLowerCase();
    document.getElementById(tableId)?.querySelectorAll('.vt-row').forEach(row => {
      row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
  }

  function _sortVulnTable(col, tableId, th) {
    const tbl = document.getElementById(tableId);
    if (!tbl) return;
    _sortDir[tableId + col] = !_sortDir[tableId + col];
    const asc   = _sortDir[tableId + col];
    const tbody = tbl.querySelector('tbody');
    const rows  = Array.from(tbody.querySelectorAll('.vt-row'));
    rows.sort((a, b) => {
      let av = a.dataset[col] || '', bv = b.dataset[col] || '';
      const isNum = !isNaN(parseFloat(av));
      if (isNum) return asc ? parseFloat(av) - parseFloat(bv) : parseFloat(bv) - parseFloat(av);
      return asc ? av.localeCompare(bv) : bv.localeCompare(av);
    });
    rows.forEach(r => tbody.appendChild(r));
    tbl.querySelectorAll('.sort-arrow').forEach(el => el.textContent = '↕');
    if (th) th.querySelector('.sort-arrow').textContent = asc ? '↑' : '↓';
  }
