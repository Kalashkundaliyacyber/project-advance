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
    // FIX DUPLICATE TABLE: removed _renderLiveVulnTable(ip) — it created an
    // SSE-driven live table that appeared alongside the post-scan confirmation
    // table, resulting in two separate tables in the chat.  We now show a
    // slim "Loading table…" placeholder that fades out the moment the
    // confirmation table replaces it.
    _showScanLoadingPlaceholder(ip);
    await runScan(ip, 'vuln_scan');
  }

  // Kept for backward compat (chat-triggered scans still use this)
  async function executeScan(ip, scanType, cardEl) {
    _currentTarget = ip;
    addMsg(`Running **${scanType}** on \`${ip}\`…`, 'user');
    // FIX DUPLICATE TABLE: replaced _renderLiveVulnTable with loading placeholder
    _showScanLoadingPlaceholder(ip);
    await runScan(ip, scanType);
  }

  /* ═══════════════════════════════════════════════════════
     LIVE VULN TABLE — appears instantly, rows animate in
  ═══════════════════════════════════════════════════════ */

  let _liveTableId      = null;
  let _liveCounters     = { total: 0, confirmed: 0, not_vuln: 0, unconfirmed: 0 };
  let _liveTableEl      = null;
  let _sseReadyResolve  = null;   // set before SSE open; resolved when server sends "ready"
  // FIX BUG 2: tracks category per port-key so port_update from NSE confirmation
  // recategorises (moves between buckets) rather than double-incrementing the total.
  let _rowCategories    = new Map(); // key: "port-protocol" → "CONFIRMED"|"NOT_VULNERABLE"|"UNCONFIRMED"
  // FIX DUPLICATE TABLE: tracks the loading placeholder id shown before the
  // confirmation table appears; null when not showing a placeholder.
  let _liveLoadingId    = null;

  // ── Sequential port-by-port NSE confirmation table state ──────────────────
  // Incremented every time _runSequentialConfirmation starts. A running loop
  // checks its captured generation against this counter each iteration — if a
  // newer scan has started, the old loop bails out instead of fighting over
  // the same DOM rows / making redundant network calls.
  let _confirmGeneration = 0;

  /* ═══════════════════════════════════════════════════════
     SCAN LOADING PLACEHOLDER
     Shown immediately when a scan starts — replaces the old SSE live
     table (_renderLiveVulnTable).  Fades out the moment the
     confirmation table (_renderPortConfirmTable) takes its place.
     This eliminates the "two tables" UX issue where the SSE table and
     the confirmation table both appeared in the chat simultaneously.
  ═══════════════════════════════════════════════════════ */

  function _showScanLoadingPlaceholder(ip) {
    // Remove any lingering placeholder from a previous scan
    _removeScanLoadingPlaceholder();

    const chat = document.getElementById('chat');
    const wrap = document.createElement('div');
    _liveLoadingId = 'scan-loading-' + Date.now();
    wrap.id        = _liveLoadingId;
    wrap.className = 'msg msg-ai live-vuln-wrap';

    wrap.innerHTML = `
      <div class="lv-header">
        <div class="lv-title-row">
          <span class="lv-scan-badge scanning" id="${_liveLoadingId}-badge">
            <span class="lv-badge-dot"></span>⚡ SCANNING
          </span>
          <span class="lv-target"><code>${ip}</code></span>
          <span class="lv-scan-label">nmap -sV --script vuln</span>
        </div>
      </div>
      <div class="lv-table-wrap" style="padding:1.6rem 2rem;text-align:center;color:var(--text3);font-style:italic;font-size:.85rem;">
        <span class="lv-pulse" style="margin-right:.5rem;"></span>Loading table…
      </div>`;

    wrap.style.opacity   = '0';
    wrap.style.transform = 'translateY(8px)';
    chat.appendChild(wrap);
    requestAnimationFrame(() => {
      wrap.style.transition = 'opacity .3s ease, transform .3s ease';
      wrap.style.opacity    = '1';
      wrap.style.transform  = 'translateY(0)';
    });
    chat.scrollTo({ top: chat.scrollHeight, behavior: 'smooth' });
  }

  function _removeScanLoadingPlaceholder() {
    if (!_liveLoadingId) return;
    const el = document.getElementById(_liveLoadingId);
    if (el) {
      el.style.transition = 'opacity .2s ease';
      el.style.opacity    = '0';
      setTimeout(() => { if (el.parentNode) el.parentNode.removeChild(el); }, 220);
    }
    _liveLoadingId = null;
  }

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

    // Reset counters and row tracking
    _liveCounters = { total: 0, confirmed: 0, not_vuln: 0, unconfirmed: 0 };
    _rowCategories = new Map();
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
    // Support both string status (new two-phase) and object status (legacy)
    const status = typeof portData.vuln_status === 'string'
      ? portData.vuln_status
      : (vs.status || 'UNCONFIRMED');
    const script = (typeof vs === 'object' && vs.script_used) || '—';
    const evid   = (typeof vs === 'object' ? (vs.evidence || '') : '').slice(0, 80) || '—';
    const ver    = [portData.product, portData.version].filter(Boolean).join(' ') || '—';

    const statusInfo = _vulnStatusBadge(status);

    // FIX BUG 2: Do NOT count here. port_update always follows port_found for every
    // port (both in real nmap streaming and simulation). All counting lives in
    // _onPortUpdate so there is exactly one count increment per port, even when
    // the NSE confirmation thread sends a second port_update for the same port.

    const rowId = _liveTableId + '-row-' + portData.port + '-' + (portData.protocol || 'tcp');
    // Remove existing row if any (dedup)
    const existing = document.getElementById(rowId);
    if (existing) existing.remove();

    const tr = document.createElement('tr');
    tr.id        = rowId;
    tr.className = 'lv-row lv-row-' + status.toLowerCase().replace(/_/g, '-');
    tr.innerHTML = `
      <td class="lv-mono">${portData.port}</td>
      <td>${portData.protocol || 'tcp'}</td>
      <td><span class="lv-svc">${portData.service || '—'}</span></td>
      <td class="lv-ver">${ver}</td>
      <td class="lv-status-cell" id="${rowId}-status">${statusInfo.badge}</td>
      <td class="lv-script" id="${rowId}-script">${script !== '—' ? `<code>${script}</code>` : '—'}</td>
      <td class="lv-evid" id="${rowId}-evid" title="${evid}">${evid}</td>`;

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

  // ── NEW: port_update handler — flips a LOADING/SCANNING row to final status ──
  function _onPortUpdate(portData) {
    if (!_liveTableId) return;

    const status = typeof portData.vuln_status === 'string'
      ? portData.vuln_status
      : ((portData.vuln_status || {}).status || 'UNCONFIRMED');

    const vs     = portData.vuln_status || {};
    const script = (typeof vs === 'object' && vs.script_used)
      || (portData.confirmation_scripts || []).join(', ') || '—';
    const evid   = ((typeof vs === 'object' ? vs.evidence : '') || '').slice(0, 80) || '—';
    const ver    = [portData.product, portData.version].filter(Boolean).join(' ') || '—';

    const rowId = _liveTableId + '-row-' + portData.port + '-' + (portData.protocol || 'tcp');
    const rowKey = portData.port + '-' + (portData.protocol || 'tcp');

    const statusCell = document.getElementById(rowId + '-status');
    const scriptCell = document.getElementById(rowId + '-script');
    const evidCell   = document.getElementById(rowId + '-evid');
    const tr         = document.getElementById(rowId);

    if (!tr) {
      // Row doesn't exist yet — fall back to creating it
      _onPortFound(portData);
      return;
    }

    // Update status cell with flip animation
    if (statusCell) {
      statusCell.style.transition = 'opacity .2s';
      statusCell.style.opacity = '0';
      setTimeout(() => {
        statusCell.innerHTML = _vulnStatusBadge(status).badge;
        statusCell.style.opacity = '1';
      }, 200);
    }
    if (scriptCell) scriptCell.innerHTML = script !== '—' ? `<code>${script}</code>` : '—';
    if (evidCell)   { evidCell.textContent = evid; evidCell.title = evid; }

    // Update row class
    tr.className = 'lv-row lv-row-' + status.toLowerCase().replace(/_/g, '-');

    // Pulse highlight to draw attention to the update
    tr.classList.add('lv-row-updated');
    setTimeout(() => tr.classList.remove('lv-row-updated'), 1200);

    // FIX BUG 2: Smart counter update using _rowCategories map.
    // - LOADING / SCANNING are intermediate states — not counted.
    // - For a genuinely new port (first terminal status) → increment total + category.
    // - For a port seen before (NSE confirmation updating an already-counted row)
    //   → move it between category buckets WITHOUT changing the total.
    //   This prevents the double-counting that occurred when both the executor
    //   port_update and the NSE confirmation port_update incremented total.
    if (status !== 'LOADING' && status !== 'SCANNING') {
      const _catBucket = (s) => {
        if (s === 'CONFIRMED')          return 'confirmed';
        if (s === 'NOT_VULNERABLE')     return 'not_vuln';
        return 'unconfirmed';
      };

      if (_rowCategories.has(rowKey)) {
        // Port was already counted — recategorise without touching total
        const oldCat = _rowCategories.get(rowKey);
        const newCat = _catBucket(status);
        if (oldCat !== newCat) {
          _liveCounters[oldCat]--;
          _liveCounters[newCat]++;
          _rowCategories.set(rowKey, newCat);
          _updateLiveCounters();
        }
      } else {
        // First time we see a terminal status for this port — count it
        _liveCounters.total++;
        const newCat = _catBucket(status);
        _liveCounters[newCat]++;
        _rowCategories.set(rowKey, newCat);
        _updateLiveCounters();
      }
    }

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
      case 'LOADING':
        return { badge: '<span class="lv-badge lv-loading"><span class="lv-spinner"></span> Detecting…</span>' };
      case 'SCANNING':
        return { badge: '<span class="lv-badge lv-scanning"><span class="lv-spinner"></span> Confirming…</span>' };
      case 'WAITING':
        return { badge: '<span class="lv-badge lv-loading">⏳ Waiting…</span>' };
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

  function _completeLiveTable(confirming = false) {
    if (!_liveTableId) return;
    const badge = document.getElementById(_liveTableId + '-badge');
    if (badge) {
      if (confirming) {
        // Scan finished but NSE confirmation is still running — show intermediate state
        badge.className = 'lv-scan-badge confirming';
        badge.innerHTML = '<span class="lv-badge-dot"></span>🔍 CONFIRMING…';
      } else {
        // All done (stream_end received) — show final complete state
        badge.className = 'lv-scan-badge complete';
        badge.innerHTML = '✔ COMPLETE';
      }
    }
  }

  /**
   * Progressive CVE table — identical to _renderVulnTableInChat but rows
   * are inserted one-by-one with a staggered delay so the user sees them
   * appear live in the chatbot rather than all at once.
   */
  function _renderVulnTableProgressively(hosts) {
    const allCves = [];
    for (const h of hosts) for (const p of h.ports || []) for (const c of p.cves || [])
      allCves.push({ ...c, port: p.port, service: p.service });
    if (!allCves.length) return;
    allCves.sort((a, b) => (b.cvss_score || 0) - (a.cvss_score || 0));

    const tableId = 'vt-' + Date.now();
    const chat    = document.getElementById('chat');
    const wrap    = document.createElement('div');
    wrap.className = 'msg msg-ai vuln-table-wrap';

    // Build the shell (header + empty tbody)
    wrap.innerHTML = `
      <div class="vt-header">
        <span class="vt-title">🔍 Vulnerability Intelligence</span>
        <span class="vt-count" id="${tableId}-count">0 CVEs detected</span>
        <button class="vd-export-btn" style="margin-left:auto" onclick="Chatbot.quickChat('/vuln')">Open Full Dashboard →</button>
      </div>
      <div class="vt-scroll">
        <table class="vt-table" id="${tableId}">
          <thead>
            <tr>
              <th>Port</th><th>Service</th><th>CVE</th>
              <th>Severity</th><th>CVSS</th><th>Description</th><th>Fix</th>
            </tr>
          </thead>
          <tbody id="${tableId}-body"></tbody>
        </table>
      </div>`;

    wrap.style.opacity   = '0';
    wrap.style.transform = 'translateY(8px)';
    chat.appendChild(wrap);
    requestAnimationFrame(() => {
      wrap.style.transition = 'opacity .3s ease, transform .3s ease';
      wrap.style.opacity    = '1';
      wrap.style.transform  = 'translateY(0)';
    });

    const tbody    = wrap.querySelector(`#${tableId}-body`);
    const countEl  = wrap.querySelector(`#${tableId}-count`);

    // Insert rows one-by-one with a 60ms stagger — feels live
    allCves.forEach((c, idx) => {
      setTimeout(() => {
        const tr = document.createElement('tr');
        tr.className = 'vt-row';
        tr.dataset.port      = c.port;
        tr.dataset.service   = c.service || '';
        tr.dataset.cve_id    = c.cve_id  || '';
        tr.dataset.severity  = c.severity || '';
        tr.dataset.cvss_score = c.cvss_score || 0;
        tr.innerHTML = `
          <td class="vt-mono">${c.port}</td>
          <td>${c.service || '—'}</td>
          <td class="vt-cve-cell">
            <a class="vt-cve-link" href="https://nvd.nist.gov/vuln/detail/${c.cve_id}" target="_blank" rel="noopener">${c.cve_id}</a>
            <button class="vt-copy-btn" onclick="navigator.clipboard.writeText('${c.cve_id}');this.textContent='✅';setTimeout(()=>this.textContent='📋',1500)">📋</button>
          </td>
          <td><span class="rb rb-${c.severity}">${c.severity || 'low'}</span></td>
          <td class="vt-cvss vt-cvss-${c.severity}">${c.cvss_score}</td>
          <td class="vt-desc">${(c.description || '—').slice(0, 80)}…</td>
          <td><button class="vd-patch-btn" onclick="Chatbot.quickChat('/patch ${c.service} ${c.port}')">🔧</button></td>`;

        tr.style.opacity   = '0';
        tr.style.transform = 'translateX(-6px)';
        tbody.appendChild(tr);
        requestAnimationFrame(() => {
          tr.style.transition = 'opacity .2s ease, transform .2s ease';
          tr.style.opacity    = '1';
          tr.style.transform  = 'translateX(0)';
        });

        // Update the live CVE counter as each row appears
        if (countEl) countEl.textContent = `${idx + 1} CVE${idx + 1 !== 1 ? 's' : ''} detected`;

        // Keep chat scrolled to bottom on each new row
        if (!_userScrolledUp) chat.scrollTo({ top: chat.scrollHeight, behavior: 'smooth' });
      }, idx * 60);   // 60ms per row — snappy but visibly progressive
    });
  }

  /* ═══════════════════════════════════════════════════════
     SEQUENTIAL NSE CONFIRMATION TABLE
     Renders one row per open port (mirrors the right-panel PORT DETAILS).
     Ports already CONFIRMED / NOT_VULNERABLE (no CVEs) show their final
     status immediately. Everything else starts as ⏳ WAITING, then the
     confirmation loop below picks the best Kali NSE script for ONE port
     at a time, sets that row to 🔄 Confirming…, awaits the result, writes
     CONFIRMED / NOT_VULNERABLE / UNCONFIRMED + script + evidence, then
     moves down to the next row. One nmap process at a time — never parallel.
  ═══════════════════════════════════════════════════════ */

  /** Normalise vuln_status to a plain string, whether it's a dict (from the
   *  initial nmap parser) or already a string (from a prior confirmation). */
  function _normalizeVS(vs) {
    if (typeof vs === 'string') return vs || 'UNCONFIRMED';
    if (vs && typeof vs === 'object') return vs.status || 'UNCONFIRMED';
    return 'UNCONFIRMED';
  }

  /**
   * Build the chatbot confirmation table for every open port found in this
   * scan. Returns { tableId, rows, toConfirmCount } for
   * _runSequentialConfirmation, or null if there are no open ports.
   */
  function _renderPortConfirmTable(ip, ports) {
    if (!ports || !ports.length) return null;

    const chat    = document.getElementById('chat');
    const tableId = 'ct-' + Date.now();

    // Decide up front which ports need a live confirmation pass and which
    // can show their final badge immediately.
    const rows = ports.map(p => {
      const status  = _normalizeVS(p.vuln_status);
      const cves    = p.cves || [];
      // A port needs confirmation unless the initial `nmap --script vuln`
      // run already CONFIRMED it, or it's NOT_VULNERABLE with zero CVE matches.
      const needsConfirm = !(status === 'CONFIRMED' || (status === 'NOT_VULNERABLE' && cves.length === 0));
      return { p, cves, needsConfirm, initialStatus: needsConfirm ? 'WAITING' : status };
    });

    const toConfirmCount = rows.filter(r => r.needsConfirm).length;

    const wrap = document.createElement('div');
    wrap.className = 'msg msg-ai live-vuln-wrap';
    wrap.id = tableId;

    const rowsHtml = rows.map(({ p, cves, initialStatus }) => {
      const rowKey = p.port + '-' + (p.protocol || 'tcp');
      const rowId  = tableId + '-row-' + rowKey;
      const ver    = [p.product, p.version].filter(Boolean).join(' ') || '—';
      const badge  = _vulnStatusBadge(initialStatus).badge;

      // CVE column — strongest CVE first, "+N more" if there are others
      let cveCell = '—';
      if (cves.length) {
        const top = cves[0];
        cveCell = `<span class="rb rb-${top.severity || 'low'}">${top.cve_id || '?'}</span>`
          + (cves.length > 1 ? ` <span class="lv-scan-label">+${cves.length - 1} more</span>` : '');
      }

      // Ports already confirmed by the initial vuln scan carry their
      // script_used / evidence in the vuln_status dict — show them now.
      const vsObj    = (p.vuln_status && typeof p.vuln_status === 'object') ? p.vuln_status : {};
      const initScript = vsObj.script_used || '—';
      const initEvid   = (vsObj.evidence || '').slice(0, 100) || '—';

      return `
      <tr class="lv-row lv-row-${initialStatus.toLowerCase().replace(/_/g, '-')}" id="${rowId}">
        <td class="lv-mono">${p.port}</td>
        <td>${p.protocol || 'tcp'}</td>
        <td><span class="lv-svc">${p.service || '—'}</span></td>
        <td class="lv-ver">${ver}</td>
        <td class="lv-cves">${cveCell}</td>
        <td class="lv-status-cell" id="${rowId}-status">${badge}</td>
        <td class="lv-script" id="${rowId}-script">${initScript !== '—' ? `<code>${initScript}</code>` : '—'}</td>
        <td class="lv-evid" id="${rowId}-evid" title="${vsObj.evidence || ''}">${initEvid}</td>
      </tr>`;
    }).join('');

    const badgeHtml = toConfirmCount
      ? `<span class="lv-badge-dot"></span>🧪 NSE CONFIRMATION — 0/${toConfirmCount}`
      : '✔ ALL CONFIRMED';

    wrap.innerHTML = `
      <div class="lv-header">
        <div class="lv-title-row">
          <span class="lv-scan-badge ${toConfirmCount ? 'scanning' : 'complete'}" id="${tableId}-badge">${badgeHtml}</span>
          <span class="lv-target"><code>${ip}</code></span>
          <span class="lv-scan-label">selecting scripts from /usr/share/nmap/scripts/</span>
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
              <th>CVEs</th>
              <th>Status</th>
              <th>Script Used</th>
              <th>Evidence</th>
            </tr>
          </thead>
          <tbody id="${tableId}-body">${rowsHtml}</tbody>
        </table>
      </div>`;

    wrap.style.opacity   = '0';
    wrap.style.transform = 'translateY(8px)';
    chat.appendChild(wrap);
    requestAnimationFrame(() => {
      wrap.style.transition = 'opacity .3s ease, transform .3s ease';
      wrap.style.opacity    = '1';
      wrap.style.transform  = 'translateY(0)';
    });
    if (!_userScrolledUp) chat.scrollTo({ top: chat.scrollHeight, behavior: 'smooth' });

    return { tableId, rows, toConfirmCount };
  }

  /**
   * Walks the ports that need confirmation ONE AT A TIME:
   *   - current row  → 🔄 Confirming… (lv-scanning)
   *   - later rows   → ⏳ Waiting… (already set by _renderPortConfirmTable)
   *   - await ApiService.confirmPort() — a single targeted nmap run
   *   - write back CONFIRMED / NOT_VULNERABLE / UNCONFIRMED + script + evidence
   *   - 400ms pause, then move to the next row
   *
   * Fire-and-forget: does not block runScan(). If a newer scan starts,
   * _confirmGeneration changes and this loop quietly stops.
   */
  async function _runSequentialConfirmation(ip, ctInfo) {
    if (!ctInfo) return;
    const { tableId, rows, toConfirmCount } = ctInfo;
    const myGen = ++_confirmGeneration;
    if (!toConfirmCount) return;

    const toConfirm = rows.filter(r => r.needsConfirm);
    const badgeEl   = document.getElementById(tableId + '-badge');
    let done = 0;

    for (const row of toConfirm) {
      if (myGen !== _confirmGeneration) return; // superseded by a newer scan

      const { p } = row;
      const rowKey = p.port + '-' + (p.protocol || 'tcp');
      const rowId  = tableId + '-row-' + rowKey;

      const tr         = document.getElementById(rowId);
      const statusCell = document.getElementById(rowId + '-status');
      const scriptCell = document.getElementById(rowId + '-script');
      const evidCell   = document.getElementById(rowId + '-evid');

      // ── Mark THIS row as actively confirming; later rows stay WAITING ──
      if (statusCell) statusCell.innerHTML = _vulnStatusBadge('SCANNING').badge;
      if (tr) tr.className = 'lv-row lv-row-scanning';

      let result;
      try {
        result = await ApiService.confirmPort(ip, {
          port:     p.port,
          protocol: p.protocol,
          service:  p.service,
          product:  p.product,
          version:  p.version,
          cves:     p.cves || [],
        });
      } catch (e) {
        result = {
          vuln_status: 'UNCONFIRMED',
          script_used: null,
          evidence: 'Confirmation request failed: ' + (e.message || 'unknown error'),
        };
      }

      if (myGen !== _confirmGeneration) return; // superseded mid-request

      const finalStatus = result.vuln_status || 'UNCONFIRMED';

      if (statusCell) {
        statusCell.style.transition = 'opacity .2s';
        statusCell.style.opacity = '0';
        setTimeout(() => {
          statusCell.innerHTML = _vulnStatusBadge(finalStatus).badge;
          statusCell.style.opacity = '1';
        }, 150);
      }
      if (scriptCell) {
        scriptCell.innerHTML = result.script_used ? `<code>${result.script_used}</code>` : '—';
      }
      if (evidCell) {
        const evid = (result.evidence || '—').slice(0, 100);
        evidCell.textContent = evid;       // textContent — raw NSE output may contain < > &
        evidCell.title       = result.evidence || '';
      }
      if (tr) {
        tr.className = 'lv-row lv-row-' + finalStatus.toLowerCase().replace(/_/g, '-');
        tr.classList.add('lv-row-updated');
        setTimeout(() => tr.classList.remove('lv-row-updated'), 1200);
      }

      done++;
      if (badgeEl) {
        badgeEl.innerHTML = `<span class="lv-badge-dot"></span>🧪 NSE CONFIRMATION — ${done}/${toConfirmCount}`;
      }

      const chat = document.getElementById('chat');
      if (chat && !_userScrolledUp) chat.scrollTo({ top: chat.scrollHeight, behavior: 'smooth' });

      // Breathing room — never hammer the target with back-to-back nmap runs
      await new Promise(r => setTimeout(r, 400));
    }

    if (myGen !== _confirmGeneration) return;
    if (badgeEl) {
      badgeEl.className = 'lv-scan-badge complete';
      badgeEl.innerHTML = '✔ ALL CONFIRMED';
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

        // ── port_update — flip LOADING/SCANNING row to final status ──
        if (d.type === 'port_update') {
          _onPortUpdate(d.port);
          return;
        }

        // ── ready — SSE pipe confirmed; signal runScan it's safe to POST ──
        if (d.type === 'ready') {
          if (typeof _sseReadyResolve === 'function') {
            _sseReadyResolve();
            _sseReadyResolve = null;
          }
          return;
        }

        // ── stream_end — NSE confirmation thread has finished, safe to close ──
        // This is the ONLY event that should close the EventSource now.
        // (Previously the code closed on status:"complete" which caused all
        //  NSE confirmation port_update events to be missed — Bug 1.)
        if (d.type === 'stream_end') {
          es.close();
          _progressTimer = null;
          _completeLiveTable(false);   // show "✔ COMPLETE"
          return;
        }

        // Progress event — update the progress bar UI
        _updateProgressUI(d);

        // FIX BUG 1: Do NOT close the EventSource on status "complete".
        // The NSE confirmation thread hasn't run yet at this point. We close
        // on stream_end (above) or on "stopped" (below). "complete" now shows
        // a "CONFIRMING…" badge so the user knows confirmation is in progress.
        if (d.status === 'stopped') {
          es.close();
          _progressTimer = null;
          Utils.setStatus('stopped');
          _completeLiveTable(false);
        } else if (d.status === 'complete' || (!d.running && d.status !== 'running')) {
          // Initial scan finished — show confirming state while NSE thread runs
          _completeLiveTable(true);    // show "🔍 CONFIRMING…"
        }
      } catch (e) {}
    };
    es.onerror = () => {
      // Resolve ready on error too so runScan never hangs
      if (typeof _sseReadyResolve === 'function') {
        _sseReadyResolve();
        _sseReadyResolve = null;
      }
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

    // ── RACE FIX: open SSE pipe first, wait for server's "ready" event,
    // THEN send the POST. This guarantees no port_found events are missed
    // in the 200-500ms window while the EventSource is connecting.
    const _sseReadyPromise = new Promise(resolve => { _sseReadyResolve = resolve; });
    _startProgressPolling();
    // Wait for ready, but cap at 1.5s so we never block if server is slow
    await Promise.race([_sseReadyPromise, new Promise(r => setTimeout(r, 1500))]);

    const progressMsg = addMsg(`⏳ Scanning \`${target}\` — **${scan_type}**…`, 'sys');
    _saveRichMsg('SCAN_PROGRESS', { target, scan_type, started_at: new Date().toISOString() });

    // Show AI "analyzing" typing indicator while the scan runs
    let _scanTyping    = addTyping();
    let _analyzeTyping = null;

    try {
      const d = await ApiService.startScan(target, scan_type, SessionManager.getProjectName());

      // Replace typing indicator with "AI is processing results" message
      if (_scanTyping) { _scanTyping.remove(); _scanTyping = null; }
      _analyzeTyping = addTyping();
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

      // Remove the "analyzing" typing indicator now that results are ready
      if (_analyzeTyping) _analyzeTyping.remove();

      // Append scan complete card
      try {
        const _scanRichData = {
          target, scan_type: d.scan_type, duration: d.duration,
          summary: d.explanation?.summary || '', recommendation: d.recommendation?.reason || '',
          risk: d.risk, ai_analysis: d.ai_analysis, explanation: d.explanation,
        };
        _renderScanCompleteCard(_scanRichData);
        _saveRichMsg('SCAN_COMPLETE', _scanRichData);
      } catch (scErr) {
        console.error('[ThreatWeave] scan-complete-card render failed:', scErr);
      }

      // Append CVE table only when new CVEs found — rows reveal progressively
      const hosts   = d.risk?.hosts || [];
      try {
        const newCves = [];
        for (const h of hosts) for (const p of h.ports || []) for (const c of p.cves || [])
          newCves.push({ ...c, port: p.port, service: p.service });
        if (newCves.length > 0) {
          _renderVulnTableProgressively(hosts);
          _saveRichMsg('VULN_TABLE', newCves);
        } else {
          const prevCveCount = (cumulative?.cves || []).length;
          const noNewMsg = prevCveCount > 0
            ? `✅ **${d.scan_type || 'Scan'} complete** on \`${target}\` — ${d.duration}s. No new CVEs found. (${prevCveCount} CVE(s) from earlier scans still tracked above.)`
            : `✅ **Scan complete** on \`${target}\` — ${d.duration}s. No CVEs detected.\n\n${d.explanation?.summary || ''}`;
          addMsg(noNewMsg, 'ai');
        }
      } catch (cveErr) {
        console.error('[ThreatWeave] CVE table render failed:', cveErr);
      }

      // ── NSE confirmation table — one open port per row, confirmed
      // sequentially (one nmap process at a time) using the best-matching
      // script picked from /usr/share/nmap/scripts/ for each port's
      // service/version/CVEs. Fire-and-forget — runs in the background
      // while the rest of runScan() finishes normally.
      try {
        // Prefer this scan's own ports (`hosts`, from `d.risk.hosts`). If THIS
        // scan came back with zero ports (e.g. nothing new this round) but the
        // right panel still shows data, that data came from `dMerged` (current
        // scan + cumulative history). Fall back to that same source so the chat
        // table always matches what the right panel is displaying.
        let portSourceHosts = hosts;
        let allOpenPorts = [];
        for (const h of portSourceHosts) for (const p of h.ports || []) allOpenPorts.push(p);

        if (allOpenPorts.length === 0) {
          const mergedHosts = dMerged.risk?.hosts || [];
          for (const h of mergedHosts) for (const p of h.ports || []) allOpenPorts.push(p);
          if (allOpenPorts.length > 0) {
            console.log('[ThreatWeave] confirm-table: using cumulative/dMerged ports (this scan returned 0 new ports)');
          }
        }

        if (allOpenPorts.length > 0) {
          // FIX DUPLICATE TABLE: remove the loading placeholder now that
          // the real confirmation table is about to render in its place.
          _removeScanLoadingPlaceholder();
          const ctInfo = _renderPortConfirmTable(target, allOpenPorts);
          if (ctInfo) _runSequentialConfirmation(target, ctInfo);
        } else {
          _removeScanLoadingPlaceholder();   // clean up placeholder even with no ports
          console.log('[ThreatWeave] confirm-table: skipped — no open ports in d.risk.hosts or dMerged.risk.hosts');
        }
      } catch (ctErr) {
        console.error('[ThreatWeave] confirm-table render failed:', ctErr);
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
      if (_scanTyping)   _scanTyping.remove();
      if (_analyzeTyping) _analyzeTyping.remove();
      if (progressMsg) progressMsg.remove();
      _completeLiveTable(false);
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
    _completeLiveTable(false);
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
    _currentTarget  = '';
    _liveTableId    = null;
    _liveTableEl    = null;
    _liveLoadingId  = null;
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
