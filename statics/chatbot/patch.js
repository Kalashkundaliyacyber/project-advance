/**
 * chatbot/patch.js
 * /patch remediation dashboard, single-port guidance, /patch add, /help.
 *
 * FIXES in this version:
 *   1. Added OS selector UI to /patch all dashboard.
 *      Users can now choose Ubuntu/Debian, RHEL/CentOS, Arch, or Windows
 *      before fetching patch commands. The selection is passed as os_hint.
 *
 *   2. Fixed _handlePatchAll() — now calls RemediationClient.getPatchAll()
 *      with the chosen os_hint, then maps backend results into the dashboard.
 *      Previously it only rendered local in-memory scan data and always used
 *      hardcoded Ubuntu apt commands regardless of OS selection.
 *
 *   3. Fixed _genPatchCmds(e, osHint) — now accepts an OS hint parameter
 *      and returns the correct package manager commands per OS family.
 *      Previously hardcoded to Ubuntu/apt for every OS.
 *
 *   4. Added _cmdPatchAdd(parts) — handler for the /patch add slash command.
 *      Calls POST /api/patch/add to store a manual patch into patches.db.
 *      Usage: /patch add <CVE-ID> <package> <os-family> <command>
 */


  /* ═══════════════════════════════════════════════════════
     OS HINT STATE — shared by patch dashboard
  ═══════════════════════════════════════════════════════ */

  let _patchOsHint = 'ubuntu'; // default; updated by OS selector in dashboard

  const _OS_FAMILIES = [
    { key: 'ubuntu',   label: '🐧 Ubuntu/Debian', pkgMgr: 'apt' },
    { key: 'rhel',     label: '🎩 RHEL/CentOS',   pkgMgr: 'dnf' },
    { key: 'arch',     label: '⚙️ Arch Linux',     pkgMgr: 'pacman' },
    { key: 'windows',  label: '🪟 Windows',        pkgMgr: 'winget' },
  ];


  /* ═══════════════════════════════════════════════════════
     /patch all — PREMIUM REMEDIATION DASHBOARD
  ═══════════════════════════════════════════════════════ */

  async function _handlePatchAll() {
    const data      = App.getLastData();
    const sessionId = App.getCurrentSession() || '';
    const hosts     = data?.risk?.hosts || [];
    const ai        = data?.ai_analysis || {};

    // Build entries from local scan data first (for immediate render)
    const entries = [];
    for (const h of hosts) {
      for (const p of h.ports || []) {
        const cves   = p.cves || [];
        const risk   = p.risk || {};
        const topCve = cves[0];
        const aiRec  = (ai.recommendations || []).find(r => r.port == p.port || r.service === p.service);
        const aiRisk = (ai.risk_analysis   || []).find(r => r.port == p.port || r.service === p.service);

        entries.push({
          port:        p.port,
          service:     p.service || '—',
          product:     p.product || '',
          version:     p.version || '—',
          risk_level:  risk.level || 'low',
          risk_score:  risk.score || 0,
          cve:         topCve?.cve_id || '—',
          severity:    topCve?.severity || risk.level || 'low',
          cvss:        topCve?.cvss_score || risk.score || 0,
          cve_desc:    topCve?.description || aiRisk?.reason || 'No CVE data — run version_deep scan for accurate matching.',
          patch_note:  topCve?.patch || '',
          ai_action:   aiRec?.action || '',
          ai_priority: aiRec?.priority || risk.level || 'low',
          reasons:     risk.reasons || [],
          all_cves:    cves,
          // commands from backend will be merged in after API call
          backend_cmds: null,
          os_hint:     _patchOsHint,
        });
      }
    }

    if (!entries.length) {
      addMsg('No scan data found. Run a scan first, then try `/patch all` again.', 'ai');
      return;
    }

    entries.sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3 };
      return (order[a.risk_level] || 3) - (order[b.risk_level] || 3);
    });

    // Render dashboard immediately with local data
    _renderPatchDashboard(entries, sessionId);

    // Then fetch backend patch commands (multi-OS aware) and merge in
    if (sessionId) {
      _fetchAndMergeBackendPatches(sessionId, _patchOsHint, entries);
    }
  }

  /**
   * Fetch OS-aware patch commands from backend and update dashboard rows.
   * Called after initial render so the dashboard appears instantly.
   */
  async function _fetchAndMergeBackendPatches(sessionId, osHint, entries) {
    try {
      const resp = await RemediationClient.getPatchAll(sessionId, osHint);
      if (!resp?.ok || !resp.results?.length) return;

      // Build a service→result map from backend response
      const byService = {};
      for (const r of resp.results) {
        const key = (r.service || '').toLowerCase();
        byService[key] = r;
      }

      // Update each entry with backend-supplied commands
      for (const entry of entries) {
        const key = (entry.service || '').toLowerCase();
        const backendResult = byService[key];
        if (backendResult) {
          // Prefer backend multi-OS commands dict, fall back to patch_command string
          const cmds = backendResult.commands || backendResult.patch_command || {};
          entry.backend_cmds = typeof cmds === 'object' ? cmds : { [osHint]: cmds };
          entry.os_hint = osHint;
        }
      }

      // Re-render all expanded rows to reflect backend commands
      // (collapsed rows will pick up new data when user expands them)
      document.querySelectorAll('.pd-expand-row[data-entry]').forEach(row => {
        try {
          const entryData = JSON.parse(row.dataset.entry);
          const key = (entryData.service || '').toLowerCase();
          if (byService[key]) {
            const updated = entries.find(e => (e.service||'').toLowerCase() === key);
            if (updated) {
              row.dataset.entry = JSON.stringify(updated);
              const cmds = _genPatchCmds(updated, osHint);
              row.dataset.cmds  = JSON.stringify(cmds);
            }
          }
        } catch (_) {}
      });

    } catch (e) {
      // Silently fail — dashboard already shows local data
      console.warn('[patch.js] Backend patch merge failed:', e.message);
    }
  }

  function _renderPatchDashboard(entries, sessionId) {
    const dashId  = 'pd-' + Date.now();
    const counts  = { critical: 0, high: 0, medium: 0, low: 0 };
    entries.forEach(e => counts[e.risk_level] = (counts[e.risk_level] || 0) + 1);
    const immediate = entries.filter(e => ['critical','high'].includes(e.risk_level)).length;

    const chat = document.getElementById('chat');
    const wrap = document.createElement('div');
    wrap.className = 'msg msg-ai patch-dash-wrap';

    // Build OS selector buttons
    const osBtns = _OS_FAMILIES.map(os =>
      `<button class="pd-os-btn ${_patchOsHint === os.key ? 'active' : ''}"
               id="${dashId}-os-${os.key}"
               onclick="Chatbot._setPatchOs('${dashId}','${os.key}','${sessionId || ''}',${JSON.stringify(entries).replace(/"/g,'&quot;')})"
               title="Switch all patch commands to ${os.label}">
        ${os.label}
       </button>`
    ).join('');

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
        <!-- ── OS SELECTOR (FIX: was missing, caused all commands to be Ubuntu-only) ── -->
        <div class="pd-os-selector">
          <span class="pd-os-label">Target OS:</span>
          ${osBtns}
          <span class="pd-os-status" id="${dashId}-os-status">Using cached commands</span>
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
      </div>
    `;

    wrap.style.opacity = '0'; wrap.style.transform = 'translateY(8px)';
    chat.appendChild(wrap);
    requestAnimationFrame(() => {
      wrap.style.transition = 'opacity .3s ease, transform .3s ease';
      wrap.style.opacity = '1'; wrap.style.transform = 'translateY(0)';
    });
    chat.scrollTo({ top: chat.scrollHeight, behavior: 'smooth' });
    _saveRichMsg('PATCH_DASH', entries);
  }

  /**
   * OS selector handler — re-fetches backend patch commands for the chosen OS
   * and refreshes all patch command cells in the dashboard.
   */
  async function _setPatchOs(dashId, osKey, sessionId, entries) {
    _patchOsHint = osKey;

    // Update button active state
    _OS_FAMILIES.forEach(os => {
      const btn = document.getElementById(`${dashId}-os-${os.key}`);
      if (btn) btn.classList.toggle('active', os.key === osKey);
    });

    const statusEl = document.getElementById(`${dashId}-os-status`);
    if (statusEl) statusEl.textContent = 'Fetching commands…';

    // Update all existing expanded rows with new OS commands immediately (local)
    document.querySelectorAll(`#${dashId}-body .pd-expand-row`).forEach(row => {
      try {
        const entryData = JSON.parse(row.dataset.entry);
        entryData.os_hint = osKey;
        const cmds = _genPatchCmds(entryData, osKey);
        row.dataset.cmds = JSON.stringify(cmds);
        // Re-render tab content if visible
        const tabContent = row.querySelector('.pd-tab-content');
        if (tabContent && tabContent.style.display !== 'none') {
          tabContent.innerHTML = _genTabContent(entryData, cmds, 'mitigation');
        }
        // Re-render step commands
        _updateRowUpgradeSteps(row, cmds);
      } catch (_) {}
    });

    // Fetch from backend for accurate multi-OS commands
    if (sessionId) {
      try {
        const resp = await RemediationClient.getPatchAll(sessionId, osKey);
        if (resp?.ok && resp.results?.length) {
          const byService = {};
          resp.results.forEach(r => { byService[(r.service||'').toLowerCase()] = r; });

          entries.forEach(entry => {
            const key = (entry.service||'').toLowerCase();
            const backendResult = byService[key];
            if (backendResult) {
              const cmdData = backendResult.commands || backendResult.patch_command || {};
              entry.backend_cmds = typeof cmdData === 'object' ? cmdData : { [osKey]: cmdData };
              entry.os_hint = osKey;
            }
          });

          if (statusEl) statusEl.textContent = `✅ Showing ${_OS_FAMILIES.find(o=>o.key===osKey)?.label || osKey} commands`;
        }
      } catch (e) {
        if (statusEl) statusEl.textContent = `⚠ Using local commands (${osKey})`;
      }
    } else {
      if (statusEl) statusEl.textContent = `Using local commands (${osKey})`;
    }
  }

  /** Update the upgrade/restart/verify step commands in an already-rendered expand row */
  function _updateRowUpgradeSteps(row, cmds) {
    const stepCmds = row.querySelectorAll('.pd-cmd');
    if (stepCmds.length >= 1 && cmds.upgrade) stepCmds[0].textContent = cmds.upgrade;
    if (stepCmds.length >= 2 && cmds.restart)  stepCmds[1].textContent = cmds.restart;
    if (stepCmds.length >= 3 && cmds.verify)   stepCmds[2].textContent = cmds.verify;
  }

  function _patchRow(e, i, dashId) {
    const expId    = `${dashId}-exp-${i}`;
    const sev      = e.severity.toLowerCase();
    const pri      = (e.ai_priority || 'low').toLowerCase();
    const pctScore = Math.min((e.risk_score || e.cvss || 0) * 10, 100);
    const hasPatch = !!e.patch_note || !!e.ai_action;
    const patchStatus = hasPatch
      ? `<span class="pd-patch-avail">✅ Available</span>`
      : `<span class="pd-patch-none">🔍 Research</span>`;
    const priorityBadge = `<span class="pd-pri pd-pri-${pri}">${pri.toUpperCase()}</span>`;

    const upgCmds = _genPatchCmds(e, _patchOsHint);
    const tabContentId = `${expId}-tabcontent`;

    return `
      <tr class="pd-row" data-sev="${e.risk_level}" data-text="${(e.port+' '+e.service+' '+e.cve+' '+(e.cve_desc||'')).toLowerCase()}"
          onclick="Chatbot._togglePatchExpand('${expId}', this)">
        <td class="vd-mono">${e.port}</td>
        <td><span class="vd-svc-tag">${e.service}</span>${e.product ? `<br><small style="color:var(--text3)">${e.product}</small>` : ''}</td>
        <td class="vt-cve-cell">
          ${e.cve !== '—'
            ? `<a class="vt-cve-link" href="https://nvd.nist.gov/vuln/detail/${e.cve}" target="_blank" rel="noopener" onclick="event.stopPropagation()">${e.cve}</a>
               <button class="vt-copy-btn" onclick="event.stopPropagation();navigator.clipboard.writeText('${e.cve}');this.textContent='✅';setTimeout(()=>this.textContent='📋',1500)">📋</button>`
            : '<span style="color:var(--text3)">—</span>'}
        </td>
        <td><span class="rb rb-${sev}">${sev}</span></td>
        <td>
          <div class="vd-cvss-wrap">
            <span class="vd-cvss-num vd-cvss-${e.risk_level}">${(e.risk_score||e.cvss||0).toFixed(1)}</span>
            <div class="vd-cvss-bar"><div class="vd-cvss-fill vd-cvss-fill-${e.risk_level}" style="width:${pctScore}%"></div></div>
          </div>
        </td>
        <td><code style="font-size:11px;color:var(--purple)">${e.version}</code></td>
        <td>${patchStatus}</td>
        <td>${priorityBadge}</td>
        <td><span class="pd-expand-arrow" id="${expId}-arrow">▶</span></td>
      </tr>
      <tr class="pd-expand-row" id="${expId}" style="display:none"
          data-entry="${JSON.stringify(e).replace(/"/g,'&quot;')}"
          data-cmds="${JSON.stringify(upgCmds).replace(/"/g,'&quot;')}">
        <td colspan="9">
          <div class="pd-expand-body">

            <!-- ── Step commands: Upgrade / Restart / Verify ── -->
            ${upgCmds.upgrade ? `
            <div class="pd-cmd-steps">
              <div class="pd-cmd-step">
                <span class="pd-step-num">1 UPGRADE</span>
                <div class="pd-cmd-row">
                  <code class="pd-cmd">${upgCmds.upgrade}</code>
                  <button class="vt-copy-btn" onclick="navigator.clipboard.writeText('${upgCmds.upgrade.replace(/'/g,"\\'")}');this.textContent='✅';setTimeout(()=>this.textContent='📋',1500)">📋</button>
                </div>
              </div>
              ${upgCmds.restart ? `
              <div class="pd-cmd-step">
                <span class="pd-step-num">2 RESTART</span>
                <div class="pd-cmd-row">
                  <code class="pd-cmd">${upgCmds.restart}</code>
                  <button class="vt-copy-btn" onclick="navigator.clipboard.writeText('${upgCmds.restart.replace(/'/g,"\\'")}');this.textContent='✅';setTimeout(()=>this.textContent='📋',1500)">📋</button>
                </div>
              </div>` : ''}
              ${upgCmds.verify ? `
              <div class="pd-cmd-step">
                <span class="pd-step-num">3 VERIFY</span>
                <div class="pd-cmd-row">
                  <code class="pd-cmd">${upgCmds.verify}</code>
                  <button class="vt-copy-btn" onclick="navigator.clipboard.writeText('${upgCmds.verify.replace(/'/g,"\\'")}');this.textContent='✅';setTimeout(()=>this.textContent='📋',1500)">📋</button>
                </div>
              </div>` : ''}
            </div>` : ''}

            <!-- ── Tab Bar ── -->
            <div class="pd-tab-bar">
              <button class="pd-tab active" data-tab="mitigation" onclick="Chatbot._switchPatchTab('${tabContentId}', 'mitigation', this)">🛡 Mitigation</button>
              <button class="pd-tab" data-tab="cause"       onclick="Chatbot._switchPatchTab('${tabContentId}', 'cause', this)">⚙ Cause</button>
              <button class="pd-tab" data-tab="riskscore"   onclick="Chatbot._switchPatchTab('${tabContentId}', 'riskscore', this)">📊 Risk Score</button>
              <button class="pd-tab" data-tab="impact"      onclick="Chatbot._switchPatchTab('${tabContentId}', 'impact', this)">💥 Impact</button>
              <button class="pd-tab" data-tab="risklevel"   onclick="Chatbot._switchPatchTab('${tabContentId}', 'risklevel', this)">🚨 Risk Level</button>
              <button class="pd-tab" data-tab="severity"    onclick="Chatbot._switchPatchTab('${tabContentId}', 'severity', this)">⚠ Severity</button>
            </div>

            <!-- ── Tab Content Area ── -->
            <div class="pd-tab-content" id="${tabContentId}">
              ${_genTabContent(e, upgCmds, 'mitigation')}
            </div>

            <!-- ── Footer actions ── -->
            <div class="pd-exp-actions">
              ${e.cve !== '—' ? `<a class="vd-exp-btn" href="https://nvd.nist.gov/vuln/detail/${e.cve}" target="_blank" rel="noopener">🔗 NVD Advisory</a>` : ''}
              <button class="vd-exp-btn" onclick="Chatbot.quickChat('/patch ${e.service} ${e.port}')">💬 Ask AI for Full Guide</button>
              ${e.patch_note ? `<div class="pd-exp-text" style="margin-top:8px"><strong>Official patch note:</strong> ${e.patch_note}</div>` : ''}
            </div>
          </div>
        </td>
      </tr>`;
  }

  function _genTabContent(e, upgCmds, tab) {
    const sev   = (e.severity || e.risk_level || 'low').toLowerCase();
    const cvss  = parseFloat(e.cvss || e.risk_score || 0);
    const score = parseFloat(e.risk_score || e.cvss || 0);
    const pct   = Math.min(cvss * 10, 100);
    const scorePct = Math.min(score * 10, 100);

    const _sevColor = s => ({ critical:'#f87171', high:'#fbbf24', medium:'#60a5fa', low:'#34d399' }[s] || '#9ca3af');
    const _bar = (val, max, color) => `<div style="background:rgba(255,255,255,0.07);border-radius:4px;height:6px;overflow:hidden;margin-top:4px"><div style="width:${Math.min(val/max*100,100).toFixed(1)}%;height:100%;background:${color};border-radius:4px;transition:width .4s"></div></div>`;

    const content = {
      mitigation: `
        <div class="pdt-section">
          <div class="pdt-label">Recommended Actions</div>
          <div class="pdt-text" style="white-space:pre-line">${upgCmds.mitigation || '• Apply latest security patches for ' + e.service + '\n• Restrict port ' + e.port + ' access via firewall\n• Monitor service logs for anomalous activity'}</div>
        </div>
        ${e.ai_action ? `<div class="pdt-section"><div class="pdt-label">AI Recommendation</div><div class="pdt-text">${e.ai_action}</div></div>` : ''}
        ${e.patch_note ? `<div class="pdt-section"><div class="pdt-label">Vendor Patch Note</div><div class="pdt-text">${e.patch_note}</div></div>` : ''}`,

      cause: `
        <div class="pdt-section">
          <div class="pdt-label">Vulnerability Description</div>
          <div class="pdt-text">${e.cve_desc || 'No description available. Run a version_deep scan for accurate CVE matching.'}</div>
        </div>
        <div class="pdt-grid">
          <div class="pdt-kv"><span class="pdt-key">Service</span><span class="pdt-val"><code>${e.service}</code></span></div>
          <div class="pdt-kv"><span class="pdt-key">Version</span><span class="pdt-val" style="color:#fbbf24"><code>${e.version || 'unknown'}</code></span></div>
          <div class="pdt-kv"><span class="pdt-key">CVE ID</span><span class="pdt-val">${e.cve !== '—' ? `<a href="https://nvd.nist.gov/vuln/detail/${e.cve}" target="_blank" style="color:#60a5fa">${e.cve}</a>` : '—'}</span></div>
          <div class="pdt-kv"><span class="pdt-key">Root Cause</span><span class="pdt-val">${cvss >= 9 ? 'Remote code execution vector — critical unpatched component' : cvss >= 7 ? 'Exploitable vulnerability with known attack surface' : 'Security misconfiguration or outdated component'}</span></div>
        </div>
        ${e.reasons && e.reasons.length ? `<div class="pdt-section"><div class="pdt-label">Risk Reasons</div>${e.reasons.map(r => `<div class="pdt-reason">• ${r}</div>`).join('')}</div>` : ''}`,

      riskscore: `
        <div class="pdt-score-hero">
          <div class="pdt-score-ring">
            <span class="pdt-score-num" style="color:${_sevColor(sev)}">${score.toFixed(1)}</span>
            <span class="pdt-score-denom">/10</span>
          </div>
          <div class="pdt-score-details">
            <div class="pdt-kv"><span class="pdt-key">Risk Score</span><span class="pdt-val" style="color:${_sevColor(sev)};font-weight:700">${score.toFixed(1)} / 10</span></div>
            ${_bar(score, 10, _sevColor(sev))}
            <div class="pdt-kv" style="margin-top:10px"><span class="pdt-key">CVSS Score</span><span class="pdt-val" style="color:${_sevColor(sev)};font-weight:700">${cvss.toFixed(1)} / 10</span></div>
            ${_bar(cvss, 10, _sevColor(sev))}
            <div class="pdt-kv" style="margin-top:10px"><span class="pdt-key">Severity</span><span class="pdt-val"><span class="rb rb-${sev}">${sev}</span></span></div>
            <div class="pdt-kv"><span class="pdt-key">Exploitability</span><span class="pdt-val">${cvss >= 8.5 ? '⚠️ High — active exploits known' : cvss >= 7 ? '⚠ Medium — exploitation likely' : '✅ Low — limited exploit surface'}</span></div>
          </div>
        </div>
        ${e.all_cves && e.all_cves.length > 1 ? `
        <div class="pdt-section"><div class="pdt-label">All CVEs (${e.all_cves.length})</div>
        ${e.all_cves.slice(0,5).map(c => `<div class="pdt-cve-row"><span class="pdt-cve-id">${c.cve_id||''}</span><span class="rb rb-${(c.severity||'low').toLowerCase()}" style="font-size:10px">${(c.severity||'low')}</span><span class="pdt-cve-score">${(c.cvss_score||0).toFixed(1)}</span></div>`).join('')}
        </div>` : ''}`,

      impact: `
        <div class="pdt-grid">
          <div class="pdt-impact-card" style="border-color:rgba(248,113,113,0.3)">
            <div class="pdt-impact-icon">🏢</div>
            <div class="pdt-impact-title">Business Impact</div>
            <div class="pdt-impact-text">${cvss >= 9 ? 'Potential full system compromise. Service disruption, data breach, and reputational damage likely if exploited.' : cvss >= 7 ? 'Significant risk of unauthorized access or service degradation. Prompt remediation required.' : 'Moderate business risk. May expose internal services if combined with other vulnerabilities.'}</div>
          </div>
          <div class="pdt-impact-card" style="border-color:rgba(96,165,250,0.3)">
            <div class="pdt-impact-icon">💻</div>
            <div class="pdt-impact-title">Technical Impact</div>
            <div class="pdt-impact-text">${cvss >= 9 ? 'Remote code execution possible. Attacker may gain root/admin privileges and lateral movement capability.' : cvss >= 7 ? 'Privilege escalation or data exfiltration risk. Service availability may be compromised.' : 'Information disclosure or minor service degradation. Limited attack surface.'}</div>
          </div>
        </div>`,

      risklevel: `
        <div class="pdt-rl-hero">
          <div class="pdt-rl-badge rb-${sev}" style="font-size:22px;padding:10px 20px;border-radius:10px">${sev.toUpperCase()}</div>
          <div style="flex:1">
            <div class="pdt-kv"><span class="pdt-key">Classification</span><span class="pdt-val" style="color:${_sevColor(sev)};font-weight:700">${sev.toUpperCase()} RISK</span></div>
            <div class="pdt-kv"><span class="pdt-key">Priority Action</span><span class="pdt-val" style="color:${_sevColor(sev)}">${sev === 'critical' ? '🚨 Patch IMMEDIATELY' : sev === 'high' ? '⚠ Patch within 24–48 hours' : sev === 'medium' ? 'Patch within 7 days' : 'Schedule for next maintenance'}</span></div>
          </div>
        </div>`,

      severity: `
        <div class="pdt-kv"><span class="pdt-key">Severity Level</span><span class="pdt-val"><span class="rb rb-${sev}">${sev}</span></span></div>
        <div class="pdt-kv"><span class="pdt-key">CVSS Score</span><span class="pdt-val" style="color:${_sevColor(sev)};font-weight:700">${cvss.toFixed(1)}</span></div>
        ${_bar(cvss, 10, _sevColor(sev))}
        <div class="pdt-kv" style="margin-top:8px"><span class="pdt-key">NVD Rating</span><span class="pdt-val">${cvss >= 9 ? 'Critical (9.0–10.0)' : cvss >= 7 ? 'High (7.0–8.9)' : cvss >= 4 ? 'Medium (4.0–6.9)' : 'Low (0.1–3.9)'}</span></div>`
    };

    return content[tab] || content['mitigation'];
  }

  /**
   * Generate patch commands for a given entry and OS hint.
   *
   * FIX: Previously this was always hardcoded to Ubuntu/apt commands regardless
   * of what OS the user selected. Now accepts osHint and returns the correct
   * package manager commands per OS family.
   *
   * Priority order:
   *   1. backend_cmds[osHint]   — from /api/patch/all response (most accurate)
   *   2. local service map      — hardcoded per-service per-OS commands
   *   3. generic fallback       — generic upgrade command for the OS
   */
  function _genPatchCmds(e, osHint) {
    const svc = (e.service || '').toLowerCase();
    const os  = (osHint || _patchOsHint || 'ubuntu').toLowerCase();

    // 1. Use backend-supplied commands if available
    if (e.backend_cmds) {
      const osKey = os === 'rhel' ? 'rhel/centos' : os === 'ubuntu' ? 'ubuntu/debian' : os;
      const backendCmd = e.backend_cmds[osKey] || e.backend_cmds[os] || Object.values(e.backend_cmds)[0];
      if (backendCmd) {
        return {
          upgrade: backendCmd,
          restart: _getRestartCmd(svc),
          verify:  _getVerifyCmd(svc),
          mitigation: _getMitigation(svc),
        };
      }
    }

    // 2. Local service map — per-OS commands
    const svcMap = {
      ssh: {
        ubuntu:  { upgrade: 'apt update && apt install --only-upgrade openssh-server', restart: 'systemctl restart ssh',    verify: 'ssh -V' },
        rhel:    { upgrade: 'dnf update openssh-server -y',                             restart: 'systemctl restart sshd',   verify: 'ssh -V' },
        arch:    { upgrade: 'pacman -Syu openssh --noconfirm',                          restart: 'systemctl restart sshd',   verify: 'ssh -V' },
        windows: { upgrade: 'winget upgrade Microsoft.OpenSSH.Beta',                   restart: 'Restart-Service sshd',     verify: 'ssh -V' },
      },
      http: {
        ubuntu:  { upgrade: 'apt update && apt install --only-upgrade apache2',        restart: 'systemctl restart apache2', verify: 'apache2 -v' },
        rhel:    { upgrade: 'dnf update httpd -y',                                      restart: 'systemctl restart httpd',  verify: 'httpd -v' },
        arch:    { upgrade: 'pacman -Syu apache --noconfirm',                           restart: 'systemctl restart httpd',  verify: 'httpd -v' },
        windows: { upgrade: 'winget upgrade Apache.ApacheHTTPServer',                  restart: 'net stop Apache2.4 && net start Apache2.4', verify: 'httpd -v' },
      },
      https: {
        ubuntu:  { upgrade: 'apt update && apt install --only-upgrade apache2 nginx', restart: 'systemctl restart nginx', verify: 'nginx -v' },
        rhel:    { upgrade: 'dnf update nginx -y',                                     restart: 'systemctl restart nginx', verify: 'nginx -v' },
        arch:    { upgrade: 'pacman -Syu nginx --noconfirm',                           restart: 'systemctl restart nginx', verify: 'nginx -v' },
        windows: { upgrade: 'winget upgrade Nginx.Nginx',                              restart: 'net stop nginx && net start nginx', verify: 'nginx -v' },
      },
      ftp: {
        ubuntu:  { upgrade: 'apt remove vsftpd && apt install openssh-server',         restart: 'systemctl restart ssh', verify: 'sftp -V' },
        rhel:    { upgrade: 'dnf remove vsftpd && dnf install openssh-server -y',      restart: 'systemctl restart sshd', verify: 'sftp -V' },
        arch:    { upgrade: 'pacman -Rs vsftpd && pacman -S openssh --noconfirm',      restart: 'systemctl restart sshd', verify: 'sftp -V' },
        windows: { upgrade: 'Disable-WindowsOptionalFeature -Online -FeatureName IIS-FTPServer', restart: 'iisreset /restart', verify: 'ftp -?' },
      },
      telnet: {
        ubuntu:  { upgrade: 'apt remove telnetd && apt install openssh-server',        restart: 'systemctl restart ssh', verify: 'ssh -V' },
        rhel:    { upgrade: 'dnf remove telnet-server && dnf install openssh-server -y',restart: 'systemctl restart sshd', verify: 'ssh -V' },
        arch:    { upgrade: 'pacman -Rs inetutils && pacman -S openssh --noconfirm',   restart: 'systemctl restart sshd', verify: 'ssh -V' },
        windows: { upgrade: 'Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient', restart: '', verify: 'ssh -V' },
      },
      mysql: {
        ubuntu:  { upgrade: 'apt update && apt install --only-upgrade mysql-server',   restart: 'systemctl restart mysql', verify: 'mysql --version' },
        rhel:    { upgrade: 'dnf update mysql-server -y',                              restart: 'systemctl restart mysqld', verify: 'mysql --version' },
        arch:    { upgrade: 'pacman -Syu mysql --noconfirm',                           restart: 'systemctl restart mysqld', verify: 'mysql --version' },
        windows: { upgrade: 'winget upgrade Oracle.MySQL',                             restart: 'net stop MySQL80 && net start MySQL80', verify: 'mysql --version' },
      },
      smb: {
        ubuntu:  { upgrade: 'apt update && apt install --only-upgrade samba',          restart: 'systemctl restart smbd', verify: 'samba --version' },
        rhel:    { upgrade: 'dnf update samba -y',                                     restart: 'systemctl restart smb', verify: 'samba --version' },
        arch:    { upgrade: 'pacman -Syu samba --noconfirm',                           restart: 'systemctl restart smb', verify: 'samba --version' },
        windows: { upgrade: 'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force', restart: 'Restart-Service LanmanServer', verify: 'Get-SmbServerConfiguration | Select EnableSMB1Protocol' },
      },
      rdp: {
        ubuntu:  { upgrade: 'apt update && apt install --only-upgrade xrdp',           restart: 'systemctl restart xrdp', verify: 'xrdp --version' },
        rhel:    { upgrade: 'dnf update xrdp -y',                                      restart: 'systemctl restart xrdp', verify: 'xrdp --version' },
        arch:    { upgrade: 'pacman -Syu xrdp --noconfirm',                            restart: 'systemctl restart xrdp', verify: 'xrdp --version' },
        windows: { upgrade: 'Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V; Set-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server" -Name "NLA" -Value 1', restart: 'Restart-Service TermService', verify: 'qwinsta' },
      },
      snmp: {
        ubuntu:  { upgrade: 'apt update && apt install --only-upgrade snmpd',          restart: 'systemctl restart snmpd', verify: 'snmpd --version' },
        rhel:    { upgrade: 'dnf update net-snmp -y',                                  restart: 'systemctl restart snmpd', verify: 'snmpd --version' },
        arch:    { upgrade: 'pacman -Syu net-snmp --noconfirm',                        restart: 'systemctl restart snmpd', verify: 'snmpd --version' },
        windows: { upgrade: 'Set-Service -Name SNMP -StartupType Disabled; Stop-Service SNMP', restart: '', verify: 'Get-Service SNMP' },
      },
    };

    const osKey = os.startsWith('rhel') || os.startsWith('centos') ? 'rhel' : os;
    const svcOs = svcMap[svc]?.[osKey] || svcMap[svc]?.['ubuntu'];

    if (svcOs) {
      return {
        ...svcOs,
        mitigation: _getMitigation(svc),
      };
    }

    // 3. Generic fallback per OS
    const genericUpgrade = {
      ubuntu:  `apt update && apt install --only-upgrade ${svc || 'package'} -y`,
      rhel:    `dnf update ${svc || 'package'} -y`,
      arch:    `pacman -Syu ${svc || 'package'} --noconfirm`,
      windows: `winget upgrade ${svc || 'package'}`,
    };

    return {
      upgrade: genericUpgrade[osKey] || genericUpgrade.ubuntu,
      mitigation: `• Review if port ${e.port} needs to be exposed\n• Apply latest security patches for ${svc || 'this service'}\n• Restrict access via firewall rules`,
    };
  }

  function _getRestartCmd(svc) {
    const map = { ssh:'systemctl restart ssh', http:'systemctl restart apache2', https:'systemctl restart nginx',
                  mysql:'systemctl restart mysql', smb:'systemctl restart smbd', ftp:'systemctl restart ssh',
                  snmp:'systemctl restart snmpd', rdp:'systemctl restart xrdp' };
    return map[svc] || '';
  }

  function _getVerifyCmd(svc) {
    const map = { ssh:'ssh -V', http:'apache2 -v', https:'nginx -v', mysql:'mysql --version',
                  smb:'samba --version', snmp:'snmpd --version', rdp:'xrdp --version' };
    return map[svc] || `${svc} --version`;
  }

  function _getMitigation(svc) {
    const map = {
      ssh:    '• Disable root login: set PermitRootLogin no in /etc/ssh/sshd_config\n• Use key-based authentication only\n• Enable fail2ban to block brute-force attempts',
      http:   '• Redirect all HTTP traffic to HTTPS immediately\n• Hide server version: ServerTokens Prod\n• Enable HSTS header',
      https:  '• Enforce TLS 1.2+ only — disable SSLv3, TLS 1.0, TLS 1.1\n• Use strong cipher suites (ECDHE + AES-GCM)\n• Enable OCSP stapling and HSTS',
      ftp:    '• Replace FTP with SFTP (SSH File Transfer Protocol)\n• Block port 21 at firewall\n• Disable anonymous FTP login',
      telnet: '• Remove Telnet daemon immediately\n• Install OpenSSH as replacement\n• Block port 23 at firewall',
      smb:    '• Disable SMBv1: set "min protocol = SMB2"\n• Block ports 139/445 at perimeter\n• Enable SMB signing',
      rdp:    '• Place RDP behind VPN — never expose directly to internet\n• Enable Network Level Authentication (NLA)\n• Require MFA for all RDP sessions',
      snmp:   '• Upgrade from SNMPv1/v2c to SNMPv3\n• Change default community strings\n• Restrict SNMP access to monitoring host IPs only',
    };
    return map[svc] || `• Review if this service needs to be exposed\n• Apply latest security patches\n• Restrict access via firewall rules`;
  }

  function _togglePatchExpand(expId, row) {
    const tr    = document.getElementById(expId);
    const arrow = document.getElementById(expId + '-arrow');
    if (!tr) return;
    const open = tr.style.display !== 'none';
    tr.style.display = open ? 'none' : 'table-row';
    if (arrow) arrow.textContent = open ? '▶' : '▼';
    row.classList.toggle('pd-row-open', !open);
  }

  function _switchPatchTab(contentId, tab, btn) {
    const container = document.getElementById(contentId);
    if (!container) return;

    const tabBar = btn?.closest('.pd-tab-bar');
    if (tabBar) {
      tabBar.querySelectorAll('.pd-tab').forEach(t => t.classList.remove('active'));
      btn.classList.add('active');
    }

    const expandRow = container.closest('.pd-expand-row');
    const entryStr  = expandRow?.dataset?.entry;
    const cmdStr    = expandRow?.dataset?.cmds;

    let e, upgCmds;
    try { e = JSON.parse(entryStr || 'null'); } catch(err) { e = null; }
    try { upgCmds = JSON.parse(cmdStr || 'null'); } catch(err) { upgCmds = null; }

    if (!e) return;
    if (!upgCmds) upgCmds = _genPatchCmds(e, _patchOsHint);

    container.style.opacity = '0';
    container.style.transform = 'translateY(4px)';
    setTimeout(() => {
      container.innerHTML = _genTabContent(e, upgCmds, tab);
      container.style.transition = 'opacity .22s ease, transform .22s ease';
      container.style.opacity = '1';
      container.style.transform = 'translateY(0)';
    }, 120);
  }

  function _filterPatchDash(dashId, sev) {
    ['all','critical','high','medium','low'].forEach(s => document.getElementById(`${dashId}-f-${s}`)?.classList.remove('active'));
    document.getElementById(`${dashId}-f-${sev || 'all'}`)?.classList.add('active');
    const rows = document.querySelectorAll(`#${dashId}-body .pd-row`);
    let shown = 0;
    rows.forEach(row => {
      const match = !sev || row.dataset.sev === sev;
      row.style.display = match ? '' : 'none';
      const expId = row.getAttribute('onclick')?.match(/'([^']+)'/)?.[1];
      if (expId) { const exp = document.getElementById(expId); if (exp) exp.style.display = 'none'; }
      if (match) shown++;
    });
    document.getElementById(`${dashId}-cnt`).textContent = `${shown} services shown`;
  }

  function _searchPatchDash(dashId) {
    const q    = document.getElementById(`${dashId}-search`)?.value.toLowerCase() || '';
    const rows = document.querySelectorAll(`#${dashId}-body .pd-row`);
    let shown = 0;
    rows.forEach(row => {
      const match = !q || row.dataset.text.includes(q);
      row.style.display = match ? '' : 'none';
      if (match) shown++;
    });
    document.getElementById(`${dashId}-cnt`).textContent = `${shown} services shown`;
  }

  function _copyPatchCSV(dashId) {
    const rows  = document.querySelectorAll(`#${dashId}-body .pd-row`);
    const lines = ['Port,Service,CVE,Severity,Risk Score,Version,Priority'];
    rows.forEach(row => {
      const cells = row.querySelectorAll('td');
      lines.push([
        cells[0]?.textContent.trim(),
        cells[1]?.textContent.trim().split('\n')[0],
        cells[2]?.querySelector('.vt-cve-link')?.textContent.trim() || '—',
        cells[3]?.textContent.trim(),
        cells[4]?.querySelector('.vd-cvss-num')?.textContent.trim(),
        cells[5]?.textContent.trim(),
        cells[7]?.textContent.trim(),
      ].join(','));
    });
    navigator.clipboard.writeText(lines.join('\n'));
  }


  /* ═══════════════════════════════════════════════════════
     /patch <ip> <port> — SINGLE PORT GUIDANCE
  ═══════════════════════════════════════════════════════ */

  async function _handlePatchCommand(ip, port) {
    if (!ip || !port) {
      addMsg('**Patch Command Usage:**\n- `/patch all` — Full remediation dashboard for all services\n- `/patch <ip> <port>` — Specific port guidance, e.g. `/patch 192.168.1.1 22`\n- `/patch add <CVE> <pkg> <os> <cmd>` — Manually add a patch to the repository', 'ai');
      return;
    }
    const t = addTyping();
    try {
      const d = await ApiService.sendChatMessage(`/patch ${ip} ${port}`, ip, App.getCurrentSession() || '');
      t.remove();
      if (d.patch_data) _renderPatchCard(ip, port, d.patch_data);
      else _renderPatchCard(ip, port, null, d.reply);
    } catch (e) {
      t.remove();
      addMsg(`Patch lookup error: ${e.message}`, 'ai');
    }
  }

  function _renderPatchCard(ip, port, data, rawText) {
    const chat = document.getElementById('chat');
    const d    = document.createElement('div');
    d.className = 'msg msg-ai patch-card-wrap';
    if (rawText) {
      d.innerHTML = `
        <div class="patch-header">
          <span class="patch-badge">🔧 Patch Guidance</span>
          <span class="patch-target">${ip}:${port}</span>
        </div>
        <div class="patch-body">${Utils.renderMarkdown(rawText)}</div>`;
    } else if (data) {
      const sev = data.severity || 'medium';
      d.innerHTML = `
        <div class="patch-header">
          <span class="patch-badge">🔧 Patch Guidance</span>
          <span class="patch-target">${ip}:${port}</span>
          <span class="rb rb-${sev}">${sev}</span>
        </div>
        <div class="patch-sections">
          ${data.summary ? `<div class="patch-section"><div class="ps-title">📋 Summary</div><div class="ps-body">${data.summary}</div></div>` : ''}
          ${data.upgrade_cmd ? `<div class="patch-section"><div class="ps-title">⬆️ Upgrade</div><div class="pd-cmd-row"><code class="pd-cmd">${data.upgrade_cmd}</code><button class="vt-copy-btn" onclick="navigator.clipboard.writeText('${data.upgrade_cmd.replace(/'/g,"\\'")}');this.textContent='✅';setTimeout(()=>this.textContent='📋',1500)">📋</button></div></div>` : ''}
          ${data.mitigation ? `<div class="patch-section"><div class="ps-title">🛡 Mitigation</div><div class="ps-body">${data.mitigation}</div></div>` : ''}
        </div>`;
    }
    d.style.opacity = '0'; d.style.transform = 'translateY(6px)';
    chat.appendChild(d);
    requestAnimationFrame(() => { d.style.transition = 'opacity .25s ease, transform .25s ease'; d.style.opacity = '1'; d.style.transform = 'translateY(0)'; });
    chat.scrollTo({ top: chat.scrollHeight, behavior: 'smooth' });
  }


  /* ═══════════════════════════════════════════════════════
     /patch add — MANUAL PATCH STORE  (NEW)
     Usage: /patch add <CVE-ID> <package> <os-family> <command>
     Example: /patch add CVE-2024-6387 openssh ubuntu "apt-get install -y openssh-server=9.8p1"
  ═══════════════════════════════════════════════════════ */

  async function _cmdPatchAdd(parts) {
    // parts: ['/patch', 'add', <cve>, <pkg>, <os>, ...rest=<cmd>]
    const cveId = parts[2] || '';
    const pkg   = parts[3] || '';
    const os    = parts[4] || 'ubuntu';
    const cmd   = parts.slice(5).join(' ').replace(/^["']|["']$/g, '');

    if (!cveId || !pkg) {
      addMsg(
        '**Usage:** `/patch add <CVE-ID> <package> <os-family> <command>`\n\n' +
        '**Example:**\n```\n/patch add CVE-2024-6387 openssh ubuntu "apt-get install -y openssh-server"\n```\n\n' +
        '**Supported OS families:** `ubuntu` · `rhel` · `arch` · `windows`\n\n' +
        'The patch will be stored in the local repository and used as the primary resolution for this CVE.',
        'ai'
      );
      return;
    }

    const t = addTyping();
    try {
      const resp = await fetch('/api/patch/add', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({
          cve_id:        cveId.toUpperCase(),
          vendor:        pkg,
          product:       pkg,
          fixed_version: '',
          commands:      { [os]: cmd },
          confidence:    90,
        }),
      });
      t.remove();

      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        addMsg(`❌ Failed to store patch: ${err.detail || resp.statusText}`, 'ai');
        return;
      }

      const data = await resp.json();
      addMsg(
        `✅ **Patch stored successfully**\n\n` +
        `**CVE:** \`${cveId.toUpperCase()}\`\n` +
        `**Package:** \`${pkg}\`\n` +
        `**OS:** \`${os}\`\n` +
        `**Command:** \`${cmd || '(none)'}\`\n\n` +
        `This patch is now in the local repository (Layer 1). Future \`/patch\` calls for \`${cveId.toUpperCase()}\` will use it as the primary resolution.`,
        'ai'
      );
    } catch (e) {
      t.remove();
      addMsg(`❌ Patch store error: ${e.message}`, 'ai');
    }
  }


  /* ═══════════════════════════════════════════════════════
     HELP CARD
  ═══════════════════════════════════════════════════════ */

  function _showHelpCard() {
    const chat = document.getElementById('chat');
    const d    = document.createElement('div');
    d.className = 'msg msg-ai help-card';
    const cmds = [
      { icon:'🔧', cmd:'/patch all',              label:'/patch all',                      desc:'Full remediation dashboard for all vulnerabilities' },
      { icon:'🔧', cmd:'/patch 192.168.1.1 22',   label:'/patch &lt;ip&gt; &lt;port&gt;',  desc:'Patch guidance for a specific port' },
      { icon:'➕', cmd:'/patch add CVE-2024-6387 openssh ubuntu ""', label:'/patch add &lt;CVE&gt; &lt;pkg&gt; &lt;os&gt; &lt;cmd&gt;', desc:'Add a custom patch to the local patch repository' },
      { icon:'🔎', cmd:'/vuln',                   label:'/vuln',                            desc:'CVE intelligence dashboard from last scan' },
      { icon:'📄', cmd:'/report pdf',             label:'/report [pdf|html]',               desc:'Export the last scan report as PDF or HTML' },
      { icon:'⚙️', cmd:'/settings',               label:'/settings',                        desc:'View current configuration' },
      { icon:'🗑️', cmd:'/clear',                  label:'/clear',                           desc:'Clear this chat window' },
      { icon:'⏹️', cmd:'/stop',                   label:'/stop',                            desc:'Abort the running scan' },
    ];
    d.innerHTML = `
      <div class="help-title">📖 &nbsp;ThreatWeave AI — Commands</div>
      <div class="help-grid">${cmds.map(c => `
        <div class="help-cmd" onclick="_helpCmdClick(this,'${c.cmd}')">
          <span class="hc-badge">${c.icon}</span>
          <div class="hc-info"><span class="hc-name">${c.label}</span><span class="hc-desc">${c.desc}</span></div>
        </div>`).join('')}</div>
      <div class="help-tip">✨ Click any card to run the command instantly</div>`;
    chat.appendChild(d);
    chat.scrollTo({ top: chat.scrollHeight, behavior: 'smooth' });
  }

  window._helpCmdClick = function(el, cmd) {
    el.style.background = 'rgba(37,99,235,0.45)'; el.style.borderColor = '#60a5fa';
    setTimeout(() => { el.style.background = ''; el.style.borderColor = ''; Chatbot.quickChat(cmd); }, 180);
  };

