/**
 * chatbot/patch.js
 * /patch remediation dashboard, single-port guidance, /help.
 */


  /* ═══════════════════════════════════════════════════════
     /patch all — PREMIUM REMEDIATION DASHBOARD
  ═══════════════════════════════════════════════════════ */

  async function _handlePatchAll() {
    const data  = App.getLastData();
    const ai    = data?.ai_analysis || {};

    // ── Use cumulative merged ports (all scans in this session) ──
    // Falls back to lastData ports so a single-scan session still works.
    const cumulative  = SessionManager.getCumulativeState();
    const cumulPorts  = cumulative?.ports?.length ? cumulative.ports : null;
    const lastHosts   = data?.risk?.hosts || [];
    const lastPorts   = lastHosts.flatMap(h => h.ports || []);

    // Prefer cumulative (covers multi-scan sessions); fall back to last scan
    const allPorts = cumulPorts || lastPorts;

    if (!allPorts.length && !lastPorts.length) {
      addMsg('No scan data found. Run a scan first, then try `/patch all` again.', 'ai');
      return;
    }

    // Build remediation entries from every port across all scans
    const entries = [];
    for (const p of allPorts) {
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
      });
    }

    if (!entries.length) {
      addMsg('No scan data found. Run a scan first, then try `/patch all` again.', 'ai');
      return;
    }

    entries.sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3 };
      return (order[a.risk_level] || 3) - (order[b.risk_level] || 3);
    });

    _renderPatchDashboard(entries);
  }

  function _renderPatchDashboard(entries) {
    const dashId  = 'pd-' + Date.now();
    const counts  = { critical: 0, high: 0, medium: 0, low: 0 };
    entries.forEach(e => counts[e.risk_level] = (counts[e.risk_level] || 0) + 1);
    const immediate = entries.filter(e => ['critical','high'].includes(e.risk_level)).length;

    const chat = document.getElementById('chat');
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
      </div>
    `;

    wrap.style.opacity = '0'; wrap.style.transform = 'translateY(8px)';
    chat.appendChild(wrap);
    requestAnimationFrame(() => {
      wrap.style.transition = 'opacity .3s ease, transform .3s ease';
      wrap.style.opacity = '1'; wrap.style.transform = 'translateY(0)';
    });
    chat.scrollTo({ top: chat.scrollHeight, behavior: 'smooth' });
    // Persist as rich token for session restore
    _saveRichMsg('PATCH_DASH', entries);
  }

  function _patchRow(e, i, dashId) {
    const expId    = `${dashId}-exp-${i}`;
    const sev      = e.severity.toLowerCase();
    const pri      = e.ai_priority.toLowerCase();
    const pctScore = Math.min((e.risk_score || e.cvss || 0) * 10, 100);
    const hasPatch = !!e.patch_note || !!e.ai_action;
    const patchStatus = hasPatch
      ? `<span class="pd-patch-avail">✅ Available</span>`
      : `<span class="pd-patch-none">🔍 Research</span>`;
    const priorityBadge = `<span class="pd-pri pd-pri-${pri}">${pri.toUpperCase()}</span>`;

    // Generate smart patch commands based on service
    const upgCmds = _genPatchCmds(e);

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
      <tr class="pd-expand-row" id="${expId}" style="display:none">
        <td colspan="9">
          <div class="pd-expand-body">
            <div class="pd-exp-grid">
              <div class="pd-exp-section">
                <div class="pd-exp-title">📋 Vulnerability Summary</div>
                <div class="pd-exp-text">${e.cve_desc || 'No description available.'}</div>
                ${e.reasons.length ? `<div class="pd-exp-reasons">${e.reasons.map(r => `<div class="pd-reason">• ${r}</div>`).join('')}</div>` : ''}
              </div>
              <div class="pd-exp-section">
                <div class="pd-exp-title">📦 Affected Software</div>
                <div class="pd-exp-text">
                  <div>Service: <code>${e.service}</code></div>
                  <div>Current: <code style="color:var(--orange)">${e.version || 'unknown'}</code></div>
                  ${e.cve !== '—' ? `<div>CVE: <code>${e.cve}</code> (CVSS ${e.cvss})</div>` : ''}
                </div>
              </div>
            </div>

            ${upgCmds.upgrade ? `
            <div class="pd-exp-cmd-block">
              <div class="pd-exp-title">⬆️ Upgrade Command</div>
              <div class="pd-cmd-row">
                <code class="pd-cmd">${upgCmds.upgrade}</code>
                <button class="vt-copy-btn" onclick="navigator.clipboard.writeText('${upgCmds.upgrade.replace(/'/g,"\\'")}');this.textContent='✅';setTimeout(()=>this.textContent='📋',1500)">📋</button>
              </div>
            </div>` : ''}

            ${e.ai_action ? `
            <div class="pd-exp-cmd-block">
              <div class="pd-exp-title">🤖 AI Recommendation</div>
              <div class="pd-exp-text">${e.ai_action}</div>
            </div>` : ''}

            ${upgCmds.mitigation ? `
            <div class="pd-exp-cmd-block">
              <div class="pd-exp-title">🛡️ Mitigation</div>
              <div class="pd-exp-text">${upgCmds.mitigation}</div>
            </div>` : ''}

            ${upgCmds.restart ? `
            <div class="pd-exp-cmd-block">
              <div class="pd-exp-title">🔄 Restart Service</div>
              <div class="pd-cmd-row">
                <code class="pd-cmd">${upgCmds.restart}</code>
                <button class="vt-copy-btn" onclick="navigator.clipboard.writeText('${upgCmds.restart.replace(/'/g,"\\'")}');this.textContent='✅';setTimeout(()=>this.textContent='📋',1500)">📋</button>
              </div>
            </div>` : ''}

            ${upgCmds.verify ? `
            <div class="pd-exp-cmd-block">
              <div class="pd-exp-title">✅ Verify Fix</div>
              <div class="pd-cmd-row">
                <code class="pd-cmd">${upgCmds.verify}</code>
                <button class="vt-copy-btn" onclick="navigator.clipboard.writeText('${upgCmds.verify.replace(/'/g,"\\'")}');this.textContent='✅';setTimeout(()=>this.textContent='📋',1500)">📋</button>
              </div>
            </div>` : ''}

            <div class="pd-exp-actions">
              ${e.cve !== '—' ? `<a class="vd-exp-btn" href="https://nvd.nist.gov/vuln/detail/${e.cve}" target="_blank" rel="noopener">🔗 NVD Advisory</a>` : ''}
              <button class="vd-exp-btn" onclick="Chatbot.quickChat('/patch ${e.service} ${e.port}')">💬 Ask AI for Full Guide</button>
              ${e.patch_note ? `<div class="pd-exp-text" style="margin-top:8px"><strong>Official patch note:</strong> ${e.patch_note}</div>` : ''}
            </div>
          </div>
        </td>
      </tr>`;
  }

  function _genPatchCmds(e) {
    const svc = (e.service || '').toLowerCase();
    const map = {
      ssh:    { upgrade: 'apt update && apt install --only-upgrade openssh-server', restart: 'systemctl restart ssh', verify: 'ssh -V', mitigation: 'Disable root login: set PermitRootLogin no in /etc/ssh/sshd_config. Use key-based auth only.' },
      http:   { upgrade: 'apt update && apt install --only-upgrade apache2', restart: 'systemctl restart apache2', verify: 'apache2 -v', mitigation: 'Redirect HTTP to HTTPS. Hide server version: ServerTokens Prod in apache2.conf.' },
      https:  { upgrade: 'apt update && apt install --only-upgrade apache2 nginx', restart: 'systemctl restart nginx', verify: 'nginx -v', mitigation: 'Enforce TLS 1.2+ only. Disable SSLv3, TLS 1.0/1.1.' },
      ftp:    { upgrade: 'apt remove vsftpd && apt install sftp', restart: 'systemctl restart ssh', verify: 'sftp -V', mitigation: 'Replace FTP with SFTP. Disable anonymous access. Block port 21 at firewall.' },
      telnet: { upgrade: 'apt remove telnetd && apt install openssh-server', restart: 'systemctl restart ssh', verify: 'ssh -V', mitigation: 'Remove Telnet entirely. Use SSH. Block port 23 at firewall.' },
      mysql:  { upgrade: 'apt update && apt install --only-upgrade mysql-server', restart: 'systemctl restart mysql', verify: 'mysql --version', mitigation: 'Bind to 127.0.0.1 only. Disable remote root login. Use mysql_secure_installation.' },
      smb:    { upgrade: 'apt update && apt install --only-upgrade samba', restart: 'systemctl restart smbd', verify: 'samba --version', mitigation: 'Disable SMBv1. Block ports 139/445 at firewall perimeter. Enable SMB signing.' },
      rdp:    { upgrade: 'Enable Network Level Authentication (NLA) in System Properties > Remote', restart: 'net stop termservice && net start termservice', verify: 'qwinsta', mitigation: 'Put RDP behind VPN. Restrict by IP. Enable NLA. Rename default RDP port.' },
      snmp:   { upgrade: 'apt update && apt install --only-upgrade snmpd', restart: 'systemctl restart snmpd', verify: 'snmpd --version', mitigation: 'Upgrade to SNMPv3. Change community strings. Restrict to monitoring host IPs only.' },
    };
    return map[svc] || { upgrade: `apt update && apt install --only-upgrade ${svc || 'package'}`, mitigation: `Review if port ${e.port} needs to be exposed. Apply latest security patches.` };
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
    const q   = document.getElementById(`${dashId}-search`)?.value.toLowerCase() || '';
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
      addMsg('**Patch Command Usage:**\n- `/patch all` — Full remediation dashboard for all services\n- `/patch <ip> <port>` — Specific port guidance, e.g. `/patch 192.168.1.1 22`', 'ai');
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
    // Persist so the card survives session restore / history reload
    _saveRichMsg('PATCH_CARD', { ip, port, data: data || null, rawText: rawText || null });
  }

  /* ═══════════════════════════════════════════════════════
     HELP CARD
  ═══════════════════════════════════════════════════════ */

  function _showHelpCard() {
    const chat = document.getElementById('chat');
    const d    = document.createElement('div');
    d.className = 'msg msg-ai help-card';
    const cmds = [
      { icon:'🔧', cmd:'/patch all',           label:'/patch all',                   desc:'Full remediation dashboard for all vulnerabilities' },
      { icon:'🔧', cmd:'/patch 192.168.1.1 22',label:'/patch &lt;ip&gt; &lt;port&gt;',desc:'Patch guidance for a specific port' },
      { icon:'🔎', cmd:'/vuln',               label:'/vuln',                         desc:'CVE intelligence dashboard from last scan' },
      { icon:'📄', cmd:'/report pdf',         label:'/report [pdf|html]',            desc:'Export the last scan report as PDF or HTML' },
      { icon:'⚙️', cmd:'/settings',           label:'/settings',                     desc:'View current configuration' },
      { icon:'🗑️', cmd:'/clear',              label:'/clear',                        desc:'Clear this chat window' },
      { icon:'⏹️', cmd:'/stop',               label:'/stop',                         desc:'Abort the running scan' },
    ];
    d.innerHTML = `
      <div class="help-title">📖 &nbsp;ScanWise AI — Commands</div>
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

  /* ═══════════════════════════════════════════════════════
     RENDER PANELS
  ═══════════════════════════════════════════════════════ */
