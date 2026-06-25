/**
 * chatbot/commands.js
 * Autocomplete, message sending, slash-command dispatcher.
 */

  /* ── Autocomplete ─────────────────────────────────────────── */

  function onChatInput(event) {
    const val = event.target.value;
    const ac  = document.getElementById('chat-autocomplete');
    if (!ac) return;
    if (!val.startsWith('/') || val.includes(' ')) { ac.style.display = 'none'; _autocompleteIdx = -1; return; }
    const matches = SLASH_CMDS.filter(c => c.cmd.startsWith(val.toLowerCase()));
    if (!matches.length) { ac.style.display = 'none'; return; }
    ac.innerHTML = matches.map(c => `
      <div class="ac-item" data-cmd="${c.hint}" onmousedown="Chatbot.selectAutocomplete('${c.hint}')">
        <span class="ac-cmd">${c.hint}</span>
        <span class="ac-desc">${c.desc}</span>
      </div>`).join('');
    ac.style.display = 'block';
    _autocompleteIdx = -1;
  }

  function onChatKeyDown(event) {
    const ac    = document.getElementById('chat-autocomplete');
    const items = ac ? ac.querySelectorAll('.ac-item') : [];
    if (ac && ac.style.display !== 'none' && items.length) {
      if (event.key === 'ArrowDown')  { event.preventDefault(); _autocompleteIdx = Math.min(_autocompleteIdx + 1, items.length - 1); items.forEach((el,i) => el.classList.toggle('active', i === _autocompleteIdx)); return; }
      if (event.key === 'ArrowUp')    { event.preventDefault(); _autocompleteIdx = Math.max(_autocompleteIdx - 1, 0); items.forEach((el,i) => el.classList.toggle('active', i === _autocompleteIdx)); return; }
      if (event.key === 'Tab' || (event.key === 'Enter' && _autocompleteIdx >= 0)) { event.preventDefault(); const active = items[_autocompleteIdx >= 0 ? _autocompleteIdx : 0]; if (active) selectAutocomplete(active.dataset.cmd); return; }
      if (event.key === 'Escape') { ac.style.display = 'none'; return; }
    }
    if (event.key === 'Enter') sendChat();
  }

  function selectAutocomplete(hint) {
    const inp = document.getElementById('chat-inp');
    if (inp) inp.value = hint;
    const ac = document.getElementById('chat-autocomplete');
    if (ac) ac.style.display = 'none';
    inp && inp.focus();
  }

  /* ── Send / handle ─────────────────────────────────────────── */

  /* ═══════════════════════════════════════════════════════
     FIX 1 — CENTRALIZED SLASH COMMAND PARSER
     Validates, routes, handles loading states + errors.
  ═══════════════════════════════════════════════════════ */

  // Command registry — single source of truth for all commands
  // Phase 19: Full slash command registry
  const CMD_REGISTRY = {
    '/graph':     { fn: _cmdGraph,     needsScan: false, desc: 'Open a graph in a new tab' },
    '/scan':      { fn: _cmdScan,      needsScan: false, desc: 'Scan a target' },
    '/patch':     { fn: _cmdPatch,     needsScan: false, desc: 'Patch guidance (/patch all, /patch <svc> <port>, /patch add)' },
    '/vuln':      { fn: _cmdVuln,      needsScan: true,  desc: 'CVE dashboard' },
    '/report':    { fn: _cmdReport,    needsScan: true,  desc: 'Export report' },
    '/risk':      { fn: _cmdRisk,      needsScan: false, desc: 'Security score + risk breakdown' },
    '/remediate': { fn: _cmdRemediate, needsScan: true,  desc: 'Full remediation dashboard' },
    '/cve':       { fn: _cmdCveSearch, needsScan: false, desc: 'CVE intelligence lookup' },
    '/export':    { fn: _cmdExport,    needsScan: true,  desc: 'Export report' },
    '/projects':  { fn: _cmdProjects,  needsScan: false, desc: 'List projects' },
    '/model':     { fn: _cmdModel,     needsScan: false, desc: 'Model status' },
    '/history':   { fn: _cmdHistory,   needsScan: false, desc: 'Scan history' },
    '/settings':  { fn: _cmdSettings,  needsScan: false, desc: 'Configuration' },
    '/clear':     { fn: _cmdClear,     needsScan: false, desc: 'Clear chat' },
    '/stop':      { fn: _cmdStop,      needsScan: false, desc: 'Stop scan' },
    '/help':      { fn: _cmdHelp,      needsScan: false, desc: 'Show commands' },
  };

  async function _dispatchCommand(cmd, parts, msg) {
    const entry = CMD_REGISTRY[cmd];
    if (!entry) {
      // Unknown command — pass to AI
      return false;
    }
    // Validate: commands that need scan data
    if (entry.needsScan && !App.getLastData()) {
      const activeSess = SessionManager.active();
      if (activeSess?.scan_results) { App.setLastData(activeSess.scan_results); if (activeSess.scan_session) App.setCurrentSession(activeSess.scan_session); }
    }
    if (entry.needsScan && !App.getLastData()) {
      addMsg('⚠️ **`' + cmd + '`** requires a completed scan. Run `/scan <ip>` first.', 'ai');
      return true;
    }
    try {
      await entry.fn(parts);
    } catch (e) {
      const errEl = addMsg(`❌ **Command error:** ${e.message || 'Unknown error'}`, 'ai');
      if (errEl) errEl.classList.add('cmd-error');
    }
    return true;
  }

  function _normalizeTarget(raw) {
    if (!raw) return raw;
    // Auto-correct "10.83.113,112" → "10.83.113.112"
    const m = raw.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3}),(\d{1,3})$/);
    return m ? `${m[1]}.${m[2]}.${m[3]}.${m[4]}` : raw;
  }

  async function _cmdScan(parts)     { if (parts[1]) { _autoStartVulnScan(_normalizeTarget(parts[1])); } else { _promptScanIP(); } }
  async function _cmdPatch(parts)    {
    const sub = (parts[1] || '').toLowerCase();
    if (sub === 'all')  { await _handlePatchAll(); }
    else if (sub === 'add') { await _cmdPatchAdd(parts); }  // NEW: /patch add
    else { await _handlePatchCommand(parts[1], parts[2]); }
  }
  async function _cmdVuln()          { await _handleVulnCommand(); }
  async function _cmdReport(parts) {
    const fmt = (parts[1] || '').toLowerCase();
    if (fmt && !['pdf','html'].includes(fmt)) { addMsg('⚠️ `/report` supports: `pdf` or `html` only.', 'ai'); return; }
    if (!App.getCurrentSession()) { addMsg('⚠️ Run a scan first to generate a report.', 'ai'); return; }
    if (fmt) { selectFmt(fmt); await doExportReport(); }
    else { showReportModal(); }
  }
  async function _cmdSettings()      { const sessionId = App.getCurrentSession() || ''; const t = addTyping(); try { const d = await ApiService.sendChatMessage('/settings', _currentTarget, sessionId, SessionManager.getProjectName()); t.remove(); addMsg(d.reply, 'ai'); } catch(e) { t.remove(); addMsg('Cannot reach server.', 'ai'); } }
  async function _cmdClear() {
    // Fix #12: clear frontend AND persist clear to backend
    const chat = document.getElementById('chat');
    if (chat) chat.innerHTML = '';
    SessionManager.create(); // new fresh session
    showGreeting();
  }
  async function _cmdStop()          { confirmStop(); }
  async function _cmdHelp()          { _showHelpCard(); }

  function _cmdGraph() {
    const chat = document.getElementById('chat');
    if (!chat) return;

    const hasScan = !!App.getLastData();

    const wrap = document.createElement('div');
    wrap.className = 'msg msg-ai graph-picker-wrap';
    wrap.innerHTML = `
      <div class="gp-title">📈 Open a graph <span class="gp-tab-badge">↗ opens in new tab</span></div>
      <div class="gp-subtitle">Select a graph type to visualise your scan data</div>
      <div class="gp-grid">
        <div class="gp-card" onclick="Chatbot._openGraph('osint')">
          <div class="gp-card-icon">🕸</div>
          <div class="gp-card-body">
            <div class="gp-card-name">Infrastructure Intelligence Graph</div>
            <div class="gp-card-desc">Interactive click-to-expand intelligence tree. Reveals host → ports → services → CVEs progressively.</div>
            ${!hasScan ? '<div class="gp-card-warn">⚠ Run a scan first for live data</div>' : ''}
          </div>
          <div class="gp-card-arrow">↗</div>
        </div>
        <div class="gp-card" onclick="Chatbot._openGraph('dashboard')">
          <div class="gp-card-icon">📊</div>
          <div class="gp-card-body">
            <div class="gp-card-name">Vulnerability Intelligence Dashboard</div>
            <div class="gp-card-desc">SOC-style view — severity donut, risk radar, CVE bar chart, service breakdown, and trend lines.</div>
            ${!hasScan ? '<div class="gp-card-warn">⚠ Run a scan first for live data</div>' : ''}
          </div>
          <div class="gp-card-arrow">↗</div>
        </div>
      </div>`;

    wrap.style.opacity = '0';
    wrap.style.transform = 'translateY(6px)';
    chat.appendChild(wrap);
    requestAnimationFrame(() => {
      wrap.style.transition = 'opacity .25s ease, transform .25s ease';
      wrap.style.opacity = '1';
      wrap.style.transform = 'translateY(0)';
    });
    chat.scrollTo({ top: chat.scrollHeight, behavior: 'smooth' });
  }

  function _openGraph(type) {
    const data = App.getLastData();
    try {
      localStorage.setItem('threatweave_graph_type', type);
      localStorage.setItem('threatweave_graph_data', data ? JSON.stringify(data) : '');
    } catch (e) {
      addMsg('Could not write graph data to localStorage: ' + e.message, 'ai');
      return;
    }
    window.open('graph_viewer.html?type=' + type, '_blank');
  }
  // Phase 19: New slash command handlers
  async function _cmdRisk(parts) {
    const sessionId = App.getCurrentSession() || '';
    const t = addTyping();
    try {
      const d = await ApiService.sendChatMessage('/risk', _currentTarget, sessionId, SessionManager.getProjectName());
      t.remove();
      addMsg(d.reply || 'No risk data available. Run a scan first.', 'ai');
    } catch(e) { t.remove(); addMsg('❌ Risk command error: ' + (e.message || e), 'ai'); }
  }

  async function _cmdRemediate(parts) {
    // Same as /patch all
    await _handlePatchAll();
  }

  async function _cmdCveSearch(parts) {
    const cveId = parts[1] || '';
    const sessionId = App.getCurrentSession() || '';
    const t = addTyping();
    try {
      const d = await ApiService.sendChatMessage('/cve ' + cveId, _currentTarget, sessionId, SessionManager.getProjectName());
      t.remove();
      addMsg(d.reply || `No data found for ${cveId}`, 'ai');
    } catch(e) { t.remove(); addMsg('❌ CVE lookup error: ' + (e.message || e), 'ai'); }
  }

  async function _cmdExport(parts) {
    const fmt = (parts[1] || 'html').toLowerCase();
    if (!['pdf','html','json'].includes(fmt)) {
      addMsg('⚠️ `/export` supports: `pdf`, `html`, or `json`', 'ai'); return;
    }
    await _cmdReport([null, fmt]);
  }

  async function _cmdProjects(parts) {
    const sessionId = App.getCurrentSession() || '';
    const t = addTyping();
    try {
      const d = await ApiService.sendChatMessage('/projects', _currentTarget, sessionId, SessionManager.getProjectName());
      t.remove();
      addMsg(d.reply || 'No projects found.', 'ai');
    } catch(e) { t.remove(); addMsg('❌ Projects error: ' + (e.message || e), 'ai'); }
  }

  async function _cmdHistory(parts) {
    addMsg('📁 Use the **sidebar drawer** (☰ button) to browse all scan history and past projects.', 'ai');
  }

  async function sendChat() {
    const inp = document.getElementById('chat-inp');
    const msg = inp.value.trim();
    if (!msg) return;
    inp.value = '';
    const ac = document.getElementById('chat-autocomplete');
    if (ac) ac.style.display = 'none';

    const parts = msg.split(/\s+/);
    const cmd   = parts[0].toLowerCase();

    // Always show user message first
    addMsg(msg, 'user');

    // Try slash command dispatch (Fix 1)
    if (cmd.startsWith('/')) {
      const handled = await _dispatchCommand(cmd, parts, msg);
      if (handled) return;
      // Unknown slash command — fall through to AI with error hint
      const t = addTyping();
      _updateModelIndicator({ checking: true });
      const t0 = Date.now();
      try {
        const d = await ApiService.sendChatMessage(msg, _currentTarget, App.getCurrentSession() || '', SessionManager.getProjectName());
        const latency = Date.now() - t0;
        _lastLatency = latency;
        t.remove();
        const el = addMsg(d.reply, 'ai');
        _updateModelIndicator({ latency, provider: d.model });
        _handleAction(d);
      } catch (e) {
        t.remove();
        _updateModelIndicator({ error: true });
        addMsg(`❌ Unknown command \`${cmd}\`. Type \`/help\` to see all available commands.`, 'ai');
      }
      return;
    }

    // Natural language → AI
    const sessionId = App.getCurrentSession() || '';
    const t = addTyping();
    _updateModelIndicator({ checking: true });
    const t0 = Date.now();
    try {
      const d = await ApiService.sendChatMessage(msg, _currentTarget, sessionId, SessionManager.getProjectName());
      const latency = Date.now() - t0;
      _lastLatency = latency; _lastTokens = d.tokens || null;
      t.remove();
      addMsg(d.reply, 'ai');
      _updateModelIndicator({ latency, provider: d.model });
      _handleAction(d);
    } catch (e) {
      t.remove();
      _updateModelIndicator({ error: true });
      addMsg('❌ Cannot reach server. Check your connection and try again.', 'ai');
    }
  }

  function quickChat(m) {
    document.getElementById('chat-inp').value = m;
    sendChat();
  }

  /* SESSION RESUME: restore messages with scroll position */
  function restoreChatMessages(messages, scrollPos) {
    if (!messages || !messages.length) return;
    const chat = document.getElementById('chat');
    // Only clear if we actually have content to render
    const validMsgs = messages.filter(m => m && m.text && m.type);
    if (!validMsgs.length) return;
    chat.innerHTML = '';

    // Show a subtle restore banner
    const banner = document.createElement('div');
    banner.className = 'session-restored-banner';
    banner.innerHTML = '🔄 Session restored — continuing where you left off';
    chat.appendChild(banner);
    setTimeout(() => { if (banner.parentNode) banner.remove(); }, 4000);

    // Batch render: build DOM fragment then insert (avoids reflow per-message)
    const frag = document.createDocumentFragment();
    let count = 0;
    const INITIAL_RENDER = 60; // render last N messages immediately

    // If too many messages, only render tail
    const toRender = validMsgs.length > INITIAL_RENDER
      ? validMsgs.slice(-INITIAL_RENDER)
      : validMsgs;

    if (validMsgs.length > INITIAL_RENDER) {
      const skipped = document.createElement('div');
      skipped.className = 'msg msg-sys';
      skipped.textContent = `↑ ${validMsgs.length - INITIAL_RENDER} earlier messages (scroll up to load)`;
      chat.appendChild(skipped);
    }

    for (const m of toRender) {
      // Reconstruct greeting card from saved token
      if (m.type === 'ai' && typeof m.text === 'string' && m.text.startsWith('__GREETING__:')) {
        const pName = m.text.slice('__GREETING__:'.length);
        const d = document.createElement('div');
        d.className = 'msg msg-ai';
        d.innerHTML = `
          <div class="post-ob-msg">
            <span style="color:var(--purple);font-weight:700">📁 ${pName}</span>
            &nbsp;— workspace active. You can now:
          </div>
          <div class="post-ob-actions">
            <button class="post-ob-btn" onclick="Chatbot._promptScanIP()">
              <span class="pob-icon">🔍</span>
              <span class="pob-text"><strong>Scan a Target</strong><small>TCP, UDP, OS, service fingerprinting</small></span>
            </button>
            <button class="post-ob-btn" onclick="Chatbot.quickChat('/vuln')">
              <span class="pob-icon">🔎</span>
              <span class="pob-text"><strong>Vulnerability Intelligence</strong><small>All CVEs from last scan session</small></span>
            </button>
            <button class="post-ob-btn" onclick="Chatbot.quickChat('/patch all')">
              <span class="pob-icon">🔧</span>
              <span class="pob-text"><strong>Patch All Vulnerabilities</strong><small>Full remediation dashboard</small></span>
            </button>
            <button class="post-ob-btn" onclick="Chatbot.quickChat('/report html')">
              <span class="pob-icon">📄</span>
              <span class="pob-text"><strong>Generate Report</strong><small>Export PDF or HTML</small></span>
            </button>
            <button class="post-ob-btn" onclick="Chatbot.quickChat('/help')">
              <span class="pob-icon">📖</span>
              <span class="pob-text"><strong>All Commands</strong><small>Full slash command reference</small></span>
            </button>
          </div>
          <div class="post-ob-hint">What would you like to do first?</div>`;
        frag.appendChild(d);
        count++;
        continue;
      }

      // Reconstruct rich structured widgets from saved tokens
      if (m.type === 'rich' && typeof m.text === 'string') {
        const richMatch = m.text.match(/^__([A-Z_]+)__:(.+)$/s);
        if (richMatch) {
          try {
            const tokenType = richMatch[1];
            const data = JSON.parse(richMatch[2]);
            _restoreRichWidget(tokenType, data, frag);
            count++;
          } catch (e) { /* skip malformed token */ }
          continue;
        }
      }

      const d = document.createElement('div');
      d.className = `msg msg-${m.type}`;
      d.innerHTML = Utils.renderMarkdown(m.text);
      frag.appendChild(d);
      count++;
    }
    chat.appendChild(frag);

    // Restore scroll position (Fix 7)
    requestAnimationFrame(() => {
      if (scrollPos && scrollPos > 100) {
        chat.scrollTop = scrollPos;
      } else {
        chat.scrollTo({ top: chat.scrollHeight, behavior: 'instant' });
      }
    });
  }

  /* ── Action dispatcher ─────────────────────────────────────── */

  function _handleAction(d) {
    if (!d.action || d.action === 'none') return;
    switch (d.action) {
      case 'show_scan_selector': if (d.data?.target) _autoStartVulnScan(d.data.target); break;
      case 'prefill_target':     if (d.data?.target) _promptScanIP(); break;
      case 'open_report_modal':
        if (App.getLastData()) { if (d.data?.format) selectFmt(d.data.format); showReportModal(); }
        else addMsg('Run a scan first to generate a report.', 'ai');
        break;
      case 'navigate': break; // legacy nav actions ignored
      case 'stop_scan': confirmStop(); break;
      case 'clear_chat': { const chat = document.getElementById('chat'); chat.innerHTML = ''; showGreeting(); break; }
      case 'vuln_lookup': _handleVulnCommand(); break;
      case 'show_help': _showHelpCard(); break;
    }
  }

