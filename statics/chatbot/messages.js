/**
 * chatbot/messages.js
 * Chat message rendering, scroll management, greeting, project onboarding.
 */

  /* ═══════════════════════════════════════════════════════
     CHAT CORE
  ═══════════════════════════════════════════════════════ */

  /* ─── FIX 8: scroll-to-bottom tracking ─── */
  let _userScrolledUp = false;

  function _isNearBottom(chat) {
    return chat.scrollHeight - chat.scrollTop - chat.clientHeight < 120;
  }

  function _onChatScroll() {
    const chat = document.getElementById('chat');
    const btn  = document.getElementById('scroll-to-bottom');
    if (!chat || !btn) return;
    _userScrolledUp = !_isNearBottom(chat);
    if (_userScrolledUp) {
      btn.classList.add('visible');
    } else {
      btn.classList.remove('visible');
      btn.classList.remove('has-unread');
    }
    // Save scroll position for session restore (Fix 7)
    SessionManager.saveScrollPos(null, chat.scrollTop);
  }

  function scrollToBottom() {
    const chat = document.getElementById('chat');
    const btn  = document.getElementById('scroll-to-bottom');
    if (chat) chat.scrollTo({ top: chat.scrollHeight, behavior: 'smooth' });
    if (btn)  { btn.classList.remove('visible'); btn.classList.remove('has-unread'); }
    _userScrolledUp = false;
  }

  function addMsg(txt, type) {
    SessionManager.saveMsg(type, txt);
    const chat = document.getElementById('chat');
    const d    = document.createElement('div');
    d.className = `msg msg-${type}`;
    d.innerHTML = Utils.renderMarkdown(txt);
    d.style.opacity = '0'; d.style.transform = 'translateY(6px)';
    chat.appendChild(d);
    requestAnimationFrame(() => {
      d.style.transition = 'opacity .2s ease, transform .2s ease';
      d.style.opacity = '1'; d.style.transform = 'translateY(0)';
    });
    // FIX 8: only auto-scroll if user is near bottom; else show scroll button
    if (!_userScrolledUp) {
      chat.scrollTo({ top: chat.scrollHeight, behavior: 'smooth' });
    } else {
      const btn = document.getElementById('scroll-to-bottom');
      if (btn) { btn.classList.add('visible'); btn.classList.add('has-unread'); }
    }
    return d;
  }

  /**
   * Save a rich structured widget token to the session so it can be
   * reconstructed exactly on restore/refresh.
   * Token format: __TOKEN_TYPE__:<json>
   * Type is used by restoreChatMessages() to decide which render fn to call.
   */
  function _saveRichMsg(tokenType, data) {
    try {
      const payload = JSON.stringify(data);
      SessionManager.saveMsg('rich', `__${tokenType}__:${payload}`);
    } catch (e) { /* ignore serialization errors */ }
  }

  /**
   * Reconstruct a rich widget from a saved token and append it to the chat
   * fragment (used during restoreChatMessages).
   */
  function _restoreRichWidget(tokenType, data, frag) {
    try {
      switch (tokenType) {
        case 'SCAN_COMPLETE':   _buildScanSummaryEl(data, frag);    break;
        case 'VULN_TABLE':      _buildVulnTableEl(data, frag);      break;
        case 'VULN_DASH':       _buildVulnDashEl(data, frag);       break;
        case 'PATCH_DASH':      _buildPatchDashEl(data, frag);      break;
        case 'PATCH_CARD':      _buildPatchCardEl(data, frag);      break;
        case 'SCAN_PROGRESS':   _buildScanProgressEl(data, frag);   break;
        case 'SCAN_SELECTOR':   _buildScanSelectorEl(data, frag);   break;
        case 'IP_PROMPT':       _buildIpPromptEl(data, frag);       break;
        case 'SCAN_RUNNING':    _buildScanRunningEl(data, frag);    break;
        default: break;
      }
    } catch (e) { /* widget reconstruction error — skip silently */ }
  }

  function addTyping() {
    const chat = document.getElementById('chat');
    const d    = document.createElement('div');
    d.className = 'msg msg-ai typing';
    d.innerHTML = '<span></span><span></span><span></span>';
    chat.appendChild(d);
    chat.scrollTo({ top: chat.scrollHeight, behavior: 'smooth' });
    return d;
  }

  function showGreeting() {
    _pollAIStatus();
    const h = new Date().getHours();
    const g = h < 5  ? 'Good night' :
              h < 12 ? 'Good morning' :
              h < 17 ? 'Good afternoon' : 'Good evening';

    // If this session already has a project name (e.g. restored), skip onboarding
    const existingProject = SessionManager.getProjectName();
    if (existingProject) {
      _showPostOnboarding(existingProject);
      return;
    }

    _showProjectOnboarding(g);
  }

  /** Step 1 — Project name onboarding card */
  function _showProjectOnboarding(greeting) {
    const chat = document.getElementById('chat');
    chat.innerHTML = '';
    const uid = 'proj-onboard-' + Date.now();
    const d   = document.createElement('div');
    d.className = 'msg msg-ai onboard-card';
    d.id = uid;

    d.innerHTML = `
      <div class="ob-shield-wrap">
        <div class="ob-shield">🛡️</div>
        <div class="ob-ripple"></div>
      </div>
      <div class="ob-greeting ob-typewriter" id="${uid}-greeting">${greeting}, Sir.</div>
      <div class="ob-welcome" id="${uid}-welcome" style="opacity:0">
        Welcome back to <span class="ob-brand">ScanWise AI</span> —<br>
        your intelligent cybersecurity analysis workspace.
      </div>
      <div class="ob-prompt" id="${uid}-prompt" style="opacity:0">
        Before we begin, what project are we working on today?
      </div>
      <div class="ob-input-wrap" id="${uid}-inputwrap" style="opacity:0">
        <div class="ob-input-row">
          <span class="ob-input-icon">📁</span>
          <input class="ob-input" id="${uid}-inp" type="text"
                 placeholder="e.g. Enterprise Audit, College Network, Lab Assessment…"
                 maxlength="60"
                 onkeydown="if(event.key==='Enter') Chatbot._submitProjectName('${uid}')"/>
          <button class="ob-submit-btn" onclick="Chatbot._submitProjectName('${uid}')">
            <span>Initialize</span> →
          </button>
        </div>
        <div class="ob-quick-projects">
          <span class="ob-qp-label">Quick start:</span>
          <button class="ob-qp-btn" onclick="Chatbot._setProjectQuick('${uid}','Enterprise Audit')">Enterprise Audit</button>
          <button class="ob-qp-btn" onclick="Chatbot._setProjectQuick('${uid}','College Network')">College Network</button>
          <button class="ob-qp-btn" onclick="Chatbot._setProjectQuick('${uid}','Lab Assessment')">Lab Assessment</button>
          <button class="ob-qp-btn" onclick="Chatbot._setProjectQuick('${uid}','Personal Project')">Personal Project</button>
        </div>
      </div>
    `;

    d.style.opacity = '0';
    chat.appendChild(d);

    // Staged reveal animation
    requestAnimationFrame(() => {
      d.style.transition = 'opacity .4s ease';
      d.style.opacity    = '1';

      setTimeout(() => _fadeIn(`${uid}-welcome`,  0.35), 900);
      setTimeout(() => _fadeIn(`${uid}-prompt`,   0.35), 1700);
      setTimeout(() => {
        _fadeIn(`${uid}-inputwrap`, 0.35);
        setTimeout(() => document.getElementById(`${uid}-inp`)?.focus(), 400);
      }, 2400);
    });
  }

  function _fadeIn(id, dur = 0.3) {
    const el = document.getElementById(id);
    if (!el) return;
    el.style.transition = `opacity ${dur}s ease, transform ${dur}s ease`;
    el.style.transform  = 'translateY(6px)';
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        el.style.opacity   = '1';
        el.style.transform = 'translateY(0)';
      });
    });
  }

  function _setProjectQuick(uid, name) {
    const inp = document.getElementById(`${uid}-inp`);
    if (inp) { inp.value = name; inp.focus(); }
  }

  function _submitProjectName(uid) {
    const inp  = document.getElementById(`${uid}-inp`);
    const name = inp?.value?.trim();
    if (!name) {
      inp && (inp.style.borderColor = 'var(--red)');
      inp && inp.focus();
      return;
    }

    // Save to session
    SessionManager.setProjectName(name);
    // Persist immediately to backend so it survives refresh (like ChatGPT/Claude)
    SessionManager.persist().catch(() => {});

    // Animate card out
    const card = document.getElementById(uid);
    if (card) {
      card.style.transition = 'opacity .3s ease, transform .3s ease';
      card.style.opacity    = '0';
      card.style.transform  = 'translateY(-8px)';
      setTimeout(() => { card.remove(); _showProjectInitialized(name); }, 320);
    } else {
      _showProjectInitialized(name);
    }

    // Update drawer immediately
    loadDrawer();
  }

  /** Step 2 — Project initialized confirmation + action menu */
  function _showProjectInitialized(projectName) {
    const chat = document.getElementById('chat');

    // Save greeting to session so it survives reload
    SessionManager.saveMsg('ai', `__GREETING__:${projectName}`);

    // Project initialized message
    const confirm = document.createElement('div');
    confirm.className = 'msg msg-ai project-init-card';
    confirm.innerHTML = `
      <div class="pi-header">
        <span class="pi-check">✅</span>
        <div>
          <div class="pi-title">Project "<span class="pi-name">${projectName}</span>" initialized</div>
          <div class="pi-sub">Workspace ready · ScanWise AI is standing by</div>
        </div>
      </div>
    `;
    confirm.style.opacity = '0';
    chat.appendChild(confirm);
    requestAnimationFrame(() => {
      confirm.style.transition = 'opacity .3s ease, transform .3s ease';
      confirm.style.transform  = 'translateY(6px)';
      requestAnimationFrame(() => { confirm.style.opacity = '1'; confirm.style.transform = 'translateY(0)'; });
    });

    // Action menu (slight delay for stagger)
    setTimeout(() => {
      const menu = document.createElement('div');
      menu.className = 'msg msg-ai';
      menu.innerHTML = `
        <div class="post-ob-msg">Excellent. You can now:</div>
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
        <div class="post-ob-hint">What would you like to do first?</div>
      `;
      menu.style.opacity = '0'; menu.style.transform = 'translateY(8px)';
      chat.appendChild(menu);
      requestAnimationFrame(() => {
        menu.style.transition = 'opacity .35s ease, transform .35s ease';
        requestAnimationFrame(() => { menu.style.opacity = '1'; menu.style.transform = 'translateY(0)'; });
      });
      chat.scrollTo({ top: chat.scrollHeight, behavior: 'smooth' });
    }, 400);
  }

  /** Shown when returning to a session that already has a project name */
  function _showPostOnboarding(projectName) {
    const chat = document.getElementById('chat');
    const d    = document.createElement('div');
    d.className = 'msg msg-ai';
    d.innerHTML = `
      <div class="post-ob-msg">
        <span style="color:var(--purple);font-weight:700">📁 ${projectName}</span>
        &nbsp;— workspace active. What would you like to do?
      </div>
      <div class="post-ob-actions">
        <button class="post-ob-btn" onclick="Chatbot._promptScanIP()">
          <span class="pob-icon">🔍</span>
          <span class="pob-text"><strong>Scan a Target</strong><small>TCP, UDP, OS, service fingerprinting</small></span>
        </button>
        <button class="post-ob-btn" onclick="Chatbot.quickChat('/vuln')">
          <span class="pob-icon">🔎</span>
          <span class="pob-text"><strong>Vulnerability Intelligence</strong><small>CVEs from last scan</small></span>
        </button>
        <button class="post-ob-btn" onclick="Chatbot.quickChat('/patch all')">
          <span class="pob-icon">🔧</span>
          <span class="pob-text"><strong>Patch Dashboard</strong><small>Remediation for all services</small></span>
        </button>
        <button class="post-ob-btn" onclick="Chatbot.quickChat('/help')">
          <span class="pob-icon">📖</span>
          <span class="pob-text"><strong>All Commands</strong><small>Full reference</small></span>
        </button>
      </div>
    `;
    d.style.opacity = '0';
    chat.appendChild(d);
    requestAnimationFrame(() => {
      d.style.transition = 'opacity .3s ease';
      d.style.opacity = '1';
    });
    chat.scrollTo({ top: chat.scrollHeight, behavior: 'smooth' });
  }

  /* ── IP prompt card (replaces auto-fill) ─────────────────── */

  function _promptScanIP() {
    const chat = document.getElementById('chat');
    const uid  = 'ip-prompt-' + Date.now();
    const d    = document.createElement('div');
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
    d.style.opacity = '0'; d.style.transform = 'translateY(8px)';
    chat.appendChild(d);
    requestAnimationFrame(() => {
      d.style.transition = 'opacity .25s ease, transform .25s ease';
      d.style.opacity = '1'; d.style.transform = 'translateY(0)';
    });
    chat.scrollTo({ top: chat.scrollHeight, behavior: 'smooth' });
    setTimeout(() => document.getElementById(uid + '-inp')?.focus(), 300);
    // Persist so IP prompt survives refresh
    _saveRichMsg('IP_PROMPT', {});
  }

  function _submitScanIP(uid) {
    const inp = document.getElementById(uid + '-inp');
    let ip    = inp?.value?.trim();
    if (!ip) { inp && (inp.style.borderColor = '#e24b4a'); return; }

    // Auto-correct comma-instead-of-dot typo: "10.83.113,112" → "10.83.113.112"
    const commaFix = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3}),(\d{1,3})$/);
    if (commaFix) {
      const fixed = `${commaFix[1]}.${commaFix[2]}.${commaFix[3]}.${commaFix[4]}`;
      console.info(`[ScanWise] Auto-corrected target: "${ip}" → "${fixed}"`);
      ip = fixed;
    }

    // Basic client-side format check before hitting the server
    const validPattern = /^((\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?|localhost|([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,})$/;
    if (!validPattern.test(ip)) {
      if (inp) {
        inp.style.borderColor = '#e24b4a';
        inp.value = ip;
        // Show inline hint
        let hint = inp.parentElement.querySelector('.ip-err-hint');
        if (!hint) {
          hint = document.createElement('div');
          hint.className = 'ip-err-hint';
          hint.style.cssText = 'color:#e24b4a;font-size:12px;margin-top:4px;';
          inp.parentElement.appendChild(hint);
        }
        hint.textContent = '⚠️ Invalid format. Use e.g. 192.168.1.1, 10.0.0.5, or scanme.nmap.org';
      }
      return;
    }

    // Remove the prompt card
    document.getElementById(uid)?.remove();
    addMsg(`/scan ${ip}`, 'user');
    _showScanTypeSelector(ip);
  }

