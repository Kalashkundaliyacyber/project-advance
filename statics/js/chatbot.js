const Chatbot = (() => {
/**
 * chatbot/constants.js
 * Shared state variables, slash-command list, and scan-type registry.
 * All symbols live inside the Chatbot IIFE — this file is concatenated, not a module.
 */

  // ── Mutable state ──────────────────────────────────────────
  let _progressTimer   = null;
  let _selectedFmt     = 'html';
  let _currentTarget   = '';
  let _lastLatency     = null;
  let _lastTokens      = null;
  let _modelOk         = false;
  let _autocompleteIdx = -1;
  let _sortDir         = {};
  let _drawerMenuId    = null;

  let _modelName      = 'Detecting…';
  let _modelProvider  = 'Starting…';
  let _activeProvider = 'unknown';   // 'qwen' | 'llama' | 'nemotron' | 'gpt_oss' | 'deepseek_flash' | 'llama33' | 'gemma4' | 'rule-based'

  // ── Slash commands ─────────────────────────────────────────
  const SLASH_CMDS = [
    { cmd: '/graph',    hint: '/graph',                  desc: 'Open Infrastructure Intelligence Graph or Vulnerability Intelligence Dashboard' },
    { cmd: '/patch',    hint: '/patch all',              desc: 'AI patch remediation dashboard for all vulnerabilities' },
    { cmd: '/patch',    hint: '/patch <service> <port>', desc: 'Patch guidance for a specific port' },
    { cmd: '/report',   hint: '/report [pdf|html]',      desc: 'Export scan report (PDF or HTML)' },
    { cmd: '/clear',    hint: '/clear',                  desc: 'Clear chat window' },
    { cmd: '/stop',     hint: '/stop',                   desc: 'Abort running scan' },
    { cmd: '/help',     hint: '/help',                   desc: 'Show all commands' },
  ];


  const SCAN_TYPES = [
    // PORT SCANNING — Homepage featured
    { key: 'tcp_basic',          icon: '⚡', name: 'Quick TCP Scan',         category: 'port_scanning',    risk: 'moderate',   duration: '~30s',      recommended: true,  advanced: false, desc: 'Fast top-1000 TCP port discovery. Best for initial recon.',               cmd: 'nmap -sS -T4 --top-ports 1000' },
    { key: 'full_tcp',           icon: '🔓', name: 'Full TCP Scan',          category: 'port_scanning',    risk: 'aggressive', duration: '~5-15m',    recommended: true,  advanced: false, desc: 'Scans ALL 65535 TCP ports (-p-). Finds hidden services & backdoors.',      cmd: 'nmap -p- -sS -T4' },
    { key: 'udp_scan',           icon: '📡', name: 'Full UDP Scan',          category: 'port_scanning',    risk: 'aggressive', duration: '~30-60m',   recommended: true,  advanced: false, desc: 'All UDP ports. Detects DNS, SNMP, NTP, TFTP, VPN. Slow but essential.',   cmd: 'nmap -sU -p- --max-retries 2' },
    { key: 'stealth_syn',        icon: '🥷', name: 'Stealth SYN Scan',       category: 'port_scanning',    risk: 'moderate',   duration: '~3-5m',     recommended: true,  advanced: false, desc: 'Low-speed stealthy SYN scan. Evades basic IDS/firewall detection.',        cmd: 'nmap -sS -Pn -T2' },

    // ENUMERATION — Homepage featured
    { key: 'service_detect',     icon: '🔍', name: 'Service Detection',      category: 'enumeration',      risk: 'moderate',   duration: '~45s',      recommended: true,  advanced: false, desc: 'Identifies services and versions on open TCP ports.',                      cmd: 'nmap -sT -sV -T3' },
    { key: 'full_service_enum',  icon: '🔬', name: 'Full Service Enum',      category: 'enumeration',      risk: 'aggressive', duration: '~15-30m',   recommended: false, advanced: false, desc: 'Scans ALL ports (-p-) and detects versions, banners, daemon info.',        cmd: 'nmap -p- -sV -sS -T4' },
    { key: 'os_detect',          icon: '💻', name: 'OS Fingerprinting',      category: 'enumeration',      risk: 'moderate',   duration: '~60s',      recommended: false, advanced: false, desc: 'Identifies the target OS via TCP/IP stack fingerprinting.',                cmd: 'nmap -O --osscan-guess' },
    { key: 'banner_grab',        icon: '🪧', name: 'Banner Grabbing',        category: 'enumeration',      risk: 'moderate',   duration: '~45s',      recommended: false, advanced: false, desc: 'Grabs service banners for technology identification.',                     cmd: 'nmap -sT -sV --version-intensity 5 -T3' },
    { key: 'enum_scripts',       icon: '📜', name: 'Default Script Scan',    category: 'enumeration',      risk: 'moderate',   duration: '~90s',      recommended: false, advanced: false, desc: 'Runs safe NSE default scripts for deeper service enumeration.',            cmd: 'nmap -sC -sV' },
    { key: 'db_discovery',       icon: '🗄️', name: 'Database Discovery',     category: 'enumeration',      risk: 'moderate',   duration: '~30s',      recommended: false, advanced: false, desc: 'Scans MSSQL, MySQL, PostgreSQL, MongoDB, Redis ports.',                   cmd: 'nmap -p 1433,3306,5432,27017,6379 -sV' },

    // VULNERABILITY ASSESSMENT — Homepage featured
    { key: 'vuln_scan',          icon: '⚠️', name: 'Vulnerability Scan',     category: 'vuln_assessment',  risk: 'aggressive', duration: '~20-40m',   recommended: true,  advanced: false, desc: 'NSE vuln scripts across ALL ports (-p-). Detects CVEs and misconfigs.',    cmd: 'nmap --script vuln -p-' },
    { key: 'web_pentest',        icon: '🌐', name: 'Web Pentest Scan',       category: 'vuln_assessment',  risk: 'moderate',   duration: '~60s',      recommended: true,  advanced: false, desc: 'HTTP enum scripts on web ports. Finds admin panels, headers, directories.',cmd: 'nmap -p 80,443,8080,8000,8443 --script http-enum,http-title,http-headers' },
    { key: 'smb_audit',          icon: '🪟', name: 'SMB Security Audit',     category: 'vuln_assessment',  risk: 'moderate',   duration: '~30s',      recommended: false, advanced: false, desc: 'Enumerates SMB shares and users. Essential for Windows pentesting.',       cmd: 'nmap --script smb-enum-shares,smb-enum-users -p 445' },
    { key: 'ftp_audit',          icon: '📁', name: 'FTP Security Audit',     category: 'vuln_assessment',  risk: 'moderate',   duration: '~20s',      recommended: false, advanced: false, desc: 'Checks for anonymous FTP login and vsftpd backdoor.',                      cmd: 'nmap --script ftp-anon,ftp-vsftpd-backdoor -p 21' },
    { key: 'ssh_audit',          icon: '🔐', name: 'SSH Security Audit',     category: 'vuln_assessment',  risk: 'moderate',   duration: '~20s',      recommended: false, advanced: false, desc: 'Enumerates SSH auth methods and supported algorithms.',                    cmd: 'nmap --script ssh-auth-methods,ssh2-enum-algos -p 22' },

    // DISCOVERY
    { key: 'ping_sweep',         icon: '📶', name: 'Ping Sweep',             category: 'discovery',        risk: 'safe',       duration: '~15s',      recommended: false, advanced: false, desc: 'Discovers live hosts via ICMP echo requests.',                             cmd: 'nmap -sn' },
    { key: 'host_discovery',     icon: '🖧',  name: 'Host Discovery',         category: 'discovery',        risk: 'safe',       duration: '~20s',      recommended: false, advanced: false, desc: 'Multi-method host discovery without port scanning.',                       cmd: 'nmap -sn -PE -PS22,80,443 -PA80' },
    { key: 'arp_discovery',      icon: '🔗', name: 'ARP Discovery',          category: 'discovery',        risk: 'safe',       duration: '~10s',      recommended: false, advanced: false, desc: 'LAN ARP-based host discovery. Fastest for local networks.',                cmd: 'nmap -sn -PR' },

    // ADVANCED PENTESTING
    { key: 'ultimate_recon',     icon: '💀', name: 'Ultimate Recon',         category: 'advanced',         risk: 'very_noisy', duration: '~45-120m',  recommended: true,  advanced: true,  desc: 'All ports (-p-), OS+version, scripts, vuln scan. Very slow and noisy.',    cmd: 'nmap -p- -A -sV -O -sC --script vuln' },
    { key: 'aggressive_pentest', icon: '🚀', name: 'Aggressive Pentest',     category: 'advanced',         risk: 'very_noisy', duration: '~20-45m',   recommended: false, advanced: true,  desc: 'Full OS+version+traceroute+NSE across ALL ports (-p-).',                   cmd: 'nmap -A -p- -T4' },
    { key: 'firewall_evasion',   icon: '🛡️', name: 'Firewall Evasion',       category: 'advanced',         risk: 'aggressive', duration: '~3-5m',     recommended: false, advanced: true,  desc: 'ACK scan to map firewall rules and detect filtered ports.',                cmd: 'nmap -sA -T2' },
    { key: 'frag_scan',          icon: '🧩', name: 'Fragmented Packets',     category: 'advanced',         risk: 'aggressive', duration: '~2-5m',     recommended: false, advanced: true,  desc: 'IP fragmentation to evade packet-filter firewalls and IDS.',               cmd: 'nmap -sS -f -T3' },
    { key: 'decoy_scan',         icon: '🎭', name: 'Decoy Scan',             category: 'advanced',         risk: 'aggressive', duration: '~2-4m',     recommended: false, advanced: true,  desc: 'Masks real source IP with random decoys. Advanced evasion.',               cmd: 'nmap -sS -D RND:5 -T3' },
    { key: 'timing_manipulation',icon: '⏱️', name: 'Timing Manipulation',    category: 'advanced',         risk: 'moderate',   duration: '~10-20m',   recommended: false, advanced: true,  desc: 'Paranoid-speed scan (T1) to evade time-based IDS detection.',              cmd: 'nmap -sS -T1 --top-ports 100' },
  ];


/**
 * chatbot/model.js
 * AI model indicator bar — status dot, provider name, latency.
 */

  /* ═══════════════════════════════════════════════════════
     MODEL INDICATOR
  ═══════════════════════════════════════════════════════ */


  /* ══════════════════════════════════════════════════════
     FIX19: Breadcrumb navigation helper
     Updates "ThreatWeave AI > Project > Target" in topbar
  ══════════════════════════════════════════════════════ */
  function _updateBreadcrumb(project, target) {
    let el = document.getElementById('topbar-breadcrumb');
    if (!el) {
      // Inject breadcrumb element into topbar between logo and model indicator
      const topbar = document.querySelector('.topbar');
      const logo   = topbar && topbar.querySelector('.logo');
      if (!topbar || !logo) return;
      el = document.createElement('div');
      el.id = 'topbar-breadcrumb';
      logo.after(el);
    }
    const p = project || '';
    const t = target  || '';
    if (!p && !t) { el.innerHTML = ''; return; }
    const parts = ['<span class="bc-root">ThreatWeave AI</span>'];
    if (p) parts.push(`<span class="bc-sep">›</span><span class="bc-current">${_esc(p)}</span>`);
    if (t) parts.push(`<span class="bc-sep">›</span><span>${_esc(t)}</span>`);
    el.innerHTML = parts.join('');
  }
  function _esc(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  function _updateModelIndicator(opts = {}) {
    const dot  = document.getElementById('model-dot');
    const name = document.getElementById('model-name');
    const meta = document.getElementById('model-meta');
    if (!dot || !name || !meta) return;
    if (opts.checking) { dot.className = 'model-dot checking'; name.textContent = 'Detecting…'; meta.textContent = 'Checking…'; return; }
    if (opts.error)    { dot.className = 'model-dot error';    name.textContent = 'Unavailable'; meta.textContent = 'Retrying…'; return; }

    // Dot colour map — covers all active providers
    const DOT_CLASS = {
      qwen:                  'model-dot local',
      llama:                 'model-dot local',
      nemotron:              'model-dot cloud',
      gpt_oss:               'model-dot cloud',
      deepseek_flash:        'model-dot cloud',
      llama33:               'model-dot cloud',
      gemma4:                'model-dot cloud',
      'rule-based':          'model-dot fallback',
      'rule-based-fallback': 'model-dot fallback',
    };

    // Display name map — used when backend display_name is absent
    const PNAMES = {
      qwen:                  'Qwen2.5-Coder (Local)',
      llama:                 'Llama (Local)',
      nemotron:              'Nemotron 3 Super 120B',
      gpt_oss:               'GPT-OSS 120B',
      deepseek_flash:        'DeepSeek V4 Flash',
      llama33:               'Llama 3.3 70B',
      gemma4:                'Gemma 4 27B',
      'rule-based':          'Rule Engine',
      'rule-based-fallback': 'Rule Engine',
    };
    const PLABELS = {
      qwen:                  'Ollama · Local Primary',
      llama:                 'Ollama · Local Chat',
      nemotron:              'OpenRouter · Gen #1',
      gpt_oss:               'OpenRouter · Gen #2',
      deepseek_flash:        'OpenRouter · Fallback',
      llama33:               'OpenRouter · Chat #1',
      gemma4:                'OpenRouter · Chat #2',
      'rule-based':          'No AI · Offline Mode',
      'rule-based-fallback': 'No AI · Offline Mode',
    };

    // Update from /api/ai/status payload
    if (opts.aiStatus) {
      const st = opts.aiStatus;
      _activeProvider = st.active_provider || 'unknown';
      _modelName      = st.display_name     || PNAMES[_activeProvider]  || _activeProvider;
      _modelProvider  = st.display_provider || PLABELS[_activeProvider] || '';
      dot.className   = DOT_CLASS[_activeProvider] || 'model-dot cloud';
    }

    // Update from per-response provider field
    if (opts.provider) {
      _activeProvider = opts.provider;
      if (!opts.aiStatus) {
        _modelName     = PNAMES[opts.provider]  || opts.provider;
        _modelProvider = PLABELS[opts.provider] || opts.provider;
      }
      dot.className = DOT_CLASS[opts.provider] || 'model-dot cloud';
    }

    name.textContent = _modelName;
    const lat = opts.latency || (opts.aiStatus && opts.aiStatus.last_latency_ms);
    meta.textContent = _modelProvider + (lat ? ` · ${lat}ms` : '');
    _modelOk = true;
  }

  /** Poll /api/ai/status on startup and update indicator. */
  async function _pollAIStatus() {
    _updateModelIndicator({ checking: true });
    try {
      const st = await ApiService.getAIStatus();
      _updateModelIndicator({ aiStatus: st });
    } catch (e) {
      _updateModelIndicator({ error: true });
    }
  }



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

  /* FIX20: inject copy-code buttons into <pre> blocks inside a message el */
  function _injectCopyButtons(el) {
    el.querySelectorAll('pre').forEach(pre => {
      if (pre.querySelector('.copy-code-btn')) return;  // already injected
      const btn = document.createElement('button');
      btn.className   = 'copy-code-btn';
      btn.textContent = '⧉ Copy';
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const code = pre.querySelector('code')?.innerText || pre.innerText;
        navigator.clipboard.writeText(code).then(() => {
          btn.textContent = '✓ Copied';
          setTimeout(() => { btn.textContent = '⧉ Copy'; }, 1800);
        }).catch(() => {});
      });
      pre.style.position = 'relative';
      pre.appendChild(btn);
    });
  }

  function addMsg(txt, type) {
    // Intercept special server tokens that trigger client-side widgets
    if (type === 'ai' && typeof txt === 'string') {
      if (txt === '__HELP_CARD__')        { _showHelpCard();      return null; }
      if (txt === '__VULN_DASHBOARD__')   { _handleVulnCommand(); return null; }
      if (txt === '__PATCH_ALL__')        { _handlePatchAll();    return null; }
    }
    SessionManager.saveMsg(type, txt);
    const chat = document.getElementById('chat');
    if (!chat) { console.warn('[addMsg] #chat not in DOM yet'); return null; }
    const d    = document.createElement('div');
    d.className = `msg msg-${type}`;
    d.innerHTML = Utils.renderMarkdown(txt);
    d.style.opacity = '0'; d.style.transform = 'translateY(6px)';
    chat.appendChild(d);
    _injectCopyButtons(d);   // FIX20: inject copy buttons on code blocks
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


  /* ══════════════════════════════════════════════════════
     FIX16: Rotating placeholder text for chat input
     Cycles every 3.5s when the input is empty and unfocused
  ══════════════════════════════════════════════════════ */
  const _PLACEHOLDERS = [
    'Scan a target…',
    'Ask about a CVE…',
    'Type /scan 192.168.1.1',
    'Type /vuln to see findings…',
    'Try /patch for remediation…',
    'Ask about risk scoring…',
  ];
  let _phIdx = 0, _phTimer = null;

  function _startPlaceholderRotation() {
    const inp = document.getElementById('chat-inp');
    if (!inp) return;
    if (_phTimer) clearInterval(_phTimer);
    _phTimer = setInterval(() => {
      // For textarea: check value and activeElement
      if (document.activeElement === inp || inp.value) return;
      inp.style.transition = 'opacity .25s';
      inp.style.opacity    = '0';
      setTimeout(() => {
        _phIdx = (_phIdx + 1) % _PLACEHOLDERS.length;
        inp.setAttribute('placeholder', _PLACEHOLDERS[_phIdx]);
        inp.style.opacity  = '1';
      }, 260);
    }, 3500);
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
        Welcome back to <span class="ob-brand">ThreatWeave AI</span> —<br>
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
                 onkeydown="if(event.key==='Enter'){Chatbot._submitProjectName('${uid}');}"
                 oninput="(function(){const c=document.getElementById('${uid}-chips');if(c)c.style.display='flex';})()"/>
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
        <!-- FIX17: Quick action chips — after naming project, user can jump straight to action -->
        <div class="ob-quick-chips" id="${uid}-chips" style="display:none;margin-top:14px">
          <button class="ob-chip" onclick="Chatbot._setProjectQuick('${uid}','Quick Scan');Chatbot._submitProjectName('${uid}')">⚡ Quick Scan</button>
          <button class="ob-chip" onclick="Chatbot._setProjectQuick('${uid}','Full Audit');Chatbot._submitProjectName('${uid}')">🔍 Full Audit</button>
          <button class="ob-chip" onclick="Chatbot._setProjectQuick('${uid}','UDP Scan');Chatbot._submitProjectName('${uid}')">📡 UDP Scan</button>
          <button class="ob-chip" onclick="Chatbot.quickChat('/help');Chatbot._submitProjectName('${uid}')">📖 Help</button>
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
    _updateBreadcrumb(name, '');  // FIX19: update breadcrumb

    // Animate card out
    const card = document.getElementById(uid);
    if (card) {
      // FIX17: smooth dissolve animation
      card.classList.add('ob-dissolve');
      setTimeout(() => { card.remove(); _showProjectInitialized(name); }, 420);
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
          <div class="pi-sub">Workspace ready · ThreatWeave AI is standing by</div>
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
            <span class="pob-icon">🎯</span>
            <span class="pob-text"><strong>Start Scanning</strong><small>Single IP or Multiple IPs from file</small></span>
          </button>
          <button class="post-ob-btn" onclick="Chatbot.openVulnDashboard()">
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
          <span class="pob-icon">🎯</span>
          <span class="pob-text"><strong>Start Scanning</strong><small>Single IP or Multiple IPs from file</small></span>
        </button>
        <button class="post-ob-btn" onclick="Chatbot.openVulnDashboard()">
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
      console.info(`[ThreatWeave] Auto-corrected target: "${ip}" → "${fixed}"`);
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
    _autoStartVulnScan(ip);
  }



/**
 * chatbot/commands.js
 * Autocomplete, message sending, slash-command dispatcher.
 */

  /* ── Autocomplete ─────────────────────────────────────────── */

  function onChatInput(event) {
    const ta  = event.target;
    const val = ta.value;

    // FIX 1: Auto-expand textarea height — reset then set to scrollHeight
    ta.style.height = 'auto';
    ta.style.height = Math.min(ta.scrollHeight, 160) + 'px';

    // Autocomplete for slash commands
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
    // FIX 1: Enter = send, Shift+Enter = newline (textarea behavior)
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();  // prevent newline on send
      sendChat();
    }
    // Shift+Enter: do nothing — browser inserts newline naturally in textarea
  }

  function selectAutocomplete(hint) {
    const inp = document.getElementById('chat-inp');
    if (inp) {
      inp.value = hint;
      // FIX 1: re-adjust textarea height after setting value
      inp.style.height = 'auto';
      inp.style.height = Math.min(inp.scrollHeight, 160) + 'px';
    }
    const ac = document.getElementById('chat-autocomplete');
    if (ac) ac.style.display = 'none';
    inp && inp.focus();
  }

  /* ── Send / handle ─────────────────────────────────────────── */

  /* ═══════════════════════════════════════════════════════
     FIX 1 — CENTRALIZED SLASH COMMAND PARSER
     Validates, routes, handles loading states + errors.
  ═══════════════════════════════════════════════════════ */

  async function _cmdModel() {
    try {
      const st = await ApiService.getAIStatus();
      const active   = st.display_name     || st.active_provider || 'Unknown';
      const provider = st.display_provider || '';
      const ollama   = st.ollama_available   ? '✅ Online' : '❌ Offline — run Ollama to enable local models';
      const qwen     = st.qwen_available   ? `✅ ${st.qwen_model  || 'qwen'}` : '❌ Not found  →  ollama pull qwen2.5-coder:3b';
      const llama    = st.llama_available  ? `✅ ${st.llama_model || 'llama'}` : '❌ Not found  →  ollama pull llama3.2:1b';
      const cloud    = st.openrouter_available ? '✅ Configured' : '❌ Not configured  →  set OPENROUTER_API_KEY in .env';
      const cbLines  = Object.entries(st.circuit_breakers || {})
        .map(([n, cb]) => `  • ${n}: ${cb.state}  (${cb.success_rate || '—'})`)
        .join('\n');
      _updateModelIndicator({ aiStatus: st });
      addMsg(
        `**🤖 AI Model Status**\n\n` +
        `**Active:** ${active}  ·  ${provider}\n\n` +
        `**Local Ollama:** ${ollama}\n` +
        `  • Qwen2.5-Coder: ${qwen}\n` +
        `  • Llama:         ${llama}\n\n` +
        `**Cloud (OpenRouter):** ${cloud}\n` +
        `  Generate stack: Nemotron → GPT-OSS → DeepSeek Flash\n` +
        `  Chat stack:     Llama 3.3 → Gemma 4 → DeepSeek Flash\n` +
        (cbLines ? `\n**Circuit Breakers:**\n${cbLines}` : ''),
        'ai'
      );
    } catch (e) {
      addMsg('❌ Could not reach server to fetch model status. Is the server running?', 'ai');
    }
  }

  /* ── Graph picker ─────────────────────────────────────────── */
  function _cmdGraph() {
    // Clear any stale graph data from localStorage to free quota before user picks a graph
    try { localStorage.removeItem('threatweave_graph_data'); localStorage.removeItem('threatweave_graph_type'); } catch (_) {}
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
    const json = data ? JSON.stringify(data) : '';

    // Try sessionStorage first (much larger quota than localStorage, same-session only)
    // If that also fails, strip heavy fields and try again before giving up.
    const _tryStore = (payload) => {
      try {
        sessionStorage.setItem('threatweave_graph_type', type);
        sessionStorage.setItem('threatweave_graph_data', payload);
        return true;
      } catch (e1) {
        // sessionStorage also full — try localStorage as second option
        try {
          localStorage.setItem('threatweave_graph_type', type);
          localStorage.setItem('threatweave_graph_data', payload);
          return true;
        } catch (e2) {
          return false;
        }
      }
    };

    // First attempt: full data
    if (!_tryStore(json)) {
      // Second attempt: strip large description fields to reduce size
      let slim = json;
      try {
        const d = JSON.parse(json);
        // Remove verbose CVE descriptions and raw nmap output to cut size
        (d.risk?.hosts || []).forEach(h =>
          (h.ports || []).forEach(p =>
            (p.cves || []).forEach(c => { delete c.description; delete c.raw; })
          )
        );
        delete d.raw_output;
        delete d.nmap_xml;
        slim = JSON.stringify(d);
      } catch (_) {}

      if (!_tryStore(slim)) {
        addMsg('⚠️ Graph data is too large for browser storage. Try running a targeted scan (fewer ports) to reduce data size, then use `/graph` again.', 'ai');
        return;
      }
    }

    window.open('graph_viewer.html?type=' + type, '_blank');
  }

  /* ── Extra slash command handlers ─────────────────────────── */
  async function _cmdRisk(parts) {
    const sessionId = App.getCurrentSession() || '';
    const t = addTyping();
    try {
      const d = await ApiService.sendChatMessage('/risk', _currentTarget, sessionId, SessionManager.getProjectName());
      t.remove();
      addMsg(d.reply || 'No risk data available. Run a scan first.', 'ai');
    } catch(e) { t.remove(); addMsg('❌ Risk command error: ' + (e.message || e), 'ai'); }
  }

  async function _cmdRemediate(parts) { await _handlePatchAll(); }

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
    if (!['pdf','html','json'].includes(fmt)) { addMsg('⚠️ `/export` supports: `pdf`, `html`, or `json`', 'ai'); return; }
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

  /* ── Tab-based patch card functions ───────────────────────── */
  function _genTabContent(e, upgCmds, tab) {
    const sev   = (e.severity || e.risk_level || 'low').toLowerCase();

    // CVSS: try every possible field, then fall back to best CVE score from all_cves
    let cvss = parseFloat(e.cvss) || parseFloat(e.cvss_score) || parseFloat(e.risk_score) || 0;
    if (cvss === 0 && e.all_cves && e.all_cves.length) {
      cvss = Math.max(...e.all_cves.map(c => parseFloat(c.cvss_score) || 0));
    }
    // Also try primary CVE match
    if (cvss === 0 && e.cve && e.cve !== '—' && e.all_cves && e.all_cves.length) {
      const matched = e.all_cves.find(c => (c.cve_id||'') === e.cve);
      if (matched) cvss = parseFloat(matched.cvss_score) || 0;
    }
    const score = cvss; // risk_score == cvss when not separately provided

    // Correct severity from CVSS if the passed severity seems wrong (e.g. "medium" but cvss=9.8)
    const _sevFromCvss = v => v >= 9 ? 'critical' : v >= 7 ? 'high' : v >= 4 ? 'medium' : v > 0 ? 'low' : sev;
    const effectiveSev = (sev === 'medium' && cvss >= 7) ? _sevFromCvss(cvss) : sev;

    const _sevColor = s => ({ critical:'#f87171', high:'#fbbf24', medium:'#60a5fa', low:'#34d399' }[s] || '#9ca3af');
    const clr = _sevColor(effectiveSev);
    const _bar = (val, max, color) => `<div style="background:rgba(255,255,255,0.07);border-radius:4px;height:6px;overflow:hidden;margin-top:4px"><div style="width:${Math.min(val/max*100,100).toFixed(1)}%;height:100%;background:${color};border-radius:4px;transition:width .4s"></div></div>`;

    // Build CVSS vector from actual data when available, fall back to cvss-score-based estimate
    const cvssVector = e.cvss_vector || e.cvss_v3_vector || (
      cvss >= 9   ? 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' :
      cvss >= 7   ? 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L' :
      cvss >= 4   ? 'AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N' :
                    'AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N'
    );

    const cveLabel = (e.cve && e.cve !== '—') ? e.cve : (e.all_cves && e.all_cves[0]?.cve_id) || '—';

    const content = {
      mitigation: `
        <div class="pdt-section">
          <div class="pdt-label">Recommended Actions</div>
          <div class="pdt-text" style="white-space:pre-line">${upgCmds.mitigation || '• Apply latest security patches for ' + e.service + '\n• Restrict port ' + e.port + ' access via firewall\n• Monitor service logs for anomalous activity'}</div>
        </div>
        ${e.ai_action ? `<div class="pdt-section"><div class="pdt-label">AI Recommendation</div><div class="pdt-text">${e.ai_action}</div></div>` : ''}
        ${e.patch_note ? `<div class="pdt-section"><div class="pdt-label">Vendor Patch Note</div><div class="pdt-text">${e.patch_note}</div></div>` : ''}`,

      riskscore: `
        <div class="pdt-score-hero">
          <div class="pdt-score-ring">
            <span class="pdt-score-num" style="color:${clr}">${cvss > 0 ? cvss.toFixed(1) : '—'}</span>
            <span class="pdt-score-denom">/10</span>
          </div>
          <div class="pdt-score-details">
            <div class="pdt-kv"><span class="pdt-key">CVSS Score</span><span class="pdt-val" style="color:${clr};font-weight:700">${cvss > 0 ? cvss.toFixed(1) + ' / 10' : 'Not available'}</span></div>
            ${cvss > 0 ? _bar(cvss, 10, clr) : ''}
            <div class="pdt-kv" style="margin-top:10px"><span class="pdt-key">Severity</span><span class="pdt-val"><span class="rb rb-${effectiveSev}">${effectiveSev.toUpperCase()}</span></span></div>
            <div class="pdt-kv"><span class="pdt-key">NVD Rating</span><span class="pdt-val" style="color:${clr}">${cvss >= 9 ? 'Critical (9.0–10.0)' : cvss >= 7 ? 'High (7.0–8.9)' : cvss >= 4 ? 'Medium (4.0–6.9)' : cvss > 0 ? 'Low (0.1–3.9)' : 'N/A'}</span></div>
            <div class="pdt-kv"><span class="pdt-key">Exploitability</span><span class="pdt-val">${cvss >= 8.5 ? '🔴 High — active exploits known' : cvss >= 7 ? '🟡 Medium — exploitation likely' : '🟢 Low — limited exploit surface'}</span></div>
            <div class="pdt-kv"><span class="pdt-key">Data Source</span><span class="pdt-val">${cveLabel !== '—' ? '✅ CVE-matched — ' + cveLabel : '⚠ Estimated from service version'}</span></div>
          </div>
        </div>
        ${e.all_cves && e.all_cves.length > 1 ? `
        <div class="pdt-section"><div class="pdt-label">All Matched CVEs (${e.all_cves.length})</div>
        ${e.all_cves.slice(0,6).map(c => `<div class="pdt-cve-row">
          <span class="pdt-cve-id"><a href="https://nvd.nist.gov/vuln/detail/${c.cve_id||''}" target="_blank" style="color:#60a5fa;text-decoration:none">${c.cve_id||''}</a></span>
          <span class="rb rb-${(c.severity||'low').toLowerCase()}" style="font-size:10px">${(c.severity||'low').toUpperCase()}</span>
          <span class="pdt-cve-score" style="color:${_sevColor((c.severity||'low').toLowerCase())};font-weight:700">${(c.cvss_score||0).toFixed(1)}</span>
        </div>`).join('')}
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
        </div>
        <div class="pdt-grid" style="margin-top:8px">
          <div class="pdt-kv"><span class="pdt-key">Confidentiality</span><span class="pdt-val" style="color:${cvss >= 7 ? '#f87171' : '#34d399'}">${cvss >= 9 ? 'HIGH — data exposure risk' : cvss >= 7 ? 'MEDIUM — partial data risk' : 'LOW'}</span></div>
          <div class="pdt-kv"><span class="pdt-key">Integrity</span><span class="pdt-val" style="color:${cvss >= 7 ? '#f87171' : '#34d399'}">${cvss >= 9 ? 'HIGH — modification risk' : cvss >= 7 ? 'MEDIUM' : 'LOW'}</span></div>
          <div class="pdt-kv"><span class="pdt-key">Availability</span><span class="pdt-val" style="color:${cvss >= 7 ? '#fbbf24' : '#34d399'}">${cvss >= 7 ? 'MEDIUM — DoS possible' : 'LOW'}</span></div>
          <div class="pdt-kv"><span class="pdt-key">Scope</span><span class="pdt-val">${cvss >= 9 ? 'Network-wide' : 'Host-level'}</span></div>
        </div>`,

      risklevel: `
        <div class="pdt-rl-hero">
          <div class="pdt-rl-badge rb-${effectiveSev}" style="font-size:22px;padding:10px 20px;border-radius:10px">${effectiveSev.toUpperCase()}</div>
          <div style="flex:1">
            <div class="pdt-kv"><span class="pdt-key">Risk Classification</span><span class="pdt-val" style="color:${clr};font-weight:700">${effectiveSev.toUpperCase()} RISK</span></div>
            <div class="pdt-kv"><span class="pdt-key">CVSS Score</span><span class="pdt-val" style="color:${clr};font-weight:700">${cvss > 0 ? cvss.toFixed(1) + ' / 10' : 'N/A'}</span></div>
            ${cvss > 0 ? `<div style="margin:4px 0 8px">${_bar(cvss, 10, clr)}</div>` : ''}
            <div class="pdt-kv"><span class="pdt-key">Attack Vector</span><span class="pdt-val">${cvss >= 7 ? '🌐 Network — remotely exploitable' : '🏠 Local — requires physical/local access'}</span></div>
            <div class="pdt-kv"><span class="pdt-key">Attack Complexity</span><span class="pdt-val">${cvss >= 9 ? '🟢 Low — trivially exploitable' : cvss >= 7 ? '🟡 Low-Medium' : '🔴 High — specific conditions required'}</span></div>
            <div class="pdt-kv"><span class="pdt-key">Privileges Required</span><span class="pdt-val">${cvss >= 9 ? '✅ None required' : cvss >= 7 ? '⚠ None to low' : '🔐 Authenticated access needed'}</span></div>
            <div class="pdt-kv"><span class="pdt-key">Priority Action</span><span class="pdt-val" style="color:${clr};font-weight:600">${effectiveSev === 'critical' ? '🚨 Patch IMMEDIATELY — within hours' : effectiveSev === 'high' ? '⚠ Patch within 24–48 hours' : effectiveSev === 'medium' ? '📅 Patch within 7 days' : '🗓 Schedule for next maintenance window'}</span></div>
          </div>
        </div>`,

      severity: `
        <div style="display:flex;align-items:center;gap:20px;padding:8px 0 12px;flex-wrap:wrap">
          <div style="display:flex;flex-direction:column;align-items:center;gap:6px;min-width:80px">
            <div style="display:flex;gap:3px;align-items:flex-end;height:40px">
              ${['low','medium','high','critical'].map((s,i) => `<div style="width:14px;border-radius:3px 3px 0 0;background:${_sevColor(s)};height:${25+i*5}px;opacity:${s===effectiveSev?'1':'0.25'};transition:opacity .2s"></div>`).join('')}
            </div>
            <div style="font-size:13px;font-weight:800;color:${clr};letter-spacing:.5px">${effectiveSev.toUpperCase()}</div>
          </div>
          <div style="flex:1;display:flex;flex-direction:column;gap:7px">
            <div class="pdt-kv"><span class="pdt-key">Severity Level</span><span class="pdt-val"><span class="rb rb-${effectiveSev}">${effectiveSev.toUpperCase()}</span></span></div>
            <div class="pdt-kv"><span class="pdt-key">CVSS Score</span><span class="pdt-val" style="color:${clr};font-weight:700;font-size:16px">${cvss > 0 ? cvss.toFixed(1) : 'N/A'}<span style="font-size:11px;color:#6e7681;font-weight:400"> / 10</span></span></div>
            ${cvss > 0 ? _bar(cvss, 10, clr) : ''}
            <div class="pdt-kv" style="margin-top:4px"><span class="pdt-key">NVD Rating</span><span class="pdt-val" style="color:${clr}">${cvss >= 9 ? 'Critical (9.0–10.0)' : cvss >= 7 ? 'High (7.0–8.9)' : cvss >= 4 ? 'Medium (4.0–6.9)' : cvss > 0 ? 'Low (0.1–3.9)' : 'No score available'}</span></div>
            <div class="pdt-kv"><span class="pdt-key">CVE Reference</span><span class="pdt-val">${cveLabel !== '—' ? `<a href="https://nvd.nist.gov/vuln/detail/${cveLabel}" target="_blank" style="color:#60a5fa">${cveLabel}</a>` : 'No CVE matched'}</span></div>
            <div class="pdt-kv"><span class="pdt-key">Description</span><span class="pdt-val" style="color:#8b949e">${effectiveSev === 'critical' ? 'Exploitation likely to result in full system compromise' : effectiveSev === 'high' ? 'Significant vulnerability with high exploitation probability' : effectiveSev === 'medium' ? 'Exploitable under specific conditions — patch promptly' : 'Limited attack surface — monitor and schedule patch'}</span></div>
          </div>
        </div>`
    };
    return content[tab] || content['mitigation'];
  }

  function _switchPatchTab(contentId, tab, btn) {
    const container = document.getElementById(contentId);
    if (!container) return;

    // Works for both .pnc-tab-bar (new cards) and .pd-tab-bar (legacy)
    const tabBar = btn?.closest('.pnc-tab-bar') || btn?.closest('.pd-tab-bar');
    if (tabBar) {
      tabBar.querySelectorAll('.pnc-tab, .pd-tab').forEach(t => t.classList.remove('active'));
      btn.classList.add('active');
    }

    // Data is on the container itself (pnc-tab-content carries data-entry/data-cmds)
    const entryRaw = container.dataset?.entry || '';
    const cmdRaw   = container.dataset?.cmds  || '';
    let e, upgCmds;
    try { e       = JSON.parse(entryRaw.replace(/&quot;/g, '"')); } catch(_) { e = null; }
    try { upgCmds = JSON.parse(cmdRaw.replace(/&quot;/g, '"'));   } catch(_) { upgCmds = null; }

    if (!e) return;
    if (!upgCmds) upgCmds = { upgrade: '', restart: '', verify: '', mitigation: '' };

    container.style.opacity   = '0';
    container.style.transform = 'translateY(4px)';
    setTimeout(() => {
      container.innerHTML = _genTabContent(e, upgCmds, tab);
      container.style.transition = 'opacity .22s ease, transform .22s ease';
      container.style.opacity    = '1';
      container.style.transform  = 'translateY(0)';
    }, 120);
  }

  // Command registry — single source of truth for all commands
  // Phase 0 Part B: trimmed from 18 commands down to 6. Everything else
  // (scanning, CVE matching, confirmation routing) now runs automatically —
  // no slash command gates any core pipeline step. /scan's old job (set
  // target + start the scan) moved to automatic bare-target detection in
  // sendChat() below; it is no longer a typeable command.
  const CMD_REGISTRY = {
    '/report':   { fn: _cmdReport,   needsScan: true,  desc: 'Export report' },
    '/clear':    { fn: _cmdClear,    needsScan: false, desc: 'Clear chat' },
    '/stop':     { fn: _cmdStop,     needsScan: false, desc: 'Stop scan' },
    '/help':     { fn: _cmdHelp,     needsScan: false, desc: 'Show commands' },
    '/graph':    { fn: _cmdGraph,    needsScan: false, desc: 'Open a graph in a new tab' },
    '/patch':    { fn: _cmdPatch,    needsScan: false, desc: 'Patch guidance' },
  };

  async function _dispatchCommand(cmd, parts, msg) {
    const entry = CMD_REGISTRY[cmd];
    if (!entry) {
      // Unknown command — pass to AI
      return false;
    }
    // Validate: commands that need scan data
    // Try to restore from active session first (user may have refreshed the page)
    if (entry.needsScan && !App.getLastData()) {
      const activeSess = SessionManager.active();
      if (activeSess?.scan_results) {
        App.setLastData(activeSess.scan_results);
        if (activeSess.scan_session) App.setCurrentSession(activeSess.scan_session);
      }
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

  async function _cmdScan(parts) {
    const raw = parts[1] || '';
    if (raw) {
      // Auto-correct comma in IP (e.g. 10.83.113,112 → 10.83.113.112)
      const m = raw.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3}),(\d{1,3})$/);
      const target = m ? `${m[1]}.${m[2]}.${m[3]}.${m[4]}` : raw;
      _autoStartVulnScan(target);
    } else {
      _promptScanIP();
    }
  }

  async function _cmdPatch(parts) {
    if (parts[1]?.toLowerCase() === 'all') {
      // /patch all needs scan data
      if (!App.getLastData()) {
        const activeSess = SessionManager.active();
        if (activeSess?.scan_results) {
          App.setLastData(activeSess.scan_results);
          if (activeSess.scan_session) App.setCurrentSession(activeSess.scan_session);
        }
      }
      if (!App.getLastData()) {
        addMsg('⚠️ **`/patch all`** requires a completed scan. Run `/scan <ip>` first.', 'ai');
        return;
      }
      await _handlePatchAll();
    } else {
      await _handlePatchCommand(parts[1], parts[2]);
    }
  }
  async function _cmdVuln()          { await _handleVulnCommand(); }
  async function _cmdReport(parts) {
    const fmt = (parts[1] || '').toLowerCase();
    if (fmt && !['pdf','html'].includes(fmt)) {
      addMsg('⚠️ `/report` supports: `pdf` or `html` only.', 'ai'); return;
    }
    if (!App.getCurrentSession()) {
      addMsg('⚠️ Run a scan first to generate a report.', 'ai'); return;
    }
    if (fmt) {
      // Format was explicitly specified — skip modal, go straight to export
      selectFmt(fmt);
      await doExportReport();
    } else {
      // No format specified — open modal for user to choose
      showReportModal();
    }
  }
  async function _cmdClear() {
    // FIX 3: Clear chat UI only — do NOT create a new session (would break FIX 3)
    // Only create a new session if explicitly using newChat() (sidebar New Chat button)
    const chat = document.getElementById('chat');
    if (chat) chat.innerHTML = '';
    // Clear the saved messages in the current session, but keep session ID
    const activeSess = SessionManager.active();
    if (activeSess) activeSess.messages = [];
    SessionManager.persistAll();
    showGreeting();
  }
  async function _cmdStop()          { confirmStop(); }
  async function _cmdHelp()          { _showHelpCard(); }

  // Phase 0: "type an IP, no slash command needed" — the deterministic
  // client-side check, mirrors the same regex _submitScanIP already used to
  // validate manually-entered targets. Returns the normalised target string,
  // or null if `text` isn't (just) a target.
  function _extractBareTarget(text) {
    let candidate = text.trim();
    if (!candidate || /\s/.test(candidate)) return null;
    const commaFix = candidate.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3}),(\d{1,3})$/);
    if (commaFix) candidate = `${commaFix[1]}.${commaFix[2]}.${commaFix[3]}.${commaFix[4]}`;
    const validPattern = /^((\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?|localhost|([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,})$/;
    return validPattern.test(candidate) ? candidate : null;
  }

  async function sendChat() {
    const inp = document.getElementById('chat-inp');
    const msg = inp.value.trim();
    if (!msg) return;

    // FIX 3: Prevent duplicate submissions
    if (inp.dataset.sending === 'true') return;
    inp.dataset.sending = 'true';

    // Clear input and reset height BEFORE async work (FIX 1)
    inp.value = '';
    inp.style.height = 'auto';
    inp.removeAttribute('data-sending');

    const ac = document.getElementById('chat-autocomplete');
    if (ac) ac.style.display = 'none';

    // Phase 0: no slash command needed — if the whole message is a target,
    // run the same automatic full scan _autoStartVulnScan() uses for the
    // "Scan a Target" button (rich live table + charts + floating panel),
    // instead of sending it to the AI chat endpoint at all.
    const bareTarget = _extractBareTarget(msg);
    if (bareTarget) {
      await _autoStartVulnScan(bareTarget);
      return;
    }

    const parts = msg.split(/\s+/);
    const cmd   = parts[0].toLowerCase();

    // Always show user message first
    addMsg(msg, 'user');

    // FIX 3: Get current session ID — use existing active session, never create new one here.
    const _getSessionId = () => {
      // Prefer App's tracked session (scan session)
      const appSess = App.getCurrentSession();
      if (appSess) return appSess;
      // Fall back to SessionManager's active session (chat session)
      const smSess = SessionManager.activeId();
      if (smSess) return smSess;
      // FIX 2: Never auto-create a session just to send a message.
      // If there's no session yet, the user hasn't initialized a project.
      // Return a temporary placeholder — the backend will handle it gracefully.
      console.warn('[ThreatWeave] No active session — user must initialize a project first.');
      return 'no-session';
    };

    // Try slash command dispatch (Fix 1)
    if (cmd.startsWith('/')) {
      const handled = await _dispatchCommand(cmd, parts, msg);
      if (handled) return;
      // Unknown slash command — fall through to AI with error hint
      const t = addTyping();
      _updateModelIndicator({ checking: true });
      const t0 = Date.now();
      try {
        const sessionId = _getSessionId();
        console.debug('[ThreatWeave] sendChat (slash unknown) → session:', sessionId);
        const d = await ApiService.sendChatMessage(msg, _currentTarget, sessionId, SessionManager.getProjectName());
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
    const sessionId = _getSessionId();
    console.debug('[ThreatWeave] sendChat → session:', sessionId);
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
    const inp = document.getElementById('chat-inp');
    if (inp) {
      inp.value = m;
      // Trigger auto-expand visually before sendChat clears it
      inp.style.height = 'auto';
    }
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
              <span class="pob-icon">🎯</span>
              <span class="pob-text"><strong>Start Scanning</strong><small>Single IP or Multiple IPs from file</small></span>
            </button>
            <button class="post-ob-btn" onclick="Chatbot.openVulnDashboard()">
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
        if (App.getCurrentSession()) { if (d.data?.format) selectFmt(d.data.format); showReportModal(); }
        else addMsg('Run a scan first to generate a report.', 'ai');
        break;
      case 'navigate': break;
      case 'stop_scan': confirmStop(); break;
      case 'clear_chat': { const chat = document.getElementById('chat'); if (chat) chat.innerHTML = ''; const s = SessionManager.active(); if (s) s.messages = []; SessionManager.persistAll(); showGreeting(); break; }
      case 'patch_all':      _handlePatchAll();             break;
      case 'patch_all_data': _renderPatchAllFromServer(d.patch_all_data); break;
      case 'vuln_lookup':    _handleVulnCommand();          break;
      case 'show_help':      _showHelpCard();               break;
    }
  }



/**
 * chatbot/scan.js
 * Scan-type selector, scan execution, real-time progress bar, stop.
 */

  /* ═══════════════════════════════════════════════════════
     AUTO VULN SCAN — replaces the scan selector completely
  ═══════════════════════════════════════════════════════ */

  let _liveTableId  = null;
  let _liveTableEl  = null;
  let _liveCounters = { total: 0, confirmed: 0, not_vuln: 0, unconfirmed: 0 };

  // ── Sequential port-by-port NSE confirmation table state ──────────────────
  // Incremented every time _runSequentialConfirmation starts. A running loop
  // checks its captured generation against this counter each iteration — if a
  // newer scan has started, the old loop bails out instead of fighting over
  // the same DOM rows / making redundant network calls.
  let _confirmGeneration = 0;

  async function _autoStartVulnScan(ip) {
    _currentTarget = ip;
    addMsg(`🎯 Target set: \`${ip}\` — starting the full scan automatically…`, 'user');
    _renderLiveVulnTable(ip);
    await runScan(ip, 'full_scan');
  }

  async function executeScan(ip, scanType) {
    _currentTarget = ip;
    addMsg(`Running **${scanType}** on \`${ip}\`…`, 'user');
    _renderLiveVulnTable(ip);
    await runScan(ip, scanType);
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
              <th>Port</th><th>Protocol</th><th>Service</th><th>Version</th>
              <th>Vuln Status</th><th>Script Used</th><th>Evidence</th>
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
    wrap.style.opacity = '0'; wrap.style.transform = 'translateY(8px)';
    chat.appendChild(wrap);
    _liveTableEl = wrap;
    requestAnimationFrame(() => {
      wrap.style.transition = 'opacity .3s ease, transform .3s ease';
      wrap.style.opacity = '1'; wrap.style.transform = 'translateY(0)';
    });
    chat.scrollTo({ top: chat.scrollHeight, behavior: 'smooth' });
    _liveCounters = { total: 0, confirmed: 0, not_vuln: 0, unconfirmed: 0 };
    _saveRichMsg('LIVE_VULN_TABLE_START', { ip, tableId: _liveTableId });
  }

  function _onPortFound(portData) {
    if (!_liveTableId) return;
    const tbody = document.getElementById(_liveTableId + '-body');
    if (!tbody) return;
    const ph = document.getElementById(_liveTableId + '-placeholder');
    if (ph) ph.remove();
    const vs     = portData.vuln_status || {};
    const status = vs.status || 'UNCONFIRMED';
    const script = vs.script_used || '—';
    const evid   = (vs.evidence || '').slice(0, 80) || '—';
    const ver    = [portData.product, portData.version].filter(Boolean).join(' ') || '—';
    const badge  = _vulnStatusBadge(status);
    _liveCounters.total++;
    if (status === 'CONFIRMED')          _liveCounters.confirmed++;
    else if (status === 'NOT_VULNERABLE') _liveCounters.not_vuln++;
    else                                  _liveCounters.unconfirmed++;
    _updateLiveCounters();
    const tr = document.createElement('tr');
    tr.className = 'lv-row lv-row-' + status.toLowerCase().replace('_', '-');
    tr.innerHTML = `
      <td class="lv-mono">${portData.port}</td>
      <td>${portData.protocol || 'tcp'}</td>
      <td><span class="lv-svc">${portData.service || '—'}</span></td>
      <td class="lv-ver">${ver}</td>
      <td class="lv-status-cell">${badge}</td>
      <td class="lv-script">${script !== '—' ? `<code>${script}</code>` : '—'}</td>
      <td class="lv-evid" title="${evid}">${evid}</td>`;
    tr.style.opacity = '0'; tr.style.transform = 'translateX(-8px)';
    tbody.appendChild(tr);
    requestAnimationFrame(() => {
      tr.style.transition = 'opacity .25s ease, transform .25s ease';
      tr.style.opacity = '1'; tr.style.transform = 'translateX(0)';
    });
    const chat = document.getElementById('chat');
    if (chat && !_userScrolledUp) chat.scrollTo({ top: chat.scrollHeight, behavior: 'smooth' });
  }

  function _vulnStatusBadge(status) {
    if (status === 'CONFIRMED')      return '<span class="lv-badge lv-confirmed">✅ CONFIRMED VULNERABLE</span>';
    if (status === 'NOT_VULNERABLE') return '<span class="lv-badge lv-not-vuln">🟢 NOT VULNERABLE</span>';
    if (status === 'WAITING')        return '<span class="lv-badge lv-loading">⏳ Waiting…</span>';
    if (status === 'SCANNING')       return '<span class="lv-badge lv-scanning"><span class="lv-spinner"></span> Confirming…</span>';
    // FIX: these three statuses were falling through to the generic
    // "⚠️ UNCONFIRMED" badge below even though the router had already
    // determined something more specific — a version-range hit with no
    // script proof, a heuristic misconfiguration flag, or "there was
    // nothing at all to check" are not the same thing as "checked and
    // inconclusive", and conflating them hid real findings in the table.
    if (status === 'POTENTIALLY_VULNERABLE') return '<span class="lv-badge lv-potential">🟠 POTENTIALLY VULNERABLE</span>';
    if (status === 'MISCONFIGURED')          return '<span class="lv-badge lv-misconfig">🟣 MISCONFIGURED</span>';
    if (status === 'NOT_VALIDATABLE')        return '<span class="lv-badge lv-notvalidatable">❔ NOT VALIDATABLE</span>';
    return '<span class="lv-badge lv-unconfirmed">⚠️ UNCONFIRMED</span>';
  }

  function _updateLiveCounters() {
    const bump = (id, val, suffix) => {
      const el = document.getElementById(id);
      if (!el) return;
      el.textContent = val + suffix;
      el.classList.remove('lv-bump'); void el.offsetWidth; el.classList.add('lv-bump');
    };
    bump(_liveTableId + '-c-total',   _liveCounters.total,       ' ports');
    bump(_liveTableId + '-c-confirm', _liveCounters.confirmed,   ' ✅ CONFIRMED');
    bump(_liveTableId + '-c-notvuln', _liveCounters.not_vuln,    ' 🟢 NOT VULNERABLE');
    bump(_liveTableId + '-c-unconf',  _liveCounters.unconfirmed, ' ⚠️ UNCONFIRMED');
  }

  function _completeLiveTable() {
    if (!_liveTableId) return;
    const badge = document.getElementById(_liveTableId + '-badge');
    if (badge) { badge.className = 'lv-scan-badge complete'; badge.innerHTML = '✔ COMPLETE'; }
  }

  /* ═══════════════════════════════════════════════════════
     SEQUENTIAL NSE CONFIRMATION TABLE
     Renders one row per open port (mirrors the right-panel PORT DETAILS).
     Ports already CONFIRMED / NOT_VULNERABLE (no CVEs) show their final
     status immediately. Everything else starts as ⏳ WAITING, then the
     confirmation loop below picks the best Kali NSE script for ONE port
     at a time, sets that row to 🔄 Confirming…, awaits the result via
     POST /api/scan/confirm-port, writes CONFIRMED / NOT_VULNERABLE /
     UNCONFIRMED + script + evidence, then moves to the next row.
     One nmap process at a time — never parallel.
  ═══════════════════════════════════════════════════════ */

  /** Normalise vuln_status to a plain string, whether it's a dict (from the
   *  initial nmap parser) or already a string (from a prior confirmation). */
  function _normalizeVS(vs) {
    if (typeof vs === 'string') return vs || 'UNCONFIRMED';
    if (vs && typeof vs === 'object') return vs.status || 'UNCONFIRMED';
    return 'UNCONFIRMED';
  }

  /** Returns every misconfig_findings entry for a given port number. Each
   *  entry (from app/scanner/misconfig_checker.py) has at least: name,
   *  description, severity, evidence, remediation, port. */
  function _misconfigsForPort(misconfigFindings, port) {
    if (!misconfigFindings || !misconfigFindings.length) return [];
    return misconfigFindings.filter(m => m && m.port === port);
  }

  /**
   * FIX (multi-vulnerability / misconfig visibility): a single port often
   * carries SEVERAL distinct, independently-named findings — e.g. port 25's
   * ssl-dh-params alone reports 3 separate named vulnerabilities (anonymous
   * DH, Logjam, insufficient DH group strength) plus ssl-poodle reports a
   * 4th, all on the same port. Misconfigurations (TRACE enabled, CSRF-able
   * forms, exposed admin paths) are equally real findings with no CVE
   * number. None of this reached the table before — only ONE summary
   * verdict per port did. This combines both sources into one ordered list
   * of {title, status, script, cve, evidence} objects, used to render one
   * sub-row per item underneath each port's primary row.
   */
  function _additionalFindingsForPort(p, misconfigFindings) {
    const out = [];
    for (const m of _misconfigsForPort(misconfigFindings, p.port)) {
      out.push({
        title:    m.description || m.name || 'Misconfiguration',
        status:   'MISCONFIGURED',
        script:   m.name || null,
        cve:      null,
        evidence: m.evidence || m.description || '',
      });
    }
    for (const f of (p.all_findings || [])) {
      out.push({
        title:    f.title || f.script,
        status:   f.status || 'UNCONFIRMED',
        script:   f.script || null,
        cve:      f.cve || null,
        evidence: f.evidence || '',
      });
    }
    return out;
  }

  /** Same escaping as _esc(), plus quotes — needed when the value is going
   *  inside an HTML attribute (e.g. title="..."), since raw NSE output can
   *  contain quote characters that would otherwise break out of it. */
  function _escAttr(s) {
    return _esc(s).replace(/"/g, '&quot;');
  }

  /** Renders one indented sub-row for a single additional finding beneath
   *  a port's primary row. Spans the Protocol+Service columns for the title
   *  since there's no separate per-finding protocol/service to show. */
  function _findingSubRowHtml(rowId, idx, finding) {
    const status    = finding.status || 'UNCONFIRMED';
    const badge     = _vulnStatusBadge(status);
    const cveTag    = finding.cve ? `<span class="rb rb-high">${_esc(finding.cve)}</span>` : '—';
    const scriptTag = finding.script ? `<code>${_esc(finding.script)}</code>` : '—';
    const titleSafe = _esc(finding.title || finding.script || 'Finding');
    const evidFull  = finding.evidence || '';
    const evidShort = _esc(evidFull.slice(0, 100)) || '—';
    return `
      <tr class="lv-row lv-subrow lv-row-${status.toLowerCase().replace(/_/g, '-')}" id="${rowId}-f${idx}">
        <td class="lv-mono lv-subindent">↳</td>
        <td colspan="2" class="lv-subtitle" title="${titleSafe}">${titleSafe}</td>
        <td class="lv-ver">—</td>
        <td class="lv-cves">${cveTag}</td>
        <td class="lv-status-cell">${badge}</td>
        <td class="lv-script">${scriptTag}</td>
        <td class="lv-evid" title="${_escAttr(evidFull)}">${evidShort}</td>
      </tr>`;
  }

  /**
   * Build the chatbot confirmation table for every open port found in this
   * scan. Returns { tableId, rows, toConfirmCount } for
   * _runSequentialConfirmation, or null if there are no open ports.
   */
  function _renderPortConfirmTable(ip, ports, misconfigFindings) {
    if (!ports || !ports.length) return null;
    misconfigFindings = misconfigFindings || [];

    const chat    = document.getElementById('chat');
    const tableId = 'ct-' + Date.now();

    // Decide up front which ports need a live confirmation pass and which
    // can show their final badge immediately.
    const rows = ports.map(p => {
      const status     = _normalizeVS(p.vuln_status);
      const cves       = p.cves || [];
      const extra      = _additionalFindingsForPort(p, misconfigFindings);
      // A port needs confirmation unless the initial `nmap --script vuln`
      // run already CONFIRMED it, or it's NOT_VULNERABLE with zero CVE matches.
      const needsConfirm = !(status === 'CONFIRMED' || (status === 'NOT_VULNERABLE' && cves.length === 0));
      return { p, cves, extra, needsConfirm, initialStatus: needsConfirm ? 'WAITING' : status };
    });

    const toConfirmCount = rows.filter(r => r.needsConfirm).length;

    const wrap = document.createElement('div');
    wrap.className = 'msg msg-ai live-vuln-wrap';
    wrap.id = tableId;

    const rowsHtml = rows.map(({ p, cves, extra, initialStatus }) => {
      const rowKey = p.port + '-' + (p.protocol || 'tcp');
      const rowId  = tableId + '-row-' + rowKey;
      const ver    = [p.product, p.version].filter(Boolean).join(' ') || '—';

      // CVE column — strongest CVE first, "+N more" if there are others
      let cveCell = '—';
      if (cves.length) {
        const top = cves[0];
        cveCell = `<span class="rb rb-${top.severity || 'low'}">${top.cve_id || '?'}</span>`
          + (cves.length > 1 ? ` <span class="lv-scan-label">+${cves.length - 1} more</span>` : '');
      }
      // FIX (multi-finding visibility): hint that more detail is sitting
      // right below in the sub-rows, whether that's extra named
      // vulnerabilities pulled out of one script's output or misconfigs —
      // a port with ONLY a misconfig (no CVE match at all) used to show a
      // blank "—" here with no hint anything was found at all.
      if (extra.length) {
        const eTag = `<span class="lv-scan-label">⚠ +${extra.length} finding${extra.length > 1 ? 's' : ''}</span>`;
        cveCell = cveCell === '—' ? eTag : `${cveCell} ${eTag}`;
      }

      // Ports already confirmed by the initial vuln scan carry their
      // script_used / evidence in the vuln_status dict — show them now.
      const vsObj = (p.vuln_status && typeof p.vuln_status === 'object') ? p.vuln_status : {};
      const scriptOut = vsObj.script_used || '—';
      const evidOut   = (vsObj.evidence || '').slice(0, 100) || '—';
      const badge     = _vulnStatusBadge(initialStatus);

      const primaryRow = `
      <tr class="lv-row lv-row-${initialStatus.toLowerCase().replace(/_/g, '-')}" id="${rowId}">
        <td class="lv-mono">${p.port}</td>
        <td>${p.protocol || 'tcp'}</td>
        <td><span class="lv-svc">${p.service || '—'}</span></td>
        <td class="lv-ver">${ver}</td>
        <td class="lv-cves">${cveCell}</td>
        <td class="lv-status-cell" id="${rowId}-status">${badge}</td>
        <td class="lv-script" id="${rowId}-script">${scriptOut !== '—' ? `<code>${scriptOut}</code>` : '—'}</td>
        <td class="lv-evid" id="${rowId}-evid" title="${_escAttr(vsObj.evidence || '')}">${_esc(evidOut)}</td>
      </tr>`;

      // FIX (multi-vulnerability / misconfig visibility): one sub-row per
      // additional finding, rendered once here (these come from the
      // original scan and don't change after live confirmation, unlike the
      // primary row above).
      const subRows = extra.map((f, idx) => _findingSubRowHtml(rowId, idx, f)).join('');

      return primaryRow + subRows;
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
      if (statusCell) statusCell.innerHTML = _vulnStatusBadge('SCANNING');
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
      const finalScript = result.script_used || '—';
      const finalEvid   = (result.evidence || '—').slice(0, 100);

      if (statusCell) {
        statusCell.style.transition = 'opacity .2s';
        statusCell.style.opacity = '0';
        setTimeout(() => {
          statusCell.innerHTML = _vulnStatusBadge(finalStatus);
          statusCell.style.opacity = '1';
        }, 150);
      }
      if (scriptCell) {
        scriptCell.innerHTML = (finalScript && finalScript !== '—') ? `<code>${finalScript}</code>` : '—';
      }
      if (evidCell) {
        evidCell.textContent = finalEvid || '—';   // textContent — raw NSE output may contain < > &
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
     SCAN
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
    // Persist so selector survives refresh — kept for restore compat
    _saveRichMsg('SCAN_SELECTOR', { ip });
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
        // Route by event type
        if (d.type === 'port_found') {
          _onPortFound(d.port);
          return;
        }
        // Progress event
        _updateProgressUI(d);
        if (!d.running && d.status !== 'running') {
          es.close(); _progressTimer = null;
          if (d.status === 'stopped') Utils.setStatus('stopped');
          _completeLiveTable();
        }
      } catch (e) {}
    };
    es.onerror = () => { es.close(); _progressTimer = null; _completeLiveTable(); };
  }

  function _updateProgressUI(d) {
    // progress bar removed from UI — no-op
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
  }

  async function runScan(target, scan_type) {
    if (!target) { addMsg('Please provide a target IP or hostname.', 'ai'); return; }
    _setScanUIRunning(true);
    // FIX 6+7: Mark scan as running immediately so crash recovery knows
    SessionManager.markScanRunning(target, scan_type);

    // SESSION ISOLATION FIX: Capture the originating session ID at scan start.
    // All result rendering below is guarded — results only appear in THIS session.
    const _originSessionId = SessionManager.activeId();

    Utils.setStatus('scanning', target);
    _startProgressPolling();
    // Show floating slider toolbar, open to Risk tab
    _frsSetToolbarVisible(true);
    frsOpen('risk');
    const progressMsg = addMsg(`⏳ Scanning \`${target}\` — **${scan_type}**…`, 'sys');
    // Save scan-started token so even interrupted scans appear in history
    _saveRichMsg('SCAN_PROGRESS', { target, scan_type, started_at: new Date().toISOString() });
    try {
      const d = await ApiService.startScan(target, scan_type, SessionManager.getProjectName());
      const fill  = document.getElementById('prog-fill');
      const pctEl = document.getElementById('prog-pct');
      const lbl   = document.getElementById('prog-lbl');
      // progress bar removed — these are no-ops kept for safety

      // SESSION ISOLATION: store results into originating session regardless of
      // which session is currently active (user may have switched chats).
      SessionManager.saveScanToSession(_originSessionId, d);
      App.setLastData(d);
      App.setCurrentSession(d.session_id);
      try { localStorage.setItem('threatweave_last_session', JSON.stringify({ sessionId: d.session_id, data: d })); } catch (e) {}

      // Only render results + update UI if user is still in the originating session.
      // If they switched chats, silently store data — they'll see it when they return.
      const _currentlyActiveId = SessionManager.activeId();
      if (_currentlyActiveId === _originSessionId) {
        Utils.setStatus('processing');

        // FIX 4: Build a cumulative-merged view for renderAll() so the right-panel
        // dashboard always shows ALL findings across every scan in this session,
        // not just the latest scan. Without this, running OS discovery after a
        // vuln scan would wipe the CVE/risk panels because OS discovery has no CVEs.
        const cumulative = SessionManager.getCumulativeState();
        const dMerged = Object.assign({}, d);
        if (cumulative && cumulative.ports.length > 0) {
          dMerged.risk = d.risk ? JSON.parse(JSON.stringify(d.risk)) : { hosts: [] };
          if (!dMerged.risk.hosts || dMerged.risk.hosts.length === 0) {
            dMerged.risk.hosts = [{ ip: d.target, ports: [], risk_summary: {}, os: null }];
          }
          dMerged.risk.hosts[0].ports = cumulative.ports;
          // FIX: count PORT risk levels (not CVE severities) — matches renderRisk() expectations
          const allSev = { critical: 0, high: 0, medium: 0, low: 0 };
          let _overallLvl = 'low';
          for (const p of cumulative.ports) {
            const portLevel = (p.risk && p.risk.level ? p.risk.level : 'low').toLowerCase();
            if (portLevel in allSev) allSev[portLevel]++;
          }
          if (allSev.critical > 0)     _overallLvl = 'critical';
          else if (allSev.high > 0)    _overallLvl = 'high';
          else if (allSev.medium > 0)  _overallLvl = 'medium';
          dMerged.risk.hosts[0].risk_summary = Object.assign(
            {}, dMerged.risk.hosts[0].risk_summary || {},
            { counts: allSev, total_ports: cumulative.ports.length, overall: _overallLvl }
          );
          if (cumulative.os_fingerprints.length > 0) {
            const latestOs = cumulative.os_fingerprints[cumulative.os_fingerprints.length - 1];
            dMerged.risk.hosts[0].os = { name: latestOs.os_name, version: latestOs.os_version };
          }
        }

        renderAll(dMerged);
        loadDrawer();
        if (progressMsg) progressMsg.remove();

        // ── RENDER COMPREHENSIVE SCAN RESULTS IN CHAT ───────────────
        const _scanRichData = {
          target, scan_type: d.scan_type, duration: d.duration,
          summary: d.explanation?.summary || '', recommendation: d.recommendation?.reason || '',
          risk: d.risk, ai_analysis: d.ai_analysis, explanation: d.explanation,
        };
        _renderScanCompleteCard(_scanRichData);
        _saveRichMsg('SCAN_COMPLETE', _scanRichData);

        // FIX 4: Only append NEW CVEs/ports to chat that weren't shown before.
        // Count how many CVEs this specific scan found (not cumulative) and
        // only render a vuln table if this scan actually found new ones.
        const hosts     = d.risk?.hosts || [];
        const newCves   = [];
        for (const h of hosts) for (const p of h.ports || []) for (const c of p.cves || [])
          newCves.push({ ...c, port: p.port, service: p.service });
        if (newCves.length > 0) {
          _renderVulnTableInChat(hosts);
          _saveRichMsg('VULN_TABLE', newCves);
        } else {
          // No new CVEs from this scan — add a brief status message only
          const prevCveCount = (cumulative?.cves || []).length;
          const noNewMsg = prevCveCount > 0
            ? `✅ **${d.scan_type || 'Scan'} complete** on \`${target}\` — ${d.duration}s. No new CVEs found. (${prevCveCount} CVE(s) from earlier scans still tracked above.)`
            : `✅ **Scan complete** on \`${target}\` — ${d.duration}s. No CVEs detected.\n\n${d.explanation?.summary || ''}`;
          addMsg(noNewMsg, 'ai');
        }

        // ── NSE confirmation table — one open port per row, confirmed
        // sequentially (one nmap process at a time) using the best-matching
        // script picked from /usr/share/nmap/scripts/ for each port's
        // service/version/CVEs. Fire-and-forget — runs in the background
        // while runScan() finishes normally.
        try {
          // Prefer this scan's own ports (`hosts`, from `d.risk.hosts`). If THIS
          // scan came back with zero ports (e.g. nothing new this round) but the
          // right panel still shows data, that data came from `dMerged` (current
          // scan + cumulative history). Fall back to that same source so the chat
          // table always matches what the right panel is displaying.
          let allOpenPorts = [];
          for (const h of hosts) for (const p of h.ports || []) allOpenPorts.push(p);

          if (allOpenPorts.length === 0) {
            const mergedHosts = dMerged.risk?.hosts || [];
            for (const h of mergedHosts) for (const p of h.ports || []) allOpenPorts.push(p);
            if (allOpenPorts.length > 0) {
              console.log('[ThreatWeave] confirm-table: using cumulative/dMerged ports (this scan returned 0 new ports)');
            }
          }

          if (allOpenPorts.length > 0) {
            // FIX (misconfig visibility): misconfig_findings is already
            // computed by app/scanner/misconfig_checker.py during the main
            // scan (d.misconfig_findings) but was never passed into this
            // table before, so real misconfigurations (anon FTP, TRACE
            // enabled, SMB signing off, etc.) were invisible here.
            const ctInfo = _renderPortConfirmTable(target, allOpenPorts, d.misconfig_findings || []);
            if (ctInfo) _runSequentialConfirmation(target, ctInfo);
          } else {
            console.log('[ThreatWeave] confirm-table: skipped — no open ports in d.risk.hosts or dMerged.risk.hosts');
          }
        } catch (ctErr) {
          console.error('[ThreatWeave] confirm-table render failed:', ctErr);
        }

        // scan complete (progress bar removed)
      } else {
        // User is in a different chat — store results silently, show a non-intrusive
        // notification that does NOT inject content into the wrong session.
        if (progressMsg) progressMsg.remove();
        Utils.setStatus('idle');
        // Persist the completed scan data into the originating session for when user returns
        const _scanRichData = {
          target, scan_type: d.scan_type, duration: d.duration,
          summary: d.explanation?.summary || '', recommendation: d.recommendation?.reason || '',
          risk: d.risk, ai_analysis: d.ai_analysis, explanation: d.explanation,
        };
        SessionManager.storeRichMsgForSession(_originSessionId, 'SCAN_COMPLETE', _scanRichData);
        const hosts = d.risk?.hosts || [];
        const totalCves = hosts.reduce((n, h) => n + (h.ports || []).reduce((m, p) => m + (p.cves || []).length, 0), 0);
        if (totalCves > 0) {
          const _allCvesForToken = [];
          for (const h of hosts) for (const p of h.ports || []) for (const c of p.cves || [])
            _allCvesForToken.push({ ...c, port: p.port, service: p.service });
          SessionManager.storeRichMsgForSession(_originSessionId, 'VULN_TABLE', _allCvesForToken);
        }
        // Show a small non-blocking badge notification only — NO popup in wrong chat
        _showScanReadyBadge(target, _originSessionId);
        // scan complete (progress bar removed)
      }
    } catch (e) {
      if (progressMsg) progressMsg.remove();
      if (!e.message?.includes('stopped')) {
        // Only show error in the originating session if possible
        if (SessionManager.activeId() === _originSessionId) {
          // Produce a clear, actionable error message
          let errMsg = e.message || 'Unknown error';
          if (errMsg.includes('Cannot reach server') || errMsg.includes('NetworkError') || errMsg.includes('Failed to fetch')) {
            errMsg = [
              '❌ **Cannot reach the ThreatWeave server.**',
              '',
              'Possible causes:',
              '• The server stopped — run `./run.sh --restart`',
              '• Your IP changed — the server needs a restart to pick up the new LAN IP',
              '• You are on a different network than the server',
              '',
              `Technical detail: ${e.message}`,
            ].join('\n');
          } else if (errMsg.includes('409')) {
            errMsg = '⚠️ A scan is already running. Wait for it to finish or click **Stop**.';
          } else if (errMsg.includes('401')) {
            errMsg = '🔒 API token required. Set it in Settings or .env file.';
          }
          addMsg(errMsg, 'ai');
        }
        Utils.setStatus('error', 'Scan failed');
        // progress bar removed
      }
    } finally {
      _stopProgressPolling();
      _setScanUIRunning(false);
      SessionManager.clearScanState(); // FIX 7: clear interrupted scan flag
    }
  }

  /** Show a small non-intrusive badge when a scan finishes in a background session. */
  function _showScanReadyBadge(target, originSessionId) {
    // Remove any existing badge
    const old = document.getElementById('scan-ready-badge');
    if (old) old.remove();
    const badge = document.createElement('div');
    badge.id = 'scan-ready-badge';
    badge.style.cssText = [
      'position:fixed','bottom:80px','right:20px','z-index:9999',
      'background:var(--card-bg,#1e1e2e)','border:1px solid var(--purple,#7c3aed)',
      'border-radius:10px','padding:10px 14px','cursor:pointer',
      'box-shadow:0 4px 16px rgba(0,0,0,.4)','font-size:13px',
      'color:var(--text1,#e2e8f0)','max-width:240px','line-height:1.4',
    ].join(';');
    badge.innerHTML = `<strong>✅ Scan ready</strong><br><small>Results for <code>${target}</code> are waiting in another chat.</small>`;
    badge.onclick = () => {
      badge.remove();
      // Switch back to the originating session
      if (originSessionId) SessionManager.switchTo(originSessionId);
    };
    document.body.appendChild(badge);
    setTimeout(() => { if (badge.parentNode) badge.remove(); }, 15000);
  }

  async function confirmStop() { Utils.openModal('stop-modal'); }

  async function doStop() {
    Utils.closeModal('stop-modal');
    await ApiService.stopScan();
    _stopProgressPolling();
    _setScanUIRunning(false);
    
    // progress bar removed
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
    // FIX 3: Create intentional blank workspace (user must provide project name)
    // allowUnnamed=true here because this is an explicit "new chat" action by the user,
    // not an auto-creation on refresh/load.
    SessionManager.create('', true);
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
    _startPlaceholderRotation();       // FIX16: rotating placeholder
  }



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

    // FIX18: green flash on the chat container
    chat.classList.add('scan-complete-flash');
    setTimeout(() => chat.classList.remove('scan-complete-flash'), 1200);
    _updateBreadcrumb(SessionManager.getProjectName(), data.target || '');  // FIX19

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

    // FIX18: zero-CVE special class for pulse animation
    const zeroCveClass = allCves.length === 0 ? 'zero-cve-pulse' : '';

    d.innerHTML = `
      <div class="src-header">
        <div class="src-title-row">
          <span class="src-icon">${allCves.length === 0 ? '🎉' : '✅'}</span>
          <div>
            <!-- FIX18: Strong risk badge hierarchy -->
            <span class="src-risk-badge ${level}">${level.toUpperCase()} RISK · ${score}/10</span>
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
        <button class="post-ob-btn" style="font-size:12px;padding:6px 12px" onclick="Chatbot.openVulnDashboard()">🔎 Full CVE Dashboard</button>
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
        <button class="vd-export-btn" style="margin-left:auto" onclick="Chatbot.openVulnDashboard()">Open Full Dashboard →</button>
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


/**
 * chatbot/patch.js
 * /patch remediation dashboard, single-port guidance, /model diagnostics, /help.
 */


  /* ═══════════════════════════════════════════════════════
     /patch all — renders AI patches for ALL ports
     Two paths:
       1. Server returned __PATCH_ALL_DATA__ with AI results → _renderPatchAllFromServer()
       2. Server returned __PATCH_ALL__ (no scan in session)     → _handlePatchAll() uses local data
  ═══════════════════════════════════════════════════════ */

  async function _handlePatchAll() {
    // This is the LOCAL fallback — server didn't have scan context
    const data  = App.getLastData();
    const hosts = data?.risk?.hosts || [];

    if (!hosts.length) {
      addMsg('No scan data found. Run a scan first, then try `/patch all` again.', 'ai');
      return;
    }

    // Build port list from local scan data
    const entries = [];
    for (const h of hosts) {
      for (const p of h.ports || []) {
        const cves   = p.cves || [];
        const risk   = p.risk || {};
        const topCve = cves[0];
        entries.push({
          ip:         h.ip || '',
          port:       p.port,
          service:    p.service || '—',
          version:    p.version || p.product || 'unknown',
          risk_level: risk.level || 'low',
          risk_score: risk.score || 0,
          cve_id:     topCve?.cve_id || 'unknown',
          severity:   topCve?.severity || risk.level || 'low',
          cve_desc:   topCve?.description || '',
          all_cves:   cves,
          // Static patch commands as fallback until AI loads
          upgrade_command: _genPatchCmds(p).upgrade || `apt update && apt install --only-upgrade ${p.service || 'package'}`,
          mitigation:      _genPatchCmds(p).mitigation || `Restrict port ${p.port} via firewall`,
          restart_command: _genPatchCmds(p).restart || `systemctl restart ${p.service}`,
          verify_command:  _genPatchCmds(p).verify  || `${p.service} --version`,
          engine:          'local-static',
        });
      }
    }

    if (!entries.length) {
      addMsg('No open ports found in last scan. Run `/scan` first.', 'ai');
      return;
    }

    entries.sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3 };
      return (order[a.risk_level] || 3) - (order[b.risk_level] || 3);
    });

    // Render with static data first, then fetch AI per entry
    _renderPatchAllInChat(entries, true /* fetchingAI */);
  }

  /** Render patch-all results returned directly from server (AI already done) */
  function _renderPatchAllFromServer(patchResults) {
    if (!patchResults || !patchResults.length) {
      addMsg('No patch data returned. Make sure a scan has been completed first.', 'ai');
      return;
    }
    _renderPatchAllInChat(patchResults, false);
  }

  /** Core renderer for /patch all — shows a card per port with Gemini patch data */
  function _renderPatchAllInChat(entries, fetchGemini) {
    const chat  = document.getElementById('chat');
    const wrap  = document.createElement('div');
    wrap.className = 'msg msg-ai patch-all-wrap';

    const CLRS = { critical: '#e24b4a', high: '#ef9f27', medium: '#378add', low: '#1d9e75' };
    const immediate = entries.filter(e => ['critical','high'].includes(e.risk_level)).length;

    const sessionId = App.getCurrentSession() || SessionManager.activeId() || '';

    // Build per-entry OS command data and store as JSON for the global switcher
    const allOsData = entries.map(e => _buildOsCommands(e));
    const wrapId = 'paw-' + Date.now();

    let cardsHtml = entries.map((e, idx) => {
      const clr     = CLRS[e.risk_level] || '#888';
      const sev     = (e.severity || e.risk_level || 'low').toLowerCase();
      const hdg     = e.config_hardening || [];
      const eng     = e.engine || '';
      const tabId   = `ptab-${idx}-${wrapId}`;
      const os      = allOsData[idx];
      const _os     = os?.linux || { upgrade: `apt update && apt install --only-upgrade ${e.service||'package'}`, restart: `systemctl restart ${e.service||'service'}`, verify: `${e.service||'service'} --version`, mitigation: `Restrict port ${e.port} via firewall. Apply latest security patches.` };

      // All CVE tags row
      const allCvesHtml = (e.all_cves || []).slice(0, 5).map(c => {
        const cs = (c.severity || 'low').toLowerCase();
        const cs_clr = CLRS[cs] || '#888';
        return `<span class="pnc-cve-tag" style="background:${cs_clr}22;color:${cs_clr};border:1px solid ${cs_clr}44">${c.cve_id||''} (${(c.cvss_score||0).toFixed(1)})</span>`;
      }).join('');

      // Primary CVE tag
      const primaryCve = e.cve || e.cve_id || '';
      const cvss = parseFloat(e.cvss || e.risk_score || 0);

      // Distro/version tags
      const distroTags = [];
      if (e.product) distroTags.push(`<span class="pnc-tag pnc-tag-os">${e.product}</span>`);
      if (e.version && e.version !== 'unknown') distroTags.push(`<span class="pnc-tag pnc-tag-ver">${e.version}</span>`);

      const _copyIcon = `<svg width="14" height="14" viewBox="0 0 16 16" fill="none"><rect x="5.5" y="1.5" width="9" height="11" rx="1.5" stroke="currentColor" stroke-width="1.4"/><rect x="1.5" y="4.5" width="9" height="10" rx="1.5" stroke="currentColor" stroke-width="1.4" fill="var(--bg2,#161b22)"/></svg>`;

      // Numbered command blocks (always visible — no expand)
      const cmdBlocks = [
        { n: 1, label: 'UPGRADE', cmd: _os.upgrade,  cls: 'pa-os-upgrade'  },
        { n: 2, label: 'RESTART', cmd: _os.restart,  cls: 'pa-os-restart'  },
        { n: 3, label: 'VERIFY',  cmd: _os.verify,   cls: 'pa-os-verify'   },
      ].filter(b => b.cmd).map(b => `
        <div class="pnc-cmd-block">
          <div class="pnc-cmd-label"><span class="pnc-cmd-num">${b.n}</span>${b.label}</div>
          <div class="pnc-cmd-row">
            <code class="pnc-cmd ${b.cls}">${b.cmd}</code>
            <button class="pnc-copy-btn" title="Copy" onclick="event.stopPropagation();var c=this.previousElementSibling;navigator.clipboard.writeText(c.textContent.trim());var o=this.innerHTML;this.innerHTML='<svg width=14 height=14 viewBox=\\'0 0 16 16\\'><polyline points=\\'2,8 6,12 14,4\\' stroke=\\'#4caf50\\' stroke-width=\\'2\\' fill=\\'none\\'/></svg>';setTimeout(()=>{this.innerHTML=o},1500)" type="button">${_copyIcon}</button>
          </div>
        </div>`).join('');

      // 5 tab buttons + Severity
      const tabs = [
        { id: 'mitigation', icon: '🛡', label: 'Mitigation' },
        { id: 'riskscore',  icon: '📊', label: 'Risk Score' },
        { id: 'impact',     icon: '💥', label: 'Impact'     },
        { id: 'risklevel',  icon: '🚨', label: 'Risk Level' },
        { id: 'severity',   icon: '⚠',  label: 'Severity'  },
      ];

      // Encode entry as JSON for tab switching (escape quotes for html attr)
      const entryJson = JSON.stringify({
        port: e.port, service: e.service, cve: primaryCve, cve_desc: e.cve_desc || '',
        severity: sev, risk_level: e.risk_level || sev, risk_score: e.risk_score || cvss,
        cvss, version: e.version || 'unknown', reasons: e.reasons || [],
        all_cves: e.all_cves || [], ai_action: e.ai_action || '', patch_note: e.patch_note || '',
        mitigation: _os.mitigation || '',
      }).replace(/"/g, '&quot;');

      const cmdsJson = JSON.stringify({
        upgrade: _os.upgrade, restart: _os.restart, verify: _os.verify,
        mitigation: _os.mitigation,
      }).replace(/"/g, '&quot;');

      return `
        <div class="pnc-card" data-card-idx="${idx}" data-sev="${sev}" style="border-left:3px solid ${clr}">
          <!-- Header row: port + service + version/distro tags + CVE + severity badge + score -->
          <div class="pnc-header" onclick="Chatbot._togglePncCard(this)" style="cursor:pointer">
            <div class="pnc-header-left">
              <span class="pnc-port-badge" style="background:${clr}22;color:${clr};border:1px solid ${clr}44">Port ${e.port}</span>
              <span class="pnc-svc">${e.service}</span>
              ${distroTags.join('')}
            </div>
            <div class="pnc-header-right">
              ${primaryCve ? `<a class="pnc-cve-primary" href="https://nvd.nist.gov/vuln/detail/${primaryCve}" target="_blank" rel="noopener" onclick="event.stopPropagation()">${primaryCve}</a>` : ''}
              <span class="rb rb-${sev}" style="font-size:11px;padding:2px 8px">${sev.toUpperCase()}</span>
              <span class="pnc-score" style="color:${clr}">${cvss.toFixed(1)}/10</span>
              ${primaryCve ? `<a class="pnc-nvd-link" href="https://nvd.nist.gov/vuln/detail/${primaryCve}" target="_blank" rel="noopener" onclick="event.stopPropagation()" title="View on NVD" style="color:#6e7681;font-size:11px;text-decoration:none;padding:2px 6px;border:1px solid #30363d;border-radius:4px">NVD ↗</a>` : ''}
              <span class="pnc-toggle-arrow">▼</span>
            </div>
          </div>

          <!-- Collapsible body — hidden by default -->
          <div class="pnc-card-body" style="display:none">
            ${e.cve_desc ? `<div class="pnc-desc">${e.cve_desc}</div>` : ''}
            ${allCvesHtml ? `<div class="pnc-cve-tags">${allCvesHtml}</div>` : ''}
            <div class="pnc-cmds" data-idx="${idx}">${cmdBlocks}</div>
            ${hdg.length ? `<div class="pnc-hardening"><div class="pnc-hdg-title">⚙️ Hardening</div><ul class="pnc-hdg-list">${hdg.map(h=>`<li>${h}</li>`).join('')}</ul></div>` : ''}
            ${eng ? `<div class="pa-engine-badge">✨ ${eng}</div>` : ''}
            <div class="pnc-tab-bar" data-tabgroup="${tabId}">
              ${tabs.map((t, ti) => `<button class="pnc-tab${ti===0?' active':''}" data-tab="${t.id}"
                onclick="event.stopPropagation();Chatbot._switchPatchTab('${tabId}-content','${t.id}',this)"
              >${t.icon} ${t.label}</button>`).join('')}
            </div>
            <div class="pnc-tab-content pd-expand-row" id="${tabId}-content"
                 data-entry="${entryJson}" data-cmds="${cmdsJson}">
              ${_genTabContent({ port: e.port, service: e.service, cve: primaryCve, cve_desc: e.cve_desc||'', severity: sev, risk_level: e.risk_level||sev, risk_score: e.risk_score||cvss, cvss, version: e.version||'unknown', reasons: e.reasons||[], all_cves: e.all_cves||[], ai_action: e.ai_action||'', patch_note: e.patch_note||'' }, { upgrade: _os.upgrade, restart: _os.restart, verify: _os.verify, mitigation: _os.mitigation }, 'mitigation')}
            </div>
            ${fetchGemini ? `<div class="pa-gemini-loading" id="pa-gem-${tabId}"><span class="pa-gem-spinner"></span> Fetching AI data…</div>` : ''}
          </div>
        </div>`;
    }).join('');

    // Global OS switcher — clicking it updates ALL cards at once
    const globalOsHtml = `
      <div class="pa-global-os" id="global-os-${wrapId}">
        <span class="pa-global-os-title">🔧 AI Patch Remediation — All Vulnerabilities</span>
        <div class="pa-global-os-tabs">
          <button class="pa-gos-tab active" data-gos="linux" onclick="Chatbot._switchPatchOs(this,'${wrapId}','linux')">🐧 Linux</button>
          <button class="pa-gos-tab" data-gos="windows" onclick="Chatbot._switchPatchOs(this,'${wrapId}','windows')">🪟 Windows</button>
          <button class="pa-gos-tab" data-gos="macos" onclick="Chatbot._switchPatchOs(this,'${wrapId}','macos')">🍎 macOS</button>
        </div>
      </div>`;

    wrap.innerHTML = `
      <div class="pa-header">
        <div class="pa-subtitle">${entries.length} services · ${immediate} need immediate action</div>
        <div class="pa-stats">
          ${['critical','high','medium','low'].map(s => {
            const n = entries.filter(e=>e.risk_level===s).length;
            return n ? `<span class="pa-stat pa-stat-${s}">${n} ${s}</span>` : '';
          }).join('')}
        </div>
      </div>
      ${globalOsHtml}
      <div class="pa-cards" id="pa-cards-${wrapId}">${cardsHtml}</div>
      <div class="pa-footer">

      </div>`;

    wrap._patchEntries = entries;
    wrap._allOsData    = allOsData;
    wrap._wrapId       = wrapId;
    wrap.style.opacity = '0'; wrap.style.transform = 'translateY(8px)';
    chat.appendChild(wrap);
    requestAnimationFrame(() => {
      wrap.style.transition = 'opacity .3s ease, transform .3s ease';
      wrap.style.opacity = '1'; wrap.style.transform = 'translateY(0)';
    });
    chat.scrollTo({ top: chat.scrollHeight, behavior: 'smooth' });

    // ── BUG 1 FIX: Persist patch-all output to session history ───────────────
    // Save a serialisable snapshot of entries (no DOM refs) so it can be
    // restored exactly on page reload via _restoreRichWidget → PATCH_ALL_WRAP
    _saveRichMsg('PATCH_ALL_WRAP', entries.map(e => ({
      ip:         e.ip        || '',
      port:       e.port,
      service:    e.service   || '',
      version:    e.version   || '',
      risk_level: e.risk_level|| 'low',
      risk_score: e.risk_score|| 0,
      cve_id:     e.cve_id    || '',
      severity:   e.severity  || '',
      cve_desc:   e.cve_desc  || '',
      all_cves:   e.all_cves  || [],
      summary:         e.summary          || '',
      upgrade_command: e.upgrade_command  || e.upgrade_cmd || '',
      restart_command: e.restart_command  || '',
      verify_command:  e.verify_command   || '',
      mitigation:      e.mitigation       || '',
      config_hardening:e.config_hardening || [],
      references:      e.references       || [],
      engine:          e.engine           || '',
    })));

    // Cards are always expanded — no auto-expand needed for new layout

    // If fetchGemini=true, fetch AI patches asynchronously per entry (deduplicated)
    if (fetchGemini) {
      _fetchAIPatchesForAll(entries, wrap, sessionId);
    }
  }

  /** Fetch AI patches for all entries — deduplicated, sequential to respect queue */
  async function _fetchAIPatchesForAll(entries, wrapEl, sessionId) {
    for (let i = 0; i < entries.length; i++) {
      const e = entries[i];
      // Find card by data-card-idx (new layout — always visible, no expand panel)
      const cardEl  = wrapEl.querySelector(`.pnc-card[data-card-idx="${i}"]`);
      if (!cardEl) continue;
      const loadEl  = cardEl.querySelector(`[id^="pa-gem-"]`);

      try {
        const data = typeof RemediationClient !== 'undefined'
          ? await RemediationClient.getPatchGuidance({
              service:    e.service,
              port:       e.port,
              version:    e.version    || 'unknown',
              cve_id:     e.cve_id     || e.cve || 'unknown',
              severity:   e.severity   || 'medium',
              session_id: sessionId,
            })
          : await ApiService.getPatchGuidance(
              e.service, e.port, e.version || 'unknown',
              e.cve_id || e.cve || 'unknown', e.severity || 'medium', sessionId
            );

        // Merge AI data into entry
        entries[i] = { ...e, ...data, ip: e.ip, port: e.port, service: e.service,
                       risk_level: e.risk_level, risk_score: e.risk_score,
                       cve: e.cve || e.cve_id, cve_desc: e.cve_desc, all_cves: e.all_cves };

        const upd      = entries[i];
        const newOsData = _buildOsCommands(upd);
        wrapEl._allOsData[i] = newOsData;
        const activeOs  = wrapEl._activeOs || 'linux';
        const osCmd     = newOsData[activeOs] || newOsData.linux;

        // Update command blocks in the card
        const cmdsEl = cardEl.querySelector(`.pnc-cmds[data-idx="${i}"]`);
        if (cmdsEl) {
          const _copyIcon = `<svg width="14" height="14" viewBox="0 0 16 16" fill="none"><rect x="5.5" y="1.5" width="9" height="11" rx="1.5" stroke="currentColor" stroke-width="1.4"/><rect x="1.5" y="4.5" width="9" height="10" rx="1.5" stroke="currentColor" stroke-width="1.4" fill="var(--bg2,#161b22)"/></svg>`;
          cmdsEl.innerHTML = [
            { n:1, label:'UPGRADE', cmd: osCmd.upgrade,  cls: 'pa-os-upgrade'  },
            { n:2, label:'RESTART', cmd: osCmd.restart,  cls: 'pa-os-restart'  },
            { n:3, label:'VERIFY',  cmd: osCmd.verify,   cls: 'pa-os-verify'   },
          ].filter(b => b.cmd).map(b => `
            <div class="pnc-cmd-block">
              <div class="pnc-cmd-label"><span class="pnc-cmd-num">${b.n}</span>${b.label}</div>
              <div class="pnc-cmd-row">
                <code class="pnc-cmd ${b.cls}">${b.cmd}</code>
                <button class="pnc-copy-btn" title="Copy" onclick="event.stopPropagation();var c=this.previousElementSibling;navigator.clipboard.writeText(c.textContent.trim());var o=this.innerHTML;this.innerHTML='<svg width=14 height=14 viewBox=\\'0 0 16 16\\'><polyline points=\\'2,8 6,12 14,4\\' stroke=\\'#4caf50\\' stroke-width=\\'2\\' fill=\\'none\\'/></svg>';setTimeout(()=>{this.innerHTML=o},1500)" type="button">${_copyIcon}</button>
              </div>
            </div>`).join('');
        }

        // Update tab content data attrs so tabs reflect AI-enriched data
        const tabContent = cardEl.querySelector('.pnc-tab-content');
        if (tabContent) {
          const updatedEntry = {
            port: upd.port, service: upd.service, cve: upd.cve || upd.cve_id || '',
            cve_desc: upd.cve_desc || '', severity: (upd.severity||upd.risk_level||'low').toLowerCase(),
            risk_level: upd.risk_level || upd.severity || 'low',
            risk_score: upd.risk_score || 0, cvss: parseFloat(upd.cvss || upd.risk_score || 0),
            version: upd.version || 'unknown', reasons: upd.reasons || [],
            all_cves: upd.all_cves || [], ai_action: data.ai_action || data.summary || '',
            patch_note: data.notes || data.patch_note || '',
            mitigation: osCmd.mitigation || '',
          };
          tabContent.dataset.entry = JSON.stringify(updatedEntry).replace(/"/g, '&quot;');
          tabContent.dataset.cmds  = JSON.stringify({ upgrade: osCmd.upgrade, restart: osCmd.restart, verify: osCmd.verify, mitigation: osCmd.mitigation }).replace(/"/g, '&quot;');
          // Re-render active tab with fresh data
          const activeTabBtn = cardEl.querySelector('.pnc-tab.active');
          if (activeTabBtn) {
            const activeTab = activeTabBtn.dataset.tab || 'mitigation';
            tabContent.innerHTML = _genTabContent(updatedEntry, { upgrade: osCmd.upgrade, restart: osCmd.restart, verify: osCmd.verify, mitigation: osCmd.mitigation }, activeTab);
          }
        }

        if (loadEl) loadEl.remove();
        // Pulse card to signal AI update
        cardEl.classList.add('pnc-card-updated');
        setTimeout(() => cardEl.classList.remove('pnc-card-updated'), 800);

      } catch (err) {
        if (loadEl) loadEl.innerHTML = `<span style="color:var(--text3);font-size:11px">⚠️ AI unavailable — showing rule-based patch guide</span>`;
      }
    }

    // Re-save enriched entries after all AI calls finish
    try {
      const sess = SessionManager.active();
      if (sess) _saveRichMsg('PATCH_ALL_WRAP', entries.map(e => ({
        ip:         e.ip        || '',
        port:       e.port,
        service:    e.service   || '',
        version:    e.version   || '',
        risk_level: e.risk_level|| 'low',
        risk_score: e.risk_score|| 0,
        cve_id:     e.cve_id    || '',
        severity:   e.severity  || '',
        cve_desc:   e.cve_desc  || '',
        all_cves:   e.all_cves  || [],
        summary:         e.summary          || '',
        upgrade_command: e.upgrade_command  || e.upgrade_cmd || '',
        restart_command: e.restart_command  || '',
        verify_command:  e.verify_command   || '',
        mitigation:      e.mitigation       || '',
        config_hardening:e.config_hardening || [],
        references:      e.references       || [],
        engine:          e.engine           || '',
      })));
    } catch (_) {}
  }



  function _buildOsCommands(entry) {
    const svc     = (entry && entry.service) ? entry.service.toLowerCase() : 'service';
    const upg     = entry && (entry.upgrade_command || entry.upgrade_cmd) ? (entry.upgrade_command || entry.upgrade_cmd) : '';
    const rst     = entry && entry.restart_command ? entry.restart_command : '';
    const vrfy    = entry && entry.verify_command  ? entry.verify_command  : '';
    const mit     = entry && entry.mitigation      ? entry.mitigation      : '';

    // Service → package name map for each OS
    const PKG = {
      ssh:       { linux: 'openssh-server', win: 'OpenSSH.Server', brew: 'openssh' },
      openssh:   { linux: 'openssh-server', win: 'OpenSSH.Server', brew: 'openssh' },
      http:      { linux: 'apache2',        win: 'Apache.ApacheHTTPServer', brew: 'httpd' },
      https:     { linux: 'apache2',        win: 'Apache.ApacheHTTPServer', brew: 'httpd' },
      apache:    { linux: 'apache2',        win: 'Apache.ApacheHTTPServer', brew: 'httpd' },
      nginx:     { linux: 'nginx',          win: 'Nginx.Nginx',             brew: 'nginx' },
      ftp:       { linux: 'vsftpd',         win: null,                      brew: null },
      mysql:     { linux: 'mysql-server',   win: 'Oracle.MySQL',            brew: 'mysql' },
      mssql:     { linux: 'mssql-server',   win: 'Microsoft.SQLServer',     brew: null },
      postgresql:{ linux: 'postgresql',     win: 'PostgreSQL.PostgreSQL',   brew: 'postgresql' },
      postgres:  { linux: 'postgresql',     win: 'PostgreSQL.PostgreSQL',   brew: 'postgresql' },
      smb:       { linux: 'samba',          win: null,                      brew: 'samba' },
      samba:     { linux: 'samba',          win: null,                      brew: 'samba' },
      rdp:       { linux: 'xrdp',           win: null,                      brew: null },
      telnet:    { linux: 'telnetd',        win: null,                      brew: null },
      smtp:      { linux: 'postfix',        win: null,                      brew: 'postfix' },
      dns:       { linux: 'bind9',          win: null,                      brew: 'bind' },
      iis:       { linux: null,             win: 'Microsoft.IIS',           brew: null },
    };

    // Match service name to pkg entry
    let pkgKey = Object.keys(PKG).find(k => svc.includes(k)) || null;
    const pkg = pkgKey ? PKG[pkgKey] : { linux: svc, win: svc, brew: svc };

    // Restart command map by service
    const RESTART = {
      ssh: { linux: 'systemctl restart ssh', win: 'Restart-Service sshd', mac: 'sudo launchctl kickstart -k system/com.openssh.sshd' },
      http: { linux: 'systemctl restart apache2', win: 'Restart-Service W3SVC', mac: 'brew services restart httpd' },
      https: { linux: 'systemctl restart apache2', win: 'Restart-Service W3SVC', mac: 'brew services restart httpd' },
      apache: { linux: 'systemctl restart apache2', win: 'Restart-Service W3SVC', mac: 'brew services restart httpd' },
      nginx: { linux: 'systemctl restart nginx', win: 'Restart-Service nginx', mac: 'brew services restart nginx' },
      mysql: { linux: 'systemctl restart mysql', win: 'Restart-Service MySQL80', mac: 'brew services restart mysql' },
      postgresql: { linux: 'systemctl restart postgresql', win: 'Restart-Service postgresql', mac: 'brew services restart postgresql' },
      postgres: { linux: 'systemctl restart postgresql', win: 'Restart-Service postgresql', mac: 'brew services restart postgresql' },
      smb: { linux: 'systemctl restart smbd', win: 'Restart-Service LanmanServer', mac: 'brew services restart samba' },
      samba: { linux: 'systemctl restart smbd', win: 'Restart-Service LanmanServer', mac: 'brew services restart samba' },
      smtp: { linux: 'systemctl restart postfix', win: 'Restart-Service SMTPSVC', mac: 'brew services restart postfix' },
      dns: { linux: 'systemctl restart bind9', win: 'Restart-Service DNS', mac: 'brew services restart bind' },
    };
    const rstKey = Object.keys(RESTART).find(k => svc.includes(k));
    const rstMap = rstKey ? RESTART[rstKey] : {
      linux: `systemctl restart ${svc}`,
      win: `Restart-Service ${svc}`,
      mac: `brew services restart ${svc}`
    };

    // Verify commands
    const VERIFY = {
      ssh: { linux: 'ssh -V', win: 'Get-Service sshd', mac: 'ssh -V' },
      http: { linux: 'apache2 -v', win: 'Get-Service W3SVC', mac: 'httpd -v' },
      https: { linux: 'apache2 -v', win: 'Get-Service W3SVC', mac: 'httpd -v' },
      apache: { linux: 'apache2 -v', win: 'Get-Service W3SVC', mac: 'httpd -v' },
      nginx: { linux: 'nginx -v', win: 'Get-Service nginx', mac: 'nginx -v' },
      mysql: { linux: 'mysql --version', win: 'Get-Service MySQL80', mac: 'mysql --version' },
      postgresql: { linux: 'psql --version', win: 'Get-Service postgresql', mac: 'psql --version' },
      smb: { linux: 'smbstatus --version', win: 'Get-Service LanmanServer', mac: 'smbutil statshares -a' },
    };
    const vrfKey = Object.keys(VERIFY).find(k => svc.includes(k));
    const vrfMap = vrfKey ? VERIFY[vrfKey] : {
      linux: `${svc} --version 2>/dev/null || systemctl status ${svc}`,
      win: `Get-Service ${svc}`,
      mac: `${svc} --version 2>/dev/null || brew services list | grep ${svc}`
    };

    const port = entry && entry.port ? entry.port : 'PORT';

    // Mitigation text per OS — multi-line for readability
    const MIT_LINUX = mit ||
      `• Block the port at firewall: <code>ufw deny ${port}/tcp && ufw reload</code>\n` +
      `• Restrict service to localhost if external access is not needed.\n` +
      `• Apply patches immediately and monitor logs for exploitation attempts.`;

    const MIT_WIN =
      `• Open Windows Defender Firewall → Advanced Settings.\n` +
      `• Add inbound rule to block port ${port} for untrusted networks.\n` +
      `• Apply the update via Windows Update or winget, then re-enable the rule.\n` +
      `• Review firewall logs for any suspicious connection attempts.`;

    const MIT_MAC =
      `• Add firewall rule: <code>sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /usr/sbin/${svc}</code>\n` +
      `• Disable the service if unused: <code>sudo launchctl disable system/${svc}</code>\n` +
      `• Verify firewall is active: <code>sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate</code>`;

    // Build final per-OS command objects
    // Prefer AI-generated commands where available (for Linux only — that's what the backend returns)
    const linuxUpg = upg || (pkg.linux ? `apt update && apt install --only-upgrade ${pkg.linux}` : `# Update ${svc} via your package manager`);
    const winUpg   = pkg.win  ? `winget upgrade ${pkg.win}` : `# Check vendor site for ${svc} Windows update`;
    const macUpg   = pkg.brew ? `brew update && brew upgrade ${pkg.brew}` : `# Check vendor site for ${svc} macOS update`;

    return {
      linux: {
        icon: '🐧', label: 'Linux',
        upgrade:    linuxUpg,
        restart:    rst  || rstMap.linux,
        verify:     vrfy || vrfMap.linux,
        mitigation: MIT_LINUX,
      },
      windows: {
        icon: '🪟', label: 'Windows',
        upgrade:    winUpg,
        restart:    rstMap.win,
        verify:     vrfMap.win,
        mitigation: MIT_WIN,
      },
      macos: {
        icon: '🍎', label: 'macOS',
        upgrade:    macUpg,
        restart:    rstMap.mac,
        verify:     vrfMap.mac,
        mitigation: MIT_MAC,
      },
    };
  }

  window.CopyCmd = function(btn) {
    var code = btn.previousElementSibling || btn.closest('.pa-cmd-row').querySelector('code');
    var text = code ? code.textContent.trim() : '';
    if (!text) return;
    Utils.safeCopy(text, function() {
      var orig = btn.innerHTML;
      btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 16 16"><polyline points="2,8 6,12 14,4" stroke="#4caf50" stroke-width="2" fill="none"/></svg>';
      setTimeout(function(){ btn.innerHTML = orig; }, 1500);
    });
  };

  /**
   * Build the cross-platform OS command selector.
   * Switches all patch cards in the wrap to show commands for the selected OS.
   */
  function _switchPatchOs(btn, wrapId, os) {
    // Update active tab style
    const osBar = btn.closest('.pa-global-os');
    osBar.querySelectorAll('.pa-gos-tab').forEach(t => t.classList.remove('active'));
    btn.classList.add('active');

    // Find the wrap element — search by wrapId in pa-cards container, then get parent
    const cardsContainer = document.getElementById('pa-cards-' + wrapId);
    const wrap = cardsContainer ? cardsContainer.closest('.patch-all-wrap') : null;
    if (!wrap) { console.warn('[OS Switch] Could not find wrap for', wrapId); return; }

    // Rebuild allOsData from _patchEntries if not present (e.g. after DOM restore)
    if (!wrap._allOsData && wrap._patchEntries) {
      wrap._allOsData = wrap._patchEntries.map(e => _buildOsCommands(e));
    }
    const allOsData = wrap._allOsData || [];
    wrap._activeOs = os;

    // Update every card's command fields using OS-aware CSS selectors
    wrap.querySelectorAll('.pnc-card').forEach(card => {
      const idx = parseInt(card.dataset.cardIdx, 10);
      const data = allOsData[idx];
      if (!data || !data[os]) return;
      const sel = data[os];

      // Update OS-aware command elements (present in both initial render and AI-enriched cards)
      const upg = card.querySelector('.pa-os-upgrade');
      const rst = card.querySelector('.pa-os-restart');
      const vrf = card.querySelector('.pa-os-verify');
      const mit = card.querySelector('.pa-os-mitigation');
      if (upg) upg.textContent = sel.upgrade;
      if (rst) rst.textContent = sel.restart;
      if (vrf) vrf.textContent = sel.verify;
      if (mit) mit.innerHTML   = sel.mitigation;

      // Re-render the cmd blocks entirely so RESTART/VERIFY rows that were
      // previously hidden (no command for that OS) appear/disappear correctly,
      // and so newly-added rows get working copy buttons.
      const cmdsEl = card.querySelector('.pnc-cmds');
      if (cmdsEl) {
        const _copyIcon = '<svg width="14" height="14" viewBox="0 0 16 16" fill="none"><rect x="5.5" y="1.5" width="9" height="11" rx="1.5" stroke="currentColor" stroke-width="1.4"/><rect x="1.5" y="4.5" width="9" height="10" rx="1.5" stroke="currentColor" stroke-width="1.4" fill="var(--bg2,#161b22)"/></svg>';
        cmdsEl.innerHTML = [
          { n:1, label:'UPGRADE', cmd: sel.upgrade, cls: 'pa-os-upgrade' },
          { n:2, label:'RESTART', cmd: sel.restart, cls: 'pa-os-restart' },
          { n:3, label:'VERIFY',  cmd: sel.verify,  cls: 'pa-os-verify'  },
        ].filter(b => b.cmd).map(b => `
          <div class="pnc-cmd-block">
            <div class="pnc-cmd-label"><span class="pnc-cmd-num">${b.n}</span>${b.label}</div>
            <div class="pnc-cmd-row">
              <code class="pnc-cmd ${b.cls}">${b.cmd}</code>
              <button class="pnc-copy-btn" title="Copy" onclick="event.stopPropagation();var c=this.previousElementSibling;navigator.clipboard.writeText(c.textContent.trim());var o=this.innerHTML;this.innerHTML='<svg width=14 height=14 viewBox=\\'0 0 16 16\\'><polyline points=\\'2,8 6,12 14,4\\' stroke=\\'#4caf50\\' stroke-width=\\'2\\' fill=\\'none\\'/></svg>';setTimeout(()=>{this.innerHTML=o},1500)" type="button">${_copyIcon}</button>
            </div>
          </div>`).join('');
      }
    });
  }

  function _togglePaExpand(expId) {
    const el  = document.getElementById(expId);
    const arr = document.getElementById('arr-' + expId);
    if (!el) {
      // Try finding within the most recent patch-all-wrap (DOM restore edge case)
      const cards = document.querySelectorAll('.patch-all-wrap .pa-expand');
      for (const c of cards) {
        if (c.id === expId) { c.style.display = c.style.display === 'none' ? 'block' : 'none'; return; }
      }
      console.warn('[patch] expand element not found:', expId); return;
    }
    const open = el.style.display !== 'none';
    el.style.display  = open ? 'none' : 'block';
    if (arr) arr.textContent = open ? '▶' : '▼';
  }

  function _copyPatchAllCSV(btn) {
    const wrap  = btn.closest('.patch-all-wrap');
    const cards = wrap ? wrap.querySelectorAll('.pa-card') : [];
    const lines = ['Port,Service,Severity,Risk Score,CVE,Upgrade Command'];
    cards.forEach(card => {
      const port  = card.querySelector('.pa-port-badge')?.textContent.replace('Port ','').trim() || '';
      const svc   = card.querySelector('.pa-svc')?.textContent.trim() || '';
      const sev   = card.querySelector('.rb')?.textContent.trim() || '';
      const score = card.querySelector('.pa-score')?.textContent.replace('/10','').trim() || '';
      const cve   = card.querySelector('.pa-cve-link')?.textContent.trim() || '';
      const upg   = card.querySelector('.pa-cmd')?.textContent.trim().replace(/,/g,';') || '';
      lines.push(`${port},${svc},${sev},${score},${cve},"${upg}"`);
    });
    navigator.clipboard.writeText(lines.join('\n'));
    btn.textContent = '✅ Copied!';
    setTimeout(() => btn.textContent = '📋 Export CSV', 2000);
  }

  /* ═══════════════════════════════════════════════════════
     /patch <service> <port> — SINGLE PORT GUIDANCE
     Completely rewrites _handlePatchCommand to show AI
     data directly in the chat as a rich card.
  ═══════════════════════════════════════════════════════ */

  async function _handlePatchCommand(serviceOrIp, port) {
    if (!serviceOrIp || !port) {
      addMsg('**Usage:** `/patch <service> <port>` e.g. `/patch ftp 21` or `/patch all`', 'ai');
      return;
    }
    const t = addTyping();
    try {
      const sessionId = App.getCurrentSession() || SessionManager.activeId() || '';
      const d = await ApiService.sendChatMessage(
        `/patch ${serviceOrIp} ${port}`,
        serviceOrIp,
        sessionId,
        SessionManager.getProjectName() || ''
      );
      t.remove();

      // The backend now ALWAYS returns a rich markdown reply in d.reply
      // AND a structured patch_data object. Render BOTH.
      if (d.reply && d.reply !== '__PATCH_ALL__' && d.reply !== '__PATCH_ALL_DATA__') {
        // Show markdown reply as chat bubble
        addMsg(d.reply, 'ai');
      }

      // If we also have structured patch_data, render as a rich card below the bubble
      if (d.patch_data) {
        _renderRichPatchCard(serviceOrIp, port, d.patch_data);
      }

      _handleAction(d);
    } catch (e) {
      t.remove();
      addMsg(`❌ Patch lookup error: ${e.message}`, 'ai');
    }
  }

  /** Rich patch card — shown below the markdown bubble for /patch <service> <port> */
  function _renderRichPatchCard(serviceOrIp, port, data) {
    const chat = document.getElementById('chat');
    const d    = document.createElement('div');
    d.className = 'msg msg-ai rich-patch-card';

    const sev  = data.severity || 'medium';
    const CLRS = { critical: '#e24b4a', high: '#ef9f27', medium: '#378add', low: '#1d9e75' };
    const clr  = CLRS[sev] || '#888';
    const upg  = data.upgrade_command || data.upgrade_cmd || '';
    const rst  = data.restart_command || '';
    const vrfy = data.verify_command  || '';
    const mit  = data.mitigation      || '';
    const hdg  = data.config_hardening || [];
    const refs = data.references || [];
    const eng  = data.engine || '';
    const cveId = data.cve_id || '';
    const allCves = data.all_cves || [];

    d.innerHTML = `
      <div class="rpc-header" style="border-left:3px solid ${clr}">
        <div class="rpc-title-row">
          <span class="rpc-title">🔧 ${data.service || serviceOrIp} · Port ${port}</span>
          <span class="rb rb-${sev}">${sev}</span>
          ${eng ? `<span class="rpc-engine">✨ ${eng}</span>` : ''}
        </div>
        ${data.summary ? `<div class="rpc-summary">${data.summary}</div>` : ''}
        ${cveId && cveId !== 'unknown' ? `<div class="rpc-cve-row">
          <a class="rpc-cve-link" href="https://nvd.nist.gov/vuln/detail/${cveId}" target="_blank" rel="noopener">🔴 ${cveId}</a>
          ${data.cve_desc ? `<span class="rpc-cve-desc">${data.cve_desc.slice(0,120)}${data.cve_desc.length>120?'…':''}</span>` : ''}
        </div>` : ''}
        ${allCves.length > 1 ? `<div class="rpc-all-cves">${allCves.slice(0,4).map(c=>`<span class="pa-cve-tag" style="color:${CLRS[c.severity]||'#888'}">${c.cve_id}</span>`).join('')}${allCves.length>4?`<span class="pa-cve-tag" style="color:var(--text3)">+${allCves.length-4} more</span>`:''}</div>` : ''}
      </div>
      <div class="rpc-body">
        ${data.recommended_version ? `<div class="rpc-rec-ver">📦 Recommended: <code>${data.recommended_version}</code></div>` : ''}
        ${upg  ? `<div class="pa-cmd-block"><div class="pa-cmd-title">⬆️ Upgrade</div><div class="pa-cmd-row"><code class="pa-cmd">${upg}</code><button class="vt-copy-btn" onclick="navigator.clipboard.writeText(${JSON.stringify(upg)});this.textContent='✅';setTimeout(()=>this.textContent='📋',1500)">📋</button></div></div>` : ''}
        ${rst  ? `<div class="pa-cmd-block"><div class="pa-cmd-title">🔄 Restart</div><div class="pa-cmd-row"><code class="pa-cmd">${rst}</code><button class="vt-copy-btn" onclick="navigator.clipboard.writeText(${JSON.stringify(rst)});this.textContent='✅';setTimeout(()=>this.textContent='📋',1500)">📋</button></div></div>` : ''}
        ${vrfy ? `<div class="pa-cmd-block"><div class="pa-cmd-title">✅ Verify</div><div class="pa-cmd-row"><code class="pa-cmd">${vrfy}</code><button class="vt-copy-btn" onclick="navigator.clipboard.writeText(${JSON.stringify(vrfy)});this.textContent='✅';setTimeout(()=>this.textContent='📋',1500)">📋</button></div></div>` : ''}
        ${mit  ? `<div class="pa-cmd-block"><div class="pa-cmd-title">🛡️ Mitigation</div><div class="pa-mit">${mit}</div></div>` : ''}
        ${hdg.length ? `<div class="pa-cmd-block"><div class="pa-cmd-title">⚙️ Config Hardening</div><ul class="pa-hdg-list">${hdg.map(h=>`<li>${h}</li>`).join('')}</ul></div>` : ''}
        ${refs.length ? `<div class="pa-cmd-block"><div class="pa-cmd-title">🔗 References</div>${refs.slice(0,3).map(r=>`<a class="pa-ref-link" href="${r}" target="_blank" rel="noopener">${r.slice(0,60)}${r.length>60?'…':''}</a>`).join('')}</div>` : ''}
      </div>`;

    d.style.opacity = '0'; d.style.transform = 'translateY(6px)';
    chat.appendChild(d);
    requestAnimationFrame(() => {
      d.style.transition = 'opacity .25s ease, transform .25s ease';
      d.style.opacity = '1'; d.style.transform = 'translateY(0)';
    });
    chat.scrollTo({ top: chat.scrollHeight, behavior: 'smooth' });
  }

  // Keep old _renderPatchCard for any legacy callers
  function _renderPatchCard(ip, port, data, rawText) {
    if (rawText) { addMsg(rawText, 'ai'); return; }
    if (data) _renderRichPatchCard(ip, port, data);
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

      <div class="pd-scroll pnc-cards-wrap" id="${dashId}-cards">
        ${entries.map((e, i) => {
          const clr   = CLRS[e.risk_level] || '#888';
          const sev   = (e.severity || e.risk_level || 'low').toLowerCase();
          const cvss  = parseFloat(e.cvss || e.risk_score || 0);
          const pCve  = e.cve || e.cve_id || '';
          const tabId = `ptab-d-${i}-${dashId}`;
          const osCmd = _buildOsCommands(e).linux;
          const _copyIcon = `<svg width="14" height="14" viewBox="0 0 16 16" fill="none"><rect x="5.5" y="1.5" width="9" height="11" rx="1.5" stroke="currentColor" stroke-width="1.4"/><rect x="1.5" y="4.5" width="9" height="10" rx="1.5" stroke="currentColor" stroke-width="1.4" fill="var(--bg2,#161b22)"/></svg>`;
          const allCvesHtml = (e.all_cves||[]).slice(0,5).map(c=>{const cs=(c.severity||'low').toLowerCase();const cc=CLRS[cs]||'#888';return `<span class="pnc-cve-tag" style="background:${cc}22;color:${cc};border:1px solid ${cc}44">${c.cve_id||''} (${(c.cvss_score||0).toFixed(1)})</span>`;}).join('');
          const cmdBlocks = [{n:1,label:'UPGRADE',cmd:osCmd.upgrade,cls:'pa-os-upgrade'},{n:2,label:'RESTART',cmd:osCmd.restart,cls:'pa-os-restart'},{n:3,label:'VERIFY',cmd:osCmd.verify,cls:'pa-os-verify'}].filter(b=>b.cmd).map(b=>`<div class="pnc-cmd-block"><div class="pnc-cmd-label"><span class="pnc-cmd-num">${b.n}</span>${b.label}</div><div class="pnc-cmd-row"><code class="pnc-cmd ${b.cls}">${b.cmd}</code><button class="pnc-copy-btn" title="Copy" onclick="event.stopPropagation();var c=this.previousElementSibling;navigator.clipboard.writeText(c.textContent.trim());var o=this.innerHTML;this.innerHTML='<svg width=14 height=14 viewBox=\\'0 0 16 16\\'><polyline points=\\'2,8 6,12 14,4\\' stroke=\\'#4caf50\\' stroke-width=\\'2\\' fill=\\'none\\'/></svg>';setTimeout(()=>{this.innerHTML=o},1500)" type="button">${_copyIcon}</button></div></div>`).join('');
          const entryJson = JSON.stringify({port:e.port,service:e.service,cve:pCve,cve_desc:e.cve_desc||'',severity:sev,risk_level:e.risk_level||sev,risk_score:e.risk_score||cvss,cvss,version:e.version||'unknown',reasons:e.reasons||[],all_cves:e.all_cves||[],ai_action:e.ai_action||'',patch_note:e.patch_note||'',mitigation:osCmd.mitigation||''}).replace(/"/g,'&quot;');
          const cmdsJson  = JSON.stringify({upgrade:osCmd.upgrade,restart:osCmd.restart,verify:osCmd.verify,mitigation:osCmd.mitigation}).replace(/"/g,'&quot;');
          return `<div class="pnc-card" data-card-idx="${i}" data-sev="${sev}" style="border-left:3px solid ${clr}">
            <div class="pnc-header" onclick="Chatbot._togglePncCard(this)" style="cursor:pointer">
              <div class="pnc-header-left">
                <span class="pnc-port-badge" style="background:${clr}22;color:${clr};border:1px solid ${clr}44">Port ${e.port}</span>
                <span class="pnc-svc">${e.service}</span>
                ${e.version&&e.version!=='unknown'?`<span class="pnc-tag pnc-tag-ver">${e.version}</span>`:''}
              </div>
              <div class="pnc-header-right">
                ${pCve?`<a class="pnc-cve-primary" href="https://nvd.nist.gov/vuln/detail/${pCve}" target="_blank" rel="noopener" onclick="event.stopPropagation()">${pCve}</a>`:''}
                <span class="rb rb-${sev}" style="font-size:11px;padding:2px 8px">${sev.toUpperCase()}</span>
                <span class="pnc-score" style="color:${clr}">${cvss.toFixed(1)}/10</span>
                ${pCve?`<a class="pnc-nvd-link" href="https://nvd.nist.gov/vuln/detail/${pCve}" target="_blank" rel="noopener" onclick="event.stopPropagation()" title="View on NVD" style="color:#6e7681;font-size:11px;text-decoration:none;padding:2px 6px;border:1px solid #30363d;border-radius:4px">NVD ↗</a>`:''}
                <span class="pnc-toggle-arrow">▼</span>
              </div>
            </div>
            <div class="pnc-card-body" style="display:none">
              ${e.cve_desc?`<div class="pnc-desc">${e.cve_desc}</div>`:''}
              ${allCvesHtml?`<div class="pnc-cve-tags">${allCvesHtml}</div>`:''}
              <div class="pnc-cmds" data-idx="${i}">${cmdBlocks}</div>
              <div class="pnc-tab-bar" data-tabgroup="${tabId}">
                ${[{id:'mitigation',icon:'🛡',label:'Mitigation'},{id:'riskscore',icon:'📊',label:'Risk Score'},{id:'impact',icon:'💥',label:'Impact'},{id:'risklevel',icon:'🚨',label:'Risk Level'},{id:'severity',icon:'⚠',label:'Severity'}].map((t,ti)=>`<button class="pnc-tab${ti===0?' active':''}" data-tab="${t.id}" onclick="event.stopPropagation();Chatbot._switchPatchTab('${tabId}-content','${t.id}',this)">${t.icon} ${t.label}</button>`).join('')}
              </div>
              <div class="pnc-tab-content pd-expand-row" id="${tabId}-content" data-entry="${entryJson}" data-cmds="${cmdsJson}">
                ${_genTabContent({port:e.port,service:e.service,cve:pCve,cve_desc:e.cve_desc||'',severity:sev,risk_level:e.risk_level||sev,risk_score:e.risk_score||cvss,cvss,version:e.version||'unknown',reasons:e.reasons||[],all_cves:e.all_cves||[],ai_action:e.ai_action||'',patch_note:e.patch_note||''},{upgrade:osCmd.upgrade,restart:osCmd.restart,verify:osCmd.verify,mitigation:osCmd.mitigation},'mitigation')}
              </div>
            </div>
          </div>`;
        }).join('')}
      </div>

      <div class="pd-footer">
        <span id="${dashId}-cnt">${entries.length} services</span>

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
              <div class="pd-exp-text" style="white-space:pre-line">${upgCmds.mitigation}</div>
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
              <button class="vd-exp-btn vd-exp-btn-ai" id="${expId}-ai-btn"
                      onclick="Chatbot._fetchAIPatch('${expId}', '${e.service}', ${JSON.stringify(e.port)}, '${(e.version||'unknown').replace(/'/g,"\\'")}', '${(e.cve||'unknown').replace(/'/g,"\\'")}', '${e.severity}')">
                ✨ Get AI Patch Guide
              </button>
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

  function _togglePncCard(headerEl) {
    const card = headerEl.closest('.pnc-card');
    if (!card) return;
    const body  = card.querySelector('.pnc-card-body');
    const arrow = headerEl.querySelector('.pnc-toggle-arrow');
    if (!body) return;
    const isOpen = body.style.display !== 'none';
    if (isOpen) {
      body.style.display = 'none';
      if (arrow) arrow.textContent = '▼';
      card.classList.remove('pnc-card-open');
    } else {
      body.style.display = 'block';
      if (arrow) arrow.textContent = '▲';
      card.classList.add('pnc-card-open');
    }
  }

  function _filterPatchDash(dashId, sev) {
    ['all','critical','high','medium','low'].forEach(s => document.getElementById(`${dashId}-f-${s}`)?.classList.remove('active'));
    document.getElementById(`${dashId}-f-${sev || 'all'}`)?.classList.add('active');
    const cards = document.querySelectorAll(`#${dashId}-cards .pnc-card`);
    let shown = 0;
    cards.forEach(card => {
      const match = !sev || card.dataset.sev === sev;
      card.style.display = match ? '' : 'none';
      if (match) shown++;
    });
    const cnt = document.getElementById(`${dashId}-cnt`); if (cnt) cnt.textContent = `${shown} services shown`;
  }

  function _searchPatchDash(dashId) {
    const q     = document.getElementById(`${dashId}-search`)?.value.toLowerCase() || '';
    const cards = document.querySelectorAll(`#${dashId}-cards .pnc-card`);
    let shown = 0;
    cards.forEach(card => {
      const text = (card.querySelector('.pnc-svc')?.textContent || '') + ' ' +
                   (card.querySelector('.pnc-port-badge')?.textContent || '') + ' ' +
                   (card.querySelector('.pnc-cve-primary')?.textContent || '') + ' ' +
                   (card.querySelector('.pnc-desc')?.textContent || '');
      const match = !q || text.toLowerCase().includes(q);
      card.style.display = match ? '' : 'none';
      if (match) shown++;
    });
    const cnt = document.getElementById(`${dashId}-cnt`); if (cnt) cnt.textContent = `${shown} services shown`;
  }

  function _copyPatchCSV(dashId) {
    const cards = document.querySelectorAll(`#${dashId}-cards .pnc-card`);
    const lines = ['Port,Service,CVE,Severity,Risk Score,Version'];
    cards.forEach(card => {
      try {
        const entry = JSON.parse((card.querySelector('.pnc-tab-content')?.dataset?.entry || '{}').replace(/&quot;/g,'"'));
        lines.push([entry.port, entry.service, entry.cve||'—', entry.severity, (entry.cvss||entry.risk_score||0).toFixed(1), entry.version||'—'].join(','));
      } catch(_) {}
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
  }

  /* ═══════════════════════════════════════════════════════
     HELP CARD
  ═══════════════════════════════════════════════════════ */

  function _showHelpCard() {
    const chat = document.getElementById('chat');
    const d    = document.createElement('div');
    d.className = 'msg msg-ai help-card';
    const cmds = [
      { icon:'❓', cmd:'/help',               label:'/help',                         desc:'Show this command list' },
      { icon:'🔧', cmd:'/patch all',          label:'/patch [all|<svc> <port>]',     desc:'AI-assisted remediation guidance for findings' },
      { icon:'📊', cmd:'/graph',              label:'/graph',                        desc:'Open Infrastructure Intelligence Graph or Vulnerability Intelligence Dashboard in new tab' },
      { icon:'📄', cmd:'/report pdf',         label:'/report [pdf|html]',            desc:'Export the last scan report as PDF or HTML' },
      { icon:'🗑️', cmd:'/clear',              label:'/clear',                        desc:'Clear this chat window' },
      { icon:'⏹️', cmd:'/stop',               label:'/stop',                         desc:'Abort the running scan' },
    ];
    d.innerHTML = `
      <div class="help-title">📖 &nbsp;ThreatWeave AI — Commands</div>
      <div class="help-grid">${cmds.map(c => `
        <div class="help-cmd" onclick="_helpCmdClick(this,'${c.cmd}')">
          <span class="hc-badge">${c.icon}</span>
          <div class="hc-info"><span class="hc-name">${c.label}</span><span class="hc-desc">${c.desc}</span></div>
        </div>`).join('')}</div>
      <div class="help-tip">✨ Just type an IP address or hostname to scan it automatically — no command needed. Click any card above to run a command instantly.</div>`;
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


/**
 * chatbot/restore.js
 * Rich-token serialisation, session restore, panel render (renderAll / rTab).
 */


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
        <button class="post-ob-btn" style="font-size:12px;padding:6px 12px" onclick="Chatbot.openVulnDashboard()">🔎 Full CVE Dashboard</button>
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
        <button class="vd-export-btn" style="margin-left:auto" onclick="Chatbot.openVulnDashboard()">Open Full Dashboard →</button>
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
      <div class="pd-scroll pnc-cards-wrap" id="${dashId}-cards">
            ${entries.map((e, i) => {
              const clr   = CLRS[e.risk_level] || '#888';
              const sev   = (e.severity || e.risk_level || 'low').toLowerCase();
              const cvss  = parseFloat(e.cvss || e.risk_score || 0);
              const pCve  = e.cve || e.cve_id || '';
              const tabId = `ptab-r-${i}-${dashId}`;
              const osCmd = _buildOsCommands(e).linux;
              const _copyIcon = `<svg width="14" height="14" viewBox="0 0 16 16" fill="none"><rect x="5.5" y="1.5" width="9" height="11" rx="1.5" stroke="currentColor" stroke-width="1.4"/><rect x="1.5" y="4.5" width="9" height="10" rx="1.5" stroke="currentColor" stroke-width="1.4" fill="var(--bg2,#161b22)"/></svg>`;
              const allCvesHtml = (e.all_cves||[]).slice(0,5).map(c=>{const cs=(c.severity||'low').toLowerCase();const cc=CLRS[cs]||'#888';return `<span class="pnc-cve-tag" style="background:${cc}22;color:${cc};border:1px solid ${cc}44">${c.cve_id||''} (${(c.cvss_score||0).toFixed(1)})</span>`;}).join('');
              const cmdBlocks = [{n:1,label:'UPGRADE',cmd:osCmd.upgrade,cls:'pa-os-upgrade'},{n:2,label:'RESTART',cmd:osCmd.restart,cls:'pa-os-restart'},{n:3,label:'VERIFY',cmd:osCmd.verify,cls:'pa-os-verify'}].filter(b=>b.cmd).map(b=>`<div class="pnc-cmd-block"><div class="pnc-cmd-label"><span class="pnc-cmd-num">${b.n}</span>${b.label}</div><div class="pnc-cmd-row"><code class="pnc-cmd ${b.cls}">${b.cmd}</code><button class="pnc-copy-btn" title="Copy" onclick="event.stopPropagation();var c=this.previousElementSibling;navigator.clipboard.writeText(c.textContent.trim());var o=this.innerHTML;this.innerHTML='<svg width=14 height=14 viewBox=\\'0 0 16 16\\'><polyline points=\\'2,8 6,12 14,4\\' stroke=\\'#4caf50\\' stroke-width=\\'2\\' fill=\\'none\\'/></svg>';setTimeout(()=>{this.innerHTML=o},1500)" type="button">${_copyIcon}</button></div></div>`).join('');
              const entryJson = JSON.stringify({port:e.port,service:e.service,cve:pCve,cve_desc:e.cve_desc||'',severity:sev,risk_level:e.risk_level||sev,risk_score:e.risk_score||cvss,cvss,version:e.version||'unknown',reasons:e.reasons||[],all_cves:e.all_cves||[],ai_action:e.ai_action||'',patch_note:e.patch_note||'',mitigation:osCmd.mitigation||''}).replace(/"/g,'&quot;');
              const cmdsJson  = JSON.stringify({upgrade:osCmd.upgrade,restart:osCmd.restart,verify:osCmd.verify,mitigation:osCmd.mitigation}).replace(/"/g,'&quot;');
              return `<div class="pnc-card" data-card-idx="${i}" data-sev="${sev}" style="border-left:3px solid ${clr}">
                <div class="pnc-header" onclick="Chatbot._togglePncCard(this)" style="cursor:pointer">
                  <div class="pnc-header-left">
                    <span class="pnc-port-badge" style="background:${clr}22;color:${clr};border:1px solid ${clr}44">Port ${e.port}</span>
                    <span class="pnc-svc">${e.service}</span>
                    ${e.version&&e.version!=='unknown'?`<span class="pnc-tag pnc-tag-ver">${e.version}</span>`:''}
                  </div>
                  <div class="pnc-header-right">
                    ${pCve?`<a class="pnc-cve-primary" href="https://nvd.nist.gov/vuln/detail/${pCve}" target="_blank" rel="noopener" onclick="event.stopPropagation()">${pCve}</a>`:''}
                    <span class="rb rb-${sev}" style="font-size:11px;padding:2px 8px">${sev.toUpperCase()}</span>
                    <span class="pnc-score" style="color:${clr}">${cvss.toFixed(1)}/10</span>
                    ${pCve?`<a class="pnc-nvd-link" href="https://nvd.nist.gov/vuln/detail/${pCve}" target="_blank" rel="noopener" onclick="event.stopPropagation()" title="View on NVD" style="color:#6e7681;font-size:11px;text-decoration:none;padding:2px 6px;border:1px solid #30363d;border-radius:4px">NVD ↗</a>`:''}
                    <span class="pnc-toggle-arrow">▼</span>
                  </div>
                </div>
                <div class="pnc-card-body" style="display:none">
                  ${e.cve_desc?`<div class="pnc-desc">${e.cve_desc}</div>`:''}
                  ${allCvesHtml?`<div class="pnc-cve-tags">${allCvesHtml}</div>`:''}
                  <div class="pnc-cmds" data-idx="${i}">${cmdBlocks}</div>
                  <div class="pnc-tab-bar" data-tabgroup="${tabId}">
                    ${[{id:'mitigation',icon:'🛡',label:'Mitigation'},{id:'riskscore',icon:'📊',label:'Risk Score'},{id:'impact',icon:'💥',label:'Impact'},{id:'risklevel',icon:'🚨',label:'Risk Level'},{id:'severity',icon:'⚠',label:'Severity'}].map((t,ti)=>`<button class="pnc-tab${ti===0?' active':''}" data-tab="${t.id}" onclick="event.stopPropagation();Chatbot._switchPatchTab('${tabId}-content','${t.id}',this)">${t.icon} ${t.label}</button>`).join('')}
                  </div>
                  <div class="pnc-tab-content pd-expand-row" id="${tabId}-content" data-entry="${entryJson}" data-cmds="${cmdsJson}">
                    ${_genTabContent({port:e.port,service:e.service,cve:pCve,cve_desc:e.cve_desc||'',severity:sev,risk_level:e.risk_level||sev,risk_score:e.risk_score||cvss,cvss,version:e.version||'unknown',reasons:e.reasons||[],all_cves:e.all_cves||[],ai_action:e.ai_action||'',patch_note:e.patch_note||''},{upgrade:osCmd.upgrade,restart:osCmd.restart,verify:osCmd.verify,mitigation:osCmd.mitigation},'mitigation')}
                  </div>
                </div>
              </div>`;
            }).join('')}
          </div>
    `;
    container.appendChild(wrap);
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
          — <button class="srw-rescan-btn" onclick="Chatbot.rescan('${data.ip || ""}')">↻ Re-scan</button>
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
    // Auto-open floating slider to risk tab on scan completion
    _frsSetToolbarVisible(true);
    frsOpen('risk');
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
    const _r1 = document.getElementById('rc-risk');      if (_r1) _r1.innerHTML = html;
    const _r2 = document.getElementById('risk-empty-m'); if (_r2) _r2.style.display = 'none';
    const _r3 = document.getElementById('risk-body-m');  if (_r3) _r3.innerHTML = html;
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
    const _c1 = document.getElementById('rc-cve');       if (_c1) _c1.innerHTML = html;
    const _c2 = document.getElementById('cve-empty-m');  if (_c2) _c2.style.display = 'none';
    const _c3 = document.getElementById('cve-body-m');   if (_c3) _c3.innerHTML = html;
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
    const _f1 = document.getElementById('rc-find'); if (_f1) _f1.innerHTML = html;
  }

  function renderAI(ai) {
    if (!ai) return;
    const icon = ai.engine?.includes('claude') ? '🤖' : '⚙️';
    const lbl  = ai.engine?.includes('ollama') ? 'Ollama AI' : ai.engine?.includes('claude') ? 'Claude AI' : 'Rule-Based';
    const html = `<div class="ai-box"><h4>${icon} ${lbl}</h4>
      <div class="ai-summary">${ai.summary||''}</div>
      ${ai.overall_risk ? `<div style="margin-top:5px;font-size:12px;color:var(--purple)">Risk: <strong>${ai.overall_risk.toUpperCase()}</strong></div>` : ''}
      <div class="ai-engine">${ai.engine}</div></div>`;
    const _a1 = document.getElementById('rc-ai');       if (_a1) _a1.innerHTML = html;
    const _a2 = document.getElementById('ai-empty-m');  if (_a2) _a2.style.display = 'none';
    const _a3 = document.getElementById('ai-body-m');   if (_a3) _a3.innerHTML = html;
  }

  function rTab(name) {
    // Update floating panel tab headers
    const nameMap = { risk:'risk', cve:'cve', find:'find', ai:'ai' };
    ['risk','cve','find','ai'].forEach(n => {
      const el = document.getElementById('ft-' + n);
      if (el) el.classList.toggle('active', n === name);
    });
    // Update toolbar button active state
    ['risk','cve','find','ai'].forEach(n => {
      const tb = document.getElementById('frs-tb-' + n);
      if (tb) tb.classList.toggle('frs-active', n === name);
    });
    // Switch content panes (only inside frs-panel)
    document.querySelectorAll('#frs-panel .r-content').forEach(c => c.classList.remove('active'));
    document.getElementById(`rc-${name}`)?.classList.add('active');
  }

  /* ── Floating Right Slider helpers ────────────────────── */

  function _frsSetToolbarVisible(show) {
    const tb = document.getElementById('frs-toolbar');
    if (!tb) return;
    if (show) tb.classList.add('frs-visible');
    else      tb.classList.remove('frs-visible');
  }

  function frsOpen(tabName) {
    const panel   = document.getElementById('frs-panel');
    const toolbar = document.getElementById('frs-toolbar');
    if (!panel) return;
    panel.classList.add('frs-open');
    if (toolbar) toolbar.classList.add('frs-open');
    rTab(tabName || 'risk');
  }

  function frsClose() {
    const panel   = document.getElementById('frs-panel');
    const toolbar = document.getElementById('frs-toolbar');
    if (panel)   panel.classList.remove('frs-open');
    if (toolbar) toolbar.classList.remove('frs-open');
  }

  function frsToggle() {
    const panel = document.getElementById('frs-panel');
    if (!panel) return;
    if (panel.classList.contains('frs-open')) frsClose();
    else frsOpen('risk');
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

    // 2. Backend project sessions — deduplicated (no spam if called rapidly)
    let backendProjectSess = [];
    try {
      const pd = typeof RequestDeduplicator !== 'undefined'
        ? await RequestDeduplicator.fetch('api:project-sessions', () =>
            fetch('/api/project-sessions').then(r => r.json()), 10_000)
        : await fetch('/api/project-sessions').then(r => r.json());
      backendProjectSess = (pd.sessions || []).filter(s =>
        !memFrontendIds.has(s.session_id) && !_deletedSessionIds.has(s.session_id)
      );
    } catch (e) {}

    // 3. Backend scan sessions — deduplicated
    let backendScanSess = [];
    try {
      const sd = typeof RequestDeduplicator !== 'undefined'
        ? await RequestDeduplicator.fetch('api:history', () =>
            ApiService.getHistory(), 10_000)
        : await ApiService.getHistory();
      backendScanSess = (sd.sessions || []).filter(s =>
        !memScanIds.has(s.session_id) &&
        !memFrontendIds.has(s.session_id) &&
        !_deletedSessionIds.has(s.session_id)
      );
    } catch (e) {}

    const activeId = SessionManager.activeId();
    const curSess  = App.getCurrentSession();
    let html = '';

    // Render localStorage sessions — FIX 5: skip sessions with no name and no scan
    for (const s of memSess) {
      const hasScan  = !!s.scan_results;
      const hasName  = SessionManager.isValidProjectName(s.project_name);
      // Skip blank sessions: no name, no scan, no meaningful content
      if (!hasName && !hasScan) continue;
      const risk     = hasScan ? (s.scan_results?.risk?.hosts?.[0]?.risk_summary?.overall || 'low') : null;
      const target   = hasScan ? (s.scan_results?.target || '') : '';
      const stype    = hasScan ? (s.scan_results?.scan_type || '') : '';
      const ts       = s.updated_at?.slice(0,16).replace('T',' ') || '';
      const active   = s.session_id === activeId ? 'active' : '';
      html += _drawerItem(s.session_id, target, risk, stype, ts, active, s.project_name || '', hasScan);
    }

    // Render backend project sessions not in localStorage — FIX 5: only named ones
    for (const s of backendProjectSess) {
      // FIX 5: skip unnamed/blank backend sessions
      if (!SessionManager.isValidProjectName(s.project_name)) continue;
      html += _drawerItem(s.session_id, '', null, '', s.updated_at?.slice(0,16) || '', '', s.project_name || '', false);
    }

    // Render backend scan sessions not in localStorage
    // FIX: Only show backend scan sessions that have a real project name.
    // Without a project name the title would fall back to a raw IP address,
    // which (a) leaks target info into the history and (b) re-appears even
    // after the entry has been deleted from the local session store.
    for (const s of backendScanSess) {
      const sessionLabel = s.label || s.project_name || '';
      if (!SessionManager.isValidProjectName(sessionLabel)) continue; // skip IP-only / unnamed entries
      const active = s.session_id === curSess ? 'active' : '';
      html += _drawerItem(s.session_id, s.target || '', s.overall_risk || 'low', s.scan_type || '', s.timestamp?.slice(0,16) || '', active, sessionLabel, true);
    }

    el.innerHTML = html || '<div style="padding:20px 16px;font-size:12px;color:var(--text3);text-align:center">No sessions yet<br><small>Initialize a project to begin</small></div>';
  }

  function _drawerItem(sid, target, risk, stype, ts, active, projectName, hasScan) {
    // FIX 2: Never show "Unnamed Session". Skip entries with no name and no scan.
    const displayTitle = (projectName && projectName.trim()) || target || null;
    if (!displayTitle && !hasScan) return ''; // completely invisible — no clutter
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
            ${hasScan ? `<div class="sb-menu-item"
                 onclick="Chatbot.('${sid}')">
            </div>` : ''}
            <div class="sb-menu-item sb-menu-delete"
                 onclick="Chatbot._deleteDrawerSession('${sid}')">
              🗑️ Delete
            </div>
          </div>
        </div>
      </div>`;
  }


/**
 * chatbot/drawer.js
 * History drawer, session 3-dot menu, report modal, export.
 */


  /* ── Drawer 3-dot menu ────────────────────────────────────────── */

  function _toggleDrawerMenu(sid) {
    const menuId = 'dmenu-' + sid;
    const menu   = document.getElementById(menuId);
    if (!menu) return;
    // Close any other open drawer menu
    if (_drawerMenuId && _drawerMenuId !== menuId) {
      const prev = document.getElementById(_drawerMenuId);
      if (prev) prev.style.display = 'none';
    }
    const isOpen = menu.style.display !== 'none';
    menu.style.display = isOpen ? 'none' : 'block';
    _drawerMenuId = isOpen ? null : menuId;
    if (!isOpen) {
      setTimeout(() => {
        const handler = (e) => {
          if (!menu.contains(e.target)) {
            menu.style.display = 'none';
            _drawerMenuId = null;
            document.removeEventListener('click', handler);
          }
        };
        document.addEventListener('click', handler);
      }, 10);
    }
  }

  async function _renameDrawerSession(sid, currentName) {
    const menu = document.getElementById('dmenu-' + sid);
    if (menu) menu.style.display = 'none';
    _drawerMenuId = null;

    const item   = document.getElementById('ditem-' + sid);
    const mainEl = item?.querySelector('.sb-main');
    if (!mainEl) return;
    const origHtml = mainEl.innerHTML;

    mainEl.innerHTML = `
      <div class="sb-rename-row">
        <input class="sb-rename-inp" id="dr-inp-${sid}" type="text" value="${currentName}"
               maxlength="60" placeholder="Project name…"
               onkeydown="if(event.key==='Enter') Chatbot._submitDrawerRename('${sid}');
                          if(event.key==='Escape') Chatbot._cancelDrawerRename('${sid}','${origHtml.replace(/'/g, "\\'")}')"/>
        <button class="btn btn-pri" style="height:28px;padding:0 10px;font-size:11px"
                onclick="Chatbot._submitDrawerRename('${sid}')">Save</button>
        <button class="btn btn-sec" style="height:28px;padding:0 8px;font-size:11px"
                onclick="Chatbot._cancelDrawerRename('${sid}')">✕</button>
      </div>`;

    setTimeout(() => document.getElementById(`dr-inp-${sid}`)?.focus(), 50);
  }

  async function _submitDrawerRename(sid) {
    const inp  = document.getElementById(`dr-inp-${sid}`);
    const name = inp?.value?.trim();
    if (!name) return;
    try {
      await ApiService.renameSession(sid, name);
      loadDrawer();
    } catch (e) { loadDrawer(); }
  }

  function _cancelDrawerRename(sid) { loadDrawer(); }

  async function _deleteDrawerSession(sid) {
    const menu = document.getElementById('dmenu-' + sid);
    if (menu) menu.style.display = 'none';
    _drawerMenuId = null;

    const item   = document.getElementById('ditem-' + sid);
    const mainEl = item?.querySelector('.sb-main');
    if (!mainEl) return;

    mainEl.innerHTML = `
      <div class="sb-confirm-row">
        <span class="sb-confirm-txt">🗑️ Delete permanently?</span>
        <button class="btn" style="background:#e24b4a;color:#fff;height:26px;padding:0 10px;font-size:11px;border:none"
                onclick="Chatbot._confirmDrawerDelete('${sid}')">Delete</button>
        <button class="btn btn-sec" style="height:26px;padding:0 8px;font-size:11px"
                onclick="Chatbot.loadDrawer()">Cancel</button>
      </div>`;
  }

  // FIX 1: Set of explicitly-deleted session IDs — prevents reappearance from
  // the backend history API even if the network DELETE was slow or cached.
  const _deletedSessionIds = new Set(
    (() => { try { return JSON.parse(localStorage.getItem('threatweave_deleted_ids_v1') || '[]'); } catch(_) { return []; } })()
  );
  function _persistDeletedIds() {
    try { localStorage.setItem('threatweave_deleted_ids_v1', JSON.stringify([..._deletedSessionIds].slice(-200))); } catch(_) {}
  }

  async function _confirmDrawerDelete(sid) {
    // Mark deleted BEFORE any async work so the next loadDrawer() call skips it.
    _deletedSessionIds.add(sid);
    _persistDeletedIds();
    try {
      await ApiService.deleteSession(sid);
    } catch (e) {
      // Backend delete failed — may not exist on server. Continue with local cleanup.
    }
    // Always clean up locally regardless of backend result
    document.getElementById('ditem-' + sid)?.remove();
    const wasActive = SessionManager.activeId() === sid;
    SessionManager.remove(sid); // purge from memory + localStorage
    if (App.getCurrentSession() === sid) {
      App.setCurrentSession(null);
      App.setLastData(null);
    }
    // If we deleted the active session, switch to another one or create fresh
    if (wasActive) {
      const remaining = SessionManager.list();
      if (remaining.length > 0) {
        const next = remaining[0];
        SessionManager.switchTo(next.session_id);
      }
    }
    // Refresh drawer so deleted entry is gone for good
    loadDrawer();
  }

  async function viewSession(id) {
    // FIX 5+7: Save scroll of current session, switch, restore scroll of target
    const scrollPos = SessionManager.getScrollPos(id);
    const mem = SessionManager.switchTo(id);

    if (mem?.scan_results) {
      App.setLastData(mem.scan_results);
      App.setCurrentSession(mem.scan_session || id);
      _currentTarget = mem.scan_results?.target || '';
      Dashboard.flagOsintStale();
      renderAll(mem.scan_results);
      const chat = document.getElementById('chat');
      chat.innerHTML = '';
      if (mem.messages?.length) {
        restoreChatMessages(mem.messages, scrollPos);  // FIX 7: restore scroll
      } else {
        // Try backend SQLite store
        try {
          const loaded = await ApiService.loadChatSession(mem.session_id);
          if (loaded?.messages?.length) {
            loaded.messages.forEach(m => SessionManager.saveMsg(m.type, m.text));
            restoreChatMessages(loaded.messages, scrollPos);
          } else if (mem.project_name) {
            _showPostOnboarding(mem.project_name);
          }
        } catch (_) {
          if (mem.project_name) _showPostOnboarding(mem.project_name);
        }
      }
      Router.showPage('scan');
      return;
    }

    // Session is in memory but has no scan results yet
    if (mem) {
      App.setCurrentSession(null);
      App.setLastData(null);
      _currentTarget = '';
      const chat = document.getElementById('chat');
      chat.innerHTML = '';
      if (mem.messages?.length) {
        restoreChatMessages(mem.messages, scrollPos);  // FIX 7
      } else {
        // Try loading messages from backend SQLite store
        try {
          const loaded = await ApiService.loadChatSession(mem.session_id);
          if (loaded?.messages?.length) {
            // Merge into session manager so future saves include them
            loaded.messages.forEach(m => SessionManager.saveMsg(m.type, m.text));
            restoreChatMessages(loaded.messages, scrollPos);
          } else if (mem.project_name) {
            _showPostOnboarding(mem.project_name);
          } else {
            showGreeting();
          }
        } catch (_) {
          if (mem.project_name) _showPostOnboarding(mem.project_name);
          else showGreeting();
        }
      }
      Router.showPage('scan');
      return;
    }

    // Not in memory at all — try to load from backend (backend session ids)
    try {
      const d = await ApiService.getScanResults(id);
      if (d.risk) {
        // FIX 2: Create session with allowUnnamed=true — this is a restore from backend,
        // the project name will be set from the scan data below.
        SessionManager.create('', true);
        SessionManager.saveScan(d);
        App.setLastData(d);
        App.setCurrentSession(id);
        _currentTarget = d.target || '';
        Dashboard.flagOsintStale();
        renderAll(d);
        Router.showPage('scan');
      }
    } catch (e) {
      // FIX: Show a non-scary toast instead of error in chat
      Utils.showToast && Utils.showToast('session-not-found-toast');
      loadDrawer(); // refresh drawer to remove any stale entry
    }
  }

  /* ═══════════════════════════════════════════════════════
     EXPORT / REPORT
  ═══════════════════════════════════════════════════════ */

  function showReportModal() {
    const cur = App.getCurrentSession();
    if (!cur) { addMsg('Run a scan first to generate a report.', 'ai'); return; }
    Utils.openModal('report-modal');
  }

  function selectFmt(fmt) {
    _selectedFmt = fmt;
    document.querySelectorAll('.fmt-opt').forEach(el => el.classList.remove('selected'));
    document.getElementById('fmt-' + fmt)?.classList.add('selected');
  }

  async function doExportReport() {
    Utils.closeModal('report-modal');
    const goBtn = document.getElementById('export-go-btn');
    if (goBtn) goBtn.disabled = true;
    const cur = App.getCurrentSession();
    addMsg(`📄 Generating **${_selectedFmt.toUpperCase()}** report…`, 'sys');
    try {
      const d = await ApiService.generateReport(cur, _selectedFmt);
      const downloadUrl = d.download || '#';
      if (_selectedFmt === 'pdf') {
        try {
          const res = await fetch(downloadUrl);
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          const blob   = await res.blob();
          const objUrl = URL.createObjectURL(new Blob([blob], { type: 'application/pdf' }));
          const anchor = document.createElement('a');
          anchor.href = objUrl; anchor.download = `threatweave_report_${cur}.pdf`;
          document.body.appendChild(anchor); anchor.click(); document.body.removeChild(anchor);
          setTimeout(() => URL.revokeObjectURL(objUrl), 10000);
          document.getElementById('report-toast-title').textContent = '📄 PDF Report Ready';
          document.getElementById('report-toast-link').href = objUrl;
          document.getElementById('report-toast-link').download = `threatweave_report_${cur}.pdf`;
        } catch (dlErr) {
          document.getElementById('report-toast-title').textContent = '📄 PDF Report Ready';
          document.getElementById('report-toast-link').href = downloadUrl;
        }
      } else {
        // HTML: auto-download the file without asking, like PDF does
        try {
          const res = await fetch(downloadUrl);
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          const blob   = await res.blob();
          const objUrl = URL.createObjectURL(new Blob([blob], { type: 'text/html' }));
          const anchor = document.createElement('a');
          anchor.href = objUrl; anchor.download = `threatweave_report_${cur}.html`;
          document.body.appendChild(anchor); anchor.click(); document.body.removeChild(anchor);
          setTimeout(() => URL.revokeObjectURL(objUrl), 10000);
          document.getElementById('report-toast-title').textContent = '🌐 HTML Report Ready';
          document.getElementById('report-toast-link').href = objUrl;
          document.getElementById('report-toast-link').download = `threatweave_report_${cur}.html`;
        } catch (dlErr) {
          document.getElementById('report-toast-title').textContent = '🌐 HTML Report Ready';
          document.getElementById('report-toast-link').href = downloadUrl;
          document.getElementById('report-toast-link').setAttribute('target','_blank');
        }
      }
      Utils.showToast('report-toast');
      addMsg(`✅ **${_selectedFmt.toUpperCase()} report ready.**`, 'ai');
    } catch (e) {
      addMsg(`Report error: ${e.message}`, 'ai');
    } finally {
      if (goBtn) goBtn.disabled = false;
    }
  }

  function suggestNext() {
    const last = App.getLastData();
    if (last?.recommendation) { const r = last.recommendation; addMsg(`💡 **${r.title}**\n${r.reason}`, 'ai'); rTab('risk'); }
    else addMsg('Run a scan first to get recommendations.', 'ai');
  }



/**
 * chatbot/api.js
 * Scan-selector filter helpers and Chatbot public API surface.
 * This is the last section of the IIFE — includes the return {} statement.
 */

  /* ── Public API ─────────────────────────────────────────────── */
  // Fix #11: scan selector search + category filter
  function _filterScans(uid, query) {
    const q = query.toLowerCase().trim();
    const body = document.getElementById(uid + '_body');
    if (!body) return;
    body.querySelectorAll('.scan-card').forEach(card => {
      const text = card.textContent.toLowerCase();
      card.style.display = (!q || text.includes(q)) ? '' : 'none';
    });
    body.querySelectorAll('.ss-section').forEach(sec => {
      const visible = [...sec.querySelectorAll('.scan-card')].some(c => c.style.display !== 'none');
      sec.style.display = visible ? '' : 'none';
    });
  }

  function _filterScanCat(uid, cat, btn) {
    const body = document.getElementById(uid + '_body');
    if (!body) return;
    document.getElementById(uid + '_tabs').querySelectorAll('.ss-cat-tab').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(uid + '_search').value = '';
    body.querySelectorAll('.ss-section').forEach(sec => {
      sec.style.display = (cat === 'all' || sec.dataset.cat === cat) ? '' : 'none';
    });
    body.querySelectorAll('.scan-card').forEach(c => c.style.display = '');
  }



/* ═══════════════════════════════════════════════════════════════════
   SCAN MODE SELECTOR — Step 1 after project init
   Shows "Single IP" vs "Multiple IP" cards
═══════════════════════════════════════════════════════════════════ */

  function _showScanModeSelector() {
    const chat = document.getElementById('chat');
    const uid  = 'sms-' + Date.now();
    const d    = document.createElement('div');
    d.className = 'msg msg-ai sms-wrap';
    d.id = uid;
    d.innerHTML = `
      <div class="sms-title">🎯 How would you like to scan?</div>
      <div class="sms-subtitle">Choose your scanning mode to continue</div>
      <div class="sms-cards">
        <div class="sms-card" onclick="Chatbot._onScanModeSelect('single','${uid}')">
          <div class="sms-card-icon">🖥️</div>
          <div class="sms-card-name">Single IP Scan</div>
          <div class="sms-card-desc">Scan one target — IP address or hostname</div>
          <div class="sms-card-examples">e.g. 192.168.1.1 · scanme.nmap.org</div>
          <div class="sms-card-badge sms-badge-single">Single Target</div>
        </div>
        <div class="sms-card" onclick="Chatbot._onScanModeSelect('multi','${uid}')">
          <div class="sms-card-icon">📋</div>
          <div class="sms-card-name">Multiple IP Scan</div>
          <div class="sms-card-desc">Upload a .txt file with one target per line</div>
          <div class="sms-card-examples">Up to 100 targets · Sequential scanning</div>
          <div class="sms-card-badge sms-badge-multi">Bulk Scan</div>
        </div>
      </div>`;
    d.style.opacity = '0'; d.style.transform = 'translateY(8px)';
    chat.appendChild(d);
    requestAnimationFrame(() => {
      d.style.transition = 'opacity .25s ease, transform .25s ease';
      d.style.opacity = '1'; d.style.transform = 'translateY(0)';
    });
    chat.scrollTo({ top: chat.scrollHeight, behavior: 'smooth' });
  }

  function _onScanModeSelect(mode, uid) {
    // Highlight the selected card
    const wrap = document.getElementById(uid);
    if (wrap) {
      wrap.querySelectorAll('.sms-card').forEach(c => c.classList.remove('sms-card-selected'));
      const cards = wrap.querySelectorAll('.sms-card');
      const idx   = mode === 'single' ? 0 : 1;
      if (cards[idx]) cards[idx].classList.add('sms-card-selected');
    }
    setTimeout(() => {
      wrap && wrap.remove();
      if (mode === 'single') {
        _promptScanIP();
      } else {
        _showMultiIPUpload();
      }
    }, 200);
  }


/* ═══════════════════════════════════════════════════════════════════
   MULTI-IP UPLOAD FLOW
═══════════════════════════════════════════════════════════════════ */

  // Active multi-scan job state
  let _multiJobId        = null;
  let _multiPollTimer    = null;
  let _multiScanType     = 'service_detect';

  function _showMultiIPUpload() {
    const chat = document.getElementById('chat');
    const uid  = 'miu-' + Date.now();
    const d    = document.createElement('div');
    d.className = 'msg msg-ai miu-wrap';
    d.id = uid;
    d.innerHTML = `
      <div class="miu-header">
        <span class="miu-icon">📋</span>
        <div>
          <div class="miu-title">Multiple IP Scan</div>
          <div class="miu-sub">Upload a .txt file — one target per line</div>
        </div>
      </div>
      <div class="miu-format">
        <div class="miu-format-title">📄 File format:</div>
        <div class="miu-code">192.168.1.1<br>192.168.1.2<br>10.0.0.5<br>scanme.nmap.org</div>
        <div class="miu-rules">• One target per line &nbsp;•&nbsp; IPs or hostnames &nbsp;•&nbsp; Max 100 targets &nbsp;•&nbsp; Comments with #</div>
      </div>
      <div class="miu-upload-zone" id="${uid}-zone"
           onclick="document.getElementById('${uid}-file').click()"
           ondragover="event.preventDefault();this.classList.add('miu-drag')"
           ondragleave="this.classList.remove('miu-drag')"
           ondrop="Chatbot._onMultiFileDrop(event,'${uid}')">
        <div class="miu-upload-icon">📂</div>
        <div class="miu-upload-text">Click to select .txt file</div>
        <div class="miu-upload-hint">or drag and drop here</div>
      </div>
      <input type="file" id="${uid}-file" accept=".txt,text/plain" style="display:none"
             onchange="Chatbot._onMultiFileSelect(event,'${uid}')"/>
      <div class="miu-validation" id="${uid}-val" style="display:none"></div>
      <div class="miu-scan-type-row" id="${uid}-type-row" style="display:none">
        <label class="miu-label">Scan mode:</label>
        <select class="miu-select" id="${uid}-scan-type">
          <option value="service_detect">Service Detection (~45s)</option>
          <option value="tcp_basic">Quick TCP (~30s)</option>
          <option value="vuln_scan">Vulnerability Scan (~30m)</option>
          <option value="os_detect">OS Detection (~60s)</option>
          <option value="stealth_syn">Stealth SYN (~3-5m)</option>
        </select>
      </div>
      <div class="miu-actions" id="${uid}-actions" style="display:none">
        <button class="miu-btn-start" onclick="Chatbot._startMultiScan('${uid}')">
          ▶ Start Batch Scan
        </button>
        <button class="miu-btn-back" onclick="Chatbot._promptScanIP()">
          ← Change Mode
        </button>
      </div>`;
    d.style.opacity = '0'; d.style.transform = 'translateY(8px)';
    chat.appendChild(d);
    requestAnimationFrame(() => {
      d.style.transition = 'opacity .25s ease, transform .25s ease';
      d.style.opacity = '1'; d.style.transform = 'translateY(0)';
    });
    chat.scrollTo({ top: chat.scrollHeight, behavior: 'smooth' });
  }

  function _onMultiFileDrop(event, uid) {
    event.preventDefault();
    const zone = document.getElementById(uid + '-zone');
    if (zone) zone.classList.remove('miu-drag');
    const file = event.dataTransfer?.files?.[0];
    if (file) _processMultiFile(file, uid);
  }

  function _onMultiFileSelect(event, uid) {
    const file = event.target?.files?.[0];
    if (file) _processMultiFile(file, uid);
  }

  async function _processMultiFile(file, uid) {
    if (!file.name.endsWith('.txt') && file.type !== 'text/plain') {
      _multiShowValidation(uid, null, 'Only .txt files are accepted.');
      return;
    }
    if (file.size > 50000) {
      _multiShowValidation(uid, null, 'File too large (max 50 KB).');
      return;
    }
    const zone = document.getElementById(uid + '-zone');
    if (zone) {
      zone.innerHTML = `<div class="miu-upload-icon">⏳</div><div class="miu-upload-text">Reading file…</div>`;
    }
    try {
      const text = await file.text();
      // Preview validation via backend
      const result = await ApiService.multiScanValidate(text, 'service_detect', SessionManager.getProjectName());
      // Store txt for later use
      if (zone) zone.dataset.txt = text;
      const zone2 = document.getElementById(uid + '-zone');
      if (zone2) {
        zone2.innerHTML = `
          <div class="miu-upload-icon">✅</div>
          <div class="miu-upload-text">${file.name}</div>
          <div class="miu-upload-hint">${result.valid.length} valid targets loaded</div>`;
      }
      _multiShowValidation(uid, result, null);
      // Show scan type + start button
      const typeRow = document.getElementById(uid + '-type-row');
      const actions = document.getElementById(uid + '-actions');
      if (typeRow) typeRow.style.display = 'flex';
      if (actions) actions.style.display = 'flex';
    } catch (e) {
      if (zone) zone.innerHTML = `<div class="miu-upload-icon">📂</div><div class="miu-upload-text">Click to re-select</div>`;
      _multiShowValidation(uid, null, 'Validation failed: ' + e.message);
    }
  }

  function _multiShowValidation(uid, result, errorMsg) {
    const el = document.getElementById(uid + '-val');
    if (!el) return;
    el.style.display = 'block';
    if (errorMsg) {
      el.innerHTML = `<div class="miu-val-error">❌ ${errorMsg}</div>`;
      return;
    }
    const valid   = result?.valid   || [];
    const invalid = result?.invalid || [];
    let html = `<div class="miu-val-summary">`;
    html += `<span class="miu-val-ok">✅ ${valid.length} valid</span>`;
    if (invalid.length) html += `<span class="miu-val-err">⚠️ ${invalid.length} invalid</span>`;
    html += `</div>`;
    if (valid.length) {
      html += `<div class="miu-val-list">${valid.slice(0, 8).map(t => `<span class="miu-val-target">${t}</span>`).join('')}`;
      if (valid.length > 8) html += `<span class="miu-val-more">+${valid.length - 8} more</span>`;
      html += `</div>`;
    }
    if (invalid.length) {
      html += `<div class="miu-val-inv">`;
      invalid.slice(0, 3).forEach(inv => {
        html += `<div class="miu-val-inv-row">Line ${inv.line}: <code>${inv.raw}</code> — ${inv.reason}</div>`;
      });
      if (invalid.length > 3) html += `<div class="miu-val-inv-row">+${invalid.length - 3} more invalid entries</div>`;
      html += `</div>`;
    }
    el.innerHTML = html;
  }

  async function _startMultiScan(uid) {
    const zone     = document.getElementById(uid + '-zone');
    const typeEl   = document.getElementById(uid + '-scan-type');
    const txt      = zone?.dataset?.txt;
    const scanType = typeEl?.value || 'service_detect';

    if (!txt) { addMsg('⚠️ No file loaded. Please upload a .txt file first.', 'ai'); return; }

    _multiScanType = scanType;
    const projectName = SessionManager.getProjectName();

    // Remove upload card
    const card = document.getElementById(uid);
    if (card) {
      card.style.opacity = '0';
      setTimeout(() => card.remove(), 300);
    }

    addMsg(`🚀 Starting batch scan (${scanType})…`, 'user');
    await _runMultiScanJob(txt, scanType, projectName);
  }

  async function _runMultiScanJob(txt, scanType, projectName) {
    const chat = document.getElementById('chat');
    const progressId = 'ms-prog-' + Date.now();

    // Render progress widget
    const prog = document.createElement('div');
    prog.className = 'msg msg-ai ms-progress-wrap';
    prog.id = progressId;
    prog.innerHTML = `
      <div class="ms-prog-header">
        <span class="ms-prog-icon">📡</span>
        <div class="ms-prog-info">
          <div class="ms-prog-title">Running Batch Scan</div>
          <div class="ms-prog-target" id="${progressId}-cur">Initializing…</div>
        </div>
        <span class="ms-prog-count" id="${progressId}-count">0/0</span>
      </div>
      <div class="ms-prog-bar"><div class="ms-prog-fill" id="${progressId}-fill" style="width:0%"></div></div>
      <div class="ms-prog-status" id="${progressId}-status">Queuing targets…</div>`;
    prog.style.opacity = '0'; prog.style.transform = 'translateY(6px)';
    chat.appendChild(prog);
    requestAnimationFrame(() => {
      prog.style.transition = 'opacity .25s ease, transform .25s ease';
      prog.style.opacity = '1'; prog.style.transform = 'translateY(0)';
    });
    chat.scrollTo({ top: chat.scrollHeight, behavior: 'smooth' });

    try {
      const start = await ApiService.multiScanStart(txt, scanType, projectName);
      if (!start.ok) {
        document.getElementById(progressId)?.remove();
        addMsg(`❌ Could not start batch scan: ${start.error || 'unknown error'}`, 'ai');
        return;
      }

      _multiJobId = start.job_id;
      const total  = start.total;

      // Update widget with target count
      const countEl = document.getElementById(progressId + '-count');
      if (countEl) countEl.textContent = `0/${total}`;

      // Poll for status
      await new Promise((resolve) => {
        _multiPollTimer = setInterval(async () => {
          try {
            const status = await ApiService.multiScanStatus(_multiJobId);
            const pct    = total > 0 ? Math.round((status.completed / total) * 100) : 0;

            const fill   = document.getElementById(progressId + '-fill');
            const cur    = document.getElementById(progressId + '-cur');
            const cnt    = document.getElementById(progressId + '-count');
            const sts    = document.getElementById(progressId + '-status');

            if (fill) fill.style.width = pct + '%';
            if (cur)  cur.textContent  = status.current ? `[${status.completed + 1}/${total}] Scanning ${status.current}` : 'Processing…';
            if (cnt)  cnt.textContent  = `${status.completed}/${total}`;
            if (sts)  sts.textContent  = status.done
              ? `✅ Complete — ${status.completed} scanned, ${status.failed} failed`
              : `⏳ ${pct}% — elapsed ${status.elapsed_s}s`;

            if (status.done) {
              clearInterval(_multiPollTimer);
              _multiPollTimer = null;
              resolve(status);
            }
          } catch (e) {
            clearInterval(_multiPollTimer);
            _multiPollTimer = null;
            resolve(null);
          }
        }, 2000);
      });

      // Fetch final status with aggregate
      const finalStatus = await ApiService.multiScanStatus(_multiJobId);
      document.getElementById(progressId)?.remove();
      _renderMultiResultCards(finalStatus, scanType);

    } catch (e) {
      document.getElementById(progressId)?.remove();
      addMsg(`❌ Batch scan error: ${e.message}`, 'ai');
    }
  }


/* ═══════════════════════════════════════════════════════════════════
   MULTI-SCAN RESULT CARDS
═══════════════════════════════════════════════════════════════════ */

  const _RISK_COLORS_M = {
    critical: '#ef4444', high: '#f97316', medium: '#f59e0b',
    low: '#22c55e', unknown: '#6b7280'
  };

  function _renderMultiResultCards(status, scanType) {
    const chat   = document.getElementById('chat');
    const results = status.results || [];
    const agg     = status.aggregate || {};
    const ok      = results.filter(r => r.status === 'ok');
    const failed  = results.filter(r => r.status === 'error');

    if (!results.length) {
      addMsg('⚠️ Batch scan completed with no results.', 'ai');
      return;
    }

    // ── Aggregate summary banner ──
    const banner = document.createElement('div');
    banner.className = 'msg msg-ai ms-agg-banner';
    const aggRisk    = agg.overall_risk || 'unknown';
    const aggColor   = _RISK_COLORS_M[aggRisk] || '#6b7280';
    banner.innerHTML = `
      <div class="ms-agg-header">
        <span class="ms-agg-icon">📊</span>
        <div class="ms-agg-info">
          <div class="ms-agg-title">Batch Scan Complete</div>
          <div class="ms-agg-sub">${ok.length} scanned · ${failed.length} failed · ${agg.total_cves || 0} CVEs total · ${agg.total_ports || 0} open ports</div>
        </div>
        <span class="ms-agg-risk" style="background:${aggColor}20;color:${aggColor};border:1px solid ${aggColor}40">
          ${aggRisk.toUpperCase()}
        </span>
      </div>
      ${agg.severity ? `
      <div class="ms-agg-sev">
        <span class="ms-sev-pill ms-sev-critical">CRIT ${agg.severity.critical || 0}</span>
        <span class="ms-sev-pill ms-sev-high">HIGH ${agg.severity.high || 0}</span>
        <span class="ms-sev-pill ms-sev-medium">MED ${agg.severity.medium || 0}</span>
        <span class="ms-sev-pill ms-sev-low">LOW ${agg.severity.low || 0}</span>
      </div>` : ''}`;
    banner.style.opacity = '0';
    chat.appendChild(banner);
    requestAnimationFrame(() => {
      banner.style.transition = 'opacity .3s ease';
      banner.style.opacity = '1';
    });

    // ── Result cards grid ──
    const grid = document.createElement('div');
    grid.className = 'msg msg-ai ms-cards-wrap';

    // Search/filter bar
    const filterId = 'msf-' + Date.now();
    grid.innerHTML = `
      <div class="ms-cards-header">
        <div class="ms-cards-title">📋 Scan Results — ${results.length} Targets</div>
        <input class="ms-cards-search" id="${filterId}-search" type="text"
               placeholder="🔍 Filter targets…"
               oninput="Chatbot._filterMultiCards('${filterId}', this.value)"
               autocomplete="off"/>
      </div>
      <div class="ms-cards-grid" id="${filterId}-grid">
        ${results.map(r => _buildResultCard(r, filterId)).join('')}
      </div>`;
    grid.style.opacity = '0'; grid.style.transform = 'translateY(6px)';
    chat.appendChild(grid);
    requestAnimationFrame(() => {
      grid.style.transition = 'opacity .35s ease, transform .35s ease';
      grid.style.opacity = '1'; grid.style.transform = 'translateY(0)';
    });
    chat.scrollTo({ top: chat.scrollHeight, behavior: 'smooth' });
  }

  function _buildResultCard(r, filterId) {
    const risk      = r.overall_risk || 'unknown';
    const riskColor = _RISK_COLORS_M[risk] || '#6b7280';
    const isOk      = r.status === 'ok';
    const sev       = r.severity || {};

    if (!isOk) {
      return `
        <div class="ms-card ms-card-error" data-target="${r.target}" data-filter-id="${filterId}">
          <div class="ms-card-target">❌ ${r.target}</div>
          <div class="ms-card-error-msg">${r.reason || 'Scan failed'}</div>
        </div>`;
    }

    const sessionId = r.session_id || '';
    return `
      <div class="ms-card" data-target="${r.target}" data-filter-id="${filterId}"
           onclick="Chatbot._loadMultiIPDetail('${sessionId}','${r.target}',this)">
        <div class="ms-card-header">
          <span class="ms-card-target">${r.target}</span>
          <span class="ms-card-risk" style="color:${riskColor}">${risk.toUpperCase()}</span>
        </div>
        <div class="ms-card-stats">
          <span class="ms-stat"><span class="ms-stat-num">${r.open_ports || 0}</span><span class="ms-stat-lbl">ports</span></span>
          <span class="ms-stat"><span class="ms-stat-num">${r.cve_count || 0}</span><span class="ms-stat-lbl">CVEs</span></span>
          <span class="ms-stat-bar" style="--pct:${Math.min((r.risk_score || 0) * 10, 100)}%;--clr:${riskColor}"></span>
        </div>
        <div class="ms-card-sev">
          ${sev.critical ? `<span class="ms-sev-pill ms-sev-critical">C:${sev.critical}</span>` : ''}
          ${sev.high     ? `<span class="ms-sev-pill ms-sev-high">H:${sev.high}</span>`         : ''}
          ${sev.medium   ? `<span class="ms-sev-pill ms-sev-medium">M:${sev.medium}</span>`     : ''}
          ${sev.low      ? `<span class="ms-sev-pill ms-sev-low">L:${sev.low}</span>`           : ''}
          ${(!sev.critical && !sev.high && !sev.medium && !sev.low) ? '<span class="ms-card-clean">✅ Clean</span>' : ''}
        </div>
        ${r.ai_summary ? `<div class="ms-card-summary">${r.ai_summary.slice(0, 90)}${r.ai_summary.length > 90 ? '…' : ''}</div>` : ''}
        <div class="ms-card-footer">
          <span class="ms-card-dur">${r.duration ? r.duration.toFixed(1) + 's' : ''}</span>
          <span class="ms-card-cta">Click for details →</span>
        </div>
      </div>`;
  }

  function _filterMultiCards(filterId, query) {
    const grid = document.getElementById(filterId + '-grid');
    if (!grid) return;
    const q = query.toLowerCase().trim();
    grid.querySelectorAll('.ms-card, .ms-card-error').forEach(card => {
      const target = (card.dataset.target || '').toLowerCase();
      card.style.display = (!q || target.includes(q)) ? '' : 'none';
    });
  }

  async function _loadMultiIPDetail(sessionId, target, cardEl) {
    if (!sessionId) { addMsg(`⚠️ No session data for ${target}.`, 'ai'); return; }

    // Mark card as loading
    if (cardEl) cardEl.classList.add('ms-card-loading');

    try {
      const d = await ApiService.getScanResults(sessionId);
      if (cardEl) cardEl.classList.remove('ms-card-loading');

      // Load the full results into the app state and render all panels
      App.setLastData(d);
      App.setCurrentSession(d.session_id);
      renderAll(d);
      loadDrawer();

      // Show a confirmation message then render results in chat
      addMsg(`📊 **${target}** — loading detailed scan results…`, 'ai');
      const _scanRichData = {
        target: d.target, scan_type: d.scan_type, duration: d.duration,
        summary: d.explanation?.summary || '', recommendation: d.recommendation?.reason || '',
        risk: d.risk, ai_analysis: d.ai_analysis, explanation: d.explanation,
      };
      _renderScanCompleteCard(_scanRichData);

      const hosts     = d.risk?.hosts || [];
      const totalCves = hosts.reduce((n, h) => n + (h.ports || []).reduce((m, p) => m + (p.cves || []).length, 0), 0);
      if (totalCves > 0) {
        _renderVulnTableInChat(hosts);
      } else {
        addMsg(`✅ No CVEs detected on open ports for ${target}.`, 'ai');
      }

    } catch (e) {
      if (cardEl) cardEl.classList.remove('ms-card-loading');
      addMsg(`❌ Could not load details for ${target}: ${e.message}`, 'ai');
    }
  }


  /* ═══════════════════════════════════════════════════════
     AI PATCH FETCH — called from /patch all dashboard rows
     Uses Qwen2.5-Coder → Nemotron → GPT-OSS → DeepSeek → Rule engine fallback chain.
     Deduplicated: concurrent calls for same key share ONE request.
  ═══════════════════════════════════════════════════════ */

  async function _fetchAIPatch(expId, service, port, version, cveId, severity) {
    const btn     = document.getElementById(expId + '-ai-btn');
    const expBody = document.getElementById(expId);
    if (!expBody) return;

    if (btn) {
      btn.disabled    = true;
      btn.textContent = '⏳ Fetching AI patch…';
    }

    try {
      const sessionId = App.getCurrentSession() || SessionManager.activeId() || '';
      const data = typeof RemediationClient !== 'undefined'
        ? await RemediationClient.getPatchGuidance({ service, port, version, cve_id: cveId, severity, session_id: sessionId })
        : await ApiService.getPatchGuidance(service, port, version, cveId, severity, sessionId);

      // Build AI patch result block HTML
      const engineRaw = data.engine || 'qwen';
      const engineLabels = {
        qwen:                  'Qwen2.5-Coder 7B',
        llama:                 'Llama 3.2 3B',
        nemotron:              'Nemotron 3 Super 120B',
        gpt_oss:               'GPT-OSS 120B',
        deepseek_flash:        'DeepSeek V4 Flash',
        llama33:               'Llama 3.3 70B',
        gemma4:                'Gemma 4 27B',
        'rule-based-fallback': 'Rule Engine',
        'rule-based':          'Rule Engine',
      };
      const engine   = engineLabels[engineRaw] || engineRaw;
      // Support both old fields (upgrade_command) and new structured fields (commands[])
      const cmds     = Array.isArray(data.commands) ? data.commands.filter(Boolean) : [];
      const upg      = data.upgrade_command  || data.upgrade_cmd  || cmds[0] || '';
      const rst      = data.restart_command  || cmds[1] || '';
      const vrfy     = data.verify_command   || cmds[2] || '';
      const mit      = data.mitigation       || '';
      const hdg      = data.hardening_tips   || data.config_hardening || [];
      const refs     = data.references       || [];
      const summary  = data.summary          || '';
      const recVer   = data.recommended_version || '';

      let html = `
        <div class="pd-ai-patch-result" id="${expId}-ai-result">
          <div class="pd-ai-patch-header">
            <span class="pd-ai-badge">✨ AI Patch Guide</span>
            <span class="pd-ai-engine">${engine}</span>
          </div>`;

      if (summary) html += `<div class="pd-exp-text" style="margin-bottom:8px">${summary}</div>`;
      if (recVer)  html += `<div class="pd-exp-text"><strong>Recommended version:</strong> <code>${recVer}</code></div>`;

      if (upg) html += `
        <div class="pd-exp-cmd-block">
          <div class="pd-exp-title">⬆️ Upgrade Command</div>
          <div class="pd-cmd-row">
            <code class="pd-cmd">${upg}</code>
            <button class="vt-copy-btn" onclick="navigator.clipboard.writeText(${JSON.stringify(upg)});this.textContent='✅';setTimeout(()=>this.textContent='📋',1500)">📋</button>
          </div>
        </div>`;

      if (rst) html += `
        <div class="pd-exp-cmd-block">
          <div class="pd-exp-title">🔄 Restart Service</div>
          <div class="pd-cmd-row">
            <code class="pd-cmd">${rst}</code>
            <button class="vt-copy-btn" onclick="navigator.clipboard.writeText(${JSON.stringify(rst)});this.textContent='✅';setTimeout(()=>this.textContent='📋',1500)">📋</button>
          </div>
        </div>`;

      if (vrfy) html += `
        <div class="pd-exp-cmd-block">
          <div class="pd-exp-title">✅ Verify Fix</div>
          <div class="pd-cmd-row">
            <code class="pd-cmd">${vrfy}</code>
            <button class="vt-copy-btn" onclick="navigator.clipboard.writeText(${JSON.stringify(vrfy)});this.textContent='✅';setTimeout(()=>this.textContent='📋',1500)">📋</button>
          </div>
        </div>`;

      if (mit) html += `
        <div class="pd-exp-cmd-block">
          <div class="pd-exp-title">🛡️ Mitigation</div>
          <div class="pd-exp-text">${mit}</div>
        </div>`;

      if (hdg.length) html += `
        <div class="pd-exp-cmd-block">
          <div class="pd-exp-title">⚙️ Config Hardening</div>
          <ul class="pd-hardening-list">${hdg.map(h => `<li>${h}</li>`).join('')}</ul>
        </div>`;

      if (refs.length) html += `
        <div class="pd-exp-cmd-block">
          <div class="pd-exp-title">🔗 References</div>
          <div>${refs.slice(0,3).map(r => `<a class="vd-exp-btn" href="${r}" target="_blank" rel="noopener" style="margin-right:6px;margin-bottom:4px">${r.slice(0,50)}${r.length>50?'…':''}</a>`).join('')}</div>
        </div>`;

      html += `</div>`;

      // Remove existing result block if any, then inject
      document.getElementById(expId + '-ai-result')?.remove();
      const actionsDiv = expBody.querySelector('.pd-exp-actions');
      if (actionsDiv) actionsDiv.insertAdjacentHTML('beforebegin', html);

      // Update button to "Refresh"
      if (btn) {
        btn.disabled    = false;
        btn.textContent = '🔄 Refresh AI Patch';
      }

    } catch (err) {
      if (btn) {
        btn.disabled    = false;
        btn.textContent = '⚠️ Retry AI Patch';
      }
      // Show error inline
      const existing = document.getElementById(expId + '-ai-result');
      if (existing) existing.remove();
      const errDiv = document.createElement('div');
      errDiv.id        = expId + '-ai-result';
      errDiv.className = 'pd-ai-patch-result';
      errDiv.innerHTML = `<div class="pd-ai-patch-header"><span class="pd-ai-badge" style="background:#e24b4a22;color:#e24b4a">⚠️ AI Unavailable</span></div>
        <div class="pd-exp-text" style="color:var(--text3)">Could not fetch AI guidance: ${err.message}. Ensure Ollama is running (<code>ollama serve</code>) or run <code>setup_env.sh</code>.</div>`;
      const actionsDiv = document.getElementById(expId)?.querySelector('.pd-exp-actions');
      if (actionsDiv) actionsDiv.insertAdjacentHTML('beforebegin', errDiv.outerHTML);
    }
  }

  return {
    showGreeting, addMsg, sendChat, quickChat, restoreChatMessages,
    runScan, executeScan, confirmStop, doStop, startNewScan, newChat,
    renderAll, rTab, frsOpen, frsClose, frsToggle,
    openDrawer, closeDrawer, filterDrawer, loadDrawer, viewSession,
    showReportModal, selectFmt, doExportReport, suggestNext,
    onChatKeyDown, onChatInput, selectAutocomplete,
    _filterVulnTable, _sortVulnTable, _filterVulnDash, _searchVulnDash,
    _filterScans, _filterScanCat,
    _sortVulnDash, _toggleVulnExpand, _copyVulnCSV,
    _togglePatchExpand, _togglePncCard, _filterPatchDash, _searchPatchDash,
    _promptScanIP, _submitScanIP,
    _showProjectOnboarding, _submitProjectName, _setProjectQuick,
    // Drawer 3-dot menu
    _toggleDrawerMenu, _renameDrawerSession, _submitDrawerRename,
    _cancelDrawerRename, _deleteDrawerSession, _confirmDrawerDelete,
    // Fix 8 — scroll-to-bottom
    scrollToBottom, _onChatScroll,
    // AI patch guidance
    _fetchAIPatch,
    // Multi-OS patch switcher + patch-all card controls
    _switchPatchOs, _togglePaExpand, 
    // Tab-based details inside patch rows
    _switchPatchTab,
    // Graph picker
    _openGraph,
    // Phase 0 Part B: /vuln and /scan are gone as slash commands, but the
    // dashboards/buttons that used to fire them as quickChat('/vuln') /
    // quickChat('/scan <ip>') call these directly now instead.
    openVulnDashboard: _handleVulnCommand,
    rescan: _autoStartVulnScan,
  };
})();
