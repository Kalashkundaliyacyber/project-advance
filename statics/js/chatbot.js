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
  let _activeProvider = 'unknown';   // 'gemini' | 'ollama' | 'rule-based'

  // ── Slash commands ─────────────────────────────────────────
  const SLASH_CMDS = [
    { cmd: '/patch',    hint: '/patch <ip> <port>',     desc: 'Patch guidance for a port' },
    { cmd: '/patch',    hint: '/patch all',             desc: 'Full remediation dashboard for all vulnerabilities' },
    { cmd: '/report',   hint: '/report [pdf|html]',     desc: 'Export scan report (PDF or HTML)' },
    { cmd: '/clear',    hint: '/clear',                 desc: 'Clear chat window' },
    { cmd: '/stop',     hint: '/stop',                  desc: 'Abort running scan' },
    { cmd: '/help',     hint: '/help',                  desc: 'Show all commands' },
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
     Updates "ScanWise AI > Project > Target" in topbar
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
    const parts = ['<span class="bc-root">ScanWise AI</span>'];
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
    if (opts.checking) { dot.className = 'model-dot checking'; meta.textContent = 'Checking…'; return; }
    if (opts.error)    { dot.className = 'model-dot error';    meta.textContent = 'Unavailable'; return; }

    // Update from ai status if provided
    if (opts.aiStatus) {
      const st = opts.aiStatus;
      _activeProvider = st.active_provider || 'unknown';
      _modelName      = st.display_name    || _modelName;
      _modelProvider  = st.display_provider || _modelProvider;
      // Provider-specific dot colour
      const providerClass = {
        qwen:         'model-dot qwen',
        llama:        'model-dot llama',
        gemini:       'model-dot gemini',
        'rule-based': 'model-dot fallback',
      };
      dot.className = providerClass[_activeProvider] || 'model-dot';
    } else {
      dot.className = 'model-dot';
    }

    // Update from response provider
    if (opts.provider) {
      _activeProvider = opts.provider;
      const pNames = {
        qwen:         'Qwen2.5-Coder 7B',
        llama:        'Llama 3.2 3B',
        gemini:       'Gemini (Cloud)',
        'rule-based': 'Rule Engine',
        'rule-based-fallback': 'Rule Engine',
      };
      const pLabels = {
        qwen:         'Ollama · Primary',
        llama:        'Ollama · Chat',
        gemini:       'Google AI · Emergency Fallback',
        'rule-based': 'Offline Mode',
        'rule-based-fallback': 'Offline Mode',
      };
      _modelName     = pNames[opts.provider]  || opts.provider;
      _modelProvider = pLabels[opts.provider] || opts.provider;
      const cls = {
        qwen:         'model-dot qwen',
        llama:        'model-dot llama',
        gemini:       'model-dot gemini',
        'rule-based': 'model-dot fallback',
        'rule-based-fallback': 'model-dot fallback',
      };
      dot.className = cls[opts.provider] || 'model-dot';
    }

    name.textContent = _modelName;
    const lat = opts.latency || (opts.aiStatus && opts.aiStatus.last_latency_ms);
    const latencyStr = lat ? ` · ${lat}ms` : '';
    meta.textContent = _modelProvider + latencyStr;
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
      if (txt === '__PATCH_ALL__')        { _handlePatchAll();    return null; }
    }
    SessionManager.saveMsg(type, txt);
    const chat = document.getElementById('chat');
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
        case 'PATCH_ALL_WRAP':  _buildPatchAllWrapEl(data, frag);   break;   // BUG 3 FIX
        case 'RICH_PATCH_CARD': _buildRichPatchCardEl(data, frag);  break;   // BUG 3 FIX
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
    'Type /patch all for remediation…',
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
          <button class="post-ob-btn" onclick="Chatbot._showScanModeSelector()">
            <span class="pob-icon">🎯</span>
            <span class="pob-text"><strong>Start Scanning</strong><small>Single IP or Multiple IPs from file</small></span>
          </button>
          <button class="post-ob-btn" onclick="Chatbot.quickChat('/patch all')">
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
        <button class="post-ob-btn" onclick="Chatbot._showScanModeSelector()">
          <span class="pob-icon">🎯</span>
          <span class="pob-text"><strong>Start Scanning</strong><small>Single IP or Multiple IPs from file</small></span>
        </button>
        <button class="post-ob-btn" onclick="Chatbot.quickChat('/patch all')">
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

  // Command registry — single source of truth for all commands
  const CMD_REGISTRY = {
    '/patch':    { fn: _cmdPatch,    needsScan: false, desc: 'Patch guidance' },
    '/report':   { fn: _cmdReport,   needsScan: true,  desc: 'Export report' },
    '/clear':    { fn: _cmdClear,    needsScan: false, desc: 'Clear chat' },
    '/stop':     { fn: _cmdStop,     needsScan: false, desc: 'Stop scan' },
    '/help':     { fn: _cmdHelp,     needsScan: false, desc: 'Show commands' },
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

  async function _cmdScan(parts)     { if (parts[1]) { _showScanTypeSelector(_normalizeTarget(parts[1])); } else { _promptScanIP(); } }
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
      console.warn('[ScanWise] No active session — user must initialize a project first.');
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
        console.debug('[ScanWise] sendChat (slash unknown) → session:', sessionId);
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
    console.debug('[ScanWise] sendChat → session:', sessionId);
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
            <button class="post-ob-btn" onclick="Chatbot._showScanModeSelector()">
              <span class="pob-icon">🎯</span>
              <span class="pob-text"><strong>Start Scanning</strong><small>Single IP or Multiple IPs from file</small></span>
            </button>
            <button class="post-ob-btn" onclick="Chatbot.quickChat('/patch all')">
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
      case 'show_scan_selector': if (d.data?.target) _showScanTypeSelector(d.data.target); break;
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
      case 'show_help':      _showHelpCard();               break;
    }
  }



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

    // SESSION ISOLATION FIX: Capture the originating session ID at scan start.
    // All result rendering below is guarded — results only appear in THIS session.
    const _originSessionId = SessionManager.activeId();

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

      // SESSION ISOLATION: store results into originating session regardless of
      // which session is currently active (user may have switched chats).
      SessionManager.saveScanToSession(_originSessionId, d);
      App.setLastData(d);
      App.setCurrentSession(d.session_id);
      try { localStorage.setItem('scanwise_last_session', JSON.stringify({ sessionId: d.session_id, data: d })); } catch (e) {}

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
          const allSev = { critical: 0, high: 0, medium: 0, low: 0 };
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
        setTimeout(() => { if (prog) prog.classList.remove('on'); if (fill) fill.style.width = '0%'; }, 2000);
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
        setTimeout(() => { if (prog) prog.classList.remove('on'); if (fill) fill.style.width = '0%'; }, 2000);
      }
    } catch (e) {
      if (progressMsg) progressMsg.remove();
      if (!e.message?.includes('stopped')) {
        // Only show error in the originating session if possible
        if (SessionManager.activeId() === _originSessionId) {
          addMsg(`Scan error: ${e.message}`, 'ai');
        }
        Utils.setStatus('error', 'Scan failed');
        if (prog) prog.classList.remove('on');
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
        <button class="post-ob-btn" style="font-size:12px;padding:6px 12px" onclick="Chatbot.quickChat('/patch all')">🛡 Patch Dashboard</button>
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
        <button class="vd-export-btn" style="margin-left:auto" onclick="Chatbot.quickChat('/patch all')">Open Patch Dashboard →</button>
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
     /patch all — renders Gemini AI patches for ALL ports
     Two paths:
       1. Server returned __PATCH_ALL_DATA__ with Gemini results → _renderPatchAllFromServer()
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
          // Static patch commands as fallback until Gemini loads
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

    // Render with static data first, then fetch Gemini per entry
    _renderPatchAllInChat(entries, true /* fetchingGemini */);
  }

  /** Render patch-all results returned directly from server (Gemini already done) */
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

    let cardsHtml = entries.map((e, idx) => {
      const clr     = CLRS[e.risk_level] || '#888';
      const sev     = e.severity || e.risk_level || 'low';
      const upg     = e.upgrade_command || e.upgrade_cmd || '';
      const rst     = e.restart_command || '';
      const vrfy    = e.verify_command  || '';
      const mit     = e.mitigation      || '';
      const hdg     = e.config_hardening || [];
      const refs    = e.references || [];
      const eng     = e.engine || '';
      const expId   = `pa-exp-${idx}-${Math.random().toString(36).slice(2,7)}`;

      const allCvesHtml = (e.all_cves || []).slice(0,4).map(c =>
        `<span class="pa-cve-tag" style="color:${CLRS[c.severity]||'#888'}">${c.cve_id} (${c.cvss_score})</span>`
      ).join('');

      return `
        <div class="pa-card" id="pa-card-${expId}" style="border-left:3px solid ${clr}">
          <div class="pa-card-header" onclick="Chatbot._togglePaExpand('${expId}')">
            <div class="pa-card-left">
              <span class="pa-port-badge" style="background:${clr}22;color:${clr}">Port ${e.port}</span>
              <span class="pa-svc">${e.service}</span>
              ${e.version && e.version !== 'unknown' ? `<code class="pa-ver">${e.version}</code>` : ''}
            </div>
            <div class="pa-card-right">
              ${e.cve_id && e.cve_id !== 'unknown' ? `<a class="pa-cve-link" href="https://nvd.nist.gov/vuln/detail/${e.cve_id}" target="_blank" rel="noopener" onclick="event.stopPropagation()">${e.cve_id}</a>` : ''}
              <span class="rb rb-${sev}">${sev}</span>
              <span class="pa-score" style="color:${clr}">${e.risk_score}/10</span>
              <span class="pa-arrow" id="arr-${expId}">▶</span>
            </div>
          </div>

          ${e.cve_desc ? `<div class="pa-cve-desc">${e.cve_desc.slice(0,150)}${e.cve_desc.length>150?'…':''}</div>` : ''}
          ${allCvesHtml ? `<div class="pa-all-cves">${allCvesHtml}</div>` : ''}

          <!-- Expand panel with full Gemini patch data -->
          <div class="pa-expand" id="${expId}" data-idx="${idx}" style="display:none">
            ${e.summary ? `<div class="pa-summary">${e.summary}</div>` : ''}
            ${upg ? `<div class="pa-cmd-block">
              <div class="pa-cmd-title">⬆️ Upgrade</div>
              <div class="pa-cmd-row"><code class="pa-cmd">${upg}</code>
                <button class="vt-copy-btn" onclick="navigator.clipboard.writeText(${JSON.stringify(upg)});this.textContent='✅';setTimeout(()=>this.textContent='📋',1500)">📋</button>
              </div></div>` : ''}
            ${rst ? `<div class="pa-cmd-block">
              <div class="pa-cmd-title">🔄 Restart</div>
              <div class="pa-cmd-row"><code class="pa-cmd">${rst}</code>
                <button class="vt-copy-btn" onclick="navigator.clipboard.writeText(${JSON.stringify(rst)});this.textContent='✅';setTimeout(()=>this.textContent='📋',1500)">📋</button>
              </div></div>` : ''}
            ${vrfy ? `<div class="pa-cmd-block">
              <div class="pa-cmd-title">✅ Verify</div>
              <div class="pa-cmd-row"><code class="pa-cmd">${vrfy}</code>
                <button class="vt-copy-btn" onclick="navigator.clipboard.writeText(${JSON.stringify(vrfy)});this.textContent='✅';setTimeout(()=>this.textContent='📋',1500)">📋</button>
              </div></div>` : ''}
            ${mit ? `<div class="pa-cmd-block"><div class="pa-cmd-title">🛡️ Mitigation</div><div class="pa-mit">${mit}</div></div>` : ''}
            ${hdg.length ? `<div class="pa-cmd-block"><div class="pa-cmd-title">⚙️ Hardening</div><ul class="pa-hdg-list">${hdg.map(h=>`<li>${h}</li>`).join('')}</ul></div>` : ''}
            ${refs.length ? `<div class="pa-cmd-block"><div class="pa-cmd-title">🔗 References</div>${refs.slice(0,3).map(r=>`<a class="pa-ref-link" href="${r}" target="_blank" rel="noopener">${r.slice(0,60)}${r.length>60?'…':''}</a>`).join('')}</div>` : ''}
            ${eng ? `<div class="pa-engine-badge">✨ ${eng}</div>` : ''}
            ${fetchGemini ? `<div class="pa-gemini-loading" id="pa-gem-${expId}">
              <span class="pa-gem-spinner"></span> Fetching Gemini AI patch…
            </div>` : ''}
          </div>
        </div>`;
    }).join('');

    wrap.innerHTML = `
      <div class="pa-header">
        <div class="pa-title">🔧 AI Patch Remediation — All Vulnerabilities</div>
        <div class="pa-subtitle">${entries.length} services · ${immediate} need immediate action</div>
        <div class="pa-stats">
          ${['critical','high','medium','low'].map(s => {
            const n = entries.filter(e=>e.risk_level===s).length;
            return n ? `<span class="pa-stat pa-stat-${s}">${n} ${s}</span>` : '';
          }).join('')}
        </div>
      </div>
      <div class="pa-cards" id="pa-cards-${Date.now()}">${cardsHtml}</div>
      <div class="pa-footer">
        <button class="vd-export-btn" onclick="Chatbot._copyPatchAllCSV(this)">📋 Export CSV</button>
      </div>`;

    wrap._patchEntries = entries;
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

    // Auto-expand first critical/high entry — use data-idx for reliable DOM lookup
    const firstCritical = entries.findIndex(e => ['critical','high'].includes(e.risk_level));
    if (firstCritical >= 0) {
      setTimeout(() => {
        const expandEl = wrap.querySelector(`.pa-expand[data-idx="${firstCritical}"]`);
        if (expandEl) {
          expandEl.style.display = 'block';
          const arr = document.getElementById('arr-' + expandEl.id);
          if (arr) arr.textContent = '▼';
        }
      }, 400);
    }

    // If fetchGemini=true, fetch AI patches asynchronously per entry (deduplicated)
    if (fetchGemini) {
      _fetchAIPatchesForAll(entries, wrap, sessionId);
    }
  }

  /** Fetch AI patches for all entries — deduplicated, sequential to respect queue */
  async function _fetchAIPatchesForAll(entries, wrapEl, sessionId) {
    // Use data-idx for reliable per-card DOM lookup (NodeList index can desync if DOM mutates)
    for (let i = 0; i < entries.length; i++) {
      const e      = entries[i];
      // Find expand panel by data-idx rather than NodeList position
      const expEl  = wrapEl.querySelector(`.pa-expand[data-idx="${i}"]`);
      if (!expEl) continue;
      const loadEl = expEl.querySelector(`[id^="pa-gem-"]`);

      try {
        // Use RemediationClient if available (deduplicated), else fall back to ApiService
        const data = typeof RemediationClient !== 'undefined'
          ? await RemediationClient.getPatchGuidance({
              service:    e.service,
              port:       e.port,
              version:    e.version    || 'unknown',
              cve_id:     e.cve_id     || 'unknown',
              severity:   e.severity   || 'medium',
              session_id: sessionId,
            })
          : await ApiService.getPatchGuidance(
              e.service, e.port, e.version || 'unknown',
              e.cve_id || 'unknown', e.severity || 'medium', sessionId
            );

        // Update entry with AI data
        entries[i] = { ...e, ...data, ip: e.ip, port: e.port, service: e.service,
                       risk_level: e.risk_level, risk_score: e.risk_score,
                       cve_id: e.cve_id, cve_desc: e.cve_desc, all_cves: e.all_cves };

        // Build the new expand content
        const upg  = data.upgrade_command || data.upgrade_cmd || '';
        const rst  = data.restart_command || '';
        const vrfy = data.verify_command  || '';
        const mit  = data.mitigation      || '';
        const hdg  = data.config_hardening || [];
        const refs = data.references || [];
        const eng  = data.engine || '';
        const sum  = data.summary || '';
        const rec  = data.recommended_version || '';

        let innerHtml = '';
        if (sum) innerHtml += `<div class="pa-summary">${sum}</div>`;
        if (rec) innerHtml += `<div class="pa-rec-ver">Recommended: <code>${rec}</code></div>`;
        if (upg)  innerHtml += `<div class="pa-cmd-block"><div class="pa-cmd-title">⬆️ Upgrade</div><div class="pa-cmd-row"><code class="pa-cmd">${upg}</code><button class="vt-copy-btn" onclick="navigator.clipboard.writeText(${JSON.stringify(upg)});this.textContent='✅';setTimeout(()=>this.textContent='📋',1500)">📋</button></div></div>`;
        if (rst)  innerHtml += `<div class="pa-cmd-block"><div class="pa-cmd-title">🔄 Restart</div><div class="pa-cmd-row"><code class="pa-cmd">${rst}</code><button class="vt-copy-btn" onclick="navigator.clipboard.writeText(${JSON.stringify(rst)});this.textContent='✅';setTimeout(()=>this.textContent='📋',1500)">📋</button></div></div>`;
        if (vrfy) innerHtml += `<div class="pa-cmd-block"><div class="pa-cmd-title">✅ Verify</div><div class="pa-cmd-row"><code class="pa-cmd">${vrfy}</code><button class="vt-copy-btn" onclick="navigator.clipboard.writeText(${JSON.stringify(vrfy)});this.textContent='✅';setTimeout(()=>this.textContent='📋',1500)">📋</button></div></div>`;
        if (mit)  innerHtml += `<div class="pa-cmd-block"><div class="pa-cmd-title">🛡️ Mitigation</div><div class="pa-mit">${mit}</div></div>`;
        if (hdg.length) innerHtml += `<div class="pa-cmd-block"><div class="pa-cmd-title">⚙️ Hardening</div><ul class="pa-hdg-list">${hdg.map(h=>`<li>${h}</li>`).join('')}</ul></div>`;
        if (refs.length) innerHtml += `<div class="pa-cmd-block"><div class="pa-cmd-title">🔗 References</div>${refs.slice(0,3).map(r=>`<a class="pa-ref-link" href="${r}" target="_blank" rel="noopener">${r.slice(0,60)}${r.length>60?'…':''}</a>`).join('')}</div>`;
        if (eng) innerHtml += `<div class="pa-engine-badge">✨ ${eng}</div>`;

        expEl.innerHTML = innerHtml;
        // Pulse the card to show it was updated
        const card = expEl.closest('.pa-card');
        if (card) { card.classList.add('pa-card-updated'); setTimeout(() => card.classList.remove('pa-card-updated'), 800); }

      } catch (err) {
        if (loadEl) {
          loadEl.innerHTML = `<span style="color:var(--text3);font-size:11px">⚠️ AI unavailable — showing static patch guide</span>`;
        }
      }
    }

    // ── BUG 4 FIX: Re-save enriched entries after all AI calls finish ─────────
    // The initial save in _renderPatchAllInChat had only static data.
    // Now that AI has filled in upgrade_command, summary, etc., re-save.
    try {
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
    } catch (_) {}
  }

  function _togglePaExpand(expId) {
    const el  = document.getElementById(expId);
    const arr = document.getElementById('arr-' + expId);
    if (!el) return;
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
     Completely rewrites _handlePatchCommand to show Gemini
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

    // ── BUG 2 FIX: Persist rich patch card to session history ─────────────────
    _saveRichMsg('RICH_PATCH_CARD', {
      serviceOrIp:     serviceOrIp,
      port:            port,
      service:         data.service         || serviceOrIp,
      severity:        data.severity        || 'medium',
      summary:         data.summary         || '',
      cve_id:          data.cve_id          || '',
      cve_desc:        data.cve_desc        || '',
      all_cves:        data.all_cves        || [],
      upgrade_command: data.upgrade_command || data.upgrade_cmd || '',
      restart_command: data.restart_command || '',
      verify_command:  data.verify_command  || '',
      mitigation:      data.mitigation      || '',
      config_hardening:data.config_hardening|| [],
      references:      data.references      || [],
      recommended_version: data.recommended_version || '',
      engine:          data.engine          || '',
    });
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
      { icon:'📄', cmd:'/report pdf',         label:'/report [pdf|html]',            desc:'Export the last scan report as PDF or HTML' },
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
        <button class="post-ob-btn" style="font-size:12px;padding:6px 12px" onclick="Chatbot.quickChat('/patch all')">🛡 Patch Dashboard</button>
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
        <button class="vd-export-btn" style="margin-left:auto" onclick="Chatbot.quickChat('/patch all')">Open Patch Dashboard →</button>
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

  // ── BUG 3 FIX: Restore builders for PATCH_ALL_WRAP and RICH_PATCH_CARD ──────

  /**
   * Reconstruct a /patch all output from saved token data.
   * Called by _restoreRichWidget('PATCH_ALL_WRAP', entries, frag).
   * Renders a static version (no re-fetching AI — data is already saved).
   */
  function _buildPatchAllWrapEl(entries, container) {
    if (!entries || !entries.length) return;
    const chat  = container || document.getElementById('chat');
    const wrap  = document.createElement('div');
    wrap.className = 'msg msg-ai patch-all-wrap';
    const CLRS = { critical: '#e24b4a', high: '#ef9f27', medium: '#378add', low: '#1d9e75' };
    const immediate = entries.filter(e => ['critical','high'].includes(e.risk_level)).length;

    const cardsHtml = entries.map((e, idx) => {
      const clr   = CLRS[e.risk_level] || '#888';
      const sev   = e.severity || e.risk_level || 'low';
      const upg   = e.upgrade_command || '';
      const rst   = e.restart_command || '';
      const vrfy  = e.verify_command  || '';
      const mit   = e.mitigation      || '';
      const hdg   = e.config_hardening|| [];
      const refs  = e.references      || [];
      const eng   = e.engine          || '';
      const expId = `pa-rst-${idx}-${Math.random().toString(36).slice(2,6)}`;
      const allCvesHtml = (e.all_cves || []).slice(0,4).map(c =>
        `<span class="pa-cve-tag" style="color:${CLRS[c.severity]||'#888'}">${c.cve_id} (${c.cvss_score||''})</span>`
      ).join('');

      let expandBody = '';
      if (e.summary) expandBody += `<div class="pa-summary">${e.summary}</div>`;
      if (upg)  expandBody += `<div class="pa-cmd-block"><div class="pa-cmd-title">⬆️ Upgrade</div><div class="pa-cmd-row"><code class="pa-cmd">${upg}</code><button class="vt-copy-btn" onclick="navigator.clipboard.writeText(${JSON.stringify(upg)});this.textContent='✅';setTimeout(()=>this.textContent='📋',1500)">📋</button></div></div>`;
      if (rst)  expandBody += `<div class="pa-cmd-block"><div class="pa-cmd-title">🔄 Restart</div><div class="pa-cmd-row"><code class="pa-cmd">${rst}</code><button class="vt-copy-btn" onclick="navigator.clipboard.writeText(${JSON.stringify(rst)});this.textContent='✅';setTimeout(()=>this.textContent='📋',1500)">📋</button></div></div>`;
      if (vrfy) expandBody += `<div class="pa-cmd-block"><div class="pa-cmd-title">✅ Verify</div><div class="pa-cmd-row"><code class="pa-cmd">${vrfy}</code><button class="vt-copy-btn" onclick="navigator.clipboard.writeText(${JSON.stringify(vrfy)});this.textContent='✅';setTimeout(()=>this.textContent='📋',1500)">📋</button></div></div>`;
      if (mit)  expandBody += `<div class="pa-cmd-block"><div class="pa-cmd-title">🛡️ Mitigation</div><div class="pa-mit">${mit}</div></div>`;
      if (hdg.length) expandBody += `<div class="pa-cmd-block"><div class="pa-cmd-title">⚙️ Hardening</div><ul class="pa-hdg-list">${hdg.map(h=>`<li>${h}</li>`).join('')}</ul></div>`;
      if (refs.length) expandBody += `<div class="pa-cmd-block"><div class="pa-cmd-title">🔗 References</div>${refs.slice(0,3).map(r=>`<a class="pa-ref-link" href="${r}" target="_blank" rel="noopener">${r.slice(0,60)}${r.length>60?'…':''}</a>`).join('')}</div>`;
      if (eng) expandBody += `<div class="pa-engine-badge">✨ ${eng}</div>`;

      return `
        <div class="pa-card" style="border-left:3px solid ${clr}">
          <div class="pa-card-header" onclick="Chatbot._togglePaExpand('${expId}')">
            <div class="pa-card-left">
              <span class="pa-port-badge" style="background:${clr}22;color:${clr}">Port ${e.port}</span>
              <span class="pa-svc">${e.service}</span>
              ${e.version && e.version !== 'unknown' ? `<code class="pa-ver">${e.version}</code>` : ''}
            </div>
            <div class="pa-card-right">
              ${e.cve_id && e.cve_id !== 'unknown' ? `<a class="pa-cve-link" href="https://nvd.nist.gov/vuln/detail/${e.cve_id}" target="_blank" rel="noopener" onclick="event.stopPropagation()">${e.cve_id}</a>` : ''}
              <span class="rb rb-${sev}">${sev}</span>
              <span class="pa-score" style="color:${clr}">${e.risk_score||0}/10</span>
              <span class="pa-arrow" id="arr-${expId}">▶</span>
            </div>
          </div>
          ${e.cve_desc ? `<div class="pa-cve-desc">${e.cve_desc.slice(0,150)}${e.cve_desc.length>150?'…':''}</div>` : ''}
          ${allCvesHtml ? `<div class="pa-all-cves">${allCvesHtml}</div>` : ''}
          <div class="pa-expand" id="${expId}" data-idx="${idx}" style="display:none">
            ${expandBody || '<div style="color:var(--text3);font-size:12px;padding:8px">No AI data saved for this entry.</div>'}
          </div>
        </div>`;
    }).join('');

    wrap.innerHTML = `
      <div class="pa-header">
        <div class="pa-title">🔧 AI Patch Remediation — All Vulnerabilities <span style="font-size:11px;color:var(--text3);margin-left:8px">(restored)</span></div>
        <div class="pa-subtitle">${entries.length} services · ${immediate} need immediate action</div>
        <div class="pa-stats">
          ${['critical','high','medium','low'].map(s => {
            const n = entries.filter(e=>e.risk_level===s).length;
            return n ? `<span class="pa-stat pa-stat-${s}">${n} ${s}</span>` : '';
          }).join('')}
        </div>
      </div>
      <div class="pa-cards">${cardsHtml}</div>
      <div class="pa-footer">
        <button class="vd-export-btn" onclick="Chatbot._copyPatchAllCSV(this)">📋 Export CSV</button>
      </div>`;

    wrap._patchEntries = entries;
    container.appendChild(wrap);
  }

  /**
   * Reconstruct a /patch <service> <port> rich card from saved token data.
   * Called by _restoreRichWidget('RICH_PATCH_CARD', data, frag).
   */
  function _buildRichPatchCardEl(data, container) {
    if (!data) return;
    _renderRichPatchCard(data.serviceOrIp || data.service || '', data.port || '', data);
    // Note: _renderRichPatchCard appends to #chat directly; for restore we
    // need it in the frag. Move the last child of chat into container.
    const chat = document.getElementById('chat');
    if (chat && container !== chat && chat.lastChild && chat.lastChild.classList?.contains('rich-patch-card')) {
      container.appendChild(chat.lastChild);
    }
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
                 onclick="Chatbot._compareDrawerSession('${sid}')">
              🤖 Compare with Current
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
    (() => { try { return JSON.parse(localStorage.getItem('scanwise_deleted_ids_v1') || '[]'); } catch(_) { return []; } })()
  );
  function _persistDeletedIds() {
    try { localStorage.setItem('scanwise_deleted_ids_v1', JSON.stringify([..._deletedSessionIds].slice(-200))); } catch(_) {}
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
          anchor.href = objUrl; anchor.download = `scanwise_report_${cur}.pdf`;
          document.body.appendChild(anchor); anchor.click(); document.body.removeChild(anchor);
          setTimeout(() => URL.revokeObjectURL(objUrl), 10000);
          document.getElementById('report-toast-title').textContent = '📄 PDF Report Ready';
          document.getElementById('report-toast-link').href = objUrl;
          document.getElementById('report-toast-link').download = `scanwise_report_${cur}.pdf`;
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
          anchor.href = objUrl; anchor.download = `scanwise_report_${cur}.html`;
          document.body.appendChild(anchor); anchor.click(); document.body.removeChild(anchor);
          setTimeout(() => URL.revokeObjectURL(objUrl), 10000);
          document.getElementById('report-toast-title').textContent = '🌐 HTML Report Ready';
          document.getElementById('report-toast-link').href = objUrl;
          document.getElementById('report-toast-link').download = `scanwise_report_${cur}.html`;
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

  /**
   * FIX2: Compare a specific drawer session (via 3-dot menu) against AI vs rule-based engines.
   * Loads the chosen session, runs /api/compare, renders result in compare tab.
   */
  async function _compareDrawerSession(sid) {
    // Close the dropdown menu
    const menu = document.getElementById('dmenu-' + sid);
    if (menu) menu.style.display = 'none';
    _drawerMenuId = null;

    Chatbot.closeDrawer && Chatbot.closeDrawer();
    addMsg('🤖 Running AI vs Rule-Based comparison for session `' + sid + '`…', 'sys');

    try {
      // Fetch AI provider label for display
      try {
        const st = await ApiService.getAIStatus();
        Dashboard._setAiLabel && Dashboard._setAiLabel(st.display_name || 'AI Analysis');
      } catch (_) {}

      const d = await ApiService.runCompare(sid);
      Dashboard.renderCompare(d);
      Router.showPage('cmp');
      addMsg('✅ Comparison loaded. Viewing **Compare** tab.', 'ai');
    } catch (e) {
      addMsg('Compare error: ' + e.message, 'ai');
    }
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
        <button class="miu-btn-back" onclick="Chatbot._showScanModeSelector()">
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
     Uses Qwen2.5-Coder → Llama → Gemini → Rule engine fallback chain.
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
        gemini:                'Gemini (Cloud)',
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
    renderAll, rTab, openDrawer, closeDrawer, filterDrawer, loadDrawer, viewSession,
    showReportModal, selectFmt, doExportReport, suggestNext,
    onChatKeyDown, onChatInput, selectAutocomplete,
    _filterVulnTable, _sortVulnTable, _filterVulnDash, _searchVulnDash,
    _filterScans, _filterScanCat,
    _sortVulnDash, _toggleVulnExpand, _copyVulnCSV,
    _togglePatchExpand, _filterPatchDash, _searchPatchDash, _copyPatchCSV,
    _promptScanIP, _submitScanIP,
    _showProjectOnboarding, _submitProjectName, _setProjectQuick,
    // Scan mode selector + multi-scan
    _showScanModeSelector, _onScanModeSelect,
    _showMultiIPUpload, _onMultiFileDrop, _onMultiFileSelect,
    _startMultiScan, _filterMultiCards, _loadMultiIPDetail,
    // Drawer 3-dot menu
    _toggleDrawerMenu, _renameDrawerSession, _submitDrawerRename,
    _cancelDrawerRename, _deleteDrawerSession, _confirmDrawerDelete,
    _compareDrawerSession,
    // Fix 8 — scroll-to-bottom
    scrollToBottom, _onChatScroll,
    // Gemini patch guidance
    _fetchAIPatch,
    // Patch All card expand/CSV — were missing from exports (root cause of card expansion bug)
    _togglePaExpand, _copyPatchAllCSV,
  };
})();
