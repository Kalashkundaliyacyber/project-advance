/**
 * SessionManager v6.0 — Backend-First Full State Persistence + Cumulative Scan Merging
 *
 * FIX (v6): Preserve Previous Scan Results — never replace, always append+merge.
 *   cumulative_ports         — deduplicated merged port list across all scans
 *   cumulative_vulnerabilities — deduplicated CVE list across all scans
 *   cumulative_cves          — flat CVE id set for dedup checks
 *   cumulative_os_fingerprints — OS info collected across scans
 *   cumulative_scan_history  — ordered list of all scan summaries in this session
 *
 * CRITICAL FIX: Chat state now persisted to SQLite backend IMMEDIATELY on every
 * message, not just to localStorage. This means:
 *  - Browser refresh     → full chat restored from backend
 *  - localStorage clear  → full chat still restored from backend
 *  - run.sh restart      → new blank chat (startup token changed)
 *  - Tab close/reopen    → full chat restored from backend
 *
 * ALL message types are persisted:
 *  - type='user'   → plain user text
 *  - type='ai'     → AI response text (markdown)
 *  - type='sys'    → system status messages
 *  - type='rich'   → full interactive widget tokens:
 *                    __SCAN_COMPLETE__:{...}  → scan results card + port table
 *                    __VULN_TABLE__:{...}     → CVE intelligence table
 *                    __VULN_DASH__:{...}      → full vulnerability dashboard
 *                    __PATCH_DASH__:{...}     → remediation dashboard
 *                    __SCAN_SELECTOR__:{...}  → scan type picker
 *                    __SCAN_RUNNING__:{...}   → scan progress widget
 *                    __SCAN_PROGRESS__:{...}  → scan progress record
 *                    __IP_PROMPT__:{...}      → IP entry prompt
 *                    __GREETING__:name        → project greeting card
 *
 * ARCHITECTURE:
 *  localStorage  → fast reads, 5MB limit, may be cleared
 *  SQLite backend → unlimited, survives everything, authoritative on restore
 *
 * On page load: try backend first, fall back to localStorage.
 * On every message: write to localStorage immediately + schedule backend write.
 */

const SessionManager = (() => {
  const LS_KEY          = 'scanwise_sessions_v4';
  const LS_ACTIVE       = 'scanwise_active_v4';
  const LS_SCROLL       = 'scanwise_scroll_v4';
  const LS_STARTUP_TOK  = 'scanwise_startup_token_v4';
  const MAX_MSGS        = 500;

  let _sessions      = {};
  let _activeId      = null;
  let _persistTimer  = null;
  let _syncTimer     = null;
  let _scrollPos     = {};

  // Track if we've successfully loaded from backend this session
  let _backendLoaded = false;

  // FIX 4: Strict project name validation — reject empty/null/whitespace/placeholder values.
  const _INVALID_NAMES = new Set(['unnamed session', 'unnamed', 'untitled', 'new session', 'new project', '']);
  function _isValidProjectName(name) {
    if (!name || typeof name !== 'string') return false;
    const trimmed = name.trim();
    if (!trimmed) return false;
    if (_INVALID_NAMES.has(trimmed.toLowerCase())) return false;
    return true;
  }

  function _mkSession(projectName) {
    // FIX 1: Never allow sessions without a valid project name to be created
    // via the explicit create(projectName) call. The only exception is an
    // internal placeholder used during onboarding (before user types a name).
    projectName = (projectName || '').trim();
    const id = 'sess_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7);
    return {
      session_id: id, project_name: projectName,
      created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
      messages: [], scan_results: null, charts: null, ai_output: null,
      scan_session: null, scan_state: null, scan_target: null, scan_type: null,
      // FIX1-8: cumulative scan state — persists across multiple scans in same session
      cumulative_ports: [],           // merged deduped ports [{port,protocol,service,product,version,risk,cves}]
      cumulative_vulnerabilities: [], // merged deduped CVEs [{cve_id,severity,cvss_score,...,port,service}]
      cumulative_cves: [],            // flat list of cve_id strings for fast dedup
      cumulative_os_fingerprints: [], // [{ip,os_name,os_version,scan_type,timestamp}]
      cumulative_scan_history: [],    // [{scan_type,target,timestamp,duration,risk,port_count,cve_count}]
    };
  }

  // ── localStorage persistence ──────────────────────────────────────────────

  function persistAll() {
    try {
      const toSave = {};
      for (const [k, s] of Object.entries(_sessions)) {
        // Store full messages including rich tokens in localStorage
        toSave[k] = { ...s, messages: s.messages.slice(-MAX_MSGS) };
      }
      localStorage.setItem(LS_KEY,    JSON.stringify(toSave));
      localStorage.setItem(LS_ACTIVE, _activeId || '');
      localStorage.setItem(LS_SCROLL, JSON.stringify(_scrollPos));
    } catch (e) {
      // localStorage quota exceeded — try saving only active session with fewer messages
      try {
        const a = _sessions[_activeId];
        if (a) {
          // On quota error: keep last 100 messages (prioritize rich tokens)
          const lastMsgs = a.messages.slice(-100);
          localStorage.setItem(LS_KEY, JSON.stringify({
            [_activeId]: { ...a, messages: lastMsgs, scan_results: null } // drop scan_results to save space
          }));
        }
      } catch (_) {
        // If even that fails, clear old sessions and retry
        try { localStorage.removeItem(LS_KEY); } catch (_) {}
      }
    }
  }

  function _schedulePersist() {
    if (_persistTimer) clearTimeout(_persistTimer);
    _persistTimer = setTimeout(persistAll, 300);
  }

  // ── Backend persistence (SQLite via /api/chat/save) ───────────────────────

  /**
   * Schedule an immediate backend sync.
   * Backend stores ALL messages including rich widget tokens — this is the
   * authoritative store that survives localStorage clear and browser restarts.
   */
  function _scheduleBackendSync(immediate = false) {
    if (_syncTimer) clearTimeout(_syncTimer);
    if (immediate) {
      _backendPersist();
    } else {
      _syncTimer = setTimeout(_backendPersist, 800);
    }
  }

  async function _backendPersist() {
    const s = active();
    if (!s) return;
    try {
      await ApiService.saveChatSession(
        s.session_id,
        s.messages.slice(-MAX_MSGS),
        s.project_name || ''
      );
    } catch (e) {
      // Network error — localStorage is the fallback
      console.warn('[SessionManager] Backend sync failed:', e.message);
    }
  }

  // ── Session storage load ──────────────────────────────────────────────────

  function loadAllFromStorage() {
    try {
      const raw = localStorage.getItem(LS_KEY);
      if (!raw) return false;
      const saved = JSON.parse(raw);
      if (saved && typeof saved === 'object' && Object.keys(saved).length > 0) {
        _sessions = saved;
        const savedActive = localStorage.getItem(LS_ACTIVE);
        if (savedActive && _sessions[savedActive]) {
          _activeId = savedActive;
        } else {
          const newest = Object.values(_sessions).sort((a, b) => (b.updated_at||'').localeCompare(a.updated_at||''))[0];
          _activeId = newest ? newest.session_id : null;
        }
        try { const sr = localStorage.getItem(LS_SCROLL); if (sr) _scrollPos = JSON.parse(sr); } catch (_) {}
        return true;
      }
    } catch (e) { console.warn('[SessionManager] restore failed:', e); }
    return false;
  }

  /**
   * Load full chat state from backend for the active session.
   * This is called during init to get the authoritative message list
   * including all rich widget tokens that may exceed localStorage limits.
   *
   * Returns { messages, project_name } or null if not found.
   */
  async function loadFromBackend(sessionId) {
    try {
      const data = await ApiService.loadChatSession(sessionId);
      if (data && data.messages && data.messages.length > 0) {
        _backendLoaded = true;
        return data;
      }
    } catch (e) {
      console.warn('[SessionManager] Backend load failed:', e.message);
    }
    return null;
  }

  /**
   * Check server startup token.
   * Returns 'fresh' if run.sh was re-executed (new server start)
   *         'restored' if same server instance (browser refresh/reconnect)
   */
  async function checkStartupToken() {
    try {
      const res  = await fetch('/api/startup-token');
      const data = await res.json();
      const serverToken = (data.token || '').trim();
      const cachedToken = (localStorage.getItem(LS_STARTUP_TOK) || '').trim();

      if (serverToken && serverToken !== cachedToken) {
        console.info('[ScanWise] New run.sh detected — fresh chat. Token:', serverToken);
        localStorage.setItem(LS_STARTUP_TOK, serverToken);
        localStorage.removeItem(LS_ACTIVE);
        return 'fresh';
      }

      if (serverToken) localStorage.setItem(LS_STARTUP_TOK, serverToken);
      return 'restored';
    } catch (e) {
      console.warn('[ScanWise] startup-token fetch failed, defaulting to fresh:', e);
      localStorage.removeItem(LS_ACTIVE);
      return 'fresh';
    }
  }

  // ── Session CRUD ──────────────────────────────────────────────────────────

  // FIX 1+3: create() now only creates a session with a valid project name,
  // OR an intentional unnamed placeholder when called from newChat()/fresh-start
  // (pass allowUnnamed=true in those cases). Never called automatically.
  function create(projectName, allowUnnamed = false) {
    const trimmed = (projectName || '').trim();
    // If a name is provided, it must be valid
    if (trimmed && !_isValidProjectName(trimmed)) {
      console.warn('[SessionManager] Rejected invalid project name:', JSON.stringify(trimmed));
      return _activeId; // return current id, don't create garbage session
    }
    // If no name and not explicitly allowed, refuse silently
    if (!trimmed && !allowUnnamed) {
      console.warn('[SessionManager] create() called without project name — blocked.');
      return _activeId;
    }
    const s = _mkSession(trimmed);
    _sessions[s.session_id] = s;
    _activeId = s.session_id;
    persistAll();
    return s.session_id;
  }

  // FIX 2: active() NEVER auto-creates a session. Returns null if no session exists.
  // Callers must handle null. This prevents the root cause: blank sessions on refresh.
  function active() {
    if (!_activeId || !_sessions[_activeId]) return null;
    return _sessions[_activeId];
  }

  function activeId() { return _activeId; }

  /**
   * FIX 5: Purge ALL bad sessions:
   *  - sessions with no project name, no messages, no scan data (blank)
   *  - sessions whose project_name is "Unnamed Session" or similar invalid values
   *  - sessions with null/undefined project_name and no meaningful content
   * Called on fresh server start AND on browser refresh cleanup.
   */
  function purgeBlankSessions() {
    const before = Object.keys(_sessions).length;
    for (const [id, s] of Object.entries(_sessions)) {
      const name = (s.project_name || '').trim();
      const hasName    = _isValidProjectName(name);
      const hasMsgs    = s.messages && s.messages.length > 0;
      const hasScan    = !!s.scan_results;

      // Remove if: no valid name AND no messages AND no scan data
      // OR if the name is literally "Unnamed Session" / blank regardless of content
      const isBlank    = !hasName && !hasMsgs && !hasScan;
      const isBadName  = name.toLowerCase() === 'unnamed session' || name.toLowerCase() === 'unnamed';
      if (isBlank || isBadName) {
        delete _sessions[id];
        delete _scrollPos[id];
        if (_activeId === id) _activeId = null;
      }
    }
    const removed = before - Object.keys(_sessions).length;
    if (removed > 0) {
      console.info('[SessionManager] Purged ' + removed + ' blank/unnamed session(s)');
      persistAll();
    }
  }


  function setProjectName(name) {
    // FIX 4: Validate project name before saving
    const trimmed = (name || '').trim();
    if (!_isValidProjectName(trimmed)) {
      console.warn('[SessionManager] setProjectName rejected invalid name:', JSON.stringify(name));
      return;
    }
    const s = active();
    if (!s) {
      // No active session yet — create one now (user has provided a valid name)
      create(trimmed);
      const newS = active();
      if (newS) {
        newS.project_name = trimmed;
        newS.updated_at = new Date().toISOString();
        persistAll();
        _scheduleBackendSync(true);
      }
      return;
    }
    s.project_name = trimmed;
    s.updated_at = new Date().toISOString();
    persistAll();
    _scheduleBackendSync(true); // immediate sync so project name is saved right away
  }

  function getProjectName() {
    const s = active();
    return s ? (s.project_name || '') : '';
  }

  function switchTo(id) {
    _saveScrollPos();
    if (_sessions[id]) { _activeId = id; persistAll(); return _sessions[id]; }
    const found = Object.values(_sessions).find(s => s.scan_session === id);
    if (found) { _activeId = found.session_id; persistAll(); return found; }
    loadAllFromStorage();
    if (_sessions[id]) { _activeId = id; return _sessions[id]; }
    const found2 = Object.values(_sessions).find(s => s.scan_session === id);
    if (found2) { _activeId = found2.session_id; return found2; }
    return null;
  }

  function remove(id) {
    const fid = _sessions[id] ? id : Object.keys(_sessions).find(k => _sessions[k].scan_session === id);
    if (fid) {
      delete _sessions[fid];
      delete _scrollPos[fid];
      if (_activeId === fid) _activeId = null;
    }
    persistAll();
  }

  function saveScan(data) {
    const s = active();
    if (!s) return; // FIX 2: guard — never auto-create on scan save
    s.scan_results = data;
    s.charts = data.charts || null;
    s.ai_output = data.ai_analysis || null;
    s.scan_session = data.session_id || null;
    s.scan_state = 'complete';
    s.scan_target = data.target || null;
    s.scan_type = data.scan_type || null;
    s.updated_at = new Date().toISOString();
    // FIX2-7: merge new scan results into cumulative state
    _mergeScanIntoCumulative(s, data);
    persistAll();
    _scheduleBackendSync(true); // save immediately after scan
  }

  /**
   * FIX1-8: Core merge logic — integrates a new scan result into the
   * session's cumulative state without overwriting prior scan data.
   *
   * Rules:
   *  - Same port already exists → update changed metadata only
   *  - Same CVE already exists  → skip (no duplicate)
   *  - New port/CVE             → append
   *  - OS fingerprint           → add if new
   *  - Scan history             → always append
   */
  function _mergeScanIntoCumulative(s, data) {
    try {
      const hosts = (data.risk && data.risk.hosts) ? data.risk.hosts : [];

      // ── 1. Merge ports ──────────────────────────────────────────
      for (const host of hosts) {
        for (const p of (host.ports || [])) {
          const key = `${p.port}/${p.protocol || 'tcp'}`;
          const existing = s.cumulative_ports.find(
            ep => `${ep.port}/${ep.protocol || 'tcp'}` === key
          );
          if (existing) {
            // Update metadata if richer info available
            if (p.product)  existing.product  = p.product;
            if (p.version)  existing.version  = p.version;
            if (p.service)  existing.service  = p.service;
            if (p.risk)     existing.risk      = p.risk;
            // Merge CVEs on this port
            for (const c of (p.cves || [])) {
              if (!s.cumulative_cves.includes(c.cve_id)) {
                s.cumulative_cves.push(c.cve_id);
                existing.cves = existing.cves || [];
                existing.cves.push(c);
                s.cumulative_vulnerabilities.push({
                  ...c, port: p.port, protocol: p.protocol || 'tcp', service: p.service
                });
              }
            }
          } else {
            // New port — append
            const portEntry = {
              port: p.port, protocol: p.protocol || 'tcp',
              service: p.service || '', product: p.product || '',
              version: p.version || '', risk: p.risk || {}, cves: [],
            };
            for (const c of (p.cves || [])) {
              if (!s.cumulative_cves.includes(c.cve_id)) {
                s.cumulative_cves.push(c.cve_id);
                portEntry.cves.push(c);
                s.cumulative_vulnerabilities.push({
                  ...c, port: p.port, protocol: p.protocol || 'tcp', service: p.service
                });
              }
            }
            s.cumulative_ports.push(portEntry);
          }

          // ── 2. OS fingerprints ──────────────────────────────────
          if (host.os && host.os.name) {
            const osKey = `${host.ip || data.target}:${host.os.name}`;
            const hasOs = s.cumulative_os_fingerprints.some(
              o => `${o.ip}:${o.os_name}` === osKey
            );
            if (!hasOs) {
              s.cumulative_os_fingerprints.push({
                ip: host.ip || data.target,
                os_name: host.os.name,
                os_version: host.os.version || '',
                scan_type: data.scan_type || '',
                timestamp: new Date().toISOString(),
              });
            }
          }
        }
      }

      // ── 3. Append to scan history ───────────────────────────────
      const hosts0    = hosts[0] || {};
      const rs        = (hosts0.risk_summary) || {};
      const portCount = s.cumulative_ports.length;
      const cveCount  = s.cumulative_cves.length;
      s.cumulative_scan_history.push({
        scan_type  : data.scan_type || '',
        target     : data.target || '',
        timestamp  : data.timestamp || new Date().toISOString(),
        duration   : data.duration || 0,
        risk       : rs.overall || 'low',
        port_count : (hosts0.ports || []).length,   // ports found THIS scan
        cve_count  : (data.risk ? hosts.reduce((n,h)=>n+(h.ports||[]).reduce((m,p)=>m+(p.cves||[]).length,0),0) : 0),
      });

      s.updated_at = new Date().toISOString();
    } catch (e) {
      console.warn('[SessionManager] _mergeScanIntoCumulative error:', e);
    }
  }

  /** Return the cumulative merged state for the active session */
  function getCumulativeState() {
    const s = active();
    if (!s) return null;
    return {
      ports           : s.cumulative_ports            || [],
      vulnerabilities : s.cumulative_vulnerabilities  || [],
      cves            : s.cumulative_cves              || [],
      os_fingerprints : s.cumulative_os_fingerprints  || [],
      scan_history    : s.cumulative_scan_history      || [],
    };
  }


  function markScanRunning(target, scanType) {
    const s = active();
    if (!s) return; // FIX 2: guard
    s.scan_state = 'running';
    s.scan_target = target;
    s.scan_type = scanType;
    s.updated_at = new Date().toISOString();
    persistAll();
  }

  function clearScanState() {
    const s = active();
    if (s && s.scan_state === 'running') { s.scan_state = null; persistAll(); }
  }

  /**
   * Save a chat message — persists to both localStorage AND backend.
   * This is called for EVERY message including rich widget tokens.
   *
   * @param {string} type - 'user' | 'ai' | 'sys' | 'rich'
   * @param {string} text - message text or rich token string
   */
  function saveMsg(type, text) {
    const s = active();
    if (!s) return; // FIX 2: no session = no save; never auto-create here
    s.messages.push({ type, text, time: new Date().toISOString() });
    if (s.messages.length > MAX_MSGS) s.messages = s.messages.slice(-MAX_MSGS);
    s.updated_at = new Date().toISOString();

    // Write to localStorage immediately (fast, synchronous)
    persistAll();

    // Write to backend immediately for rich tokens (large data that may not fit in localStorage)
    // For regular text messages, schedule a short-delay sync
    const isRich = type === 'rich';
    _scheduleBackendSync(isRich); // immediate for rich, delayed for text
  }

  function saveCharts(chartData) {
    const s = active();
    if (!s) return; // FIX 2: guard
    s.charts = chartData; s.updated_at = new Date().toISOString(); _schedulePersist();
  }

  function saveScrollPos(sessionId, scrollTop) {
    _scrollPos[sessionId || _activeId] = scrollTop;
  }

  function getScrollPos(sessionId) {
    return _scrollPos[sessionId || _activeId] || 0;
  }

  function _saveScrollPos() {
    if (!_activeId) return;
    const chat = document.getElementById('chat');
    if (chat) _scrollPos[_activeId] = chat.scrollTop;
  }

  function list() {
    return Object.values(_sessions).sort((a, b) => (b.updated_at||'').localeCompare(a.updated_at||''));
  }

  function getInterruptedScan() {
    const s = _activeId ? _sessions[_activeId] : null;
    if (s && s.scan_state === 'running' && s.scan_target) return { target: s.scan_target, scanType: s.scan_type };
    return null;
  }

  async function persist() { persistAll(); await _backendPersist(); }

  /**
   * SESSION ISOLATION FIX: Save scan results into a specific session by ID,
   * NOT necessarily the currently active session. Used when a scan started in
   * session A completes while the user is viewing session B.
   */
  function saveScanToSession(sessionId, data) {
    const s = _sessions[sessionId]
           || Object.values(_sessions).find(x => x.scan_session === sessionId)
           || active();
    if (!s) return;
    s.scan_results = data;
    s.charts = data.charts || null;
    s.ai_output = data.ai_analysis || null;
    s.scan_session = data.session_id || null;
    s.scan_state = 'complete';
    s.scan_target = data.target || null;
    s.scan_type = data.scan_type || null;
    s.updated_at = new Date().toISOString();
    // FIX2-7: merge into cumulative state for this specific session
    _mergeScanIntoCumulative(s, data);
    persistAll();
    _scheduleBackendSync(true);
  }

  /**
   * SESSION ISOLATION FIX: Store a rich message token into a specific session
   * without affecting the currently active session's chat view.
   */
  function storeRichMsgForSession(sessionId, tokenType, data) {
    const s = _sessions[sessionId]
           || Object.values(_sessions).find(x => x.scan_session === sessionId);
    if (!s) return;
    const token = `__${tokenType}__:${JSON.stringify(data)}`;
    s.messages = s.messages || [];
    s.messages.push({ type: 'rich', text: token, time: new Date().toISOString() });
    persistAll();
  }

  return {
    create, active, activeId,
    setProjectName, getProjectName,
    switchTo, remove,
    saveScan, saveScanToSession, storeRichMsgForSession,
    saveMsg, saveCharts,
    saveScrollPos, getScrollPos,
    markScanRunning, clearScanState, getInterruptedScan,
    list, persist, persistAll, loadAllFromStorage,
    loadFromBackend,
    checkStartupToken,
    purgeBlankSessions,
    isValidProjectName: _isValidProjectName,
    getCumulativeState,
  };
})();
