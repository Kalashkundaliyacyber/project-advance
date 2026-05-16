/**
 * apiService.js v3.0
 * ALL backend/API communication lives here.
 *
 * v3.0 changes:
 *   - Added AbortController support to _request() via opts.signal
 *   - getPatchGuidance() uses RequestDeduplicator to prevent duplicate in-flight calls
 *   - All dangerous repeated-call patterns migrated to use deduplicator
 */

const ApiService = (() => {
  const BASE = window.location.origin + '/api';
  let _token = '';

  function setToken(t) { _token = t; }

  function _headers(extra = {}) {
    const h = { 'Content-Type': 'application/json', ...extra };
    if (_token) h['X-API-Token'] = _token;
    return h;
  }

  async function _request(url, opts = {}) {
    const res = await fetch(url, { ...opts, headers: _headers(opts.headers) });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }
    return res.json();
  }

  /* ── Scan ─────────────────────────────────────────── */
  /** Start a new scan. Includes project_name from the active session context. */
  async function startScan(target, scanType, projectName = '') {
    return _request(`${BASE}/scan`, {
      method: 'POST',
      body: JSON.stringify({ target, scan_type: scanType, project_name: projectName }),
    });
  }
  async function getScanProgress() { return _request(`${BASE}/scan/progress`); }
  async function stopScan() { return _request(`${BASE}/scan/stop`, { method: 'POST' }).catch(() => null); }

  /* ── Chat ─────────────────────────────────────────── */
  async function sendChatMessage(message, target = '', sessionId = '', projectName = '') {
    return _request(`${BASE}/chat`, {
      method: 'POST',
      body: JSON.stringify({ message, target, session_id: sessionId, project_name: projectName }),
    });
  }

  /**
   * Save chat session to backend.
   * Payload: { session_id, messages, project_name }
   * Always called — even with empty messages — so project name is persisted
   * to SQLite the moment the user names their project.
   */
  async function saveChatSession(sessionId, messages, projectName = '') {
    return _request(`${BASE}/chat/save`, {
      method: 'POST',
      body: JSON.stringify({ session_id: sessionId, messages, project_name: projectName }),
    });
  }

  /** Load saved chat messages for a session from the backend SQLite store. */
  async function loadChatSession(sessionId) {
    return _request(`${BASE}/chat/load/${encodeURIComponent(sessionId)}`);
  }

  /* ── Sessions ─────────────────────────────────────── */
  async function getScanResults(sessionId) { return _request(`${BASE}/session/${sessionId}`); }

  /**
   * NOTE: /api/session/{id}/analyze is not implemented on the backend.
   * This stub exists for forward-compatibility. It will return 404 until
   * the route is added to routes.py.
   */
  async function analyzeScan(sessionId) {
    return _request(`${BASE}/session/${sessionId}/analyze`, { method: 'POST' });
  }

  /** Rename session label (uses project name as the label). */
  async function renameSession(sessionId, name) {
    return _request(`${BASE}/session/${sessionId}/rename`, { method: 'PATCH', body: JSON.stringify({ name }) });
  }

  /** Permanently delete a session. */
  async function deleteSession(sessionId) {
    return _request(`${BASE}/session/${sessionId}`, { method: 'DELETE' });
  }

  /* ── AI Status ────────────────────────────────────── */
  /** Returns { active_provider, gemini_available, ollama_available, display_name, display_provider } */
  async function getAIStatus() {
    return _request(`${BASE}/ai/status`);
  }

  /* ── History ──────────────────────────────────────── */
  async function getHistory({ target = '', severity = '' } = {}) {
    const q = new URLSearchParams();
    if (target)   q.set('target',   target);
    if (severity) q.set('severity', severity);
    const qs = q.toString();
    return _request(`${BASE}/history${qs ? '?' + qs : ''}`);
  }
  async function getHistoryTrends() { return _request(`${BASE}/history/trends`); }

  /* ── Compare ──────────────────────────────────────── */
  async function runCompare(sessionId) {
    return _request(`${BASE}/compare`, { method: 'POST', body: JSON.stringify({ session_id: sessionId }) });
  }

  /* ── Reports ──────────────────────────────────────── */
  /**
   * Generate a report. Calls /api/report/generate (handled by multi_format.py).
   * format: 'html' | 'pdf'
   */
  async function generateReport(sessionId, format = 'html') {
    return _request(`${BASE}/report/generate`, {
      method: 'POST',
      body: JSON.stringify({ session_id: sessionId, format }),
    });
  }

  /* ── Health ───────────────────────────────────────── */
  async function healthCheck() { return _request(`${window.location.origin}/health`); }

  /**
   * REMOVED: /api/shutdown was intentionally removed from the server for security.
   * This stub prevents ReferenceErrors in any caller — it simply resolves silently.
   */
  async function shutdown() {
    console.warn('ApiService.shutdown() is disabled — use Ctrl+C or kill the server process.');
    return Promise.resolve({ ok: false, reason: 'shutdown_disabled' });
  }

  /* ── Network Discovery (FIX9) ────────────────────── */
  async function discoverHosts(subnet, timeout = 30) {
    return _request(`${BASE}/discover`, {
      method: 'POST',
      body: JSON.stringify({ subnet, timeout }),
    });
  }

  /* ── Batch scan (FIX7) ────────────────────────────── */
  async function runBatchScan(targets, scanType, projectName = '') {
    return _request(`${BASE}/scan/batch`, {
      method: 'POST',
      body: JSON.stringify({ targets, scan_type: scanType, project_name: projectName }),
    });
  }

  /* ── Multi-IP scan (modular system) ──────────────── */
  async function multiScanValidate(targetsTxt, scanType, projectName = '') {
    return _request(`${BASE}/scan/multi/validate`, {
      method: 'POST',
      body: JSON.stringify({ targets_txt: targetsTxt, scan_type: scanType, project_name: projectName }),
    });
  }
  async function multiScanStart(targetsTxt, scanType, projectName = '') {
    return _request(`${BASE}/scan/multi/start`, {
      method: 'POST',
      body: JSON.stringify({ targets_txt: targetsTxt, scan_type: scanType, project_name: projectName }),
    });
  }
  async function multiScanStatus(jobId) {
    return _request(`${BASE}/scan/multi/status/${encodeURIComponent(jobId)}`);
  }

  /* ── Schedules (FIX8) ─────────────────────────────── */
  async function getSchedules()                    { return _request(`${BASE}/schedule`); }
  async function createSchedule(target, scanType, interval, projectName = '') {
    return _request(`${BASE}/schedule`, {
      method: 'POST',
      body: JSON.stringify({ target, scan_type: scanType, interval, project_name: projectName }),
    });
  }
  async function deleteSchedule(id)               { return _request(`${BASE}/schedule/${id}`, { method: 'DELETE' }); }

  /* ── Presets (FIX10) ──────────────────────────────── */
  async function getPresets()                      { return _request(`${BASE}/presets`); }
  async function savePreset(name, target, scanType, projectName = '') {
    return _request(`${BASE}/presets`, {
      method: 'POST',
      body: JSON.stringify({ name, target, scan_type: scanType, project_name: projectName }),
    });
  }
  async function deletePreset(id)                 { return _request(`${BASE}/presets/${id}`, { method: 'DELETE' }); }

  /* ── False positive / review (FIX12) ─────────────── */
  async function getReviews()                      { return _request(`${BASE}/findings/review`); }
  async function setReview(cveId, status, note = '', reviewedBy = '') {
    return _request(`${BASE}/findings/review`, {
      method: 'POST',
      body: JSON.stringify({ cve_id: cveId, status, note, reviewed_by: reviewedBy }),
    });
  }
  async function getReview(cveId)                  { return _request(`${BASE}/findings/review/${encodeURIComponent(cveId)}`); }

  /* ── CVSS vector breakdown (FIX13) ───────────────── */
  async function cvssBreakdown(vector, cveId = '') {
    return _request(`${BASE}/cvss/breakdown`, {
      method: 'POST',
      body: JSON.stringify({ vector, cve_id: cveId }),
    });
  }

  /* ── Patch Guidance v2 — deduplicated ────────────── */
  /**
   * Fetch AI-generated patch guidance for a specific service/port.
   * Uses RequestDeduplicator: concurrent calls for same key share ONE request.
   * Cached for 60 seconds to prevent repeated AI calls.
   */
  async function getPatchGuidance(service, port, version = 'unknown', cveId = 'unknown', severity = 'medium', sessionId = '') {
    const key = `patch:${service}:${port}:${cveId}`;
    // Use RequestDeduplicator if available (loaded from utils/requestDeduplicator.js)
    if (typeof RequestDeduplicator !== 'undefined') {
      return RequestDeduplicator.fetch(key, () =>
        _request(`${BASE}/patch/guidance`, {
          method: 'POST',
          body: JSON.stringify({ service, port, version, cve_id: cveId, severity, session_id: sessionId }),
        })
      );
    }
    // Fallback: direct call
    return _request(`${BASE}/patch/guidance`, {
      method: 'POST',
      body: JSON.stringify({ service, port, version, cve_id: cveId, severity, session_id: sessionId }),
    });
  }

  /* ── Ablation testing (FIX15) ────────────────────── */
  async function runAblation(sessionId, label, promptText, compareWith = null) {
    return _request(`${BASE}/ablation/run`, {
      method: 'POST',
      body: JSON.stringify({ session_id: sessionId, prompt_label: label, prompt_text: promptText, compare_with: compareWith }),
    });
  }
  async function getAblationRuns(sessionId)        { return _request(`${BASE}/ablation/runs/${encodeURIComponent(sessionId)}`); }

  return {
    setToken,
    startScan, getScanProgress, stopScan,
    getScanResults, analyzeScan,
    sendChatMessage, saveChatSession, loadChatSession,
    renameSession, deleteSession,
    getAIStatus,
    getHistory, getHistoryTrends,
    runCompare,
    generateReport,
    healthCheck, shutdown,
    // FIX7:
    runBatchScan,
    // Multi-IP:
    multiScanValidate, multiScanStart, multiScanStatus,
    // FIX8:
    getSchedules, createSchedule, deleteSchedule,
    // FIX9:
    discoverHosts,
    // FIX10:
    getPresets, savePreset, deletePreset,
    // FIX12:
    getReviews, setReview, getReview,
    // FIX13:
    cvssBreakdown,
    // FIX15:
    runAblation, getAblationRuns,
    // Patch Guidance:
    getPatchGuidance,
  };
})();
