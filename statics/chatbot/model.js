/**
 * chatbot/model.js
 * AI model indicator bar — status dot, provider name, latency.
 */

  /* ═══════════════════════════════════════════════════════
     MODEL INDICATOR
  ═══════════════════════════════════════════════════════ */

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
      const providerClass = { gemini: 'model-dot gemini', ollama: 'model-dot', 'rule-based': 'model-dot fallback' };
      dot.className = providerClass[_activeProvider] || 'model-dot';
    } else {
      dot.className = 'model-dot';
    }

    // Update from response provider
    if (opts.provider) {
      _activeProvider = opts.provider;
      const pNames  = { gemini: 'Gemini Flash', ollama: 'Llama Fallback', 'rule-based': 'Rule Engine' };
      const pLabels = { gemini: 'Google AI · Primary', ollama: 'Llama Fallback Active', 'rule-based': 'No AI' };
      _modelName     = pNames[opts.provider]  || opts.provider;
      _modelProvider = pLabels[opts.provider] || opts.provider;
      const cls = { gemini: 'model-dot gemini', ollama: 'model-dot', 'rule-based': 'model-dot fallback' };
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

