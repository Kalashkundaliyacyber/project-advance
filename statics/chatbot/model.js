/**
 * chatbot/model.js — AI model indicator bar
 * Updated for 4-model local stack (Phase 3)
 */

  /* ═══════════════════════════════════════════════════════
     MODEL INDICATOR
  ═══════════════════════════════════════════════════════ */

  // Display names for each provider
  const _PROVIDER_NAMES = {
    qwen:       'Qwen 2.5 7B Instruct',
    llama:      'Llama 3.2 3B / 3.1 8B',
    deepseek:   'DeepSeek R1 8B Distill',
    'rule-based': 'Rule Engine',
    unknown:    'Detecting…',
    // Legacy aliases
    gemini:     'Qwen 2.5 7B (Local)',
    ollama:     'Ollama Local',
    nemotron:   'Qwen 2.5 7B (Local)',
    gpt_oss:    'Llama 3.1 8B (Local)',
    deepseek_flash: 'DeepSeek R1 8B (Local)',
    llama33:    'Llama 3.2 3B (Local)',
    gemma4:     'Llama 3.1 8B (Local)',
  };

  const _PROVIDER_META = {
    qwen:       'Ollama · Primary Chatbot',
    llama:      'Ollama · Fast / General',
    deepseek:   'Ollama · Security Analysis',
    'rule-based': 'No AI · Offline',
    unknown:    'Starting…',
    // Legacy
    gemini:     'Ollama · Local',
    ollama:     'Ollama · Local',
    nemotron:   'Ollama · Local',
    gpt_oss:    'Ollama · Local',
    deepseek_flash: 'Ollama · Local',
    llama33:    'Ollama · Local',
    gemma4:     'Ollama · Local',
  };

  const _DOT_CLASS = {
    qwen:       'model-dot',
    llama:      'model-dot',
    deepseek:   'model-dot deepseek',
    'rule-based': 'model-dot fallback',
    unknown:    'model-dot checking',
  };

  function _updateModelIndicator(opts = {}) {
    const dot  = document.getElementById('model-dot');
    const name = document.getElementById('model-name');
    const meta = document.getElementById('model-meta');
    if (!dot || !name || !meta) return;

    if (opts.checking) { dot.className = 'model-dot checking'; meta.textContent = 'Checking…'; return; }
    if (opts.error)    { dot.className = 'model-dot error';    meta.textContent = 'Unavailable'; return; }

    if (opts.aiStatus) {
      const st = opts.aiStatus;
      _activeProvider = st.active_provider || 'unknown';
      _modelName      = st.display_name    || _PROVIDER_NAMES[_activeProvider] || _activeProvider;
      _modelProvider  = st.display_provider || _PROVIDER_META[_activeProvider] || '';
      dot.className   = _DOT_CLASS[_activeProvider] || 'model-dot';
    } else {
      dot.className = 'model-dot';
    }

    if (opts.provider) {
      _activeProvider = opts.provider;
      _modelName      = _PROVIDER_NAMES[opts.provider]  || opts.provider;
      _modelProvider  = _PROVIDER_META[opts.provider]   || opts.provider;
      dot.className   = _DOT_CLASS[opts.provider]       || 'model-dot';
    }

    name.textContent = _modelName;
    const lat = opts.latency || (opts.aiStatus && opts.aiStatus.last_latency_ms);
    meta.textContent = _modelProvider + (lat ? ` · ${lat}ms` : '');
    _modelOk = true;
  }

  async function _pollAIStatus() {
    _updateModelIndicator({ checking: true });
    try {
      const st = await ApiService.getAIStatus();
      _updateModelIndicator({ aiStatus: st });
    } catch (e) {
      _updateModelIndicator({ error: true });
    }
  }
