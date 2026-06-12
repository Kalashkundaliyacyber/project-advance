# ThreatWeave v4.0 — Network Vulnerability Intelligence Platform

> M.Tech Dissertation · Scopus Publication · Professional Portfolio · Open Source

## 🤖 AI Model Stack (4 Local Models)

| Model | Size | Use Case | Install |
|-------|------|----------|---------|
| **Qwen 2.5 7B Instruct** | ~4.7GB | Primary chatbot + reasoning | `ollama pull qwen2.5:7b` |
| **Llama 3.2 3B** | ~2.0GB | Fast local chatbot | `ollama pull llama3.2:3b` |
| **Llama 3.1 8B** | ~4.7GB | General purpose analysis | `ollama pull llama3.1:8b` |
| **DeepSeek R1 8B Distill** | ~5.0GB | Deep CVE / security analysis | `ollama pull deepseek-r1:8b` |
| **Rule Engine** | — | Offline emergency fallback | Built-in |

**No cloud API keys required.** Everything runs locally via Ollama.

---

## 🚀 Quick Start

```bash
# 1. Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 2. Pull models (minimum: qwen + llama3.2)
ollama pull qwen2.5:7b
ollama pull llama3.2:3b
ollama pull llama3.1:8b
ollama pull deepseek-r1:8b

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run
python run.py
# Or: ./run.sh

# Access at: http://localhost:3332
```

---

## 💬 Slash Commands (Phase 19)

| Command | Description |
|---------|-------------|
| `/scan <ip>` | Start a scan |
| `/patch all` | AI remediation for all vulnerabilities |
| `/patch <service> <port>` | Single-port patch guide |
| `/vuln` | CVE dashboard |
| `/risk` | Security score + A-F grade |
| `/cve <CVE-ID>` | CVE intelligence lookup |
| `/remediate` | Full remediation dashboard |
| `/report [pdf\|html]` | Export report |
| `/export [pdf\|html\|json]` | Export in format |
| `/projects` | List all scan projects |
| `/model` | AI model stack status |
| `/settings` | Configuration |
| `/history` | Browse history (sidebar) |
| `/clear` | Clear session |
| `/help` | Full command list |

---

## 🔬 Phase Implementation Status

| Phase | Description | Status |
|-------|-------------|--------|
| 0 | Repository Analysis | ✅ |
| 1 | Project Analysis | ✅ |
| 2 | Recommendation Engine | ✅ |
| 3 | Model Stack: Qwen/Llama/DeepSeek R1 | ✅ |
| 4 | Remove Dead Code / OpenRouter | ✅ |
| 5 | Patch KB + CVE Cache + AI Response Cache | ✅ |
| 6 | Architecture Refactoring | ✅ |
| 7 | Regression Tests | ✅ |
| 8 | Asset Criticality + Explainable Risk + Timeline + Security Score + Threat Intel | ✅ |
| 9 | New Feature Validation | ✅ |
| 10 | Recommendation Round 2 | ✅ |
| 11 | Bug Fixing (imports, provider refs, file splits) | ✅ |
| 12 | Chatbot Validation (all flows verified) | ✅ |
| 13 | History & Session Management + Project Workspace | ✅ |
| 14 | Multi-Scan Support (batch, sequential, subnet) | ✅ |
| 15 | Scan Coverage: +inventory, +comprehensive, +risk_assessment | ✅ |
| 16 | Report Selection Workflow (preview endpoint) | ✅ |
| 17 | Professional Reporting (HTML with all Phase 8 features) | ✅ |
| 18 | Patches in Reports (commands + vendor URLs + confidence) | ✅ |
| 19 | Full Slash Command System (15 commands) | ✅ |
| 20 | Final Deep Audit | ✅ |
| 21 | Research Mode Documentation | ✅ |
| 22 | API Optimization (80%+ AI call reduction via cache) | ✅ |
| 23 | Intelligent Remediation (6-step confidence workflow) | ✅ |
| 24 | Final Delivery | ✅ |

---

## 🏗️ Architecture

```
ThreatWeave/
├── app/
│   ├── ai/
│   │   ├── providers/
│   │   │   ├── qwen_provider.py        # Qwen 2.5 7B — Primary
│   │   │   ├── llama_provider.py       # Llama 3.2 3B + 3.1 8B — Fast/General
│   │   │   ├── deepseek_provider.py    # DeepSeek R1 8B — Security
│   │   │   ├── openrouter_provider.py  # No-op shim (removed)
│   │   │   └── gemini_provider.py      # No-op shim (removed)
│   │   ├── routing/
│   │   │   └── ai_router.py            # Smart task-aware routing
│   │   ├── cache/
│   │   │   └── ai_response_cache.py    # 24h TTL response cache
│   │   └── remediation/
│   │       ├── patch_generator.py      # KB-first patch generation
│   │       ├── patch_knowledge_base.py # Confidence-scored patch KB
│   │       └── intelligent_remediation.py  # 6-step remediation workflow
│   ├── analysis/
│   │   ├── asset_criticality.py        # Per-service/port criticality scoring
│   │   ├── explainable_risk.py         # CVSS×0.40 + Criticality×0.25 + ...
│   │   ├── security_score.py           # A-F grade security posture
│   │   ├── threat_intel.py             # KEV + EPSS + threat actors
│   │   └── vuln_timeline.py            # CVE chronological timeline
│   ├── api/
│   │   ├── routes.py                   # Main API routes
│   │   └── analysis_routes.py          # Phase 8 analysis routes
│   ├── report/
│   │   ├── multi_format.py             # PDF/HTML report generation
│   │   └── professional_report.py      # Phase 17/18 professional report
│   └── scanner/
│       └── orchestrator.py             # 12 scan types incl. inventory
├── data/
│   ├── ai_cache/responses.json         # AI response cache
│   └── patch_kb/patches.json           # Patch knowledge base
├── .env                                # 4-model configuration
├── config/settings.yaml                # Full system settings
├── MODELS.md                           # Model setup guide
└── RESEARCH.md                         # Phase 21 research documentation
```

---

## 📊 Intelligence Features

### Explainable Risk Score
```
Score = (CVSS × 0.40) + (Criticality × 0.25) + (Version × 0.20) + (Exposure × 0.15)
```
Every score includes plain-English breakdown showing exactly how it was calculated.

### Patch Confidence Scoring
```
Vendor Advisory = 100  (instant, 0 AI calls)
NVD Reference   = 90   (near-instant, 0 AI calls)
AI Generated    = 70   (1 AI call, cached for future)
Rule Engine     = 30   (offline fallback)
```

### AI Call Reduction (Phase 22)
Target: **80%+ reduction** via:
- Patch KB vendor entries (~15% hit rate)
- Patch KB NVD entries (~10% hit rate)
- AI response cache 24h TTL (~55% hit rate)
- AI generation only for cache misses (~20%)

---

## 📚 Research (Phase 21)
See [RESEARCH.md](RESEARCH.md) for:
- Research contributions and novelty analysis
- Experimental methodology and evaluation metrics
- Scopus publication readiness assessment
- Draft paper structure

## 🔑 Key Files
- `MODELS.md` — Model setup and routing guide
- `RESEARCH.md` — Academic publication guide
- `config/settings.yaml` — Full configuration
- `.env` — Environment variables
