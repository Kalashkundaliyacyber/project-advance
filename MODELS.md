# ThreatWeave — Model Stack

## Active Models (Phase 3 — Local Only)

| Model | Size | Use Case | Priority | Ollama Command |
|-------|------|----------|----------|----------------|
| **Qwen 2.5 7B Instruct** | ~4.7GB | Chatbot + reasoning | ⭐ Primary | `ollama pull qwen2.5:7b` |
| **Llama 3.2 3B** | ~2.0GB | Fast local chatbot | Fast | `ollama pull llama3.2:3b` |
| **Llama 3.1 8B** | ~4.7GB | General purpose | General | `ollama pull llama3.1:8b` |
| **DeepSeek R1 8B Distill** | ~5.0GB | Security analysis | Security | `ollama pull deepseek-r1:8b` |
| **Rule Engine** | — | Offline fallback | Emergency | Built-in (no install needed) |

## Quick Setup

```bash
# Install all models (recommended)
ollama pull qwen2.5:7b
ollama pull llama3.2:3b
ollama pull llama3.1:8b
ollama pull deepseek-r1:8b

# Minimum install (chatbot only)
ollama pull qwen2.5:7b
ollama pull llama3.2:3b

# Security-focused install
ollama pull deepseek-r1:8b
ollama pull qwen2.5:7b
```

## Routing Logic

```
SECURITY TASKS (CVE, exploits, risk scoring):
  DeepSeek R1 8B → Qwen 2.5 7B → Llama 3.1 8B → Rule Engine

GENERAL ANALYSIS:
  Qwen 2.5 7B → Llama 3.1 8B → DeepSeek R1 8B → Rule Engine

NORMAL CHAT:
  Llama 3.2 3B (fast) → Qwen 2.5 7B → Rule Engine

ADVANCED CHAT (remediation, hardening):
  Qwen 2.5 7B → DeepSeek R1 8B → Llama 3.2 3B
```

## Why These Models?

- **Qwen 2.5 7B**: Excellent instruction following, code understanding, security Q&A
- **Llama 3.2 3B**: Fastest response for simple chat, lowest memory usage
- **Llama 3.1 8B**: Strong general-purpose reasoning and analysis
- **DeepSeek R1 8B**: Chain-of-thought reasoning for complex security analysis

## AI Cache

All AI responses are cached (24h TTL) to reduce repeated calls.
Cache location: `data/ai_cache/responses.json`

## Patch Knowledge Base

Pre-seeded with common CVE patches (OpenSSH, Apache, Nginx, Samba).
Location: `data/patch_kb/patches.json`
Confidence: Vendor=100, NVD=90, AI=70
