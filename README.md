# ThreatWeave — Network Vulnerability Intelligence Platform

> M.Tech Dissertation · Scopus Publication · Professional Portfolio · Open Source

ThreatWeave is a Kali Linux-based network vulnerability assessment platform. It runs a single, fully automated nmap-based scan against a target, confirms findings through a tiered local/AI cascade, maps them to CVEs, scores risk, generates remediation guidance, and produces professional HTML/PDF reports — all through a chat interface, with zero cloud API keys required.

---

## 🚀 Quick Start

```bash
# 1. First-time setup (creates venv, installs deps, pulls all 4 Ollama models)
bash setup_env.sh

# 2. Start the server (every time after)
bash run.sh

# Access at: http://localhost:3332
```

`setup_env.sh` accepts overrides for any model, e.g. `QWEN_MODEL=qwen2.5:14b bash setup_env.sh`. See [MODELS.md](MODELS.md) for the full model/routing guide and [INSTALL.md](INSTALL.md) for Kali-specific troubleshooting.

---

## 🔎 The Scan Pipeline — One Command, No Menu

There is exactly one scan in this product. There's no scan-type picker, no quick/deep choice — you type a target (IP, hostname, or CIDR) directly into the chat, and the platform takes it from there automatically:

```
nmap -Pn -p- --script="vuln" -sV -sC -O --min-rate 1000
     --max-rtt-timeout 100ms --max-retries 5 -oX - <target>
```

The pipeline then runs, in order:

1. **Active service probing** — additive HTTP/HTTPS, SSH/FTP banner reads, and SMB negotiation, layered on top of nmap's own detection without ever overwriting it.
2. **Script Output Pattern Library (SOPLib)** — purpose-built pattern matching for 8 high-value NSE scripts, so vulnerability confirmation doesn't rely on generic keyword matching alone.
3. **CVE mapping & confidence tagging** — local version-range matching plus NVD enrichment, with an explicit `exact` vs `range` confidence field on every match.
4. **Misconfiguration detection** — 5 checks (e.g. open Telnet, default SNMP community strings) that surface as findings in their own right, not just CVE side effects.
5. **Risk scoring, recommendation, and AI analysis** — run in parallel for speed.
6. **Optional authenticated scanning** — SSH (via paramiko) or SMB (via pysmb/impacket, if installed) checks, only triggered when credentials are explicitly supplied. Degrades silently and never blocks the scan if libraries or credentials are absent.

Every stage feeds one unified findings object that flows straight into risk scoring, remediation, and reporting.

---

## 🧠 Two Intelligent Systems

### 1. Tiered Confirmation Router

Every finding is confirmed through an ordered cascade, cheapest and most reliable method first:

```
Step 0  Direct backdoor pattern match  (instant, no AI)
Step 1  NSE keyword analysis           (instant, no AI)
Step 2  SOPLib pattern match           (instant, no AI)
Step 3  Gemini-selected confirmation script, conditional on CVE presence
Step 4  Local version-range check with product-mismatch guard
Step 5  Qwen (local LLM) — last-resort yes/no classification
Step 6  Fallback — UNCONFIRMED / NOT_VALIDATABLE
```

Only Step 3 reaches a cloud API, and only with minimal metadata (CVE ID, service, product, version, script list) — never raw scan output or target identity. Every confirmation carries a full `trace` showing exactly which step resolved it, for auditability.

### 2. Patch Resolution Orchestrator

CVE → patch guidance is resolved through 5 layers, cheapest first, each one populating the next:

```
Layer -1  In-memory LRU cache        (sub-millisecond, 1h TTL)
Layer  0  Learning KB                (previously AI-approved results)
Layer  1  Local Patch Repository     (SQLite, vendor-seeded)
Layer  2  Vendor Advisory Repository (Ubuntu USN / Red Hat / known advisories)
Layer  3  NVD Intelligence Cache     (NVD 2.0 API, 7-day cache, 3s timeout guard)
Layer  4  AI Remediation Engine      (DeepSeek R1 → Qwen → Llama → Rule Engine)
```

Every result carries a confidence score and label:

| Source | Confidence | AI calls |
|---|---|---|
| Vendor Advisory | 100 | 0 |
| NVD Reference | 90 | 0 |
| Community-sourced | 80 | 0 |
| AI-generated | 70 | 1 (then cached) |
| Rule Engine fallback | 30 | 0 |

Both systems are designed so AI is the *expensive, last-resort* path, not the default — local pattern matching, caches, and knowledge bases are checked first every time.

---

## 🤖 AI Model Stack (4 Local Models)

| Model | Size | Use Case | Install |
|---|---|---|---|
| **Qwen 2.5 7B Instruct** | ~4.7GB | Primary chatbot + reasoning | `ollama pull qwen2.5:7b` |
| **Llama 3.2 3B** | ~2.0GB | Fast local chatbot | `ollama pull llama3.2:3b` |
| **Llama 3.1 8B** | ~4.7GB | General-purpose analysis | `ollama pull llama3.1:8b` |
| **DeepSeek R1 8B Distill** | ~5.0GB | Deep CVE / security analysis | `ollama pull deepseek-r1:8b` |
| **Rule Engine** | — | Offline emergency fallback | Built-in |

**No cloud API keys required for the AI stack itself** — everything routes through Ollama. The one exception is the confirmation router's optional Step 3 (Gemini), which sends only minimal CVE/service metadata, never scan output.

Routing is task-aware: security-flagged prompts (CVE/exploit/CVSS keywords) go to DeepSeek R1 first; general prompts go to Qwen first; fast chat goes to Llama 3.2 3B first; each tier falls back to the next if a model is unavailable.

---

## 📊 Intelligence & Analysis Features

### Explainable Risk Score
```
Risk Score = (CVSS × 0.40) + (Asset Criticality × 0.25) + (Version Risk × 0.20) + (Exposure × 0.15)
```
Every score returns a full breakdown — each component's raw value, weight, and contribution — not just a final number.

### Security Score
A-F letter grade for overall security posture, with supporting recommendations.

### Threat Intelligence
KEV (Known Exploited Vulnerabilities) flagging and EPSS-based exploit likelihood, surfaced per finding and rolled up into report summaries.

### Vulnerability Timeline
Chronological CVE disclosure timeline across all findings in a scan.

### AI Response Caching
24-hour TTL, up to 5,000 cached entries — repeated questions about the same CVE/service don't re-trigger an AI call.

---

## 🛡️ Security & Safety Features

- **SSRF protection** — target validation blocks loopback, link-local, and cloud metadata address ranges (`127.0.0.0/8`, `169.254.0.0/16`, etc.) before any scan is allowed to start.
- **Comma-typo auto-correction** — `10.0.0,5` is automatically read as `10.0.0.5`.
- **Optional API token** — set `API_TOKEN` to require an `X-API-Token` header on scan/report/chat requests.
- **Rate limiting** — via `slowapi`, configurable per route.
- **LAN-aware CORS** — accepts requests from `localhost` and private subnets (`192.168.x.x`, `10.x.x.x`, `172.16–31.x.x`) by default; restrict with `ALLOWED_ORIGINS` for non-LAN deployments.

---

## 💬 Chat Interface

There is no separate "start a scan" command — **type a target (IP, hostname, or CIDR) directly into the chat**, and the platform scans it automatically. Everything else is a slash command:

| Command | Description |
|---|---|
| `/help` | Show the command list |
| `/patch [all\|<service> <port>]` | AI-assisted remediation guidance — for everything found, or one specific service |
| `/graph` | Open the Infrastructure Intelligence Graph (click-to-expand host→port→service→CVE tree) or the Vulnerability Intelligence Dashboard (SOC-style severity/risk/CVE charts), each in a new tab |
| `/report [pdf\|html]` | Export the last scan as a PDF or HTML report |
| `/clear` | Clear the chat window |
| `/stop` | Abort the running scan |

Anything that isn't a recognized slash command or a bare target is passed straight to the AI router as a natural-language question.

---

## 🏗️ Architecture

```
ThreatWeave/
├── app/
│   ├── scanner/
│   │   ├── scanner_core.py          # The one nmap command — locked constant
│   │   ├── service_prober.py        # Additive active service probing
│   │   ├── soplib.py                # Script Output Pattern Library (8 scripts)
│   │   ├── cpe_cve_engine.py        # CVE confidence tagging (exact/range)
│   │   ├── misconfig_checker.py     # Standalone misconfiguration findings
│   │   ├── confirmation_router.py   # 6-step tiered confirmation cascade
│   │   ├── auth_scanner.py          # Optional SSH/SMB authenticated checks
│   │   └── cve_script_mapper.py     # NSE output → vulnerability status
│   ├── ai/
│   │   ├── providers/               # Qwen / Llama / DeepSeek local providers
│   │   ├── routing/ai_router.py     # Task-aware model routing
│   │   └── cache/                   # 24h TTL AI response cache
│   ├── remediation/
│   │   └── orchestrator.py          # 5-layer patch resolution orchestrator
│   ├── analysis/                    # Risk, criticality, security score, threat intel
│   ├── report/
│   │   ├── html_report.py           # HTML report generation
│   │   └── multi_format.py          # PDF (reportlab) + HTML export routes
│   ├── api/routes.py                # Main API routes
│   └── main.py                      # FastAPI entry point
├── data/                             # SQLite caches, patch KB, scan sessions
├── config/settings.yaml              # Full system configuration
├── .env                               # Model + environment configuration
├── MODELS.md                          # Model setup and routing guide
└── RESEARCH.md                        # Research methodology and publication notes
```

---

## 🔄 Changelog — QA & Hardening Pass

A review pass against the existing test suite (28 failing → 0 of 193) and targeted integration testing surfaced and fixed the following:

**NVD Integration** (`app/vuln/nvd_client.py`)
- `NVD_API_KEY` (set in `.env`) is now actually sent with requests — previously it was read by other parts of the codebase but never wired into this client, so the rate limit stayed capped at the unauthenticated 5 req/30s tier regardless of configuration. With a key set, it now correctly rises to 45 req/30s.
- CVE normalization now extracts CPE match strings (`cpes`) from NVD's `configurations` block.
- Added the cache-management methods (`clear_expired_cache()`, `cache_stats()`) that `/api/nvd/cache/clear` was already calling — that endpoint previously raised `AttributeError` on every request.

**Patch Resolution Orchestrator**
- `verification_steps`, `rollback_steps`, `upgrade_path`, `mitigation`, and `references` are now persisted end-to-end (SQLite schema → repository lookup → orchestrator output) instead of being silently dropped between the seed data and the final API response.
- `patch_found` — read by the report generator to decide whether to include remediation guidance for a finding — is now preserved through orchestration. Previously it was dropped during result normalization, so every generated report silently omitted patch guidance for every finding regardless of whether one was actually found.
- Manual patch submission (`POST /api/patch/add`) is now functional. A missing entry in the repository's source allow-list meant every manual submission was silently rejected, while the endpoint itself reported success regardless.

**Self-Learning CVE → Script Mapping** (`app/scanner/cve_db.py`)
- Gemini's reasoning for a script selection is now correctly saved when an existing mapping (e.g. one auto-seeded from NSE filenames) gets upgraded by a later AI answer. Previously this was only persisted on the very first insert of a brand-new CVE and silently dropped on every subsequent update — the much more common path in practice.
- The confirmation trace now surfaces that reasoning when a learned answer is reused, instead of showing a bare "DB hit" with no explanation of why.

**Confirmation Table UI**
- The live per-port confirmation table now displays the NSE script and its evidence *before* the confirmed / not-confirmed verdict, both spatially (column order) and temporally (the verdict badge appears after a brief pause, once the proof is already visible) — so confirmation reads as a conclusion, not a simultaneous claim.
- A port with multiple candidate CVEs now exposes all of them behind a single collapsible toggle (closed by default), rather than showing only the strongest match. Since only one candidate per port is ever actually run through an NSE script, the rest are explicitly labeled "Not Actively Checked" instead of implying each one was individually confirmed.

**Misc.**
- Fixed a duplicate dictionary key in the misconfiguration explainer (`ftp` guidance) that was silently discarding part of its own advice text.

---

## 📚 Research

See [RESEARCH.md](RESEARCH.md) for research contributions and novelty analysis, experimental methodology, and Scopus publication readiness notes, and [RESEARCH_ASSESSMENT.md](RESEARCH_ASSESSMENT.md) for the detailed self-assessment.

## 🔑 Key Files

- `MODELS.md` — Model setup and routing guide
- `RESEARCH.md` / `RESEARCH_ASSESSMENT.md` — Academic publication guides
- `config/settings.yaml` — Full configuration
- `.env` — Environment variables
- `INSTALL.md` — Kali Linux setup troubleshooting
