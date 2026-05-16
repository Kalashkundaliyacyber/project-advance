# 🛡 ScanWise AI

**Context-Aware Explainable Vulnerability Intelligence System**

ScanWise AI is a full-stack network security analysis platform that combines nmap scanning with a three-tier AI pipeline (Gemini Flash → Ollama/Llama → rule-based engine) to produce plain-English, actionable vulnerability reports. Built for security research, lab assessments, and academic study.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Requirements](#requirements)
- [Features](#features)
  - [Scanning](#scanning)
  - [AI Analysis](#ai-analysis)
  - [CVE Intelligence](#cve-intelligence)
  - [Risk Engine](#risk-engine)
  - [Chat Interface](#chat-interface)
  - [Slash Commands](#slash-commands)
  - [Dashboard](#dashboard)
  - [Session Management](#session-management)
  - [Reports](#reports)
  - [AI Diagnostics](#ai-diagnostics)
  - [Security](#security)
- [Scan Profiles](#scan-profiles)
- [API Reference](#api-reference)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [Research](#research)

---

## Quick Start

```bash
# Clone and enter the project
git clone <your-repo-url>
cd project-advance

# Create environment file
cp .env.example .env
# Add your GEMINI_API_KEY to .env

# Run (handles venv creation, dependency install, and startup token)
bash run.sh
```

Open `http://localhost:3332` in your browser.

> **LAN access:** ScanWise AI is also reachable from any device on your network at `http://<your-ip>:3332`. The exact LAN URL is printed to the terminal on startup.

---

## Requirements

| Dependency | Version | Notes |
|---|---|---|
| Python | 3.10+ | 3.13 recommended |
| nmap | 7.80+ | `sudo apt install nmap` |
| Gemini API key | Free tier | 1,500 requests/day — [get one here](https://aistudio.google.com/) |
| Ollama (optional) | Any | Local Llama fallback — `ollama pull llama3.2` |
| NVD API key (optional) | Free | Enables live CVE lookups — [get one here](https://nvd.nist.gov/developers/request-an-api-key) |

> **No nmap installed?** ScanWise AI runs in simulation mode — all scan types work with realistic simulated output so you can explore the full UI and analysis pipeline without nmap.

---

## Features

### Scanning

#### 25+ nmap Scan Profiles
Every scan type is a fixed, pre-validated nmap argument list. No shell injection is possible — targets are appended as the final argument only after full validation.

**Discovery**
- **Ping Sweep** — ICMP echo discovery of live hosts on a network
- **Host Discovery** — Multi-method discovery (ICMP + TCP SYN + TCP ACK) without port scanning
- **ARP Discovery** — LAN-only ARP-based host discovery (fastest for local networks)

**Port Scanning**
- **Quick TCP Scan** — Top 1000 TCP ports, T4 timing (~30s)
- **Full TCP Scan** — All 65,535 TCP ports, finds hidden services and backdoors (~5–15m)
- **Full UDP Scan** — UDP ports for DNS, SNMP, NTP, TFTP, VPN detection (~30–60m)
- **Stealth SYN Scan** — T2 low-speed scan to evade basic IDS/firewall detection
- **TCP SYN Scan** — Classic SYN scan of top 1000 ports
- **Port Range 1–1024** — Well-known port scan only

**Enumeration**
- **Service Detection** — Identifies services and versions on open TCP ports
- **Full Service Enumeration** — All ports + service versions + banners
- **OS Fingerprinting** — TCP/IP stack fingerprinting to identify operating system
- **Banner Grabbing** — Service banner capture at intensity 5 for technology identification
- **Default Script Scan** — Safe NSE default scripts for service enumeration
- **Deep Version Detection** — Maximum intensity (9) version fingerprinting for precise CVE matching
- **Database Discovery** — Targeted scan of MSSQL (1433), MySQL (3306), PostgreSQL (5432), MongoDB (27017), Redis (6379)

**Vulnerability Assessment**
- **Vulnerability Scan** — NSE `vuln` scripts across all ports — detects known CVEs and misconfigurations
- **SMB Security Audit** — Enumerates SMB shares and users (`smb-enum-shares`, `smb-enum-users`)
- **FTP Security Audit** — Checks anonymous FTP login and vsftpd backdoor (`ftp-anon`, `ftp-vsftpd-backdoor`)
- **SSH Security Audit** — Enumerates SSH auth methods and algorithms (`ssh-auth-methods`, `ssh2-enum-algos`)
- **Web Pentest Scan** — HTTP scripts on ports 80/443/8080 — finds admin panels, headers, directories

**Advanced / Evasion**
- **Aggressive Pentest** — OS + version + scripts + traceroute combined (`-A`)
- **Firewall Evasion** — Fragmented packets to bypass packet inspection
- **Fragment Scan** — IP fragment evasion technique
- **Decoy Scan** — Masks source IP using 5 random decoys (`-D RND:5`)
- **Timing Manipulation** — Paranoid T1 speed scan to evade time-based IDS
- **Ultimate Recon** — Full professional recon: all ports + OS + version + scripts + vuln scan (~45–120m)

#### Real-Time Progress via Server-Sent Events
Scan progress is streamed to the browser using SSE (`/api/scan/stream`) — no polling. The frontend connects once and receives push updates for every state change. Includes nginx buffering disable and keepalive pings to maintain long-lived connections.

#### Scan Simulation Mode
If nmap is not installed, every scan type falls back to a realistic XML simulation that produces actual port, service, CVE, and risk data. The full UI and analysis pipeline works identically in simulation mode.

#### Input Validation and Safety
- IP, hostname, and CIDR notation accepted
- Auto-corrects comma-as-dot typos (`10.83.113,112` → `10.83.113.112`)
- Blocks loopback (`127.0.0.0/8`) and link-local (`169.254.0.0/16`) ranges
- No shell injection possible — target is appended after all flags, never interpolated
- Scan rate limited to 20 scans/minute per IP

#### Stop Scan
Any running scan can be stopped immediately with the Stop button. Sends `SIGTERM` then `SIGKILL` if needed. Scan state is updated instantly via SSE.

---

### AI Analysis

#### Three-Tier AI Fallback Pipeline
```
Gemini 2.5 Flash-Lite  →  Ollama / Llama 3.2  →  Rule-Based Engine
     (primary)               (local fallback)        (always available)
```

- **Gemini Flash** (primary) — Google's free-tier model. 1,500 requests/day. JSON-mode enforced. Low temperature (0.1) for consistent structured output.
- **Ollama / Llama 3.2** (fallback) — Runs locally. No internet required. No API key needed. Activated automatically if Gemini fails, hits quota, or is unavailable.
- **Rule-Based Engine** (final fallback) — Deterministic analysis using your local CVE DB and risk formulas. Works with zero AI providers. Always produces results.

Each tier is tried automatically — the user never sees a failure, only a note in the UI about which engine is active.

#### Per-Exception Routing
- `GeminiSafetyBlock` — does not retry (retrying a blocked prompt wastes quota)
- `GeminiQuotaError` — immediate fallback to Ollama
- `GeminiServerError` — retried up to 2 times with exponential backoff, then fallback
- Any other exception — immediate fallback

#### JSON Recovery (3-Strategy Parser)
AI responses are parsed with three fallback strategies:
1. Direct JSON parse
2. Extract first `{...}` block from the response
3. Strip trailing commas (common LLM mistake) and re-parse

If all three fail, the rule-based engine activates and produces a guaranteed result.

#### AI Capabilities Per Scan
- Executive summary of security posture (2–3 sentences)
- Overall risk level: `critical` / `high` / `medium` / `low`
- Per-service findings with exposure classification
- Version status per service (latest / outdated / unsupported)
- CVE insights with CVSS scores and descriptions
- Defensive patch recommendations with upgrade commands
- Next scan recommendation based on current findings
- Analyst notes and uncertainty acknowledgements

#### AI Chat (Multi-Turn)
Natural language conversation about scan results with full context window. The AI system prompt injects the last scan's target, risk level, open ports, and CVEs automatically when your message is scan-related (keyword detection). Generic messages (greetings, unrelated questions) do not inject scan context, saving tokens.

#### Auto-Scan Intent Detection
Type natural language and the AI extracts the target and picks the best scan type:
- *"check my server at 192.168.1.10"* → triggers `tcp_basic`
- *"what services are running on 10.0.0.5"* → triggers `service_detect`
- *"audit 192.168.1.1 for CVEs"* → triggers `version_deep`

---

### CVE Intelligence

#### Local CVE Database
Hardcoded, always-available CVE data for the most common services. Instant lookups with no network required:

| Service | CVEs Covered |
|---|---|
| OpenSSH | CVE-2023-38408, CVE-2023-28531, CVE-2018-15473, CVE-2016-6515, CVE-2016-0777 |
| Apache httpd | CVE-2021-41773, CVE-2021-42013, CVE-2022-31813 |
| vsftpd | CVE-2011-2523 (backdoor), CVE-2021-3618 |
| MySQL | CVE-2016-6662, CVE-2012-2122, CVE-2023-21980 |
| ISC BIND | CVE-2021-25220 |
| net-snmp | Multiple |
| Samba/SMB | EternalBlue, WannaCry-related |

#### Live NVD 2.0 API Lookups
When `NVD_API_KEY` is set in `.env`, ScanWise performs live lookups against the [National Vulnerability Database](https://nvd.nist.gov/) for any service not in the local database. Results are cached in `data/cve_db/` to avoid repeated API calls for the same service+version.

#### CVE Mapping Pipeline
For each open port:
1. Extract service name and version from nmap output
2. Check local CVE database for known matches
3. If not found locally and `NVD_API_KEY` set → live NVD lookup
4. Filter results to versions that match the detected version string
5. Attach CVSS score, severity, description, and patch advice to each CVE

---

### Risk Engine

#### Context-Aware Weighted Scoring
Every open port receives a composite risk score (0–10) using four weighted dimensions:

| Dimension | Weight | Source |
|---|---|---|
| Max CVSS score | 40% | CVE database |
| Service criticality | 25% | Context engine (18 service categories) |
| Version risk | 20% | Version engine (latest/outdated/unsupported) |
| Host exposure | 15% | Port count and exposure type |

A CVSS 10.0 finding always scores critical regardless of other dimensions.

#### Service Criticality Classification (18 Services)
| Service | Criticality | Reason |
|---|---|---|
| RDP, VNC, LDAP, Telnet, SMB, MSSQL | Critical | Remote access or directory services |
| SSH, FTP, MySQL, PostgreSQL, MongoDB, Redis, SNMP, DNS, HTTP Proxy | High | Data access or administration |
| HTTP, HTTPS, SMTP | Medium | Web/mail with variable exposure |
| Others | Low | Non-standard, verify if needed |

#### Version Risk Classification
Services are classified against a version database covering OpenSSH, Apache, nginx, vsftpd, ProFTPD, MySQL, ISC BIND, and net-snmp:
- **Latest** — current stable release
- **Outdated** — older but still supported
- **Unsupported** — past end-of-life, no patches available

#### Sequential Scan Recommendations
After each scan, the engine recommends the optimal next scan type:
1. No version info found → `service_detect`
2. Critical CVE found → `enum_scripts`
3. Outdated versions → `version_deep`
4. UDP not scanned → `udp_scan`
5. Scripts not run → `enum_scripts`
6. OS not detected → `os_detect`
7. All complete → generate report

---

### Chat Interface

#### Conversational AI Assistant
Full multi-turn chat with scan context awareness. The chat bar accepts:
- Natural language questions about scan results
- Slash commands for specific actions
- Auto-scan triggers (type an IP + intent)
- CVE and patching questions for any service

#### Rich Interactive Widgets
Chat messages are not just text — the following interactive components are embedded directly in the chat:

| Widget | Trigger | What It Shows |
|---|---|---|
| **Scan Selector** | After entering a target IP | Categorised scan type selector with descriptions, time estimates, and risk levels |
| **Scan Running Card** | When scan starts | Target, scan type, real-time progress bar via SSE |
| **Scan Complete Card** | On completion | Risk level badge, open ports, CVE count, duration, expandable port details |
| **CVE Table** | After scan with CVEs | Sortable table: CVE ID, service, port, CVSS score, severity badge, description |
| **Vuln Dashboard** | `/vuln` command | Full vulnerability analysis with AI explanation per CVE |
| **Patch Dashboard** | `/patch all` | Per-service remediation: upgrade command, restart command, verify command |
| **IP Prompt** | On new session | Project name input with quick-start scan type chips |
| **Help Card** | `/help` | All commands, scan types, and tips |

#### Widget Persistence
Every interactive widget is serialised as a rich token and saved to SQLite. On browser refresh, tab close, or server restart, all widgets are fully reconstructed — including scan cards, CVE tables, and patch dashboards. The entire workspace is restored exactly as it was.

---

### Slash Commands

| Command | What It Does |
|---|---|
| `/scan <ip>` | Set target IP and show scan type selector |
| `/vuln` | Run CVE vulnerability analysis on last scan |
| `/patch all` | Full remediation dashboard for all services |
| `/patch <ip> <port>` | Specific patch guidance for one port |
| `/report html` | Generate and download HTML report |
| `/report pdf` | Generate and download PDF report |
| `/model` | Show AI provider status, latency, success rates, last 10 call logs |
| `/settings` | Show current session settings and configuration |
| `/stop` | Stop any running scan immediately |
| `/clear` | Clear current session and start fresh |
| `/help` | Show all commands, scan types, and usage tips |

---

### Dashboard

The dashboard (📊 tab) updates automatically after every scan:

#### Risk Tab
- Risk distribution doughnut chart (Critical / High / Medium / Low port count)
- Service distribution bar chart
- Risk gauge (overall session risk level)
- Per-port risk scores and reasons

#### CVE Tab
- Complete CVE list sorted by CVSS score
- Severity breakdown chart
- CVE count per service
- CVSS score timeline

#### Findings Tab
- All open ports with service, version, state, and risk level
- Port exposure classification (commonly exposed / well-known / high port)
- Version status per service

#### AI Tab
- AI-generated executive summary
- Overall risk assessment
- Version status analysis
- AI-recommended next steps
- Patch priority list

---

### Session Management

#### Project Sessions
Every chat is a named project session. Sessions persist across browser refreshes, tab closes, and server restarts. The project history drawer (☰) shows all past sessions with:
- Session name (user-defined) or target IP
- Scan status (new / has scan data)
- Last updated time
- Search/filter by project name
- Rename via inline edit
- Delete with confirmation

#### Session Lifecycle
- **Fresh start** (after `run.sh`) — new session created, greeting shown, history preserved in drawer
- **Browser refresh** — existing session restored exactly, no new session created
- **New Chat button** — creates a new blank session, previous session preserved in history
- **Session switching** — click any session in the drawer to switch; scroll position is saved and restored per session

#### Data Persistence (SQLite)
All data is stored in `data/scanwise.db`:

| Table | Contents |
|---|---|
| `sessions` | Scan metadata: target, scan type, timestamp, risk level, port count, CVE count |
| `frontend_chat` | Full chat widget state: all messages, rich tokens, project name, scan data |
| `chat_history` | LLM conversation context (user/assistant pairs for AI continuity) |
| `scan_context` | Per-session scan context for AI system prompt injection |
| `project_sessions` | Named sessions for the history drawer |

#### Retention Policy
- Sessions older than 30 days are automatically purged
- Maximum 200 sessions stored at any time
- Oldest sessions beyond the cap are purged on each new scan
- Disk files (`data/sessions/{id}/`) are deleted with each purge

#### Raw Data Storage
Every scan saves a full audit trail to `data/sessions/{session_id}/`:
```
raw/output.txt          — raw nmap stdout
raw/output.xml          — raw nmap XML
parsed/parsed.json      — structured port/service/host data
analysis/analysis.json  — full analysis including CVEs and risk scores
logs/session.log        — session creation log
report/                 — generated reports
```

---

### Reports

#### HTML Report
Self-contained single-file HTML report with:
- Executive summary with overall risk badge
- Severity counts (critical / high / medium / low)
- Complete findings table (host, port, service, version, state, risk score, version status)
- Full CVE table sorted by CVSS score (CVE ID, service, port, CVSS, severity, description, patch advice)
- AI-generated summary and recommendations
- All values HTML-escaped to prevent XSS from malicious service banners
- Printable to PDF via browser (Ctrl+P → Save as PDF)

#### PDF Report
Programmatically generated PDF via ReportLab with the same content as the HTML report. Downloaded directly from the browser.

---

### AI Diagnostics

#### `/model` Command
Shows the full AI provider status in the chat:
- Active provider (Gemini Flash / Llama Fallback / Rule Engine)
- Gemini model version
- Ollama model and availability
- Last response latency (ms)
- Total AI calls this session
- Gemini success rate (%)
- Average latency across all calls
- Last 10 provider call log (timestamp, provider, success, latency, reason)
- Fallback reason if not on primary provider

#### AI Status Indicator (Top Bar)
The model pill in the top bar shows:
- Live provider name
- Provider type (Google AI · Primary / Llama Fallback Active / No AI · Rules only)
- Animated green dot (healthy) / yellow (checking) / red (error)
- Click to run `/model` diagnostics

#### Provider Logger
Every AI call is logged to an in-memory circular buffer (last 100 entries) tracking:
- Provider used
- Success / failure
- Latency in ms
- Failure reason if applicable
- Cumulative stats (total calls, success rate, average latency)

---

### Security

#### Input Validation
- Target validated against strict regex before any nmap command is built
- Scan type validated against explicit allowlist — unknown types rejected with HTTP 400
- SSRF protection: loopback and link-local ranges blocked
- All nmap commands are fixed argument lists — no string interpolation

#### Rate Limiting
- Scan endpoint: 20 requests/minute per IP (custom sliding-window middleware)
- Chat endpoint: 120 requests/minute per IP (slowapi)
- All other endpoints: 60 requests/minute per IP (slowapi)

#### API Token (Optional)
Set `API_TOKEN` in `.env` to require an `X-API-Token` header on all scan, report, and chat endpoints. Leave empty for open LAN access.

#### No-Cache Headers
All JS, CSS, and HTML files are served with `Cache-Control: no-cache, no-store, must-revalidate`. Code changes are reflected immediately without a hard refresh.

#### Report XSS Protection
All user-controlled values in HTML reports pass through `html.escape()` before insertion — service banners, hostnames, CVE descriptions, and version strings cannot inject HTML or JavaScript.

---

## Scan Profiles Reference

| Key | Name | Category | Root | Risk | Time |
|---|---|---|---|---|---|
| `ping_sweep` | Ping Sweep | Discovery | No | Safe | ~15s |
| `host_discovery` | Host Discovery | Discovery | Yes | Safe | ~20s |
| `arp_discovery` | ARP Discovery | Discovery | Yes | Safe | ~10s |
| `tcp_basic` | Quick TCP Scan | Port Scanning | Yes | Moderate | ~30s |
| `full_tcp` | Full TCP Scan | Port Scanning | Yes | Aggressive | ~5–15m |
| `udp_scan` | Full UDP Scan | Port Scanning | Yes | Aggressive | ~30–60m |
| `stealth_syn` | Stealth SYN Scan | Port Scanning | Yes | Moderate | ~3–5m |
| `tcp_syn` | TCP SYN Scan | Port Scanning | Yes | Moderate | ~30s |
| `port_range` | Port Range 1–1024 | Port Scanning | No | Moderate | ~40s |
| `service_detect` | Service Detection | Enumeration | No | Moderate | ~45s |
| `full_service_enum` | Full Service Enumeration | Enumeration | Yes | Aggressive | ~5–10m |
| `os_detect` | OS Fingerprinting | Enumeration | Yes | Moderate | ~30s |
| `banner_grab` | Banner Grabbing | Enumeration | No | Moderate | ~60s |
| `version_deep` | Deep Version Detection | Enumeration | No | Aggressive | ~90s |
| `db_discovery` | Database Discovery | Enumeration | No | Moderate | ~30s |
| `enum_scripts` | Default Script Scan | Enumeration | No | Moderate | ~60s |
| `vuln_scan` | Vulnerability Scan | Vuln Assessment | Yes | Aggressive | ~10–20m |
| `smb_audit` | SMB Security Audit | Vuln Assessment | No | Moderate | ~30s |
| `ftp_audit` | FTP Security Audit | Vuln Assessment | No | Moderate | ~20s |
| `ssh_audit` | SSH Security Audit | Vuln Assessment | No | Moderate | ~20s |
| `web_pentest` | Web Pentest Scan | Vuln Assessment | No | Moderate | ~60s |
| `aggressive_pentest` | Aggressive Pentest | Advanced | Yes | Aggressive | ~5–10m |
| `firewall_evasion` | Firewall Evasion | Advanced | Yes | Aggressive | ~2–4m |
| `frag_scan` | Fragment Scan | Advanced | Yes | Aggressive | ~2–4m |
| `decoy_scan` | Decoy Scan | Advanced | Yes | Aggressive | ~2–4m |
| `timing_manipulation` | Timing Manipulation | Advanced | Yes | Moderate | ~10–20m |
| `ultimate_recon` | Ultimate Recon | Advanced | Yes | Very Noisy | ~45–120m |

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/scan` | Start a scan (target, scan_type, project_name) |
| `GET` | `/api/scan/stream` | SSE stream for real-time scan progress |
| `GET` | `/api/scan/progress` | Polling fallback for scan progress |
| `POST` | `/api/scan/stop` | Stop running scan |
| `POST` | `/api/chat` | Send chat message (supports slash commands) |
| `POST` | `/api/chat/save` | Persist full frontend chat state |
| `GET` | `/api/chat/load/{session_id}` | Restore chat state for a session |
| `GET` | `/api/project-sessions` | List all named project sessions |
| `GET` | `/api/session/{session_id}` | Get full session analysis data |
| `DELETE` | `/api/session/{session_id}` | Delete a session and all its data |
| `PATCH` | `/api/session/{session_id}/rename` | Rename a session |
| `GET` | `/api/sessions` | List all scan sessions |
| `POST` | `/api/report` | Generate report (HTML/PDF) |
| `POST` | `/api/report/generate` | Multi-format report generation |
| `POST` | `/api/compare` | Compare two scan sessions (AI vs rule-based) |
| `GET` | `/api/ai/status` | AI provider status and diagnostics |
| `GET` | `/api/startup-token` | Startup token for session lifecycle |
| `GET` | `/health` | Health check |
| `GET` | `/config` | Server config (host, port, URLs) |
| `GET` | `/docs` | Interactive API documentation (FastAPI Swagger UI) |

---

## Architecture

```
ScanWise AI
├── app/
│   ├── main.py                    FastAPI app, middleware, startup
│   ├── api/
│   │   ├── routes.py              All scan, chat, session, report routes
│   │   ├── scan_control.py        Stop/progress/SSE endpoints + ScanState
│   │   └── validators.py          Target and scan type validation + SSRF protection
│   ├── scanner/
│   │   ├── orchestrator.py        25+ nmap scan profile registry
│   │   └── executor.py            Safe subprocess execution + simulation fallback
│   ├── parser/
│   │   └── nmap_parser.py         nmap XML → structured JSON
│   ├── analysis/
│   │   ├── version_engine.py      Service version classification (latest/outdated/unsupported)
│   │   ├── context_engine.py      Service criticality and exposure scoring
│   │   └── risk_engine.py         Weighted composite risk scoring (0–10)
│   ├── cve/
│   │   └── mapper.py              Local CVE DB + NVD 2.0 API live lookup + file cache
│   ├── explanation/
│   │   └── explainer.py           Defensive remediation guidance per service
│   ├── recommendation/
│   │   └── recommender.py         Next-scan recommendation engine
│   ├── services/ai/
│   │   ├── ai_router.py           Three-tier AI fallback (Gemini → Ollama → rules)
│   │   ├── gemini_provider.py     Gemini 2.5 Flash-Lite client with retry logic
│   │   ├── ollama_fallback_provider.py  Local Llama client
│   │   ├── prompt_templates.py    System prompts, scan analysis, patch, CVE explain
│   │   ├── response_parser.py     3-strategy JSON recovery + schema validation
│   │   └── ai_logger.py           Provider call tracking, latency, success rate
│   ├── ai_comparison/
│   │   └── compare.py             AI vs rule-based 5-dimension comparison scorer
│   ├── visualization/
│   │   └── charts.py              Chart.js dataset generation (6 chart types)
│   ├── report/
│   │   ├── html_report.py         Self-contained HTML report with XSS protection
│   │   ├── multi_format.py        PDF/HTML format router and download endpoints
│   │   └── template_builder.py    Report template utilities
│   ├── files/
│   │   ├── session_manager.py     SQLite CRUD, retention, live migrations, persistence
│   │   └── chat_manager.py        Chat file utilities
│   └── ai_analysis.py             AI analysis entry point (scan, patch, CVE explain)
├── statics/
│   ├── index.html                 App shell + parallel component loader
│   ├── components/
│   │   ├── navbar.html            Topbar, drawer, status strip, nav tabs
│   │   ├── chatbot.html           Chat panel
│   │   ├── dashboard.html         Risk/CVE/Findings/AI tabs
│   │   ├── history.html           Scan history page
│   │   ├── compare.html           AI vs rule-based comparison page
│   │   └── help.html              Help page
│   ├── js/
│   │   ├── app.js                 Session lifecycle, startup token, init
│   │   ├── chatbot.js             Chat engine, rich widgets, slash commands (2,871 lines)
│   │   ├── sessionManager.js      Frontend session CRUD, localStorage persistence
│   │   ├── apiService.js          All fetch calls to the backend API
│   │   ├── dashboard.js           Dashboard tab rendering
│   │   ├── graphs.js              Chart.js chart rendering
│   │   ├── router.js              Page tab routing
│   │   └── utils.js               Status indicators, shared utilities
│   └── css/
│       ├── global.css             CSS variables, reset, buttons, inputs, badges
│       ├── layout.css             App shell, topbar, drawer, nav tabs
│       ├── chatbot.css            Chat panel and all widget styles
│       ├── dashboard.css          Dashboard panel styles
│       └── responsive.css         Mobile breakpoints
└── data/                          Auto-created on first run
    ├── scanwise.db                SQLite database
    ├── sessions/                  Per-session raw/parsed/analysis files
    ├── startup_token.txt          Written by run.sh for session lifecycle
    └── logs/                      Application logs
```

---

## Configuration

All configuration is via `.env` in the project root:

```env
# AI Providers
GEMINI_API_KEY=your_key_here          # Required for AI analysis (free tier)
GEMINI_MODEL=gemini-2.5-flash-lite    # Gemini model to use
OLLAMA_URL=http://localhost:11434      # Ollama base URL (optional)
OLLAMA_MODEL=llama3.2                  # Ollama model (optional)
NVD_API_KEY=your_nvd_key              # Enables live CVE lookups (optional, free)

# Server
HOST=0.0.0.0                          # Bind address
PORT=3332                              # Port
DEBUG=false                            # Enable debug logging
API_TOKEN=                             # Optional: require token on protected endpoints
```

---

## Research

ScanWise AI was developed as a research platform for studying AI-augmented vulnerability intelligence. The key research contributions are:

**1. Context-Aware Risk Scoring** — A weighted composite scoring formula that outperforms CVSS-only prioritisation by incorporating service criticality, version status, and host exposure.

**2. AI vs Rule-Based Comparison** — A 5-dimension automated comparison framework (correctness, explainability, usefulness, conciseness, recommendation quality) for evaluating AI-generated vs deterministic security analysis.

**3. Three-Tier AI Resilience** — A provider fallback architecture ensuring the platform produces analysis under any condition — internet outage, API quota exhaustion, or safety filter rejection.

**4. Explainable Output** — Every risk score includes the reasons it was assigned. Every CVE finding includes defensive remediation steps. No black-box outputs.

### Citing This Work

```bibtex
@software{scanwise_ai,
  title  = {ScanWise AI: Context-Aware Explainable Vulnerability Intelligence System},
  author = {Your Name},
  year   = {2025},
  url    = {your-repository-url}
}
```

---

## Licence

MIT — see `LICENCE` file.
