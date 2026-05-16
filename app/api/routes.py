"""ScanWise AI — API Routes v5.0
FIX SUMMARY (15 recommendations):
  #1  Chat history persisted to SQLite per session (no RAM wipe on restart)
  #2  _last_scan_context keyed by session_id (no global race condition)
  #5  /api/scan now rate-limited (20/minute) via main.py
  #6  AI fallback reason surfaced immediately in chat reply
  #10 System prompt injects scan context only when message is scan-related
  #12 /clear deletes session DB record + disk files, not just in-memory history
  #14 enum_scripts removed from AI system prompt scan types list
"""
import os
import json
import time
import asyncio
import logging
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional

from app.api.validators import validate_target, validate_scan_type
from app.scanner.orchestrator import get_scan_command, SCAN_TEMPLATES
from app.scanner.executor import execute_scan
from app.parser.nmap_parser import parse_nmap_output
from app.analysis.version_engine import analyze_versions
from app.cve.mapper import map_cves
from app.vuln.enrichment import enrich_with_nvd_sync
from app.analysis.context_engine import analyze_context
from app.analysis.risk_engine import calculate_risk
from app.analysis.correlation.attack_chain import correlate
from app.scanner.adaptive import recommend_followup
from app.recommendation.recommender import get_recommendation
from app.explanation.explainer import generate_explanation
from app.ai_analysis import analyze_scan, explain_cve, _rule_based_analyze
from app.ai.routing.ai_router import ai_router
from app.ai.remediation.patch_generator import get_patch_guidance
from app.visualization.charts import generate_chart_data, generate_history_trends
from app.report.template_builder import build_report
from app.report.html_report import build_html_report
from app.ai_comparison.compare import compare_analyses
from app.api.findings import annotate_with_review_status
from app.services.ai.prompt_templates import CHAT_SYSTEM_TEMPLATE
from app.files.session_manager import (
    create_session, save_raw, save_parsed, save_analysis,
    list_sessions, get_session, delete_session, rename_session,
    save_chat_history, load_chat_history,
    save_scan_context, load_scan_context,
)

logger = logging.getLogger("scanwise.routes")
router = APIRouter()

MAX_HISTORY = 10

# ── Keyword set for smart context injection (Fix #10) ─────────────────────────
_SCAN_KEYWORDS = {
    "port", "service", "cve", "vuln", "risk", "open", "scan", "host",
    "version", "patch", "exploit", "ssh", "http", "ftp", "smb", "rdp",
    "finding", "result", "severity", "critical", "high", "medium", "low",
    "what", "why", "how", "fix", "remediat", "recommend", "next",
}

def _is_scan_related(msg: str) -> bool:
    ml = msg.lower()
    return any(kw in ml for kw in _SCAN_KEYWORDS)


# ── Models ─────────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    scan_type: str
    message: Optional[str] = ""
    project_name: Optional[str] = ""

class ChatRequest(BaseModel):
    message: str
    target: Optional[str] = ""
    session_id: Optional[str] = ""
    project_name: Optional[str] = ""

class ReportRequest(BaseModel):
    session_id: str

class CompareRequest(BaseModel):
    session_id: str


# ── System prompt ──────────────────────────────────────────────────────────────

def _build_system_prompt(scan_ctx: dict, inject_context: bool = True) -> str:
    # Fix #14: enum_scripts excluded from AI prompt
    scan_types_desc = "\n".join(
        f"  - {k}: {v['description']}"
        for k, v in SCAN_TEMPLATES.items()
        if k not in ("enum_scripts",)
    )

    base = f"""You are ScanWise AI, a defensive cybersecurity assistant for network scanning.

CAPABILITIES:
- Understand what the user wants in natural language
- Recommend the best scan type for their goal
- Trigger scans automatically when user provides a target and intent
- Explain scan results clearly and prioritise risks
- Answer CVE, patching, and hardening questions

AVAILABLE SCAN TYPES:
{scan_types_desc}

SAFETY RULES:
- Never suggest exploits, attack payloads, or offensive techniques
- Only provide defensive, remediation-focused guidance

INTENT DETECTION - trigger auto-scan when user implies scanning:
  Examples: "check my server", "scan 192.168.1.1", "what is open on X", "audit X"
  - Extract the target IP/hostname from the message
  - Choose scan_type based on goal:
    * open ports only -> tcp_basic
    * what services running -> service_detect
    * exact versions for CVE -> version_deep
    * UDP services (DNS/SNMP) -> udp_scan
    * OS fingerprint -> os_detect
    * well-known ports -> port_range

WHEN TRIGGERING A SCAN - respond ONLY with this exact JSON, nothing else:
{{"action": "auto_scan", "target": "<ip or hostname>", "scan_type": "<key>", "reason": "<one sentence why>"}}

WHEN ANSWERING NORMALLY - respond in plain markdown. Never mix JSON with prose."""

    # Fix #10: only inject scan context when message is scan-related
    if inject_context and scan_ctx:
        target   = scan_ctx.get("target", "unknown")
        scan_t   = scan_ctx.get("scan_type", "unknown")
        ts       = scan_ctx.get("timestamp", "")
        risk_d   = scan_ctx.get("risk", {})
        overall  = risk_d.get("overall_risk", "unknown")
        score    = risk_d.get("overall_score", "-")
        cve_count = sum(len(p.get("cves", [])) for h in risk_d.get("hosts", []) for p in h.get("ports", []))
        proj     = scan_ctx.get("project_name", "")

        ports_lines = []
        for h in risk_d.get("hosts", []):
            for p in h.get("ports", []):
                svc   = f"{p.get('port')}/{p.get('protocol','tcp')} {p.get('service','')} {p.get('product','')} {p.get('version','')}".strip()
                level = p.get("risk", {}).get("level", "low")
                cves  = ", ".join(c.get("cve_id","") for c in p.get("cves", [])[:2])
                ports_lines.append(f"    - {svc} [{level.upper()}]" + (f" - {cves}" if cves else ""))

        project_line = f"\n  Project: {proj}" if proj else ""
        base += f"""

LAST SCAN CONTEXT:{project_line}
  Target: {target} | Scan: {scan_t} | Time: {ts}
  Risk: {overall} (score {score}) | CVEs: {cve_count}
  Open ports:
{chr(10).join(ports_lines[:15]) or "    (none)"}
"""
    return base


# ── Chat history — SQLite-backed (Fix #1) ──────────────────────────────────────

def _get_history(sid: str) -> list:
    try:
        return load_chat_history(sid)
    except Exception:
        return []

def _push_history(sid: str, role: str, content: str):
    try:
        history = load_chat_history(sid)
    except Exception:
        history = []
    history.append({"role": role, "content": content})
    if len(history) > MAX_HISTORY * 2:
        history = history[-(MAX_HISTORY * 2):]
    try:
        save_chat_history(sid, history)
    except Exception as e:
        logger.warning("Failed to persist chat history for %s: %s", sid, e)


# ── Slash commands ─────────────────────────────────────────────────────────────

def _handle_slash(cmd: str, args: str, sid: str):
    cmd = cmd.lower().strip()
    if cmd == "/help":
        return {"reply": "__HELP_CARD__", "action": "show_help"}
    if cmd == "/scan":
        parts = args.strip().split()
        if parts:
            return {"reply": f"Target set to **{parts[0]}**. Choose a scan type below.", "action": "show_scan_selector", "data": {"target": parts[0]}}
        return {"reply": "Usage: `/scan <ip>` e.g. `/scan 192.168.1.10`", "action": "none"}
    if cmd == "/report":
        fmt = args.strip() or "html"
        if fmt not in ("pdf", "html"): fmt = "html"
        return {"reply": f"Opening report export for **{fmt.upper()}**.", "action": "open_report_modal", "data": {"format": fmt}}
    if cmd == "/patch":
        parts_args = args.strip().split()
        # /patch all → gather ALL port data from session and call Gemini for each
        if parts_args and parts_args[0].lower() == "all":
            # Load scan context (try chat session first, then scan session folder)
            import re as _re2
            ctx_all = {}
            try:
                ctx_all = load_scan_context(sid) or get_session(sid) or {}
            except Exception:
                ctx_all = {}

            hosts_all = (ctx_all.get("risk") or {}).get("hosts", [])
            all_ports = []
            for _h in hosts_all:
                for _p in _h.get("ports", []):
                    _cves = _p.get("cves", [])
                    _top  = _cves[0] if _cves else {}
                    all_ports.append({
                        "ip":       _h.get("ip", ""),
                        "port":     _p.get("port"),
                        "service":  _p.get("service", ""),
                        "version":  _p.get("version", "") or _p.get("product", ""),
                        "risk_level": (_p.get("risk") or {}).get("level", "low"),
                        "risk_score": (_p.get("risk") or {}).get("score", 0),
                        "cve_id":   _top.get("cve_id", "unknown"),
                        "severity": _top.get("severity", "medium"),
                        "cve_desc": _top.get("description", ""),
                        "all_cves": _cves,
                    })

            if not all_ports:
                # No scan data yet — signal frontend to use its local data
                return {"reply": "__PATCH_ALL__", "action": "patch_all", "data": {}}

            # Call Gemini for EACH port and build a comprehensive reply
            import asyncio as _asyncio
            patch_results = []
            for _entry in all_ports:
                try:
                    _pd = get_patch_guidance(
                        service  = _entry["service"] or f"port {_entry['port']}",
                        port     = int(_entry["port"]) if str(_entry.get("port","")).isdigit() else 0,
                        version  = _entry["version"] or "unknown",
                        cve_id   = _entry["cve_id"],
                        severity = _entry["severity"],
                    )
                    _pd.update({
                        "ip": _entry["ip"], "port": _entry["port"],
                        "service": _entry["service"],
                        "risk_level": _entry["risk_level"],
                        "risk_score": _entry["risk_score"],
                        "cve_id": _entry["cve_id"],
                        "cve_desc": _entry["cve_desc"],
                        "all_cves": _entry["all_cves"],
                    })
                    patch_results.append(_pd)
                except Exception as _pe:
                    logger.warning("Patch guidance failed for port %s: %s", _entry.get("port"), _pe)
                    patch_results.append({
                        "ip": _entry["ip"], "port": _entry["port"],
                        "service": _entry["service"],
                        "risk_level": _entry["risk_level"],
                        "risk_score": _entry["risk_score"],
                        "cve_id": _entry["cve_id"],
                        "cve_desc": _entry["cve_desc"],
                        "severity": _entry["severity"],
                        "summary": f"Apply latest patches for {_entry['service']} on port {_entry['port']}.",
                        "upgrade_command": f"apt update && apt install --only-upgrade {_entry['service'] or 'package'}",
                        "mitigation": f"Restrict port {_entry['port']} via firewall: ufw deny {_entry['port']}",
                        "engine": "rule-based-fallback",
                    })

            # Sort by risk level
            _risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            patch_results.sort(key=lambda x: _risk_order.get(x.get("risk_level", "low"), 3))

            return {
                "reply": "__PATCH_ALL_DATA__",
                "action": "patch_all_data",
                "patch_all_data": patch_results,
            }

        # /patch <service_or_ip> <port> → Gemini-powered single-port guidance
        if len(parts_args) >= 2:
            first_arg = parts_args[0]
            port_arg  = parts_args[1]

            import re as _re
            _is_ip = bool(_re.match(r'^\d{1,3}(\.\d{1,3}){3}$', first_arg))

            svc_name    = ""
            svc_version = ""
            cve_id      = "unknown"
            cve_severity = "medium"
            cve_desc    = ""
            ip_target   = ""
            all_cves_for_port = []

            # Load scan context — try BOTH chat session key and scan session folder
            try:
                ctx = load_scan_context(sid) or get_session(sid) or {}
                for h in (ctx.get("risk") or {}).get("hosts", []):
                    for p in h.get("ports", []):
                        port_match = str(p.get("port")) == str(port_arg)
                        svc_match  = (not _is_ip) and (p.get("service","").lower() == first_arg.lower())
                        if port_match or svc_match:
                            svc_name    = p.get("service", first_arg if not _is_ip else "")
                            svc_version = p.get("version", "") or p.get("product", "")
                            ip_target   = h.get("ip", first_arg if _is_ip else "")
                            all_cves_for_port = p.get("cves", [])
                            if all_cves_for_port:
                                top_cve     = all_cves_for_port[0]
                                cve_id      = top_cve.get("cve_id", "unknown")
                                cve_severity= top_cve.get("severity", "medium")
                                cve_desc    = top_cve.get("description", "")
                            break
            except Exception as _e:
                logger.warning("Patch context lookup failed for sid=%s: %s", sid, _e)

            if not svc_name:
                svc_name = first_arg if not _is_ip else f"port {port_arg}"
            if not ip_target:
                ip_target = first_arg if _is_ip else "target"

            label = f"{svc_name} {svc_version}".strip() or f"port {port_arg}"

            # Call Gemini
            try:
                patch_data = get_patch_guidance(
                    service  = svc_name,
                    port     = int(port_arg) if str(port_arg).isdigit() else 0,
                    version  = svc_version or "unknown",
                    cve_id   = cve_id,
                    severity = cve_severity,
                )
            except Exception as _pe:
                logger.warning("get_patch_guidance failed: %s", _pe)
                patch_data = {
                    "service":         svc_name,
                    "port":            port_arg,
                    "severity":        cve_severity,
                    "summary":         f"Apply latest security patches for {svc_name} on port {port_arg}.",
                    "upgrade_command": f"apt update && apt install --only-upgrade {svc_name}",
                    "mitigation":      f"Restrict port {port_arg} access: ufw deny {port_arg}",
                    "engine":          "rule-based-fallback",
                }

            patch_data["ip"]       = ip_target
            patch_data["port"]     = port_arg
            patch_data["cve_id"]   = cve_id
            patch_data["cve_desc"] = cve_desc
            patch_data["all_cves"] = all_cves_for_port

            # Build rich markdown reply shown directly in chat bubble
            eng         = patch_data.get("engine", "")
            upg         = patch_data.get("upgrade_command", "") or patch_data.get("upgrade_cmd", "")
            rst         = patch_data.get("restart_command", "")
            vrfy        = patch_data.get("verify_command", "")
            mit         = patch_data.get("mitigation", "")
            hdg         = patch_data.get("config_hardening", [])
            refs        = patch_data.get("references", [])
            rec_ver     = patch_data.get("recommended_version", "")
            summary     = patch_data.get("summary", "")

            reply_md  = f"### 🔧 AI Patch Guide — **{label}** · Port `{port_arg}`\n\n"
            if summary:
                reply_md += f"{summary}\n\n"
            if cve_id and cve_id != "unknown":
                reply_md += f"**🔴 CVE:** [{cve_id}](https://nvd.nist.gov/vuln/detail/{cve_id}) — **{cve_severity.upper()}**\n"
            if cve_desc:
                reply_md += f"_{cve_desc[:220]}{'…' if len(cve_desc) > 220 else ''}_\n\n"
            if rec_ver:
                reply_md += f"**Recommended version:** `{rec_ver}`\n\n"
            if upg:
                reply_md += f"**⬆️ Upgrade:**\n```bash\n{upg}\n```\n"
            if rst:
                reply_md += f"**🔄 Restart:**\n```bash\n{rst}\n```\n"
            if vrfy:
                reply_md += f"**✅ Verify:**\n```bash\n{vrfy}\n```\n"
            if mit:
                reply_md += f"\n**🛡️ Mitigation:** {mit}\n"
            if hdg:
                reply_md += "\n**⚙️ Config Hardening:**\n" + "\n".join(f"- {h}" for h in hdg) + "\n"
            if refs:
                reply_md += "\n**🔗 References:** " + "  ".join(f"[{i+1}]({r})" for i, r in enumerate(refs[:3])) + "\n"
            if eng:
                reply_md += f"\n*— Powered by {eng}*"

            # Also list ALL CVEs for this port
            if len(all_cves_for_port) > 1:
                reply_md += f"\n\n**All CVEs on this port ({len(all_cves_for_port)}):**\n"
                for _c in all_cves_for_port[:5]:
                    reply_md += f"- `{_c.get('cve_id','')}` CVSS {_c.get('cvss_score',0)} [{_c.get('severity','').upper()}]\n"

            return {
                "reply":      reply_md,
                "action":     "none",
                "patch_data": patch_data,
            }

        # /patch with no args
        return {
            "reply": (
                "**Patch Command Usage:**\n"
                "- `/patch all` — Gemini AI patch guide for ALL vulnerable ports\n"
                "- `/patch <service> <port>` — e.g. `/patch ftp 21` or `/patch ssh 22`\n"
                "- `/patch <ip> <port>` — e.g. `/patch 192.168.1.1 22`"
            ),
            "action": "none",
        }
    if cmd == "/history":
        return {"reply": "The `/history` command has been removed. Use the sidebar drawer (☰) to browse past scan sessions.", "action": "none"}
    if cmd == "/clear":
        # Fix #12: wipe AI history in DB AND session files + DB record
        try:
            save_chat_history(sid, [])
        except Exception:
            pass
        try:
            delete_session(sid)
        except Exception:
            pass
        return {"reply": "Chat, memory, and session data cleared.", "action": "clear_chat"}
    if cmd == "/settings":
        st = ai_router.status()
        qwen_tag  = "✅ available" if st.get("qwen_available")  else "❌ not running"
        llama_tag = "✅ available" if st.get("llama_available") else "❌ not running"
        gem_tag   = "✅ configured" if st.get("gemini_available") else "no key — set GEMINI_API_KEY in .env"
        return {
            "reply": (
                "**Current Settings**\n\n"
                f"- **Active AI:** `{st['display_name']}` ({st['display_provider']})\n"
                f"- **Qwen2.5-Coder 3B** (primary remediation): `{qwen_tag}`\n"
                f"- **Llama 3.2 1B** (chatbot/lightweight): `{llama_tag}`\n"
                f"- **Gemini** (emergency cloud backup): `{gem_tag}`\n"
                f"- **Ollama:** `{'running' if st['ollama_available'] else 'not running — run setup_env.sh'}`\n"
                f"- **Server:** `http://localhost:{os.environ.get('PORT', '3332')}`\n"
                f"- **Token Auth:** `{'enabled' if os.environ.get('API_TOKEN') else 'disabled'}`"
            ),
            "action": "none"
        }
    if cmd == "/stop":
        return {"reply": "Stopping scan...", "action": "stop_scan"}
    return None


# ── Auto-scan pipeline ─────────────────────────────────────────────────────────

async def _run_scan_pipeline(target: str, scan_type: str, project_name: str = "", session_id: str = "") -> dict:
    target    = validate_target(target)
    scan_type = validate_scan_type(scan_type)
    sid       = create_session(target, scan_type, project_name=project_name)
    cmd       = get_scan_command(scan_type, target)

    raw_output, xml_output, duration = execute_scan(cmd, target, scan_type)
    save_raw(sid, raw_output, xml_output)

    parsed = parse_nmap_output(xml_output, raw_output)
    save_parsed(sid, parsed)

    # Fix 9: record scan telemetry
    try:
        from app.ai.utils.telemetry import telemetry as _tel
        _tel.record_scan(
            session_id=sid,
            duration_ms=int(duration * 1000),
            host_count=len(parsed.get('hosts', [])),
            vuln_count=sum(len(h.get('ports', [])) for h in parsed.get('hosts', [])),
            scan_type=scan_type,
        )
    except Exception:
        pass

    loop = asyncio.get_event_loop()
    versioned = await loop.run_in_executor(None, analyze_versions, parsed)
    cve_data  = await loop.run_in_executor(None, map_cves, versioned)
    # NVD enrichment: normalise local CVEs + augment with live NVD intelligence
    cve_data  = await loop.run_in_executor(None, enrich_with_nvd_sync, cve_data)
    context   = await loop.run_in_executor(None, analyze_context, cve_data)
    risk      = await loop.run_in_executor(None, calculate_risk, context)
    risk      = await loop.run_in_executor(None, correlate, risk)
    # Fix 5: correlate findings into attack chains
    risk      = await loop.run_in_executor(None, correlate, risk)
    # Fix 6: adaptive scan recommendations based on detected services
    parsed    = await loop.run_in_executor(None, recommend_followup, parsed)

    recommendation, explanation, ai_analysis, charts = await asyncio.gather(
        loop.run_in_executor(None, get_recommendation, risk, scan_type),
        loop.run_in_executor(None, generate_explanation, risk, {}),
        loop.run_in_executor(None, analyze_scan, risk),
        loop.run_in_executor(None, lambda: generate_chart_data({"risk": risk})),
    )

    # FIX3: also run deterministic rule-based engine so compare module always has both outputs
    try:
        rule_based_analysis = await loop.run_in_executor(None, _rule_based_analyze, risk)
    except Exception as rb_err:
        logger.warning("FIX3: rule_based_analyze failed: %s", rb_err)
        rule_based_analysis = {}

    analysis = {
        "session_id": sid, "target": target, "scan_type": scan_type,
        "project_name": project_name, "duration": duration,
        "parsed": parsed, "versioned": versioned, "cve_data": cve_data,
        "context": context, "risk": risk, "recommendation": recommendation,
        "explanation": explanation, "ai_analysis": ai_analysis,
        "rule_based_analysis": rule_based_analysis,   # FIX3: stored alongside AI output
        "charts": charts,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    save_analysis(sid, analysis)

    # Fix #2: store context keyed by caller's frontend session_id
    if session_id:
        try:
            save_scan_context(session_id, analysis)
        except Exception as e:
            logger.warning("Failed to save scan context for %s: %s", session_id, e)

    return analysis


def _format_scan_reply(analysis: dict, reason: str) -> str:
    ai     = analysis.get("ai_analysis", {})
    risk   = analysis.get("risk", {})
    target = analysis.get("target", "target")
    scan_t = analysis.get("scan_type", "scan")
    dur    = analysis.get("duration", 0)
    sid    = analysis.get("session_id", "")
    overall = ai.get("overall_risk") or risk.get("overall_risk", "unknown")
    summary = ai.get("summary") or f"Scan complete on {target}."

    lines = [
        f"**Scan complete** - `{target}` | `{scan_t}` | {dur:.1f}s",
        f"**Overall Risk: {overall.upper()}**",
        f"> {summary}", "",
    ]

    findings = ai.get("findings") or []
    if findings:
        lines += ["**Open Services**", "| Port | Service | Version | Exposure |", "|------|---------|---------|----------|"]
        for f in findings[:12]:
            lines.append(f"| {f.get('port','')} | {f.get('service','')} | {f.get('version','-')} | {f.get('exposure','-')} |")
        lines.append("")

    risks = sorted(ai.get("risk_analysis") or [], key=lambda r: r.get("score", 0), reverse=True)
    if risks:
        lines += ["**Risk Breakdown**"]
        for r in risks[:6]:
            lines.append(f"- **{r.get('service','')}** port {r.get('port','')} score {r.get('score',0):.1f} [{r.get('risk_level','').upper()}] - {r.get('reason','')}")
        lines.append("")

    real_cves = [c for c in (ai.get("cve_insight") or []) if c.get("cve_id","").startswith("CVE")]
    if real_cves:
        lines += ["**CVEs Detected**"]
        for c in real_cves[:5]:
            lines.append(f"- `{c.get('cve_id','')}` ({c.get('service','')}) [{c.get('severity','').upper()}] - {c.get('description','')}")
        lines.append("")

    recs = sorted(ai.get("recommendations") or [], key=lambda r: {"immediate":0,"high":1,"medium":2,"low":3}.get(r.get("priority",""), 4))
    if recs:
        lines += ["**Recommended Actions**"]
        for rec in recs[:5]:
            lines.append(f"- [{rec.get('priority','').upper()}] **{rec.get('service','')}** - {rec.get('action','')}")
        lines.append("")

    next_scan = ai.get("next_scan") or {}
    if next_scan.get("type"):
        lines.append(f"**Next Step:** Run `{next_scan['type']}` - {next_scan.get('reason','')}")
        lines.append("")

    if sid:
        lines.append(f"*Session: `{sid}` - ask me anything about these results.*")
    return "\n".join(lines)


def _try_parse_auto_scan(text: str) -> Optional[dict]:
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(lines[1:-1]) if lines[-1].strip() == "```" else "\n".join(lines[1:])
    try:
        data = json.loads(text.strip())
        if isinstance(data, dict) and data.get("action") == "auto_scan":
            return data
    except (json.JSONDecodeError, ValueError):
        pass
    return None


def _keyword_fallback(msg: str) -> str:
    ml = msg.lower()
    keywords = {"tcp": "tcp_basic", "port": "tcp_basic", "udp": "udp_scan",
                 "service": "service_detect", "version": "version_deep",
                 "os": "os_detect", "syn": "tcp_syn", "range": "port_range"}
    matched = next((t for kw, t in keywords.items() if kw in ml), None)
    if matched:
        info = SCAN_TEMPLATES[matched]
        return f"I suggest a **{info['name']}** scan. {info['description']} Use `/scan <ip>` to begin."
    if any(w in ml for w in ["hello", "hi", "hey"]):
        st = ai_router.status()
        return (f"**Hello!** I am ScanWise AI — powered by {st['display_name']}.\n\n"
                "Type `/scan <ip>` to start scanning, or `/help` for all commands.")
    st = ai_router.status()
    if not st["qwen_available"] and not st["llama_available"] and not st["gemini_available"]:
        return (
            "No AI provider is available. To enable:\n\n"
            "1. **Run setup_env.sh** — installs Ollama + pulls Qwen2.5-Coder 3B and Llama 3.2 1B automatically\n"
            "2. Or manually: `ollama pull qwen2.5-coder:3b && ollama pull llama3.2:1b`\n"
            "3. Optional cloud backup: set `GEMINI_API_KEY` in `.env`\n\n"
            "The system still works in rule-based mode — ask for `/patch` guidance."
        )
    return f"AI provider: {st['display_name']} ({st['display_provider']}). Type your question or use `/help`."


# ── Chat route ─────────────────────────────────────────────────────────────────

@router.post("/chat")
async def chat(req: ChatRequest, request: Request):
    msg = req.message.strip()
    if not msg:
        return {"reply": "Please type a message.", "suggestions": []}

    sid          = req.session_id or "default"
    project_name = (req.project_name or "").strip()

    if msg.startswith("/"):
        parts  = msg.split(None, 1)
        result = _handle_slash(parts[0], parts[1] if len(parts) > 1 else "", sid)
        if result:
            return result

    # Fix #2: load context for THIS session only
    scan_ctx = {}
    if req.session_id:
        try:
            scan_ctx = load_scan_context(req.session_id) or get_session(req.session_id) or {}
        except Exception:
            scan_ctx = get_session(req.session_id) or {}

    if project_name:
        scan_ctx["project_name"] = project_name

    # Fix #10: only inject scan data when message is scan-related
    inject_ctx = _is_scan_related(msg)
    system   = _build_system_prompt(scan_ctx, inject_context=inject_ctx)
    history  = _get_history(sid)
    messages = history + [{"role": "user", "content": msg}]

    loop = asyncio.get_event_loop()
    provider_name = "unknown"
    fallback_note = ""
    try:
        raw_reply, provider_name = await loop.run_in_executor(
            None, ai_router.chat, messages, system, 1200
        )
        # Fix #6: surface fallback reason immediately when provider degraded
        st = ai_router.status()
        if st.get("fallback_reason") and provider_name != "gemini":
            fallback_note = f"\n\n> ⚠️ *Using {st['display_name']} — {st['fallback_reason']}*"
    except Exception as e:
        _push_history(sid, "user", msg)
        return {"reply": _keyword_fallback(msg), "suggestions": [], "model": "keyword-fallback", "error": str(e)}

    _push_history(sid, "user", msg)

    auto = _try_parse_auto_scan(raw_reply)

    if auto:
        target    = auto.get("target", "")
        scan_type = auto.get("scan_type", "service_detect")
        reason    = auto.get("reason", "")
        try:
            validate_target(target)
            validate_scan_type(scan_type)
        except Exception as ve:
            err = f"Identified intent to scan **{target}** but validation failed: {ve}\n\nProvide a valid IP or hostname."
            _push_history(sid, "assistant", err)
            return {"reply": err, "model": provider_name}

        try:
            analysis    = await _run_scan_pipeline(target, scan_type, project_name=project_name, session_id=sid)
            final_reply = _format_scan_reply(analysis, reason) + fallback_note
            _push_history(sid, "assistant", final_reply)
            return {
                "reply":     final_reply,
                "action":    "scan_complete",
                "data":      {"session_id": analysis["session_id"], "target": target, "scan_type": scan_type},
                "model":     provider_name,
                "auto_scan": True,
            }
        except Exception as e:
            err = (f"Scan of `{target}` failed: `{e}`\n\n"
                   "Check: target reachable? nmap installed? try a different scan type.")
            _push_history(sid, "assistant", err)
            return {"reply": err, "model": provider_name, "error": str(e)}

    final_reply = raw_reply + fallback_note
    _push_history(sid, "assistant", final_reply)
    return {"reply": final_reply, "suggestions": [], "model": provider_name}

# ── Frontend Chat Persistence ─────────────────────────────────────────────────
# These routes persist the FULL interactive chat state (messages + rich widget
# tokens) so the entire workspace survives refresh/reconnect/restart.

class ChatSaveRequest(BaseModel):
    session_id: str
    messages: list
    project_name: Optional[str] = ""

@router.post("/chat/save")
async def save_chat(req: ChatSaveRequest, request: Request):
    """
    Save full frontend chat state (messages + rich tokens) to SQLite.
    FIX 1+4: Validates project name and rejects blank/unnamed sessions with no content.
    Called by SessionManager._backendPersist() on every message + beforeunload.
    """
    try:
        from app.files.session_manager import save_frontend_chat, _is_valid_project_name
        project_name = (req.project_name or "").strip()
        messages     = req.messages or []

        # FIX 1: Reject saves with no valid project name AND no messages
        if not _is_valid_project_name(project_name) and len(messages) == 0:
            return {"ok": False, "reason": "no_name_no_messages", "session_id": req.session_id}

        save_frontend_chat(req.session_id, messages, project_name)
        return {"ok": True, "session_id": req.session_id, "count": len(messages)}
    except Exception as e:
        logger.warning("save_chat failed: %s", e)
        return {"ok": False, "error": str(e)}


@router.get("/chat/load/{session_id}")
async def load_chat(session_id: str, request: Request):
    """
    Load saved frontend chat messages for a session.
    Called on startup to restore full chat state including rich widgets.
    """
    try:
        from app.files.session_manager import load_frontend_chat
        data = load_frontend_chat(session_id)
        return {
            "session_id": session_id,
            "messages": data.get("messages", []),
            "project_name": data.get("project_name", "")
        }
    except Exception as e:
        logger.warning("load_chat failed: %s", e)
        return {"session_id": session_id, "messages": [], "project_name": ""}


@router.get("/project-sessions")
async def get_project_sessions(request: Request):
    """
    Return only NAMED frontend project sessions from SQLite.
    FIX 5: Unnamed/blank sessions are never returned — they should not appear in History.
    """
    try:
        from app.files.session_manager import list_frontend_chats
        sessions = list_frontend_chats()
        return {"sessions": sessions}
    except Exception as e:
        logger.warning("project-sessions failed: %s", e)
        return {"sessions": []}


@router.post("/chat/purge-blank")
async def purge_blank_sessions(request: Request):
    """
    FIX 5: Manually trigger cleanup of blank/unnamed sessions from SQLite.
    Safe to call at any time — only removes sessions with no name and no messages.
    """
    try:
        from app.files.session_manager import purge_blank_frontend_chats
        removed = purge_blank_frontend_chats()
        return {"ok": True, "removed": removed}
    except Exception as e:
        logger.warning("purge-blank failed: %s", e)
        return {"ok": False, "error": str(e)}



# ── Scan route ─────────────────────────────────────────────────────────────────

@router.get("/templates")
async def get_templates():
    return {"templates": [k for k in SCAN_TEMPLATES if k != "enum_scripts"]}


@router.post("/scan")
async def run_scan(req: ScanRequest, request: Request):
    from app.api.scan_control import scan_state as _global_ss

    target       = validate_target(req.target)
    scan_type    = validate_scan_type(req.scan_type)
    project_name = (req.project_name or "").strip()

    # ── Concurrent-scan guard ────────────────────────────────────────────────
    # Reject a second scan while one is already running so it cannot silently
    # overwrite the first scan's results or PID.
    if _global_ss.running:
        raise HTTPException(
            status_code=409,
            detail=(
                f"A scan is already running against '{_global_ss.target}' "
                f"({_global_ss.scan_type}). Stop it first or wait for it to finish."
            ),
        )
    # ────────────────────────────────────────────────────────────────────────

    session_id   = create_session(target, scan_type, project_name=project_name)

    try:
        raw_output, xml_output, duration = execute_scan(get_scan_command(scan_type, target), target, scan_type)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")

    save_raw(session_id, raw_output, xml_output)
    parsed = parse_nmap_output(xml_output, raw_output)
    save_parsed(session_id, parsed)

    loop = asyncio.get_event_loop()
    versioned = await loop.run_in_executor(None, analyze_versions, parsed)
    cve_data  = await loop.run_in_executor(None, map_cves, versioned)
    # NVD enrichment: normalise local CVEs + augment with live NVD intelligence
    cve_data  = await loop.run_in_executor(None, enrich_with_nvd_sync, cve_data)
    context   = await loop.run_in_executor(None, analyze_context, cve_data)
    risk      = await loop.run_in_executor(None, calculate_risk, context)
    risk      = await loop.run_in_executor(None, correlate, risk)

    recommendation, explanation, ai_analysis, charts = await asyncio.gather(
        loop.run_in_executor(None, get_recommendation, risk, scan_type),
        loop.run_in_executor(None, generate_explanation, risk, {}),
        loop.run_in_executor(None, analyze_scan, risk),
        loop.run_in_executor(None, lambda: generate_chart_data({"risk": risk})),
    )

    # FIX3: also run deterministic rule-based engine alongside AI
    try:
        rule_based_analysis = await loop.run_in_executor(None, _rule_based_analyze, risk)
    except Exception as rb_err:
        logger.warning("FIX3: rule_based_analyze failed in /scan: %s", rb_err)
        rule_based_analysis = {}

    analysis = {
        "session_id": session_id, "target": target, "scan_type": scan_type,
        "duration": duration, "project_name": project_name,
        "parsed": parsed, "versioned": versioned, "cve_data": cve_data,
        "context": context, "risk": risk, "recommendation": recommendation,
        "explanation": explanation, "ai_analysis": ai_analysis,
        "rule_based_analysis": rule_based_analysis,   # FIX3: stored for compare module
        "charts": charts,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    save_analysis(session_id, analysis)
    return analysis


# ── History ────────────────────────────────────────────────────────────────────

@router.get("/history")
async def get_history(request: Request, target: Optional[str] = None, severity: Optional[str] = None):
    return {"sessions": list_sessions(target=target, severity=severity)}

@router.get("/history/trends")
async def get_history_trends(request: Request):
    return generate_history_trends(list_sessions())

@router.get("/session/{session_id}")
async def get_session_detail(session_id: str, request: Request):
    data = get_session(session_id)
    if not data:
        raise HTTPException(status_code=404, detail="Session not found")
    # FIX12: annotate CVEs with stored review status before returning
    data = annotate_with_review_status(data)
    return data

class RenameRequest(BaseModel):
    name: str

@router.delete("/session/{session_id}")
async def delete_session_route(session_id: str, request: Request):
    ok = delete_session(session_id)
    return {"ok": ok, "session_id": session_id}

@router.patch("/session/{session_id}/rename")
async def rename_session_route(session_id: str, req: RenameRequest, request: Request):
    ok = rename_session(session_id, req.name)
    return {"ok": ok, "session_id": session_id, "name": req.name}


# ── Reports ────────────────────────────────────────────────────────────────────

@router.post("/report")
async def generate_report(req: ReportRequest, request: Request):
    data = get_session(req.session_id)
    if not data:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"session_id": req.session_id, "json_path": build_report(req.session_id, data), "html_path": build_html_report(req.session_id, data)}

@router.get("/report/download/json/{session_id}")
async def download_json_report(session_id: str, request: Request):
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "sessions", session_id, "report", "report.json")
    if not os.path.exists(path): raise HTTPException(status_code=404, detail="Report not generated yet")
    return FileResponse(path, media_type="application/json", filename=f"scanwise_{session_id}.json")

@router.get("/report/download/html/{session_id}")
async def download_html_report(session_id: str, request: Request):
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "sessions", session_id, "report", "report.html")
    if not os.path.exists(path): raise HTTPException(status_code=404, detail="HTML report not generated yet")
    return FileResponse(path, media_type="text/html", filename=f"scanwise_report_{session_id}.html")


# ── Compare / Charts ───────────────────────────────────────────────────────────

@router.post("/compare")
async def compare_ai_vs_rules(req: CompareRequest, request: Request):
    data = get_session(req.session_id)
    if not data: raise HTTPException(status_code=404, detail="Session not found")
    ai_result = data.get("ai_analysis", {})
    if not ai_result: raise HTTPException(status_code=400, detail="No AI analysis in this session")
    # FIX3: prefer stored rule_based_analysis (computed at scan time) over re-computing on demand
    rule_result = data.get("rule_based_analysis") or _rule_based_analyze(data.get("risk", {}))
    return compare_analyses(rule_result, ai_result)

@router.get("/charts/{session_id}")
async def get_charts(session_id: str, request: Request):
    data = get_session(session_id)
    if not data: raise HTTPException(status_code=404, detail="Session not found")
    return data.get("charts") or generate_chart_data({"risk": data.get("risk", {})})


# ── AI Provider Status ─────────────────────────────────────────────────────────

@router.get("/ai/status")
async def get_ai_status(request: Request):
    try:
        return ai_router.status()
    except Exception as e:
        logger.warning("ai_router.status() failed: %s", e)
        return {
            "active_provider":  "rule-based",
            "gemini_available": False,
            "qwen_available":   False,
            "llama_available":  False,
            "gemini_available": False,
            "ollama_available": False,
            "display_name":     "Rule Engine",
            "display_provider": "No AI — run setup_env.sh",
            "qwen_model":       "qwen2.5-coder:3b",
            "llama_model":      "llama3.2:1b",
            "gemini_model":     "",
            "ollama_model":     "qwen2.5-coder:3b",
            "fallback_reason":  str(e),
        }



# ── FIX7: Multi-IP / CIDR Batch Scan ──────────────────────────────────────────

import ipaddress as _ipaddress

class BatchScanRequest(BaseModel):
    targets: str          # comma-separated IPs or a single CIDR
    scan_type: str
    project_name: Optional[str] = ""

def _expand_targets(raw: str) -> list:
    """
    FIX7: Parse comma-separated IPs or a CIDR block into a list of target strings.
    CIDR /24 is capped at 255 hosts to prevent runaway scans.
    """
    raw = raw.strip()
    results = []
    # If it contains '/' treat it as CIDR
    if '/' in raw and ',' not in raw:
        try:
            net = _ipaddress.ip_network(raw, strict=False)
            hosts = list(net.hosts())
            if len(hosts) > 255:
                hosts = hosts[:255]  # safety cap
            results = [str(h) for h in hosts]
        except ValueError:
            results = [raw]
    else:
        for part in raw.split(','):
            t = part.strip()
            if t:
                results.append(t)
    return results


@router.post("/scan/batch")
async def run_batch_scan(req: BatchScanRequest, request: Request):
    """
    FIX7: Scan multiple hosts (comma-separated or CIDR) in sequence.
    Returns per-host results and aggregate risk/CVE summary.
    """
    targets = _expand_targets(req.targets)
    if not targets:
        raise HTTPException(status_code=400, detail="No valid targets provided")
    if len(targets) > 50:
        raise HTTPException(status_code=400, detail="Batch limited to 50 hosts. Use a narrower CIDR.")

    scan_type    = validate_scan_type(req.scan_type)
    project_name = (req.project_name or "").strip()

    results      = []
    all_cve_ids  = set()
    risk_levels  = []

    for target in targets:
        try:
            validate_target(target)
        except Exception:
            results.append({"target": target, "status": "skipped", "reason": "invalid target"})
            continue
        try:
            analysis = await _run_scan_pipeline(target, scan_type, project_name=project_name)
            cves = [
                c.get("cve_id", "") for h in analysis.get("risk", {}).get("hosts", [])
                for p in h.get("ports", []) for c in p.get("cves", [])
            ]
            all_cve_ids.update(c for c in cves if c.startswith("CVE"))
            overall = analysis.get("risk", {}).get("hosts", [{}])[0].get(
                "risk_summary", {}).get("overall", "low")
            risk_levels.append(overall)
            results.append({
                "target":     target,
                "status":     "ok",
                "session_id": analysis["session_id"],
                "overall_risk": overall,
                "cve_count":  len(cves),
            })
        except Exception as e:
            results.append({"target": target, "status": "error", "reason": str(e)})

    # Aggregate risk: worst level wins
    level_order = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    aggregate_risk = max(risk_levels, key=lambda l: level_order.get(l, 0)) if risk_levels else "unknown"

    return {
        "batch_targets": len(targets),
        "completed":     sum(1 for r in results if r["status"] == "ok"),
        "aggregate_risk": aggregate_risk,
        "aggregate_cve_count": len(all_cve_ids),
        "aggregate_cves": list(all_cve_ids),
        "hosts": results,
    }


# ── FIX13: CVSS Vector Breakdown ──────────────────────────────────────────────

_CVSS_METRICS = {
    "AV": ("Attack Vector",         {"N":"Network","A":"Adjacent","L":"Local","P":"Physical"}),
    "AC": ("Attack Complexity",     {"L":"Low","H":"High"}),
    "PR": ("Privileges Required",   {"N":"None","L":"Low","H":"High"}),
    "UI": ("User Interaction",      {"N":"None","R":"Required"}),
    "S":  ("Scope",                 {"U":"Unchanged","C":"Changed"}),
    "C":  ("Confidentiality",       {"N":"None","L":"Low","H":"High"}),
    "I":  ("Integrity",             {"N":"None","L":"Low","H":"High"}),
    "A":  ("Availability",          {"N":"None","L":"Low","H":"High"}),
}

def _parse_cvss_vector(vector_string: str) -> dict:
    """
    FIX13: Parse a CVSSv3 vector string like
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
    into a human-readable breakdown dict.
    """
    result = {}
    if not vector_string:
        return result
    # Strip 'CVSS:3.x/' prefix
    parts = vector_string.split("/")
    for part in parts:
        if ":" not in part:
            continue
        key, val = part.split(":", 1)
        if key in _CVSS_METRICS:
            label, mapping = _CVSS_METRICS[key]
            result[key] = {
                "metric": label,
                "code":   val,
                "value":  mapping.get(val, val),
            }
    return result


class CVSSVectorRequest(BaseModel):
    vector: str                        # raw CVSS vector string
    cve_id: Optional[str] = ""


@router.post("/cvss/breakdown")
async def cvss_breakdown(req: CVSSVectorRequest):
    """
    FIX13: Return human-readable CVSS v3 metric breakdown from a vector string.
    Frontend can call this when rendering CVE detail panels.
    """
    parsed = _parse_cvss_vector(req.vector)
    if not parsed:
        raise HTTPException(status_code=400, detail="Could not parse CVSS vector string")
    return {
        "cve_id":    req.cve_id,
        "vector":    req.vector,
        "breakdown": parsed,
        "order":     ["AV","AC","PR","UI","S","C","I","A"],
    }


# ── Multi-IP Scan (new modular system) ────────────────────────────────────────

import uuid as _uuid
from app.multi_scan.parser import parse_targets_txt, MAX_TARGETS
from app.multi_scan.orchestrator import (
    create_job, get_job, run_multi_scan, aggregate_results,
)

class MultiScanStartRequest(BaseModel):
    targets_txt: str          # raw content of uploaded .txt file
    scan_type: str
    project_name: Optional[str] = ""

class MultiScanPollRequest(BaseModel):
    job_id: str


@router.post("/scan/multi/start")
async def multi_scan_start(req: MultiScanStartRequest, request: Request):
    """
    Parse the targets TXT, validate, create a queue job, and start scanning
    in the background.  Returns job_id immediately so the frontend can poll.
    """
    parsed = parse_targets_txt(req.targets_txt)
    valid  = parsed["valid"]

    if not valid:
        return {
            "ok": False,
            "error": "No valid targets found in the uploaded file.",
            "invalid": parsed["invalid"],
        }

    scan_type    = validate_scan_type(req.scan_type)
    project_name = (req.project_name or "").strip()
    job_id       = str(_uuid.uuid4())[:8]

    queue = create_job(job_id, valid, scan_type, project_name)

    async def _pipeline(target, st, pn):
        return await _run_scan_pipeline(target, st, project_name=pn)

    # Fire-and-forget — job runs in background, frontend polls
    asyncio.create_task(run_multi_scan(queue, _pipeline))

    return {
        "ok":      True,
        "job_id":  job_id,
        "targets": valid,
        "invalid": parsed["invalid"],
        "total":   len(valid),
    }


@router.get("/scan/multi/status/{job_id}")
async def multi_scan_status(job_id: str, request: Request):
    """Poll the status of a running multi-scan job."""
    queue = get_job(job_id)
    if not queue:
        raise HTTPException(status_code=404, detail="Job not found")
    state = queue.to_dict()
    if queue.done:
        state["aggregate"] = aggregate_results(queue.results)
    return state


@router.post("/scan/multi/validate")
async def multi_scan_validate(req: MultiScanStartRequest, request: Request):
    """
    Dry-run validation of a targets TXT without starting a scan.
    Returns parsed valid/invalid lists for frontend preview.
    """
    parsed = parse_targets_txt(req.targets_txt)
    return {
        "valid":   parsed["valid"],
        "invalid": parsed["invalid"],
        "skipped": parsed["skipped"],
        "total":   parsed["total"],
        "max":     MAX_TARGETS,
    }


# ── AI Patch Guidance endpoint — used by /patch all dashboard ─────────────────

class PatchGuidanceRequest(BaseModel):
    service:  str
    port:     int
    version:  str = "unknown"
    cve_id:   str = "unknown"
    severity: str = "medium"
    session_id: str = ""

# NOTE: /patch/guidance is now handled by app/api/patch_api.py (patch_router)
# registered in main.py as: app.include_router(patch_router, prefix="/api/patch")
# The old inline route has been removed to prevent duplicate registration.

