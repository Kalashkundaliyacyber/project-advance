"""ThreatWeave AI — API Routes v5.0
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
from app.recommendation.recommender import get_recommendation
from app.explanation.explainer import generate_explanation
from app.ai_analysis import analyze_scan, explain_cve, _rule_based_analyze
from app.ai.routing.ai_router import ai_router
from app.remediation import resolve_patch, resolve_patches_batch, get_resolution_stats
from app.remediation.confidence import confidence_label
from app.visualization.charts import generate_chart_data, generate_history_trends
from app.report.template_builder import build_report
from app.report.html_report import build_html_report
from app.api.findings import annotate_with_review_status
from app.services.ai.prompt_templates import CHAT_SYSTEM_TEMPLATE
from app.files.session_manager import (
    create_session, save_raw, save_parsed, save_analysis,
    list_sessions, get_session, delete_session, rename_session,
    save_chat_history, load_chat_history,
    save_scan_context, load_scan_context,
)

logger = logging.getLogger("threatweave.routes")
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

class ConfirmPortRequest(BaseModel):
    """Single-port NSE confirmation request — called sequentially from the
    frontend, one port at a time, to avoid parallel nmap overload."""
    target:   str
    port:     int
    protocol: str  = "tcp"
    service:  str  = ""
    product:  str  = ""
    version:  str  = ""
    cves:     list = []   # list of CVE ID strings, e.g. ["CVE-2011-2523"]

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

    base = f"""You are ThreatWeave AI, a defensive cybersecurity assistant for network scanning.

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
    if cmd == "/vuln":
        # With no args: trigger client-side vuln dashboard (uses last scan data)
        # With a service name: trigger targeted CVE lookup
        svc = args.strip()
        if svc:
            return {"reply": f"Showing CVE intelligence for **{svc}**.", "action": "vuln_lookup", "data": {"service": svc}}
        # No args → signal frontend to open the full vuln dashboard
        return {"reply": "__VULN_DASHBOARD__", "action": "vuln_lookup", "data": {}}

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

            # 4-Layer Intelligent Patch Resolution (Layer1→Vendor→NVD→AI)
            patch_results = []
            for _entry in all_ports:
                try:
                    _pd = resolve_patch(
                        cve_id      = _entry["cve_id"],
                        service     = _entry["service"] or f"port {_entry['port']}",
                        version     = _entry["version"] or "unknown",
                        description = _entry.get("cve_desc", ""),
                    )
                    _cmds = _pd.get("commands") or _pd.get("patch_command") or {}
                    _upg  = next(iter(_cmds.values()), "") if isinstance(_cmds, dict) else ""
                    _pd.update({
                        "ip":             _entry["ip"],
                        "port":           _entry["port"],
                        "service":        _entry["service"],
                        "risk_level":     _entry["risk_level"],
                        "risk_score":     _entry["risk_score"],
                        "cve_id":         _entry["cve_id"],
                        "cve_desc":       _entry["cve_desc"],
                        "all_cves":       _entry["all_cves"],
                        "upgrade_command": _upg,
                        "engine": (
                            f"{_pd.get('confidence_label', _pd.get('source','?'))} "
                            f"[{_pd.get('confidence',0)}%]"
                        ),
                    })
                    patch_results.append(_pd)
                except Exception as _pe:
                    logger.warning("Patch resolution failed for port %s: %s", _entry.get("port"), _pe)
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
                        "engine": "Rule Engine [30%]",
                        "confidence": 30,
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

            # 4-Layer Intelligent Patch Resolution
            try:
                patch_data = resolve_patch(
                    cve_id      = cve_id,
                    service     = svc_name,
                    version     = svc_version or "unknown",
                    description = cve_desc,
                )
                # Normalize for frontend compatibility
                _cmds = patch_data.get("commands") or patch_data.get("patch_command") or {}
                if _cmds and not patch_data.get("upgrade_command"):
                    patch_data["upgrade_command"] = next(iter(_cmds.values()), "")
                patch_data["engine"] = (
                    f"{patch_data.get('confidence_label', patch_data.get('source','?'))} "
                    f"[{patch_data.get('confidence', 0)}%]"
                )
            except Exception as _pe:
                logger.warning("resolve_patch failed: %s", _pe)
                patch_data = {
                    "service":         svc_name,
                    "port":            port_arg,
                    "severity":        cve_severity,
                    "summary":         f"Apply latest security patches for {svc_name} on port {port_arg}.",
                    "upgrade_command": f"apt update && apt install --only-upgrade {svc_name}",
                    "mitigation":      f"Restrict port {port_arg} access: ufw deny {port_arg}",
                    "engine":          "Rule Engine [30%]",
                    "confidence":      30,
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
                "- `/patch all` — AI patch guide for ALL vulnerable ports\n"
                "- `/patch <service> <port>` — e.g. `/patch ftp 21` or `/patch ssh 22`\n"
                "- `/patch <ip> <port>` — e.g. `/patch 192.168.1.1 22`"
            ),
            "action": "none",
        }
    if cmd == "/history":
        return {"reply": "The `/history` command has been removed. Use the sidebar drawer (☰) to browse past scan sessions.", "action": "none"}
    if cmd == "/clear":
        # Fix #12: wipe AI history in DB AND session files + DB record
        errors = []
        try:
            save_chat_history(sid, [])
        except Exception as exc:
            logger.warning("/clear: failed to wipe chat history for %s: %s", sid, exc)
            errors.append(f"chat history: {exc}")
        try:
            delete_session(sid)
        except Exception as exc:
            logger.warning("/clear: failed to delete session %s: %s", sid, exc)
            errors.append(f"session data: {exc}")
        if errors:
            return {
                "reply": f"Partial clear — some data could not be removed: {'; '.join(errors)}",
                "action": "clear_chat",
            }
        return {"reply": "Chat, memory, and session data cleared.", "action": "clear_chat"}
    if cmd == "/settings":
        st        = ai_router.status()
        qwen_tag  = f"✅ {st.get('qwen_model','qwen2.5:7b')}"      if st.get("qwen_available")     else "❌ offline — ollama pull qwen2.5:7b"
        llama_tag = f"✅ {st.get('llama_chat_model','llama3.2:3b')}/{st.get('llama_gen_model','llama3.1:8b')}" if st.get("llama_available") else "❌ offline — ollama pull llama3.2:3b"
        ds_tag    = f"✅ {st.get('deepseek_model','deepseek-r1:8b')}"  if st.get("deepseek_available")  else "❌ offline — ollama pull deepseek-r1:8b"
        from app.ai.cache.ai_response_cache import ai_response_cache
        cache_stats = ai_response_cache.stats()
        try:
            res_stats  = get_resolution_stats()
            repo_total = (res_stats.get("layer1_repository") or {}).get("total", 0)
            nvd_hr     = (res_stats.get("layer3_nvd") or {}).get("hit_rate", "—")
            ai_hr      = (res_stats.get("layer4_ai") or {}).get("hit_rate", "—")
            kb_total   = (res_stats.get("learning_kb") or {}).get("total", 0)
            graph_n    = (res_stats.get("knowledge_graph") or {}).get("nodes", 0)
        except Exception:
            repo_total = nvd_hr = ai_hr = kb_total = graph_n = "—"
        return {
            "reply": (
                "**⚙️ ThreatWeave AI Settings**\n\n"
                "**🤖 Model Stack (4 Local Models)**\n"
                f"  • Qwen 2.5 7B Instruct (Primary): {qwen_tag}\n"
                f"  • Llama 3.2 3B / 3.1 8B (Fast/General): {llama_tag}\n"
                f"  • DeepSeek R1 8B Distill (Security): {ds_tag}\n"
                f"  • Rule Engine (Emergency): ✅ always available\n\n"
                f"**Active:** `{st['display_name']}` · {st['display_provider']}\n\n"
                "**🔧 4-Layer Patch Resolution**\n"
                f"  • Layer 1 — Local Repository:  {repo_total} patches stored\n"
                f"  • Layer 2 — Vendor Advisory:   Ubuntu USN / Red Hat / Known advisories\n"
                f"  • Layer 3 — NVD Cache:         {nvd_hr} hit rate (7-day TTL)\n"
                f"  • Layer 4 — AI Engine:         {ai_hr} cache hit rate\n"
                f"  • Learning KB:                 {kb_total} approved patches\n"
                f"  • Knowledge Graph:             {graph_n} nodes\n\n"
                "**📦 Caching**\n"
                f"  • AI Response Cache: {cache_stats['total_entries']} entries ({cache_stats['hit_rate']} hit rate)\n\n"
                "**🖥️ Server**\n"
                f"  • URL: `http://localhost:{os.environ.get('PORT', '3332')}`\n"
                f"  • Token Auth: `{'enabled' if os.environ.get('API_TOKEN') else 'disabled'}`\n\n"
                "**📋 Slash Commands:** `/help` for full list\n"
                "**New:** `/patch CVE-XXXX` · `/fix <service>` · `/advisory CVE-XXXX` · `/remediate critical`"
            ),
            "action": "none"
        }
    if cmd == "/stop":
        return {"reply": "Stopping scan...", "action": "stop_scan"}

    # ── Phase 19: Extended slash command system ─────────────────────────────
    if cmd == "/risk":
        ctx = load_scan_context(sid) or {}
        hosts = (ctx.get("risk") or {}).get("hosts", [])
        if not hosts:
            return {"reply": "⚠️ No scan data found. Run `/scan <ip>` first.", "action": "none"}
        try:
            from app.analysis.security_score import calculate_security_score
            score_result = calculate_security_score(ctx, {})
            grade   = score_result.get("grade", "?")
            score   = score_result.get("score", 0)
            label   = score_result.get("label", "")
            dims    = score_result.get("dimensions", [])
            recs    = score_result.get("recommendations", [])
            reply   = f"**🔐 Security Score: {grade} ({score}/100) — {label}**\n\n"
            reply  += "**Dimension Breakdown:**\n"
            for d in dims:
                bar = "█" * int(d["score"] / 10) + "░" * (10 - int(d["score"] / 10))
                reply += f"  {d['name']:25s} [{bar}] {d['score']:5.1f}/100 ({d['weight']})\n"
            if recs:
                reply += "\n**Top Recommendations:**\n" + "\n".join(f"- {r}" for r in recs[:3])
        except Exception as e:
            reply = f"Risk summary unavailable: {e}"
        return {"reply": reply, "action": "none"}

    if cmd == "/projects":
        try:
            sessions = list_sessions()
            if not sessions:
                return {"reply": "No projects found. Start a scan to create one.", "action": "none"}
            reply = f"**📁 Projects ({len(sessions)} sessions)**\n\n"
            for s in sessions[:15]:
                proj = s.get("project_name") or s.get("target", "?")
                ts   = s.get("timestamp", "")[:10]
                risk = s.get("overall_risk", "?").upper()
                ports= s.get("open_ports", 0)
                reply += f"- `{proj}` · {ts} · Risk: **{risk}** · {ports} ports\n"
            if len(sessions) > 15:
                reply += f"\n_...and {len(sessions)-15} more. Use the sidebar drawer to browse._"
        except Exception as e:
            reply = f"Could not load projects: {e}"
        return {"reply": reply, "action": "none"}

    if cmd == "/cve":
        cve_id = args.strip().upper()
        if not cve_id:
            return {"reply": "Usage: `/cve CVE-2024-6387`", "action": "none"}
        try:
            from app.analysis.threat_intel import lookup_kev
            # Use 4-layer resolver for CVE intelligence
            entry = resolve_patch(cve_id=cve_id)
            kev   = lookup_kev(cve_id)
            reply = f"**🔍 CVE Intelligence: `{cve_id}`**\n\n"
            if kev:
                reply += "🚨 **IN CISA KEV CATALOG** — Actively Exploited\n"
                reply += f"  Product: {kev['vendor']} {kev['product']}\n"
                reply += f"  Added: {kev['date_added']}\n"
                if kev.get("known_ransomware"):
                    reply += "  ⚠️ Associated with ransomware campaigns\n"
                reply += "\n"
            if entry and entry.get("patch_found"):
                conf_lbl = entry.get("confidence_label", entry.get("source", "?"))
                reply += f"**Source:** {conf_lbl}  **Confidence:** {entry.get('confidence',0)}%\n"
                reply += f"**Layer:** {entry.get('layer','?').replace('_',' ').title()}\n"
                reply += f"**Fix Version:** `{entry.get('fix_version') or entry.get('fixed_version') or 'latest'}`\n"
                cmds = entry.get("commands") or entry.get("patch_command") or {}
                if cmds:
                    reply += "\n**Patch Commands:**\n"
                    for os_name, cmd_str in list(cmds.items())[:3]:
                        reply += f"```bash\n# {os_name}\n{cmd_str}\n```\n"
                url = entry.get("vendor_url") or entry.get("official_url", "")
                if url:
                    reply += f"\n[Vendor Advisory]({url})\n"
                if entry.get("mitigation"):
                    reply += f"\n**🛡️ Mitigation:** {entry['mitigation']}\n"
            else:
                reply += "_No patch data found. Try `/patch <service> <port>` for targeted guidance._"
        except Exception as e:
            reply = f"CVE lookup error: {e}"
        return {"reply": reply, "action": "none"}

    # ── New 4-Layer patch commands ─────────────────────────────────────────────

    if cmd == "/advisory":
        # /advisory CVE-2024-6387 — show full advisory with why/confidence/source
        cve_id = args.strip().upper()
        if not cve_id:
            return {"reply": "Usage: `/advisory CVE-2024-6387`", "action": "none"}
        try:
            entry = resolve_patch(cve_id=cve_id)
            if not entry or not entry.get("patch_found"):
                return {"reply": f"No advisory data found for `{cve_id}`.", "action": "none"}
            layer    = entry.get("layer", "unknown").replace("_", " ").title()
            conf_lbl = entry.get("confidence_label", entry.get("source", "?"))
            conf_val = entry.get("confidence", 0)
            reply  = f"**📋 Security Advisory: `{cve_id}`**\n\n"
            reply += f"**Why this patch was chosen:**\n"
            reply += f"  • Source: **{conf_lbl}** via {layer}\n"
            reply += f"  • Confidence: **{conf_val}%**\n"
            reply += (
                f"  • Resolution order: Local Repository → Vendor Advisory → "
                f"NVD Cache → AI Engine\n"
            )
            reply += f"  • This result came from: **{layer}**\n\n"
            if entry.get("title"):
                reply += f"**Title:** {entry['title']}\n"
            reply += f"**Severity:** {entry.get('severity','unknown').upper()}\n"
            reply += f"**Fix Version:** `{entry.get('fix_version') or entry.get('fixed_version') or 'latest'}`\n"
            cmds = entry.get("commands") or entry.get("patch_command") or {}
            if cmds:
                reply += "\n**Patch Commands:**\n"
                for os_nm, cmd_str in list(cmds.items())[:4]:
                    reply += f"```bash\n# {os_nm}\n{cmd_str}\n```\n"
            url = entry.get("vendor_url") or entry.get("official_url", "")
            if url:
                reply += f"\n**Official Advisory:** {url}\n"
            if entry.get("mitigation"):
                reply += f"\n**🛡️ Mitigation:** {entry['mitigation']}\n"
            if entry.get("verification"):
                reply += f"\n**✅ Verification:** `{entry['verification']}`\n"
        except Exception as e:
            reply = f"Advisory lookup error: {e}"
        return {"reply": reply, "action": "none"}

    if cmd == "/fix":
        # /fix openssh  — resolve by service name, no port needed
        svc = args.strip()
        if not svc:
            return {"reply": "Usage: `/fix <service>` e.g. `/fix openssh`", "action": "none"}
        try:
            # Look up any CVE for this service in current scan context, then resolve
            ctx    = load_scan_context(sid) or {}
            cve_id = "unknown"
            for h in (ctx.get("risk") or {}).get("hosts", []):
                for p in h.get("ports", []):
                    if svc.lower() in p.get("service", "").lower():
                        cves = p.get("cves", [])
                        if cves:
                            cve_id = cves[0].get("cve_id", "unknown")
                        break

            entry  = resolve_patch(cve_id=cve_id, service=svc)
            conf_lbl = entry.get("confidence_label", entry.get("source", "?"))
            reply  = f"**🔧 Fix Guide — {svc}**\n\n"
            reply += f"**Source:** {conf_lbl}  **Confidence:** {entry.get('confidence',0)}%\n"
            reply += f"**Layer:** {entry.get('layer','?').replace('_',' ').title()}\n\n"
            cmds = entry.get("commands") or entry.get("patch_command") or {}
            if cmds:
                for os_nm, cmd_str in list(cmds.items())[:3]:
                    reply += f"```bash\n# {os_nm}\n{cmd_str}\n```\n"
            else:
                reply += f"```bash\napt-get update && apt-get upgrade -y {svc}\n```\n"
            if entry.get("mitigation"):
                reply += f"\n**🛡️ Mitigation:** {entry['mitigation']}\n"
            url = entry.get("vendor_url") or entry.get("official_url", "")
            if url:
                reply += f"\n[Advisory]({url})\n"
        except Exception as e:
            reply = f"Fix lookup error: {e}"
        return {"reply": reply, "action": "none"}

    if cmd == "/export":
        fmt = args.strip().lower() or "html"
        if fmt not in ("pdf", "html", "json"):
            fmt = "html"
        return {"reply": f"Exporting report as **{fmt.upper()}**...", "action": "open_report_modal", "data": {"format": fmt}}

    if cmd == "/remediate":
        # /remediate [critical|high|all]
        severity_filter = args.strip().lower() or "all"
        if severity_filter not in ("critical", "high", "medium", "all"):
            return {"reply": "__PATCH_ALL__", "action": "patch_all", "data": {}}

        # If filtering by severity, load scan context and resolve only matching vulns
        ctx   = load_scan_context(sid) or {}
        hosts = (ctx.get("risk") or {}).get("hosts", [])
        if not hosts:
            return {"reply": "__PATCH_ALL__", "action": "patch_all", "data": {}}

        all_ports = []
        for _h in hosts:
            for _p in _h.get("ports", []):
                _cves    = _p.get("cves", [])
                _top_cve = _cves[0] if _cves else {}
                _sev     = (_top_cve.get("severity") or _p.get("risk", {}).get("level", "low")).lower()
                if severity_filter != "all" and _sev != severity_filter:
                    continue
                all_ports.append({
                    "ip":         _h.get("ip", ""),
                    "port":       _p.get("port"),
                    "service":    _p.get("service", ""),
                    "version":    _p.get("version", "") or _p.get("product", ""),
                    "risk_level": (_p.get("risk") or {}).get("level", "low"),
                    "risk_score": (_p.get("risk") or {}).get("score", 0),
                    "cve_id":     _top_cve.get("cve_id", "unknown"),
                    "severity":   _sev,
                    "cve_desc":   _top_cve.get("description", ""),
                    "all_cves":   _cves,
                })

        if not all_ports:
            return {
                "reply": f"No **{severity_filter.upper()}** vulnerabilities found in current scan.",
                "action": "none",
            }

        patch_results = []
        for _entry in all_ports:
            try:
                _pd = resolve_patch(
                    cve_id      = _entry["cve_id"],
                    service     = _entry["service"],
                    version     = _entry["version"] or "unknown",
                    description = _entry.get("cve_desc", ""),
                )
                _cmds = _pd.get("commands") or _pd.get("patch_command") or {}
                _upg  = next(iter(_cmds.values()), "") if isinstance(_cmds, dict) else ""
                _pd.update({
                    "ip":              _entry["ip"],
                    "port":            _entry["port"],
                    "service":         _entry["service"],
                    "risk_level":      _entry["risk_level"],
                    "risk_score":      _entry["risk_score"],
                    "cve_id":          _entry["cve_id"],
                    "cve_desc":        _entry["cve_desc"],
                    "all_cves":        _entry["all_cves"],
                    "upgrade_command": _upg,
                    "engine": (
                        f"{_pd.get('confidence_label', _pd.get('source','?'))} "
                        f"[{_pd.get('confidence', 0)}%]"
                    ),
                })
                patch_results.append(_pd)
            except Exception:
                patch_results.append({**_entry, "confidence": 30, "engine": "Rule Engine [30%]"})

        _risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        patch_results.sort(key=lambda x: _risk_order.get(x.get("risk_level", "low"), 3))

        return {
            "reply":          "__PATCH_ALL_DATA__",
            "action":         "patch_all_data",
            "patch_all_data": patch_results,
        }

    if cmd == "/model":
        st = ai_router.status()
        qwen_ok = st.get("qwen_available", False)
        llama_ok = st.get("llama_available", False)
        ds_ok   = st.get("deepseek_available", False)
        reply   = "**🤖 AI Model Stack Status**\n\n"
        reply  += f"  • Qwen 2.5 7B Instruct (Primary):   {'✅' if qwen_ok  else '❌'} `{st.get('qwen_model','qwen2.5:7b')}`\n"
        reply  += f"  • Llama 3.2 3B (Fast Chat):          {'✅' if llama_ok else '❌'} `{st.get('llama_chat_model','llama3.2:3b')}`\n"
        reply  += f"  • Llama 3.1 8B (General):            {'✅' if llama_ok else '❌'} `{st.get('llama_gen_model','llama3.1:8b')}`\n"
        reply  += f"  • DeepSeek R1 8B Distill (Security): {'✅' if ds_ok   else '❌'} `{st.get('deepseek_model','deepseek-r1:8b')}`\n"
        reply  += f"  • Rule Engine (Emergency):           ✅ always available\n\n"
        reply  += f"**Active:** {st['display_name']} · {st['display_provider']}\n\n"
        if not any([qwen_ok, llama_ok, ds_ok]):
            reply += "⚠️ No models running! Start Ollama and pull models:\n"
            reply += "```bash\nollama pull qwen2.5:7b\nollama pull llama3.2:3b\nollama pull llama3.1:8b\nollama pull deepseek-r1:8b\n```"
        return {"reply": reply, "action": "none"}

    return None


# ── Auto-scan pipeline ─────────────────────────────────────────────────────────

async def _analyze_scan_capped(risk: dict, budget: float = 12.0) -> dict:
    """
    Run analyze_scan() — the AI provider chain (DeepSeek -> Qwen -> Llama,
    each with its OWN 60-90s internal HTTP timeout) — under a hard overall
    time budget.

    THE BUG: asyncio.gather() in _run_scan_pipeline waits for its SLOWEST
    member. analyze_scan() only raises (which triggers ITS OWN internal
    rule-based fallback) after ALL THREE providers individually time out —
    90s + 60s + 60s = 210 seconds, EVERY scan, even though the result is
    discarded and rule-based is used anyway. The entire /api/scan response —
    and therefore every chatbot table that depends on it — was blocked for
    3.5 minutes per scan.

    THE FIX: cap analyze_scan at `budget` seconds. If it doesn't return in
    time, return {} immediately — rule_based_analysis (computed separately
    a few lines below, always fast, no network calls) is the data the
    frontend already falls back to whenever ai_analysis is empty/marked
    "rule-based-fallback". The abandoned AI call keeps running in its
    executor thread in the background (Python can't hard-cancel a running
    thread) but no longer blocks the user-facing response.
    """
    loop = asyncio.get_event_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, analyze_scan, risk),
            timeout=budget,
        )
    except asyncio.TimeoutError:
        logger.warning(
            "analyze_scan exceeded %.0fs budget (AI providers slow/unloaded) — "
            "returning empty ai_analysis; rule_based_analysis covers this. "
            "(AI call continues in background thread, result discarded.)",
            budget,
        )
        return {"engine": "rule-based-fallback", "fallback_reason": f"AI analysis exceeded {budget:.0f}s budget"}
    except Exception as e:
        logger.warning("analyze_scan raised unexpectedly: %s", e)
        return {"engine": "rule-based-fallback", "fallback_reason": str(e)}


async def _run_scan_pipeline(target: str, scan_type: str, project_name: str = "", session_id: str = "") -> dict:
    target    = validate_target(target)
    scan_type = validate_scan_type(scan_type)
    sid       = create_session(target, scan_type, project_name=project_name)
    cmd       = get_scan_command(scan_type, target)

    loop = asyncio.get_event_loop()

    # CRITICAL: execute_scan MUST run in an executor — if called directly on the
    # async event loop thread it blocks the loop, preventing call_soon_threadsafe
    # SSE port_found events from being delivered until after the scan completes.
    raw_output, xml_output, duration = await loop.run_in_executor(
        None, execute_scan, cmd, target, scan_type
    )
    save_raw(sid, raw_output, xml_output)

    parsed = parse_nmap_output(xml_output, raw_output)
    save_parsed(sid, parsed)

    versioned = await loop.run_in_executor(None, analyze_versions, parsed)
    cve_data  = await loop.run_in_executor(None, map_cves, versioned)
    # NVD enrichment: normalise local CVEs + augment with live NVD intelligence
    cve_data  = await loop.run_in_executor(None, enrich_with_nvd_sync, cve_data)
    context   = await loop.run_in_executor(None, analyze_context, cve_data)
    risk      = await loop.run_in_executor(None, calculate_risk, context)

    recommendation, explanation, ai_analysis, charts = await asyncio.gather(
        loop.run_in_executor(None, get_recommendation, risk, scan_type),
        loop.run_in_executor(None, generate_explanation, risk, {}),
        _analyze_scan_capped(risk, budget=12.0),
        loop.run_in_executor(None, lambda: generate_chart_data({"risk": risk})),
    )

    # FIX3: also run deterministic rule-based engine so compare module always has both outputs
    try:
        rule_based_analysis = await loop.run_in_executor(None, _rule_based_analyze, risk)
    except Exception as rb_err:
        logger.warning("FIX3: rule_based_analyze failed: %s", rb_err)
        rule_based_analysis = {}

    # Feature 4: Threat Intelligence Correlation — unified threat profiles per CVE
    try:
        from app.intelligence.threat_correlator import correlate_scan_threats
        all_cves = []
        for host in (cve_data.get("hosts") or []):
            for port in (host.get("ports") or []):
                all_cves.extend(port.get("cves") or [])
        threat_correlation = correlate_scan_threats(all_cves) if all_cves else {}
    except Exception as tc_err:
        logger.warning("Threat correlation failed: %s", tc_err)
        threat_correlation = {}

    analysis = {
        "session_id": sid, "target": target, "scan_type": scan_type,
        "project_name": project_name, "duration": duration,
        "parsed": parsed, "versioned": versioned, "cve_data": cve_data,
        "context": context, "risk": risk, "recommendation": recommendation,
        "explanation": explanation, "ai_analysis": ai_analysis,
        "rule_based_analysis": rule_based_analysis,   # FIX3: stored alongside AI output
        "threat_correlation":  threat_correlation,     # Feature 4: unified threat profiles
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

    # ── NSE confirmation: handled by the frontend now ──────────────────────
    # The chatbot's "NSE Confirmation" table (statics/chatbot/scan.js,
    # _runSequentialConfirmation) drives confirmation itself — one targeted
    # nmap run per port via POST /api/scan/confirm-port, sequentially, with
    # a 400ms gap between ports. That fully replaces the old background
    # `confirm_unconfirmed_ports` thread, which:
    #   - crashed with `AttributeError: 'dict' object has no attribute 'lower'`
    #     (it passed raw CVE dicts into find_scripts_for_port(), which expects
    #     plain CVE-ID strings — see script_selector.py for the underlying fix)
    #   - ran a second, uncontrolled NSE scan in parallel with the new
    #     sequential one, which is exactly the "don't run them all at once"
    #     problem the sequential table was built to avoid.
    #
    # All that's left to do here is signal stream_end so the legacy SSE-based
    # live table (statics/chatbot/scan.js, _renderLiveVulnTable) closes its
    # EventSource cleanly instead of waiting on a timeout.
    try:
        from app.api.scan_control import scan_state as _ss_ref
        _ss_ref.broadcast_stream_end()
    except Exception as _se:
        logger.warning("stream_end broadcast failed for %s: %s", target, _se)

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
        return (f"**Hello!** I am ThreatWeave AI — powered by {st['display_name']}.\n\n"
                "Type `/scan <ip>` to start scanning, or `/help` for all commands.")
    st = ai_router.status()
    if not st["qwen_available"] and not st["llama_available"] and not st.get("deepseek_available"):
        return (
            "No AI provider is available. To enable:\n\n"
            "1. **Run setup_env.sh** — installs Ollama + pulls Qwen2.5-Coder 7B and Llama 3.2 3B automatically\n"
            "2. Or manually: `ollama pull qwen2.5-coder:7b && ollama pull llama3.2:3b`\n"
            "3. Cloud backup:      set `OPENROUTER_API_KEY` in `.env`\n\n"
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
        if st.get("fallback_reason") and provider_name not in ("rule-based",):
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



@router.post("/scan/confirm-port")
async def confirm_single_port(req: ConfirmPortRequest):
    """
    POST /api/scan/confirm-port

    Run a targeted NSE confirmation scan for ONE port and return the result.
    The frontend calls this sequentially (one at a time, 400 ms gap between
    calls) so we never run parallel nmap instances and never overload the system.

    Flow:
      1. find_scripts_for_port() picks the best matching Kali nmap scripts
         from /usr/share/nmap/scripts/ for this service/version/CVE combo.
      2. run_confirmation_scan() runs a single-port nmap with those scripts.
      3. interpret_script_output() classifies the result.
      4. Return {vuln_status, script_used, scripts_tried, evidence}.
    """
    from app.scanner.script_selector import (
        find_scripts_for_port,
        run_confirmation_scan,
        interpret_script_output,
    )

    loop = asyncio.get_event_loop()

    # ── Pick best Kali NSE scripts for this service ─────────────────────────
    scripts = find_scripts_for_port(
        service=req.service,
        product=req.product,
        version=req.version,
        cves=req.cves,          # already strings: ["CVE-2011-2523", ...]
    )

    if not scripts:
        logger.info(
            "confirm-port: no matching scripts for %s:%d (%s %s) — marking UNCONFIRMED",
            req.target, req.port, req.service, req.version
        )
        return {
            "vuln_status":   "UNCONFIRMED",
            "script_used":   None,
            "scripts_tried": [],
            "evidence":      "No matching NSE scripts found on this Kali system for the detected service/version",
        }

    logger.info(
        "confirm-port: %s:%d — running scripts: %s",
        req.target, req.port, ", ".join(scripts)
    )

    # ── Run the nmap confirmation scan in a thread (blocking call) ──────────
    output = await loop.run_in_executor(
        None,
        run_confirmation_scan,
        req.target, req.port, req.protocol, scripts,
    )

    final_status = interpret_script_output(output or "")

    # ── Extract the most meaningful lines from the script output ────────────
    evidence = ""
    if output:
        # Grab lines that actually say something useful
        useful_keywords = [
            "vulnerable", "not vulnerable", "state:", "evidence",
            "exploit", "cve", "risk", "description",
        ]
        evidence_lines = [
            l.strip() for l in output.split("\n")
            if l.strip() and any(k in l.lower() for k in useful_keywords)
        ]
        evidence = " | ".join(evidence_lines[:3])[:400]
        if not evidence:
            # Fall back to first 200 chars of raw output
            evidence = output.strip()[:200]

    return {
        "vuln_status":   final_status,
        "script_used":   scripts[0] if scripts else None,
        "scripts_tried": scripts,
        "evidence":      evidence,
    }


@router.post("/scan/auto")
async def auto_vuln_scan(req: ScanRequest, request: Request):
    """
    POST /api/scan/auto — Auto-starts a vuln scan (nmap -sV --script vuln).
    Called by the frontend when user submits an IP without choosing a scan type.
    Delegates to _run_scan_pipeline with scan_type='vuln_scan'.
    """
    from app.api.scan_control import scan_state as _global_ss

    target       = validate_target(req.target)
    scan_type    = "vuln_scan"   # always vuln scan for auto mode
    project_name = (req.project_name or "").strip()

    if _global_ss.running:
        raise HTTPException(
            status_code=409,
            detail=(
                f"A scan is already running against '{_global_ss.target}' "
                f"({_global_ss.scan_type}). Stop it first or wait for it to finish."
            ),
        )

    try:
        analysis = await _run_scan_pipeline(target, scan_type, project_name=project_name, session_id=req.message or "")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")

    return analysis


# ── Scan route ─────────────────────────────────────────────────────────────────

@router.get("/templates")
async def get_templates():
    return {"templates": [k for k in SCAN_TEMPLATES if k != "enum_scripts"]}


@router.post("/scan")
async def run_scan(req: ScanRequest, request: Request):
    """
    POST /api/scan — delegates entirely to _run_scan_pipeline().
    Duplicate pipeline code removed: single source of truth for scan logic.
    """
    from app.api.scan_control import scan_state as _global_ss

    target       = validate_target(req.target)
    scan_type    = validate_scan_type(req.scan_type)
    project_name = (req.project_name or "").strip()

    # ── Concurrent-scan guard ──────────────────────────────────────────────
    if _global_ss.running:
        raise HTTPException(
            status_code=409,
            detail=(
                f"A scan is already running against '{_global_ss.target}' "
                f"({_global_ss.scan_type}). Stop it first or wait for it to finish."
            ),
        )

    try:
        analysis = await _run_scan_pipeline(target, scan_type, project_name=project_name)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")

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
    return FileResponse(path, media_type="application/json", filename=f"threatweave_{session_id}.json")

@router.get("/report/download/html/{session_id}")
async def download_html_report(session_id: str, request: Request):
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "sessions", session_id, "report", "report.html")
    if not os.path.exists(path): raise HTTPException(status_code=404, detail="HTML report not generated yet")
    return FileResponse(path, media_type="text/html", filename=f"threatweave_report_{session_id}.html")


# ── Compare / Charts ───────────────────────────────────────────────────────────

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
            "openrouter_available": False,
            "nemotron_available":   False,
            "gpt_oss_available":    False,
            "llama33_available":    False,
            "gemma4_available":     False,
            "deepseek_available":   False,
            "qwen_available":   False,
            "llama_available":  False,
            "ollama_available": False,
            "display_name":     "Rule Engine",
            "display_provider": "No AI — run setup_env.sh",
            "qwen_model":       "qwen2.5-coder:7b",
            "llama_model":      "llama3.2:3b",
            "ollama_model":     "qwen2.5-coder:7b",
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


# ── CVE Cache API — local-first intelligent CVE lookup ───────────────────────

from fastapi import Query as _Query

@router.get("/cve/cache/stats")
async def cve_cache_stats_endpoint():
    """Return CVE intelligence cache statistics."""
    try:
        from app.cve.cve_cache_engine import cve_cache
        return {"ok": True, "stats": cve_cache.get_stats()}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.get("/cve/cache/lookup")
async def cve_cache_lookup(cve_id: str = _Query(..., description="CVE ID e.g. CVE-2023-38408")):
    """
    Look up a CVE by ID from the intelligent local cache.
    Falls back to NVD API if not cached (result is saved for future calls).
    """
    try:
        from app.cve.cve_cache_engine import cve_cache
        result = cve_cache.lookup(cve_id.strip().upper())
        if result:
            return {"ok": True, "cve": result, "source": result.get("source", "cache")}
        return {"ok": False, "cve_id": cve_id, "error": "CVE not found in cache or NVD"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ── Phase 11: 4-Layer Patch Resolution API ────────────────────────────────────

@router.get("/remediation/stats")
async def remediation_stats_endpoint():
    """
    Phase 11: API Optimization Audit.
    Returns hit rates for all 4 resolution layers.
    Target: NVD reduction >90%, AI reduction >95%.
    """
    try:
        stats = get_resolution_stats()
        return {"ok": True, "stats": stats}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.get("/remediation/resolve")
async def remediation_resolve_endpoint(
    cve_id:  str = _Query("", description="CVE ID e.g. CVE-2024-6387"),
    service: str = _Query("", description="Service name e.g. openssh"),
    version: str = _Query("", description="Service version"),
):
    """
    4-Layer patch resolution for a CVE or service.
    Tries: Local Repository → Vendor Advisory → NVD Cache → AI Engine.
    """
    if not cve_id and not service:
        return {"ok": False, "error": "Provide cve_id or service"}
    try:
        result = resolve_patch(cve_id=cve_id, service=service, version=version)
        return {"ok": True, "patch": result}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.post("/remediation/approve")
async def remediation_approve_endpoint(body: dict):
    """
    Phase 7: Mark an AI-generated patch as human-approved.
    Promotes to Layer 1 repository after approval threshold.
    """
    cve_id  = body.get("cve_id", "")
    service = body.get("service", "")
    if not cve_id:
        return {"ok": False, "error": "cve_id required"}
    try:
        from app.remediation.learning.knowledge_base import learning_kb
        learning_kb.approve(cve_id, service)
        return {"ok": True, "message": f"{cve_id} approved and queued for Layer 1 promotion"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.get("/remediation/graph")
async def remediation_graph_endpoint(limit: int = _Query(100, ge=1, le=500)):
    """Phase 8: Export patch knowledge graph as JSON for visualization."""
    try:
        from app.remediation.graph.patch_graph import patch_graph
        return {"ok": True, "graph": patch_graph.visualize_json(limit)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.get("/remediation/repository/export")
async def remediation_export_endpoint():
    """Export local patch repository to JSON file."""
    try:
        from app.remediation.repository.patch_repository import patch_repository
        path = patch_repository.export_json()
        return {"ok": True, "file": path, "stats": patch_repository.stats()}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.post("/cve/cache/search")
async def cve_cache_search(body: dict):
    """
    Search CVEs by product + version. Uses local cache first, then NVD.
    Body: {"product": "openssh", "version": "9.2"}
    """
    product = body.get("product", "").strip()
    version = body.get("version", "").strip()
    if not product:
        return {"ok": False, "error": "product is required"}
    try:
        from app.cve.cve_cache_engine import cve_cache
        results = cve_cache.lookup_by_product(product, version)
        return {"ok": True, "product": product, "version": version,
                "count": len(results), "cves": results}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ── Feature 1: Structured CVE Summarization ────────────────────────────────────

@router.post("/cve/summarize")
async def cve_summarize_endpoint(body: dict):
    """
    Feature 1 — Structured CVE Summarization.
    Produces executive, technical, and remediation summaries.

    Body: {
      "cve_id": "CVE-2024-6387",
      "service": "openssh",
      "version": "9.2",
      "cvss": 8.1,
      "severity": "high",
      "description": "...",
      "cwe": "CWE-364",
      "epss": 0.94,
      "is_kev": true
    }
    """
    cve_id = (body.get("cve_id") or "").strip().upper()
    if not cve_id:
        return {"ok": False, "error": "cve_id is required"}
    try:
        from app.intelligence.cve_summarizer import summarize_cve
        result = summarize_cve(
            cve_id      = cve_id,
            service     = body.get("service", "unknown"),
            version     = body.get("version", "unknown"),
            cvss        = float(body.get("cvss") or 0),
            severity    = body.get("severity", "unknown"),
            description = body.get("description", ""),
            cwe         = body.get("cwe", ""),
            epss        = float(body.get("epss") or 0),
            is_kev      = bool(body.get("is_kev", False)),
        )
        return {"ok": True, "summary": result}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.post("/cve/summarize/batch")
async def cve_summarize_batch_endpoint(body: dict):
    """
    Feature 1 — Batch CVE Summarization.
    Body: {"cves": [{cve_id, service, version, cvss, severity, ...}, ...]}
    """
    cves = body.get("cves", [])
    if not cves or not isinstance(cves, list):
        return {"ok": False, "error": "cves list is required"}
    try:
        from app.intelligence.cve_summarizer import summarize_cves_batch
        results = summarize_cves_batch(cves[:20])  # cap at 20 per call
        return {"ok": True, "count": len(results), "summaries": results}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ── Feature 3 + 4: Exploit Prediction + Threat Correlation ────────────────────

@router.post("/threat/exploit-predict")
async def exploit_predict_endpoint(body: dict):
    """
    Feature 3 — Exploit Prediction.
    Predicts probability that a CVE will be exploited.

    Body: {
      "cvss": 9.8, "epss": 0.94, "is_kev": true,
      "severity": "critical", "cwe": "CWE-78",
      "age_days": 120, "vendor": "OpenSSH", "product": "sshd"
    }
    Output: {"exploit_probability": 97, "risk": "Critical", ...}
    """
    try:
        from app.intelligence.threat_correlator import predict_exploit_probability
        result = predict_exploit_probability(
            cvss      = float(body.get("cvss") or 0),
            epss      = float(body.get("epss") or 0),
            is_kev    = bool(body.get("is_kev", False)),
            severity  = body.get("severity", "unknown"),
            cwe       = body.get("cwe", ""),
            age_days  = int(body.get("age_days") or 0),
            vendor    = body.get("vendor", ""),
            product   = body.get("product", ""),
        )
        return {"ok": True, "prediction": result}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.post("/threat/correlate")
async def threat_correlate_endpoint(body: dict):
    """
    Feature 4 — Unified Threat Intelligence Correlation.
    Correlates NVD + CISA KEV + EPSS for a list of CVEs.

    Body: {"cves": [{cve_id, cvss, severity, epss, is_kev, cwe, age_days, ...}, ...]}
    Output: {"profiles": [...], "overall_threat": "Critical", ...}
    """
    cves = body.get("cves", [])
    if not isinstance(cves, list):
        return {"ok": False, "error": "cves must be a list"}
    try:
        from app.intelligence.threat_correlator import correlate_scan_threats
        result = correlate_scan_threats(cves)
        return {"ok": True, "correlation": result}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.post("/threat/profile")
async def threat_profile_endpoint(body: dict):
    """
    Feature 4 — Single CVE Unified Threat Profile.
    Combines CVSS + CISA KEV + EPSS + exploit prediction into one profile.
    """
    cve_id = (body.get("cve_id") or "").strip().upper()
    if not cve_id:
        return {"ok": False, "error": "cve_id is required"}
    try:
        from app.intelligence.threat_correlator import build_unified_threat_profile
        from app.analysis.threat_intel import lookup_kev
        kev = lookup_kev(cve_id)
        result = build_unified_threat_profile(
            cve_id      = cve_id,
            cvss        = float(body.get("cvss") or 0),
            severity    = body.get("severity", "unknown"),
            epss        = float(body.get("epss") or 0),
            is_kev      = kev is not None or bool(body.get("is_kev", False)),
            kev_details = kev,
            cwe         = body.get("cwe", ""),
            age_days    = int(body.get("age_days") or 0),
            service     = body.get("service", ""),
            product     = body.get("product", ""),
            vendor      = body.get("vendor", ""),
        )
        return {"ok": True, "profile": result}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ── Feature 5: RAG over NVD + KEV + EPSS ──────────────────────────────────────

@router.post("/rag/query")
async def rag_query_endpoint(body: dict, request: Request):
    """
    Feature 5 — Lightweight RAG.
    Answers security questions grounded in local NVD/KEV/EPSS data.

    Body: {
      "query": "Is CVE-2024-6387 being actively exploited?",
      "session_id": "optional — to include current scan CVEs as context"
    }
    """
    query = (body.get("query") or "").strip()
    if not query:
        return {"ok": False, "error": "query is required"}

    sid = body.get("session_id", "")
    session_cves = []
    if sid:
        try:
            ctx = load_scan_context(sid) or {}
            cve_data = ctx.get("cve_data", {})
            for host in cve_data.get("hosts", []):
                for port in host.get("ports", []):
                    session_cves.extend(port.get("cves", []))
        except Exception:
            pass

    try:
        from app.intelligence.rag_engine import rag_answer
        result = rag_answer(query=query, session_cves=session_cves)
        return {"ok": True, "result": result}
    except Exception as e:
        return {"ok": False, "error": str(e)}
