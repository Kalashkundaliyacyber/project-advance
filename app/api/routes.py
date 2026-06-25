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

from app.api.validators import validate_target, validate_scan_type, TARGET_PATTERN, _COMMA_FIX_PATTERN
from app.scanner.scanner_core import run_full_scan, NMAP_SCRIPT_CATEGORIES, SCAN_KEY
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

# ── Warm up the CVE database at import time ────────────────────────────────
# This seeds the SQLite DB from /usr/share/nmap/scripts/ and the hardcoded
# CVE_NSE_MAP entries so the first confirm-port request is instant.
try:
    from app.scanner.cve_db import ensure_initialized as _init_cve_db
    import threading as _warmup_thread
    _warmup_thread.Thread(target=_init_cve_db, daemon=True, name="cve-db-warmup").start()
except Exception as _cve_db_err:
    pass  # Non-fatal — DB initializes lazily on first request if this fails
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
    scan_type: Optional[str] = "full_scan"   # Phase 0: vestigial, ignored — there's one scan
    message: Optional[str] = ""
    project_name: Optional[str] = ""
    # Phase 7: optional authenticated scanning — startup config/flags, NOT a
    # slash command. Absent => auth_scanner.run_auth_checks() does nothing.
    ssh_username: Optional[str] = None
    ssh_password: Optional[str] = None
    ssh_key_path: Optional[str] = None
    smb_username: Optional[str] = None
    smb_password: Optional[str] = None

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
    base = f"""You are ThreatWeave AI, a defensive cybersecurity assistant for network scanning.

CAPABILITIES:
- Understand what the user wants in natural language
- Trigger the scan automatically when user provides a target — there is
  exactly ONE scan ({NMAP_SCRIPT_CATEGORIES} script categories, all ports,
  version detection); it always runs in full, nothing to choose
- Explain scan results clearly and prioritise risks
- Answer CVE, patching, and hardening questions

SAFETY RULES:
- Never suggest exploits, attack payloads, or offensive techniques
- Only provide defensive, remediation-focused guidance

INTENT DETECTION - trigger auto-scan when user implies scanning:
  Examples: "check my server", "scan 192.168.1.1", "what is open on X", "audit X"
  - Extract the target IP/hostname from the message — that's all that's needed,
    the scan itself is fixed and automatic

WHEN TRIGGERING A SCAN - respond ONLY with this exact JSON, nothing else:
{{"action": "auto_scan", "target": "<ip or hostname>", "reason": "<one sentence why>"}}

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
    if cmd == "/stop":
        return {"reply": "Stopping scan...", "action": "stop_scan"}

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


async def _run_scan_pipeline(
    target: str, project_name: str = "", session_id: str = "",
    ssh_username: str = None, ssh_password: str = None, ssh_key_path: str = None,
    smb_username: str = None, smb_password: str = None,
) -> dict:
    target    = validate_target(target)
    sid       = create_session(target, SCAN_KEY, project_name=project_name)

    loop = asyncio.get_event_loop()

    # CRITICAL: run_full_scan MUST run in an executor — if called directly on
    # the async event loop thread it blocks the loop, preventing
    # call_soon_threadsafe SSE port_found events from being delivered until
    # after the scan completes.
    scan_result = await loop.run_in_executor(None, run_full_scan, target)
    raw_output  = scan_result["raw_output"]
    xml_output  = scan_result["xml_output"]
    duration    = scan_result["duration"]
    parsed      = scan_result["parsed"]
    save_raw(sid, raw_output, xml_output)

    # ── Phase 2: active service probing — automatic, right after the scan ──
    # Independently re-verifies each open port (HTTP GET, SSH/FTP banner,
    # SMB negotiation, raw socket). Additive only — never overwrites the
    # nmap-reported service/version fields the CVE pipeline below keys off.
    try:
        from app.scanner.service_prober import probe_all_ports, merge_into_parsed
        probed_services = await loop.run_in_executor(None, probe_all_ports, scan_result)
        parsed = merge_into_parsed(parsed, probed_services)
    except Exception as e:
        logger.warning("Phase 2 service_prober failed (non-fatal): %s", e)
        probed_services = {}

    # ── Phase 4: SOPLib — automatic, right after the scan's output exists ──
    # Reads scripts that already ran as part of the one scan (smb-security-
    # mode, ssl-enum-ciphers, etc.) and understands their non-standard output
    # formats, which the generic VULNERABLE-keyword check alone would miss.
    try:
        from app.scanner.soplib import scan_all_ports as soplib_scan_all
        soplib_findings = await loop.run_in_executor(None, soplib_scan_all, parsed)
    except Exception as e:
        logger.warning("Phase 4 soplib failed (non-fatal): %s", e)
        soplib_findings = []

    save_parsed(sid, parsed)

    versioned = await loop.run_in_executor(None, analyze_versions, parsed)
    cve_data  = await loop.run_in_executor(None, map_cves, versioned)
    # NVD enrichment: normalise local CVEs + augment with live NVD intelligence
    cve_data  = await loop.run_in_executor(None, enrich_with_nvd_sync, cve_data)

    # ── Phase 3: tag each CVE with confidence "exact" (NVD CPE / NSE-confirmed)
    # or "range" (local DB / NVD keyword) — the one piece neither existing
    # CVE engine set before this phase.
    try:
        from app.scanner.cpe_cve_engine import tag_confidence_on_parsed
        cve_data = await loop.run_in_executor(None, tag_confidence_on_parsed, cve_data)
    except Exception as e:
        logger.warning("Phase 3 cpe_cve_engine confidence tagging failed (non-fatal): %s", e)

    context   = await loop.run_in_executor(None, analyze_context, cve_data)
    risk      = await loop.run_in_executor(None, calculate_risk, context)

    def _run_misconfig():
        from app.scanner.misconfig_checker import run_all as misconfig_run_all
        return misconfig_run_all(cve_data, probed_services)

    recommendation, explanation, ai_analysis, charts, misconfig_findings = await asyncio.gather(
        loop.run_in_executor(None, get_recommendation, risk, SCAN_KEY),
        loop.run_in_executor(None, generate_explanation, risk, {}),
        _analyze_scan_capped(risk, budget=12.0),
        loop.run_in_executor(None, lambda: generate_chart_data({"risk": risk})),
        # Phase 5: misconfig checking — runs IN PARALLEL with CVE/AI analysis
        # above, not gated behind it; independent of any CVE.
        loop.run_in_executor(None, _run_misconfig),
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

    # ── Phase 7: optional authenticated scanning — runs AFTER everything ───
    # above (confirmation router lives on the separate /scan/confirm-port
    # path, driven per-port by the frontend's live table; this is the
    # pipeline-level slot the phase spec asked for, "after Phase 6"). Does
    # nothing and returns instantly if no credentials were provided —
    # never blocks or slows the unauthenticated pipeline.
    auth_findings = []
    if ssh_username or smb_username:
        try:
            from app.scanner.auth_scanner import run_auth_checks
            known_external_ports = {
                p.get("port") for h in (cve_data.get("hosts") or [])
                for p in (h.get("ports") or []) if p.get("port")
            }
            auth_findings = await loop.run_in_executor(
                None, run_auth_checks, target, known_external_ports,
                ssh_username, ssh_password, ssh_key_path, smb_username, smb_password,
            )
        except Exception as e:
            logger.warning("Phase 7 auth_scanner failed (non-fatal, optional stage): %s", e)

    analysis = {
        "session_id": sid, "target": target, "scan_type": SCAN_KEY,
        "project_name": project_name, "duration": duration,
        "parsed": parsed, "versioned": versioned, "cve_data": cve_data,
        "context": context, "risk": risk, "recommendation": recommendation,
        "explanation": explanation, "ai_analysis": ai_analysis,
        "rule_based_analysis": rule_based_analysis,   # FIX3: stored alongside AI output
        "threat_correlation":  threat_correlation,     # Feature 4: unified threat profiles
        "charts": charts,
        # Phases 2/4/5/7 — report-ready data, all automatic, all optional-safe
        "probed_services":     probed_services,
        "soplib_findings":     soplib_findings,
        "misconfig_findings":  misconfig_findings,
        "auth_findings":       auth_findings,
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
    if next_scan.get("reason"):
        # Phase 0: there's no other scan type to suggest running — the one
        # scan already covered vuln/safe/auth/default scripts + all ports.
        # Surface the underlying observation as a note, not a command.
        lines.append(f"**Note:** {next_scan['reason']}")
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
    scan_keywords = {"tcp", "port", "udp", "service", "version", "os", "syn",
                      "range", "scan", "vuln", "check", "audit"}
    if any(kw in ml for kw in scan_keywords):
        return ("Just type the IP address or hostname you want scanned — "
                "the scan starts automatically, no command needed.")
    if any(w in ml for w in ["hello", "hi", "hey"]):
        st = ai_router.status()
        return (f"**Hello!** I am ThreatWeave AI — powered by {st['display_name']}.\n\n"
                "Type a target IP/hostname to scan it automatically, or `/help` for commands.")
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

# BUG: unlike /api/scan (see _analyze_scan_capped above), this endpoint had no
# time budget at all. ai_router.chat() tries multiple providers IN SEQUENCE,
# each with its own ~20s HTTP timeout (qwen_provider.py / llama_provider.py /
# deepseek_provider.py), and only falls back to _keyword_fallback() once every
# provider in the stack has individually timed out:
#   normal chat       -> llama, qwen            = up to  40s
#   remediation/"how" -> qwen, llama             = up to  40s
#   CVE/security chat -> qwen, deepseek, llama   = up to  60s
# When local models are slow/unloaded (the same condition the scan path is
# already protected against), a single chat message can hang the request for
# up to a minute before the user sees anything.
#
# FIX: cap the executor call at CHAT_AI_BUDGET_SECS, same pattern as
# _analyze_scan_capped. On timeout we fall back to _keyword_fallback()
# immediately instead of waiting out every remaining provider in the stack;
# the abandoned call keeps running in the background thread but no longer
# blocks the response.
CHAT_AI_BUDGET_SECS = 20.0


def _extract_bare_target(msg: str) -> Optional[str]:
    """
    Phase 0: "no slash command needed — the scan runs automatically when an
    IP is submitted." This is the deterministic fast path for that: if the
    ENTIRE message is just a target (IP / hostname / CIDR, with the common
    comma-for-dot typo auto-corrected), return the normalised target.
    Anything else (a sentence, a question, multiple words) returns None and
    falls through to the AI path below, which can still extract a target
    out of natural language ("scan 192.168.1.5 for me").
    """
    candidate = msg.strip()
    if not candidate or " " in candidate or "\n" in candidate:
        return None
    m = _COMMA_FIX_PATTERN.match(candidate)
    if m:
        candidate = ".".join(m.groups())
    if TARGET_PATTERN.match(candidate):
        return candidate
    return None


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

    # ── Phase 0: automatic pipeline trigger, zero slash command needed ─────
    # If the whole message IS a target, just scan it. No AI round-trip, no
    # JSON-parsing dependency — this is the guaranteed path "type an IP and
    # the full pipeline runs" relies on.
    bare_target = _extract_bare_target(msg)
    if bare_target:
        try:
            validate_target(bare_target)
        except Exception as ve:
            err = f"`{bare_target}` doesn't look like a valid IP, hostname, or CIDR: {ve}"
            _push_history(sid, "user", msg)
            _push_history(sid, "assistant", err)
            return {"reply": err, "model": "validator"}
        _push_history(sid, "user", msg)
        try:
            analysis    = await _run_scan_pipeline(bare_target, project_name=project_name, session_id=sid)
            final_reply = _format_scan_reply(analysis, "Target submitted — running the full scan automatically.")
            _push_history(sid, "assistant", final_reply)
            return {
                "reply":     final_reply,
                "action":    "scan_complete",
                "data":      {"session_id": analysis["session_id"], "target": bare_target},
                "model":     "auto-trigger",
                "auto_scan": True,
            }
        except Exception as e:
            err = f"Scan of `{bare_target}` failed: `{e}`\n\nCheck: target reachable? nmap installed?"
            _push_history(sid, "assistant", err)
            return {"reply": err, "model": "auto-trigger", "error": str(e)}

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
        raw_reply, provider_name = await asyncio.wait_for(
            loop.run_in_executor(None, ai_router.chat, messages, system, 1200),
            timeout=CHAT_AI_BUDGET_SECS,
        )
        # Fix #6: surface fallback reason immediately when provider degraded
        st = ai_router.status()
        if st.get("fallback_reason") and provider_name not in ("rule-based",):
            fallback_note = f"\n\n> ⚠️ *Using {st['display_name']} — {st['fallback_reason']}*"
    except asyncio.TimeoutError:
        logger.warning(
            "ai_router.chat exceeded %.0fs budget (providers slow/unloaded) — "
            "falling back to keyword reply. (AI call continues in background "
            "thread, result discarded.)",
            CHAT_AI_BUDGET_SECS,
        )
        _push_history(sid, "user", msg)
        return {
            "reply": _keyword_fallback(msg), "suggestions": [], "model": "keyword-fallback",
            "error": f"AI chat exceeded {CHAT_AI_BUDGET_SECS:.0f}s budget",
        }
    except Exception as e:
        _push_history(sid, "user", msg)
        return {"reply": _keyword_fallback(msg), "suggestions": [], "model": "keyword-fallback", "error": str(e)}

    _push_history(sid, "user", msg)

    auto = _try_parse_auto_scan(raw_reply)

    if auto:
        target    = auto.get("target", "")
        reason    = auto.get("reason", "")
        try:
            validate_target(target)
        except Exception as ve:
            err = f"Identified intent to scan **{target}** but validation failed: {ve}\n\nProvide a valid IP or hostname."
            _push_history(sid, "assistant", err)
            return {"reply": err, "model": provider_name}

        try:
            analysis    = await _run_scan_pipeline(target, project_name=project_name, session_id=sid)
            final_reply = _format_scan_reply(analysis, reason) + fallback_note
            _push_history(sid, "assistant", final_reply)
            return {
                "reply":     final_reply,
                "action":    "scan_complete",
                "data":      {"session_id": analysis["session_id"], "target": target},
                "model":     provider_name,
                "auto_scan": True,
            }
        except Exception as e:
            err = (f"Scan of `{target}` failed: `{e}`\n\n"
                   "Check: target reachable? nmap installed?")
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

    Phase 6: delegates entirely to confirmation_router.route_confirmation().
    The router itself decides whether/when Gemini gets called (only when a
    CVE is present and no script has run yet) — this endpoint no longer
    contains any confirmation decision logic of its own, and is the only
    caller of the router in the live HTTP API surface.

    FIX (multi-CVE truncation bug): a single open port routinely matches
    many CVEs (an old OpenSSH/Apache/BIND banner alone can pull a dozen).
    This endpoint used to keep only cve_ids[0] and discard the rest before
    ever calling the router, so any port whose first-listed CVE had no
    mapped NSE script or version range came back UNCONFIRMED even when a
    later CVE on that exact same port had a perfectly good match. The full
    list is now passed through as "cves" so route_confirmation() — which
    already loops over every CVE it's given — actually gets to do that.
    "cve" is still set (to the first CVE) purely for any older caller that
    reads that singular field; it is no longer what confirmation is based on.
    """
    from app.scanner.confirmation_router import route_confirmation

    loop = asyncio.get_event_loop()
    cve_ids = [c.strip() for c in req.cves if c and c.strip()]

    finding = {
        "target":      req.target,
        "port":        req.port,
        "protocol":    req.protocol,
        "service":     req.service,
        "product":     req.product,
        "version":     req.version,
        "cves":        cve_ids,                          # FIX: full list, not just [0]
        "cve":         cve_ids[0] if cve_ids else "",     # kept for backward compat only
        "script_name": "",
        "raw_output":  "",
    }

    result = await loop.run_in_executor(None, route_confirmation, finding)

    # The CVE actually used to reach this verdict — may be any entry in
    # cve_ids, not necessarily the first one. Falls back to the legacy
    # singular field if the router didn't report one (e.g. Step 5/6).
    matched_cve = result.get("cve_id") or finding["cve"] or None

    # Self-learning feedback (unchanged) — reinforces good DB mappings,
    # flags bad ones, exactly as before this phase. Now keyed on the CVE
    # that was actually matched, not always the first one in the list.
    try:
        from app.scanner.cve_db import record_scan_result
        if matched_cve and result.get("script_used"):
            record_scan_result(matched_cve, result["script_used"], result["vuln_status"])
    except Exception as _fb_err:
        logger.debug("Feedback update skipped: %s", _fb_err)

    return {
        "vuln_status":    result["vuln_status"],
        "confidence":     result["confidence"],
        "script_used":    result.get("script_used"),
        "scripts_tried":  [result["script_used"]] if result.get("script_used") else [],
        "cve_confirmed":  matched_cve,
        "evidence":       result["evidence"],
        "source":         result.get("source", ""),
        "trace":          result.get("trace", []),
    }



@router.post("/scan/auto")
async def auto_vuln_scan(req: ScanRequest, request: Request):
    """
    POST /api/scan/auto — kept as an alias of /api/scan for backward
    compatibility with any client still calling this path. There's only one
    scan (Phase 0) so this and /api/scan now do exactly the same thing.
    """
    from app.api.scan_control import scan_state as _global_ss

    target       = validate_target(req.target)
    project_name = (req.project_name or "").strip()

    if _global_ss.running:
        raise HTTPException(
            status_code=409,
            detail=(
                f"A scan is already running against '{_global_ss.target}'. "
                f"Stop it first or wait for it to finish."
            ),
        )

    try:
        analysis = await _run_scan_pipeline(
            target, project_name=project_name, session_id=req.message or "",
            ssh_username=req.ssh_username, ssh_password=req.ssh_password, ssh_key_path=req.ssh_key_path,
            smb_username=req.smb_username, smb_password=req.smb_password,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")

    return analysis


# ── Scan route ─────────────────────────────────────────────────────────────────
# Phase 0: /api/templates removed — there's nothing to list, there's one scan.

@router.post("/scan")
async def run_scan(req: ScanRequest, request: Request):
    """
    POST /api/scan — delegates entirely to _run_scan_pipeline().
    Phase 0: scan_type is no longer accepted/used — there is exactly one
    scan (scanner_core.run_full_scan), and it always runs in full.
    """
    from app.api.scan_control import scan_state as _global_ss

    target       = validate_target(req.target)
    project_name = (req.project_name or "").strip()

    # ── Concurrent-scan guard ──────────────────────────────────────────────
    if _global_ss.running:
        raise HTTPException(
            status_code=409,
            detail=(
                f"A scan is already running against '{_global_ss.target}'. "
                f"Stop it first or wait for it to finish."
            ),
        )

    try:
        analysis = await _run_scan_pipeline(
            target, project_name=project_name,
            ssh_username=req.ssh_username, ssh_password=req.ssh_password, ssh_key_path=req.ssh_key_path,
            smb_username=req.smb_username, smb_password=req.smb_password,
        )
    except Exception as e:
        logger.exception("Scan pipeline failed for target=%s", target)
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
