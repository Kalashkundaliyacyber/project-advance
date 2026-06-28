"""
confirmation_router.py
========================
Phase 6 of the reconstruction — a single, ordered confirmation router,
replacing the previous "every finding goes straight to Gemini" path.

This is an ORCHESTRATOR, not a reimplementation — every step below calls an
existing, already-tested piece of this codebase:

  Step 1+2 (NSE keyword + SOPLib) -> cve_script_mapper.analyze_output()
                                      (Phase 4 already wired SOPLib into this
                                      function, right before its UNCONFIRMED
                                      fallback — see soplib.py)
  Step 3   (Gemini, conditional)  -> gemini_selector.ask_gemini() +
                                      script_selector.run_confirmation_scan()
  Step 4   (version range)        -> cve_db.get_version_ranges() +
                                      cve_script_mapper._version_in_range()
  Step 5   (Qwen, last resort)    -> app.ai.providers.qwen_provider.QwenProvider
  Step 6   (fallback)             -> plain UNCONFIRMED / NOT_VALIDATABLE

route_confirmation() is now the ONLY thing app/api/routes.py's
/scan/confirm-port endpoint calls — see the diff there. No other code path
in the automatic pipeline calls Gemini directly any more.
"""
from __future__ import annotations

import logging

logger = logging.getLogger("ThreatWeave.confirmation_router")


def _ask_qwen(raw_output: str, service: str, product: str, version: str) -> str:
    """
    Step 5 helper. Returns "issue", "no_issue", or "unavailable".
    Single-shot classification — kept deliberately narrow (yes/no) rather
    than open-ended, since this is a last-resort heuristic, not a source of
    truth, and an open-ended answer would be hard to act on automatically.
    """
    try:
        from app.ai.providers.qwen_provider import QwenProvider
        qwen = QwenProvider()
        if not qwen.is_available():
            return "unavailable"
    except Exception as e:
        logger.debug("confirmation_router: Qwen unavailable: %s", e)
        return "unavailable"

    prompt = (
        f"Service: {service} {product} {version}\n"
        f"Script output (truncated):\n{raw_output[:1500]}\n\n"
        "Does this output indicate a real security issue (vulnerability or "
        "misconfiguration)? Answer with exactly one word: YES or NO."
    )
    try:
        answer = qwen.generate(prompt, system="You are a terse security analyst. Answer only YES or NO.")
    except Exception as e:
        logger.debug("confirmation_router: Qwen call failed: %s", e)
        return "unavailable"

    answer = (answer or "").strip().upper()
    if answer.startswith("YES"):
        return "issue"
    if answer.startswith("NO"):
        return "no_issue"
    return "unavailable"


def _finalize(status: str, confidence: int, evidence: str, source: str,
              trace: list[str], finding: dict, script_used: str | None = None,
              cve_id: str | None = None) -> dict:
    _cve = cve_id or finding.get("cve") or None
    # Record ONLY that this CVE→script mapping was selected (increments used_count).
    # The verdict (status) is intentionally NOT persisted to the DB — scan outcomes
    # are target-specific and must never affect confidence for future scans of
    # different machines.  Only script_selection events (which NSE to run) are cached.
    if _cve:
        try:
            from app.scanner.cve_db import record_script_selection
            record_script_selection(_cve)
        except Exception:
            pass   # never let DB logging break the scan pipeline

    logger.info(
        "confirmation_router: %s:%s/%s -> %s (source=%s, cve=%s) | trace: %s",
        finding.get("target", "?"), finding.get("port", "?"),
        finding.get("service", "?"), status, source, _cve or "?", " | ".join(trace),
    )
    return {
        "vuln_status":   status,
        "confidence":    confidence,
        "evidence":      evidence,
        "source":        source,
        "script_used":   script_used or finding.get("script_name") or None,
        "cve_id":        _cve,
        "trace":         trace,
    }


def route_confirmation(finding: dict) -> dict:
    """
    Phase 6 main entry point.

    finding = {
        target, port, protocol, service, product, version,
        cve, script_name, raw_output,
    }
    (all optional except target/port — missing fields just skip the steps
    that need them, exactly as the phase spec describes.)

    Returns {vuln_status, confidence, evidence, source, script_used, trace}.
    """
    import re as _re
    from app.scanner.cve_script_mapper import analyze_output, _version_in_range
    from app.scanner.cve_db import get_version_ranges

    target      = finding.get("target", "")
    port        = finding.get("port")
    protocol    = finding.get("protocol", "tcp")
    service     = finding.get("service", "")
    product     = finding.get("product", "")
    version     = finding.get("version", "")

    cves = finding.get("cves") or []
    if not cves:
        legacy = finding.get("cve") or finding.get("cve_id") or ""
        cves = [legacy] if legacy else []
    cves = [c.strip() for c in cves if c and str(c).strip()]
    cve  = cves[0] if cves else ""

    script_name = finding.get("script_name", "")
    raw_output  = finding.get("raw_output", "")

    # ── All parsed scripts on this port (dict: script_id → output text) ───
    scripts_map: dict[str, str] = finding.get("scripts_map") or {}

    trace: list[str] = []

    # ── Step 0: Direct script-output scan — INDEPENDENT of CVE seeding. ───
    # FIX FIX-R1: The CVE seeding pipeline only runs if a CVE is returned by
    # the vulners/NVD lookup for a port. Certain backdoor scripts (notably
    # irc-unrealircd-backdoor) can confirm a vulnerability even when no CVE is
    # surfaced by the lookup — because the trojan is identified purely by IRC
    # protocol behaviour, not by a version number.  Without this step, ports
    # 6667/6697 (UnrealIRCd backdoor, fully confirmed by nmap) were silently
    # classified NOT_VALIDATABLE.
    #
    # This step scans every script that actually ran on this port, matches the
    # output against known confirmed-positive patterns, and short-circuits
    # before the CVE pipeline even starts.
    _DIRECT_BACKDOOR_CHECKS = {
        "irc-unrealircd-backdoor": {
            "cve": "CVE-2010-2075",
            "pattern": _re.compile(
                r"looks\s+like\s+(the\s+)?trojan(n?ed)?|trojan(n?ed)\s+version|"
                r"trojanned\s+unrealircd\s+is\s+running",
                _re.IGNORECASE,
            ),
            "title": "UnrealIRCd 3.2.8.1 trojaned backdoor",
        },
    }
    for script_id, cfg in _DIRECT_BACKDOOR_CHECKS.items():
        # Check both the scripts_map and the primary raw_output field
        output_to_check = scripts_map.get(script_id, "") or (
            raw_output if script_name == script_id else ""
        )
        if output_to_check and cfg["pattern"].search(output_to_check):
            evidence_line = output_to_check.strip()[:200]
            trace.append(f"step0(direct_backdoor):{script_id}:CONFIRMED")
            logger.info("confirmation_router: step0 direct backdoor match — %s on port %s", script_id, port)
            return _finalize(
                "CONFIRMED", 95,
                evidence_line or cfg["title"],
                "direct_script_scan",
                trace, finding,
                script_used=script_id,
                cve_id=cfg["cve"],
            )

    # ── Step 1 + 2: NSE keyword check, then SOPLib — both free, both instant.
    if raw_output and script_name:
        result = analyze_output(raw_output, script_name, cve)
        trace.append(f"step1+2(nse+soplib):{result['status']}")
        if result["status"] in ("CONFIRMED", "NOT_VULNERABLE"):
            return _finalize(result["status"], result["confidence"], result["evidence"],
                              "nse_keyword_or_soplib", trace, finding, cve_id=cve)

    # ── Step 3: Gemini — ONLY when at least one CVE is present AND no script
    if cves and not script_name:
        try:
            from app.scanner.script_selector import find_scripts_for_port_with_plan, run_confirmation_scan
            plan = find_scripts_for_port_with_plan(service, product, version, cves)
            matched_cve = plan.get("cve_id") or cve
            trace.append(f"step3(plan):{plan['action']} via {plan.get('source','?')} (cve={matched_cve})")

            if plan["action"] == "NSE" and plan.get("script") and target and port:
                chosen_script = plan["script"]
                new_output = run_confirmation_scan(target, port, protocol, [chosen_script])
                result = analyze_output(new_output or "", chosen_script, matched_cve)
                trace.append(f"step3_rerun(nse+soplib):{result['status']}")
                if result["status"] in ("CONFIRMED", "NOT_VULNERABLE"):
                    return _finalize(result["status"], result["confidence"], result["evidence"],
                                      f"{plan.get('source','plan')}_then_nse", trace, finding,
                                      script_used=chosen_script, cve_id=matched_cve)
                raw_output, script_name = (new_output or raw_output), chosen_script

            elif plan["action"] == "VERSION":
                trace.append(f"step3(plan):version_range_hit:{matched_cve}")
                return _finalize("POTENTIALLY_VULNERABLE", plan.get("confidence_if_confirmed", 60),
                                  plan.get("reason", ""), "version_range", trace, finding,
                                  cve_id=matched_cve)
        except Exception as e:
            logger.warning("confirmation_router: Step 3 plan lookup failed: %s", e)
            trace.append(f"step3(plan):error:{e}")

    # ── Step 4: Banner/version intelligence — local, no network, no AI.
    # FIX FIX-R2: Added product-mismatch guard. Before this fix, the version-
    # range check accepted any CVE whose product_keyword appeared anywhere in a
    # global lookup — meaning CVE-2021-26855 (MS Exchange ProxyLogon, product
    # keyword "exchange") appeared on Apache Tomcat (which does not contain the
    # word "exchange" in its product/service strings). The guard below rejects a
    # CVE range entry unless its product_keyword is actually present in the
    # combined service+product string of the detected service, preventing cross-
    # product false positives.
    if cves:
        try:
            combined = f"{product} {service}".lower()
            for cve_item in cves:
                ranges = get_version_ranges(cve_item)
                for prod_kw, vmin, vmax in ranges:
                    # FIX FIX-R2: product-mismatch guard
                    if prod_kw.lower() not in combined:
                        trace.append(f"step4(version_range):{cve_item}:skip (product '{prod_kw}' not in '{combined[:40]}')")
                        continue
                    if _version_in_range(version, vmin, vmax):
                        trace.append(f"step4(version_range):{cve_item} in [{vmin},{vmax}]")
                        return _finalize(
                            "POTENTIALLY_VULNERABLE", 60,
                            f"Detected version {version!r} falls in the known-vulnerable range "
                            f"{vmin}\u2013{vmax} for {cve_item}, but no script confirmed it directly.",
                            "version_range", trace, finding, cve_id=cve_item,
                        )
            trace.append("step4(version_range):no_match")
        except Exception as e:
            logger.debug("confirmation_router: version-range step failed: %s", e)

    # ── Step 5: Local Qwen AI — last resort, only with substantial output.
    if raw_output and len(raw_output) > 200:
        verdict = _ask_qwen(raw_output, service, product, version)
        trace.append(f"step5(qwen):{verdict}")
        if verdict == "issue":
            return _finalize(
                "MISCONFIGURED", 50,
                "Local Qwen AI flagged this script output as indicating a possible "
                "security issue. Heuristic judgment, not pattern-confirmed — verify manually.",
                "qwen_ai", trace, finding,
            )
        if verdict == "no_issue":
            return _finalize(
                "UNCONFIRMED", 0,
                "Local Qwen AI reviewed the output and found no clear security issue.",
                "qwen_ai", trace, finding,
            )

    # ── Step 6: Fallback.
    if raw_output:
        trace.append("step6(fallback):unconfirmed")
        return _finalize("UNCONFIRMED", 0,
                          "Output exists but no confirmation method resolved it.",
                          "fallback", trace, finding)
    trace.append("step6(fallback):not_validatable")
    return _finalize("NOT_VALIDATABLE", 0,
                      "No script output and no version-range data available to validate this finding.",
                      "fallback", trace, finding)
