"""
Multi-AI Comparison Module
Compares Claude AI output vs Rule-Based analysis on the same scan data.
Measures: correctness, explainability, usefulness, conciseness, recommendation quality.
"""
import time


def compare_analyses(rule_based: dict, ai_result: dict, ground_truth: dict = None) -> dict:
    """
    Compare rule-based vs AI analysis outputs.
    Returns scored comparison with metrics.
    """
    rb_score = _score_output(rule_based,  "rule-based")
    ai_score = _score_output(ai_result,   "claude-ai")

    comparison = {
        "timestamp":    time.strftime("%Y-%m-%d %H:%M:%S"),
        "rule_based":   _describe(rule_based,  rb_score),
        "ai_analysis":  _describe(ai_result,   ai_score),
        "winner":       _pick_winner(rb_score, ai_score),
        "metrics":      _metric_comparison(rule_based, ai_result),
        "verdict":      _verdict(rb_score, ai_score),
    }

    if ground_truth:
        comparison["recall"] = _recall_check(rule_based, ai_result, ground_truth)

    return comparison


def _score_output(result: dict, engine: str) -> dict:
    """Score an analysis result across 5 dimensions (each 0-10)."""
    scores = {}

    # 1. Correctness — did it find the right risk levels?
    risk_analysis = result.get("risk_analysis", [])
    scores["correctness"] = min(10, len(risk_analysis) * 2) if risk_analysis else 3

    # 2. Explainability — does each finding have a reason?
    findings_with_reasons = sum(
        1 for r in risk_analysis if r.get("reason") and len(r["reason"]) > 20
    )
    scores["explainability"] = round(
        (findings_with_reasons / max(len(risk_analysis), 1)) * 10, 1
    )

    # 3. Usefulness — does it have actionable recommendations?
    recs = result.get("recommendations", [])
    useful_recs = sum(1 for r in recs if r.get("action") and len(r["action"]) > 15)
    scores["usefulness"] = min(10, useful_recs * 2.5)

    # 4. Conciseness — summary length (shorter is better, but not empty)
    summary = result.get("summary", "")
    if not summary:
        scores["conciseness"] = 2
    elif len(summary) < 50:
        scores["conciseness"] = 5
    elif len(summary) <= 300:
        scores["conciseness"] = 10
    else:
        scores["conciseness"] = max(3, 10 - (len(summary) - 300) // 50)

    # 5. Recommendation quality — does next_scan have type + reason?
    ns = result.get("next_scan", {})
    rec_score = 0
    if ns.get("type"):   rec_score += 4
    if ns.get("reason") and len(ns["reason"]) > 20: rec_score += 4
    if ns.get("command_hint"):  rec_score += 2
    scores["recommendation_quality"] = rec_score

    scores["overall"] = round(sum(scores.values()) / 5, 1)
    return scores


def _describe(result: dict, scores: dict) -> dict:
    return {
        "engine":          result.get("engine", "unknown"),
        "overall_risk":    result.get("overall_risk", "unknown"),
        "findings_count":  len(result.get("findings", [])),
        "cve_count":       len([c for c in result.get("cve_insight", [])
                                if c.get("cve_id","") != "unknown"]),
        "rec_count":       len(result.get("recommendations", [])),
        "summary_length":  len(result.get("summary", "")),
        "scores":          scores,
    }


def _pick_winner(rb: dict, ai: dict) -> str:
    if rb["overall"] > ai["overall"] + 0.5:
        return "rule-based"
    if ai["overall"] > rb["overall"] + 0.5:
        return "claude-ai"
    return "tie"


def _metric_comparison(rb: dict, ai: dict) -> list:
    rb_s = _score_output(rb, "rule-based")
    ai_s = _score_output(ai, "claude-ai")

    metrics = []
    for dim in ["correctness","explainability","usefulness","conciseness","recommendation_quality"]:
        rb_v = rb_s.get(dim, 0)
        ai_v = ai_s.get(dim, 0)
        metrics.append({
            "metric":      dim.replace("_", " ").title(),
            "rule_based":  rb_v,
            "ai":          ai_v,
            "better":      "claude-ai" if ai_v > rb_v else ("rule-based" if rb_v > ai_v else "tie"),
        })
    return metrics


def _verdict(rb: dict, ai: dict) -> str:
    diff = ai["overall"] - rb["overall"]
    if diff > 1.5:
        return "Claude AI significantly outperforms rule-based analysis on this scan."
    if diff > 0.5:
        return "Claude AI performs better overall. AI mode recommended when API key is set."
    if diff < -1.5:
        return "Rule-based analysis outperforms AI on this scan (possibly due to API issues)."
    if diff < -0.5:
        return "Rule-based analysis performs comparably or better. Both methods are reliable."
    return ("Both engines produce comparable quality. "
            "Rule-based is faster; AI provides richer explanations.")


def _recall_check(rb: dict, ai: dict, truth: dict) -> dict:
    """If ground truth CVEs are provided, check recall for each engine."""
    expected = set(truth.get("cve_ids", []))
    if not expected:
        return {}

    def found_cves(result):
        return set(
            c.get("cve_id","") for c in result.get("cve_insight", [])
            if c.get("cve_id","") not in ("unknown", "")
        )

    rb_found = found_cves(rb)
    ai_found = found_cves(ai)

    return {
        "expected":      list(expected),
        "rule_based":    {"found": list(rb_found & expected),
                          "recall": round(len(rb_found & expected)/len(expected)*100, 1)},
        "ai":            {"found": list(ai_found & expected),
                          "recall": round(len(ai_found & expected)/len(expected)*100, 1)},
    }
