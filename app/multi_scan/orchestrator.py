"""
app/multi_scan/orchestrator.py
Sequential multi-target scan orchestrator.

Runs each target one-at-a-time through the full single-scan pipeline,
updating a shared queue state object so the frontend can poll progress.
"""
import asyncio
import logging
import time
from typing import Optional

logger = logging.getLogger("scanwise.multi_scan")


class MultiScanQueue:
    """
    Lightweight in-process queue tracking the state of a multi-scan job.
    One instance is created per multi-scan request and keyed by job_id.
    """

    def __init__(self, job_id: str, targets: list, scan_type: str, project_name: str = ""):
        self.job_id       = job_id
        self.targets      = list(targets)
        self.scan_type    = scan_type
        self.project_name = project_name

        self.total     = len(targets)
        self.completed = 0
        self.failed    = 0
        self.current   = ""          # target currently being scanned
        self.running   = False
        self.done      = False
        self.started_at: Optional[float] = None
        self.finished_at: Optional[float] = None

        # Per-target results
        self.results: list[dict] = []

    def to_dict(self) -> dict:
        elapsed = round(time.time() - self.started_at, 1) if self.started_at else 0
        return {
            "job_id":       self.job_id,
            "total":        self.total,
            "completed":    self.completed,
            "failed":       self.failed,
            "current":      self.current,
            "running":      self.running,
            "done":         self.done,
            "elapsed_s":    elapsed,
            "results":      self.results,
        }


# Global registry of active / recently completed jobs
_jobs: dict[str, MultiScanQueue] = {}
_MAX_JOBS = 20   # keep at most this many completed jobs in memory


def create_job(job_id: str, targets: list, scan_type: str, project_name: str = "") -> MultiScanQueue:
    q = MultiScanQueue(job_id, targets, scan_type, project_name)
    _jobs[job_id] = q
    # Evict oldest jobs when registry grows too large
    if len(_jobs) > _MAX_JOBS:
        oldest = next(iter(_jobs))
        _jobs.pop(oldest, None)
    return q


def get_job(job_id: str) -> Optional[MultiScanQueue]:
    return _jobs.get(job_id)


async def run_multi_scan(queue: MultiScanQueue, pipeline_fn) -> None:
    """
    Execute all targets in *queue* sequentially using *pipeline_fn*.

    pipeline_fn signature: async (target, scan_type, project_name) -> analysis_dict
    """
    queue.running    = True
    queue.done       = False
    queue.started_at = time.time()

    for i, target in enumerate(queue.targets):
        queue.current = target
        logger.info("[MultiScan] [%d/%d] scanning %s", i + 1, queue.total, target)

        try:
            analysis = await pipeline_fn(target, queue.scan_type, queue.project_name)

            # Extract summary fields from analysis
            risk_hosts  = analysis.get("risk", {}).get("hosts", [])
            open_ports  = sum(len(h.get("ports", [])) for h in risk_hosts)
            cves        = [
                c for h in risk_hosts
                for p in h.get("ports", [])
                for c in p.get("cves", [])
            ]
            cve_count   = len(cves)
            cve_ids     = [c.get("cve_id", "") for c in cves if c.get("cve_id", "").startswith("CVE")]
            overall_risk = (
                risk_hosts[0].get("risk_summary", {}).get("overall", "low")
                if risk_hosts else "unknown"
            )
            risk_score  = analysis.get("risk", {}).get("overall_score", 0)
            severity_counts = _count_severities(risk_hosts)
            ai_summary  = analysis.get("ai_analysis", {}).get("summary", "")

            queue.results.append({
                "target":      target,
                "index":       i + 1,
                "status":      "ok",
                "session_id":  analysis.get("session_id", ""),
                "scan_type":   queue.scan_type,
                "open_ports":  open_ports,
                "cve_count":   cve_count,
                "cve_ids":     cve_ids[:10],   # first 10 for card display
                "overall_risk": overall_risk,
                "risk_score":  risk_score,
                "severity":    severity_counts,
                "ai_summary":  ai_summary,
                "duration":    analysis.get("duration", 0),
                "timestamp":   analysis.get("timestamp", ""),
            })
            queue.completed += 1

        except Exception as exc:
            logger.warning("[MultiScan] target %s failed: %s", target, exc)
            queue.results.append({
                "target":  target,
                "index":   i + 1,
                "status":  "error",
                "reason":  str(exc),
                "overall_risk": "unknown",
                "cve_count":    0,
                "open_ports":   0,
                "severity":     {"critical": 0, "high": 0, "medium": 0, "low": 0},
            })
            queue.failed += 1

        # Tiny yield so the event loop stays responsive between scans
        await asyncio.sleep(0)

    queue.running     = False
    queue.done        = True
    queue.current     = ""
    queue.finished_at = time.time()
    logger.info("[MultiScan] job %s finished — %d ok, %d failed",
                queue.job_id, queue.completed, queue.failed)


def _count_severities(hosts: list) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for h in hosts:
        for p in h.get("ports", []):
            for cve in p.get("cves", []):
                sev = cve.get("severity", "low").lower()
                if sev in counts:
                    counts[sev] += 1
                elif sev == "unknown":
                    counts["low"] += 1
    return counts


def aggregate_results(results: list[dict]) -> dict:
    """Build aggregate stats from completed result list."""
    level_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
    ok = [r for r in results if r.get("status") == "ok"]
    if not ok:
        return {"overall_risk": "unknown", "total_cves": 0, "total_ports": 0}

    worst = max(ok, key=lambda r: level_order.get(r.get("overall_risk", "unknown"), 0))
    total_cves  = sum(r.get("cve_count", 0) for r in ok)
    total_ports = sum(r.get("open_ports", 0) for r in ok)
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in ok:
        for k, v in r.get("severity", {}).items():
            sev[k] = sev.get(k, 0) + v
    all_cve_ids = list({cid for r in ok for cid in r.get("cve_ids", [])})

    return {
        "overall_risk": worst.get("overall_risk", "unknown"),
        "total_cves":   total_cves,
        "total_ports":  total_ports,
        "severity":     sev,
        "all_cve_ids":  all_cve_ids,
    }
