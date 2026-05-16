"""
ScanWise AI — Remediation Cache
In-memory LRU cache for AI remediation responses.
Prevents duplicate AI calls for the same CVE/service/version combination.
"""
import hashlib
import json
import logging
import time
from collections import OrderedDict
from typing import Optional

logger = logging.getLogger("scanwise.ai.cache")

_CACHE_TTL    = 3600      # 1 hour — remediations don't change that fast
_CACHE_MAX    = 500       # max entries before LRU eviction
_HIT_COUNTER  = 0
_MISS_COUNTER = 0

# OrderedDict used as LRU (most-recently-used at end)
_cache: OrderedDict = OrderedDict()


def _make_key(service: str, port: int, version: str,
              cve_id: str, severity: str) -> str:
    """Stable cache key for a patch guidance request."""
    raw = f"{service.lower()}:{port}:{version.lower()}:{cve_id.lower()}:{severity.lower()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def get_cached(service: str, port: int, version: str,
               cve_id: str, severity: str) -> Optional[dict]:
    """Return cached patch response or None on miss/expiry."""
    global _HIT_COUNTER, _MISS_COUNTER
    key = _make_key(service, port, version, cve_id, severity)

    if key in _cache:
        entry = _cache[key]
        if time.time() - entry["ts"] < _CACHE_TTL:
            # Move to end (most recently used)
            _cache.move_to_end(key)
            _HIT_COUNTER += 1
            logger.debug("Cache HIT for %s port=%d cve=%s", service, port, cve_id)
            return entry["data"]
        else:
            # Expired
            del _cache[key]

    _MISS_COUNTER += 1
    return None


def set_cached(service: str, port: int, version: str,
               cve_id: str, severity: str, data: dict) -> None:
    """Store a patch response in cache. Evicts LRU entry if at capacity."""
    key = _make_key(service, port, version, cve_id, severity)

    if len(_cache) >= _CACHE_MAX:
        # Evict least-recently-used (first item)
        _cache.popitem(last=False)
        logger.debug("Cache evicted LRU entry (size=%d)", len(_cache))

    _cache[key] = {"ts": time.time(), "data": data}
    _cache.move_to_end(key)
    logger.debug("Cache SET for %s port=%d cve=%s", service, port, cve_id)


def get_stats() -> dict:
    total = _HIT_COUNTER + _MISS_COUNTER
    return {
        "size":     len(_cache),
        "max_size": _CACHE_MAX,
        "ttl_secs": _CACHE_TTL,
        "hits":     _HIT_COUNTER,
        "misses":   _MISS_COUNTER,
        "hit_rate": f"{100*_HIT_COUNTER//total}%" if total else "—",
    }


def clear_cache() -> int:
    """Clear all entries. Returns number removed."""
    count = len(_cache)
    _cache.clear()
    return count


# ── Deduplication for in-flight requests ──────────────────────────────────────
# Prevents multiple concurrent requests for the same key from all hitting AI.

import asyncio
_in_flight: dict = {}  # key -> asyncio.Event


async def deduplicated_fetch(
    service: str, port: int, version: str,
    cve_id: str, severity: str,
    fetch_fn,   # async callable -> dict
) -> dict:
    """
    If a request for this key is already in-flight, wait for it to finish
    and return the cached result instead of making a duplicate AI call.
    """
    key = _make_key(service, port, version, cve_id, severity)

    # Check cache first
    cached = get_cached(service, port, version, cve_id, severity)
    if cached is not None:
        return cached

    # If already in-flight, wait
    if key in _in_flight:
        logger.debug("Request dedup: waiting for in-flight key=%s", key)
        await _in_flight[key].wait()
        # Now it should be in cache
        cached = get_cached(service, port, version, cve_id, severity)
        return cached or {}

    # Start new in-flight marker
    event = asyncio.Event()
    _in_flight[key] = event

    try:
        result = await fetch_fn()
        set_cached(service, port, version, cve_id, severity, result)
        return result
    finally:
        event.set()
        _in_flight.pop(key, None)
