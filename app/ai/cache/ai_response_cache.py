"""
ThreatWeave — AI Response Cache (Phase 5/22)
Caches AI responses to achieve 80%+ reduction in AI calls.
Storage: data/ai_cache/responses.json | TTL: 24h | Max: 5000 entries
"""
import hashlib, json, logging, os, threading, time
from typing import Optional

logger    = logging.getLogger("ThreatWeave.ai.cache")
_BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "ai_cache")
_CACHE_FILE  = os.path.join(_BASE_DIR, "responses.json")
_CACHE_TTL   = int(os.environ.get("AI_CACHE_TTL", str(24 * 3600)))
_MAX_ENTRIES = int(os.environ.get("AI_CACHE_MAX", "5000"))


class AIResponseCache:
    """Thread-safe AI response cache with TTL + LRU eviction."""
    def __init__(self):
        self._lock, self._data = threading.Lock(), {}
        self._hits = self._misses = 0
        os.makedirs(_BASE_DIR, exist_ok=True)
        self._load()

    def get(self, prompt: str, model: str = "any") -> Optional[str]:
        key = self._key(prompt, model)
        with self._lock:
            entry = self._data.get(key)
            if not entry:
                self._misses += 1; return None
            if time.time() - entry["ts"] > _CACHE_TTL:
                del self._data[key]; self._misses += 1; return None
            entry["hits"] = entry.get("hits", 0) + 1
            self._hits += 1
            return entry["response"]

    def set(self, prompt: str, response: str, model: str = "any") -> None:
        key = self._key(prompt, model)
        with self._lock:
            self._data[key] = {"response": response, "ts": time.time(), "model": model, "hits": 0}
            if len(self._data) > _MAX_ENTRIES: self._evict()
        self._save_async()

    def stats(self) -> dict:
        total = self._hits + self._misses
        with self._lock: size = len(self._data)
        return {"cache_hits": self._hits, "cache_misses": self._misses,
                "hit_rate": f"{self._hits/total*100:.1f}%" if total else "0%",
                "total_entries": size, "ttl_hours": _CACHE_TTL // 3600}

    def clear(self) -> int:
        with self._lock: n = len(self._data); self._data.clear()
        self._save_async(); return n

    @staticmethod
    def _key(prompt: str, model: str) -> str:
        return hashlib.sha256(f"{model}::{prompt[:500]}".encode()).hexdigest()[:32]

    def _evict(self):
        keys = sorted(self._data, key=lambda k: self._data[k]["ts"])
        for k in keys[:max(1, len(keys)//5)]: del self._data[k]

    def _load(self):
        try:
            if os.path.exists(_CACHE_FILE):
                with open(_CACHE_FILE) as f: self._data = json.load(f)
                now = time.time()
                expired = [k for k, v in self._data.items() if now - v.get("ts",0) > _CACHE_TTL]
                for k in expired: del self._data[k]
                logger.info("AI cache: %d entries loaded, %d expired purged", len(self._data), len(expired))
        except Exception as e:
            logger.warning("AI cache load failed: %s", e); self._data = {}

    def _save_async(self): threading.Thread(target=self._save, daemon=True).start()

    def _save(self):
        try:
            with self._lock: snap = dict(self._data)
            with open(_CACHE_FILE, "w") as f: json.dump(snap, f, separators=(",",":"))
        except Exception as e: logger.warning("AI cache save failed: %s", e)

ai_response_cache = AIResponseCache()
