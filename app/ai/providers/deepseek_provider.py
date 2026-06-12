"""
ThreatWeave AI — DeepSeek R1 8B Distill Provider (SECURITY ANALYSIS)
Use Case: Deep security analysis, CVE reasoning, exploit chains, risk scoring.
Runs via Ollama on localhost.

Model: deepseek-r1:8b  (distilled reasoning model)
"""
import json
import logging
import os
import re
import urllib.request
import urllib.error

logger = logging.getLogger("threatweave.ai.deepseek")

OLLAMA_BASE     = os.environ.get("OLLAMA_URL", "http://localhost:11434")
DEEPSEEK_MODEL  = os.environ.get("DEEPSEEK_MODEL", "deepseek-r1:8b")
TIMEOUT_SECS    = int(os.environ.get("DEEPSEEK_TIMEOUT", "20"))  # R1 needs longer for chain-of-thought

# Strip <think>...</think> blocks that DeepSeek R1 emits before the actual answer
_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


def _strip_think(text: str) -> str:
    """Remove chain-of-thought reasoning blocks from R1 output."""
    return _THINK_RE.sub("", text).strip()


class DeepSeekProvider:
    """
    Security analysis provider — DeepSeek R1 8B Distill via Ollama.
    Best used for: CVE analysis, exploit chain reasoning, risk scoring,
                   remediation strategy, threat intelligence synthesis.
    """

    def __init__(self):
        self.model = DEEPSEEK_MODEL
        self._available: bool | None = None

    def is_available(self) -> bool:
        if self._available is not None:
            return self._available
        self._available = self._check_model()
        return self._available

    def invalidate_cache(self):
        self._available = None

    def generate(self, prompt: str, system: str = "",
                 expect_json: bool = True, max_tokens: int = 2048) -> str:
        """Single-turn generation with thinking stripped."""
        payload = json.dumps({
            "model":  self.model,
            "prompt": prompt,
            "system": system or "",
            "stream": False,
            "options": {
                "num_predict": max_tokens,
                "temperature": 0.05,   # Low temp for deterministic security analysis
                "top_p": 0.85,
                "num_ctx": 4096,       # Reduced from 8192 to lower RAM usage
            },
        }).encode()
        req = urllib.request.Request(
            f"{OLLAMA_BASE}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_SECS) as resp:
                body = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                logger.warning("DeepSeek model '%s' not found. Run: ollama pull %s", self.model, self.model)
                self._available = False
            raise
        except TimeoutError:
            logger.warning("DeepSeek generate timed out (R1 chain-of-thought can be slow).")
            raise RuntimeError("timed out")
        raw = body.get("response", "").strip()
        return _strip_think(raw)

    def chat(self, messages: list, system: str = "", max_tokens: int = 2048) -> str:
        """Multi-turn chat with thinking stripped."""
        full_messages = (
            [{"role": "system", "content": system}] if system else []
        ) + messages
        payload = json.dumps({
            "model":    self.model,
            "stream":   False,
            "messages": full_messages,
            "options":  {
                "num_predict": max_tokens,
                "temperature": 0.1,
                "top_p": 0.85,
                "num_ctx": 4096,   # Reduced to lower RAM usage
            },
        }).encode()
        req = urllib.request.Request(
            f"{OLLAMA_BASE}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_SECS) as resp:
                body = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                self._available = False
            raise
        except TimeoutError:
            logger.warning("DeepSeek chat timed out.")
            raise RuntimeError("timed out")
        raw = body.get("message", {}).get("content", "").strip()
        return _strip_think(raw)

    def analyze_security(self, cve_data: dict, context: str = "") -> str:
        """
        Specialized entry point for deep CVE/security analysis.
        Returns structured analysis with exploit chain, impact, remediation.
        """
        prompt = f"""You are a senior network security analyst. Analyze the following CVE data
and provide a structured security assessment.

CVE Data:
{json.dumps(cve_data, indent=2)}

{f'Additional Context: {context}' if context else ''}

Provide your analysis as JSON with these fields:
- severity_assessment: your severity rating (critical/high/medium/low) with justification
- exploit_likelihood: probability of exploitation (high/medium/low) with reasoning
- attack_vectors: list of possible attack vectors
- blast_radius: potential impact scope
- immediate_actions: list of immediate mitigation steps
- long_term_fix: permanent remediation strategy
- confidence_score: your confidence in this analysis (0-100)
"""
        return self.generate(prompt, expect_json=True, max_tokens=2048)

    def _check_model(self) -> bool:
        try:
            req = urllib.request.Request(f"{OLLAMA_BASE}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = json.loads(resp.read().decode())
            models = [m["name"] for m in body.get("models", [])]
            model_base = self.model.split(":")[0]
            if any(model_base in m for m in models):
                return True
            logger.warning(
                "DeepSeek model '%s' not found. Run: ollama pull %s", self.model, self.model
            )
            return False
        except Exception as e:
            logger.debug("DeepSeek availability check failed: %s", e)
            return False


# Singleton
deepseek_provider = DeepSeekProvider()
