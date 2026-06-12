"""
ThreatWeave AI — AI Request Queue
Uses asyncio.Semaphore to prevent model overload and VRAM spikes.
Limits concurrent AI calls to avoid OOM on RTX 4060 8GB.
"""
import asyncio
import logging
import time
from typing import Callable, Any

logger = logging.getLogger("threatweave.ai.queue")

# Max concurrent AI calls — set to 1 to prevent dual-model RAM spikes on limited VRAM
MAX_CONCURRENT = int(__import__("os").environ.get("AI_MAX_CONCURRENT", "1"))

_semaphore: asyncio.Semaphore | None = None
_queue_depth: int = 0


def _get_semaphore() -> asyncio.Semaphore:
    """Get or create the semaphore (lazy init — event loop must exist)."""
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    return _semaphore


async def run_with_queue(fn: Callable, *args, timeout: float = 30.0, **kwargs) -> Any:
    """
    Run an AI call through the queue.
    Blocks until a slot is available, then runs fn(*args, **kwargs).
    Raises asyncio.TimeoutError if queue wait + execution exceeds timeout.
    """
    global _queue_depth
    sem = _get_semaphore()
    _queue_depth += 1
    logger.debug("AI queue: waiting for slot (depth=%d)", _queue_depth)

    try:
        async with sem:
            _queue_depth -= 1
            logger.debug("AI queue: slot acquired (depth=%d)", _queue_depth)
            loop = asyncio.get_event_loop()
            t0 = time.time()
            result = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: fn(*args, **kwargs)),
                timeout=timeout,
            )
            logger.debug("AI queue: call done in %.1fs", time.time() - t0)
            return result
    except asyncio.TimeoutError:
        logger.warning("AI queue: call timed out after %.1fs", timeout)
        raise
    except Exception:
        _queue_depth = max(0, _queue_depth - 1)
        raise


def get_queue_depth() -> int:
    """Current number of requests waiting for a queue slot."""
    return max(0, _queue_depth)
