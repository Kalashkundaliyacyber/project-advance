"""
ThreatWeave AI — JSON Sanitizer
Fixes malformed AI responses: invalid escapes, markdown fences, trailing commas.
"""
import json
import re
import logging

logger = logging.getLogger("threatweave.ai.json_sanitizer")


def sanitize_json(text: str) -> str:
    """
    Clean AI-generated text to extract valid JSON.
    Handles:
    - Markdown code fences (```json ... ```)
    - Invalid escape sequences (\\n in strings, \\/, etc.)
    - Trailing commas before } or ]
    - BOM / leading whitespace
    - Single-quoted strings (best-effort)
    """
    if not text:
        return text

    # Strip BOM and whitespace
    text = text.strip().lstrip("\ufeff")

    # Strip markdown fences
    # ```json\n...\n``` or ```\n...\n```
    fence_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
    if fence_match:
        text = fence_match.group(1).strip()

    # If text starts with { or [ assume it's already JSON-ish
    # If not, try to extract the first JSON object/array
    if not (text.startswith("{") or text.startswith("[")):
        obj_match = re.search(r"(\{.*\}|\[.*\])", text, re.DOTALL)
        if obj_match:
            text = obj_match.group(1)

    # Fix invalid escape sequences that break json.loads:
    # Replace \/ -> /  (not required in JSON but some models emit it)
    # Replace \' -> '  (invalid in JSON strings)
    # Replace \\n inside a string context? Tricky — handle carefully.
    text = _fix_invalid_escapes(text)

    # Remove trailing commas before } or ]
    text = re.sub(r",\s*([}\]])", r"\1", text)

    return text


def safe_parse_json(text: str) -> dict | list | None:
    """
    Try to parse JSON from AI response text. Returns None on failure.
    Attempts multiple cleanup strategies including truncation repair.
    """
    if not text:
        return None

    # Attempt 1: raw parse
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        logger.warning("safe_parse_json attempt 1 (raw) failed: %s", exc)

    # Attempt 2: sanitize then parse
    cleaned = sanitize_json(text)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as exc:
        logger.warning("safe_parse_json attempt 2 (sanitized) failed: %s", exc)

    # Attempt 3: single-quote fix
    try:
        repaired = re.sub(r"(?<![\\])'", '"', cleaned)
        return json.loads(repaired)
    except json.JSONDecodeError as exc:
        logger.warning("safe_parse_json attempt 3 (single-quote fix) failed: %s", exc)

    # Attempt 4: truncated JSON repair
    # Llama often cuts off before the closing } — try to close open braces
    try:
        repaired = _repair_truncated(cleaned)
        if repaired != cleaned:
            return json.loads(repaired)
    except json.JSONDecodeError as exc:
        logger.warning("safe_parse_json attempt 4 (truncation repair) failed: %s", exc)

    logger.warning("safe_parse_json: all attempts failed. text[:200]=%s", text[:200])
    return None


def _repair_truncated(text: str) -> str:
    """Close unclosed JSON braces/brackets and fix trailing incomplete values."""
    t = text.strip()
    if not t:
        return t

    # Remove trailing incomplete key-value pair (e.g. ,"key": or ,"key":"val)
    t = re.sub(r',\s*"[^"]*"\s*:\s*"[^"]*$', '', t)   # trailing open string
    t = re.sub(r',\s*"[^"]*"\s*:\s*$', '', t)           # trailing key with no value
    t = re.sub(r',\s*"[^"]*"\s*$', '', t)                # trailing key only
    t = re.sub(r',\s*$', '', t)                            # trailing comma

    # Count open braces and brackets and close them
    opens  = t.count('{') - t.count('}')
    aopens = t.count('[') - t.count(']')

    if aopens > 0:
        t += ']'  * aopens
    if opens > 0:
        t += '}' * opens

    return t


def extract_json_field(text: str, field: str, default=None):
    """Quick field extraction without full parse — useful for partial responses."""
    parsed = safe_parse_json(text)
    if isinstance(parsed, dict):
        return parsed.get(field, default)
    return default


# ── Internal helpers ──────────────────────────────────────────────────────────

def _fix_invalid_escapes(text: str) -> str:
    r"""
    Walk the string and fix escape sequences that are invalid in JSON.
    Valid JSON escapes: \\ \" \/ \b \f \n \r \t \uXXXX
    Everything else after a backslash is invalid and should be doubled.

    Uses a proper state machine instead of a naive single-char lookbehind.
    The expression text[i-1] != '\\' incorrectly handles an even number of
    consecutive backslashes before a quote (e.g. \\\\" closes the string
    but \\" does not). We instead count trailing backslashes in the result
    buffer to determine whether a quote is escaped.
    """
    VALID_ESCAPES = set(chr(34) + chr(92) + chr(47) + "bfnrtu")
    result = []
    i = 0
    in_string = False
    while i < len(text):
        ch = text[i]
        if ch == '"':
            if not in_string:
                in_string = True
                result.append(ch)
                i += 1
            else:
                # Count consecutive backslashes already emitted to determine
                # whether this quote is escaped (odd count = escaped).
                num_bs = 0
                j = len(result) - 1
                while j >= 0 and result[j] == '\\':
                    num_bs += 1
                    j -= 1
                if num_bs % 2 == 0:
                    # Even number of preceding backslashes → quote is unescaped
                    in_string = False
                result.append(ch)
                i += 1
        elif ch == "\\" and in_string:
            if i + 1 < len(text):
                next_ch = text[i + 1]
                if next_ch in VALID_ESCAPES:
                    result.append(ch)
                    result.append(next_ch)
                    i += 2
                    continue
                else:
                    # Double the backslash to escape it
                    result.append("\\\\")
                    i += 1
                    continue
            else:
                result.append("\\\\")
                i += 1
        else:
            result.append(ch)
            i += 1
    return "".join(result)
