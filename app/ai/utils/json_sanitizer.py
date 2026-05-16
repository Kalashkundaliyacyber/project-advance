"""
ScanWise AI — JSON Sanitizer
Fixes malformed AI responses: invalid escapes, markdown fences, trailing commas,
truncated/unbalanced brackets, single-quoted strings.

FIX 4: Added bracket-balancing recovery for truncated AI responses.
"""
import json
import re
import logging

logger = logging.getLogger("scanwise.ai.json_sanitizer")


def sanitize_json(text: str) -> str:
    """
    Clean AI-generated text to extract valid JSON.
    Handles:
    - Markdown code fences (```json ... ```)
    - Invalid escape sequences
    - Trailing commas before } or ]
    - BOM / leading whitespace
    - Single-quoted strings (best-effort)
    - Truncated/unbalanced JSON (bracket recovery)
    """
    if not text:
        return text

    # Strip BOM and whitespace
    text = text.strip().lstrip("\ufeff")

    # Strip markdown fences
    fence_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
    if fence_match:
        text = fence_match.group(1).strip()

    # Extract JSON object/array if surrounded by prose
    if not (text.startswith("{") or text.startswith("[")):
        obj_match = re.search(r"(\{.*\}|\[.*\])", text, re.DOTALL)
        if obj_match:
            text = obj_match.group(1)

    # Fix invalid escape sequences
    text = _fix_invalid_escapes(text)

    # Remove trailing commas before } or ]
    text = re.sub(r",\s*([}\]])", r"\1", text)

    return text


def balance_brackets(text: str) -> str:
    """
    Attempt to close unclosed JSON brackets/braces to recover truncated responses.
    Works on text that has already been sanitized.
    """
    stack = []
    in_string = False
    escape_next = False
    PAIRS = {"{": "}", "[": "]"}
    CLOSERS = {"}", "]"}

    for ch in text:
        if escape_next:
            escape_next = False
            continue
        if ch == "\\" and in_string:
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch in PAIRS:
            stack.append(PAIRS[ch])
        elif ch in CLOSERS:
            if stack and stack[-1] == ch:
                stack.pop()
            # Mismatched closer — ignore (already malformed)

    # Append missing closers
    if stack:
        closing = "".join(reversed(stack))
        logger.debug("balance_brackets: appending %r to close truncated JSON", closing)
        text = text.rstrip().rstrip(",") + closing

    return text


def safe_parse_json(text: str) -> dict | list | None:
    """
    Try to parse JSON from AI response text. Returns None on failure.
    Attempts multiple cleanup strategies before giving up.
    """
    if not text:
        return None

    # Attempt 1: raw parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Attempt 2: sanitize then parse
    cleaned = sanitize_json(text)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # Attempt 3: bracket-balance recovery (handles truncated responses)
    balanced = balance_brackets(cleaned)
    try:
        return json.loads(balanced)
    except json.JSONDecodeError:
        pass

    # Attempt 4: single-quote replacement (very rough but catches some models)
    try:
        repaired = re.sub(r"(?<![\\\w])'(?![\w])", '"', balanced)
        return json.loads(repaired)
    except json.JSONDecodeError:
        pass

    # Attempt 5: extract the first complete {...} or [...] object with regex
    try:
        for pattern in (r"\{[^{}]*\}", r"\[[^\[\]]*\]"):
            m = re.search(pattern, cleaned, re.DOTALL)
            if m:
                result = json.loads(m.group(0))
                logger.debug("safe_parse_json: recovered partial object via regex")
                return result
    except json.JSONDecodeError:
        pass

    logger.warning("safe_parse_json: all attempts failed. text[:300]=%s", text[:300])
    return None


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
    """
    VALID_ESCAPES = set(chr(34) + chr(92) + chr(47) + "bfnrtu")
    result = []
    i = 0
    in_string = False
    while i < len(text):
        ch = text[i]
        if ch == '"' and (i == 0 or text[i-1] != "\\"):
            in_string = not in_string
            result.append(ch)
        elif ch == "\\" and in_string:
            if i + 1 < len(text):
                next_ch = text[i + 1]
                if next_ch in VALID_ESCAPES:
                    result.append(ch)
                    result.append(next_ch)
                    i += 2
                    continue
                else:
                    result.append("\\\\")
                    i += 1
                    continue
            else:
                result.append("\\\\")
        else:
            result.append(ch)
        i += 1
    return "".join(result)
