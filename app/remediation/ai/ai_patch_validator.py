"""
ThreatWeave — AI Patch Output Validator
=========================================
Validates AI-generated patch data before storage and return.
Ensures AI output is safe, complete, and properly structured.
"""
from __future__ import annotations

import re
from typing import Optional

# Commands that are clearly invalid / hallucinated
_JUNK_PATTERNS = [
    re.compile(r"<[^>]+>"),              # HTML tags
    re.compile(r"\{\{[^}]+\}\}"),        # Template placeholders
    re.compile(r"your_package"),         # Common AI hallucination
    re.compile(r"<package_name>"),
    re.compile(r"<version>"),
]

REQUIRED_OUTPUT_FIELDS = {"title", "fix_version", "commands"}


def validate_ai_patch(data: dict) -> tuple[bool, Optional[str]]:
    """
    Validate AI-generated patch data.
    Returns (is_valid, error_message).
    """
    if not isinstance(data, dict):
        return False, "AI output must be a dict"

    if not data:
        return False, "Empty AI output"

    # Check for at least one useful field
    has_useful = any(data.get(f) for f in ("commands", "patch_command", "title",
                                            "mitigation", "vendor_url", "fix_version"))
    if not has_useful:
        return False, "AI output has no useful fields"

    # Check commands don't contain junk
    cmds = data.get("commands") or data.get("patch_command") or {}
    if isinstance(cmds, dict):
        for cmd_str in cmds.values():
            if isinstance(cmd_str, str):
                for pattern in _JUNK_PATTERNS:
                    if pattern.search(cmd_str):
                        return False, f"Invalid command detected: {cmd_str[:60]}"

    return True, None


def sanitize_ai_patch(data: dict) -> dict:
    """
    Sanitize AI output: strip None values, normalize field names.
    """
    clean = {}
    for k, v in data.items():
        if v is None:
            continue
        if isinstance(v, str):
            v = v.strip()
        clean[k] = v

    # Normalize command field name
    if "commands" not in clean and "patch_commands" in clean:
        clean["commands"] = clean.pop("patch_commands")

    return clean
