"""
ScanWise AI — Response Parser
Parse and validate AI responses into expected structured formats.
"""
import json
import logging
from typing import Optional

from app.ai.utils.json_sanitizer import safe_parse_json

logger = logging.getLogger("scanwise.ai.response_parser")

# Required keys for each response type
_PATCH_REQUIRED = {"service", "summary"}
_ANALYSIS_REQUIRED = {"overall_risk", "findings"}


def parse_patch_response(text: str, fallback: dict) -> dict:
    """
    Parse AI patch guidance response. Returns fallback if unparseable.
    Validates required keys and fills missing optional keys with defaults.
    """
    parsed = safe_parse_json(text)
    if not isinstance(parsed, dict):
        logger.warning("parse_patch_response: not a dict, using fallback")
        return fallback

    # Check required keys
    if not _PATCH_REQUIRED.issubset(parsed.keys()):
        logger.warning("parse_patch_response: missing required keys %s", _PATCH_REQUIRED - parsed.keys())
        # Merge with fallback to fill missing keys
        result = {**fallback, **parsed}
        return result

    return parsed


def parse_analysis_response(text: str, fallback: dict) -> dict:
    """
    Parse AI scan analysis response. Returns fallback if unparseable.
    """
    parsed = safe_parse_json(text)
    if not isinstance(parsed, dict):
        logger.warning("parse_analysis_response: not a dict, using fallback")
        return fallback

    if not _ANALYSIS_REQUIRED.issubset(parsed.keys()):
        result = {**fallback, **parsed}
        return result

    return parsed


def parse_json_response(text: str) -> Optional[dict]:
    """Generic JSON response parser. Returns None on failure."""
    return safe_parse_json(text)
