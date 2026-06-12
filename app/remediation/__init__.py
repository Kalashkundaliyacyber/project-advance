"""
ThreatWeave — Remediation Package
====================================
4-Layer Intelligent Patch Resolution Framework.

Public API:
  from app.remediation import resolve_patch, resolve_patches_batch, get_resolution_stats
"""
from .orchestrator import resolve_patch, resolve_patches_batch, get_resolution_stats

__all__ = ["resolve_patch", "resolve_patches_batch", "get_resolution_stats"]
