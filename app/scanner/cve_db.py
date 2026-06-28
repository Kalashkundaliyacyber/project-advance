"""
app/scanner/cve_db.py
────────────────────────────────────────────────────────────────────────────
SQLite-backed CVE → NSE script mapping database for ThreatWeave AI.

This module is the single source of truth for CVE→script mappings:

  Layer 1 — Manual entries (45 CVEs from CVE_NSE_MAP, confidence 90-95)
  Layer 2 — Auto-parsed from /usr/share/nmap/scripts/*.nse at startup
             (600+ CVEs extracted from filenames + script headers)
  Layer 3 — Gemini AI suggestions (saved here after first ask, never re-asked)
  Layer 4 — Version-range fallback (POTENTIALLY_VULNERABLE, no script)

What IS stored:
  • cve_id  → script_name  (which NSE script to run for this CVE)
  • product_keywords        (which services this CVE applies to)
  • source                  (manual | nse_parse | gemini)
  • confidence              (reliability of the CVE→script mapping itself)
  • used_count              (how many times this mapping was selected)

What is NEVER stored:
  • Whether any specific target was vulnerable  ← host-specific, ephemeral
  • Whether a script returned CONFIRMED/NOT_VULNERABLE for any host
  • Failure counters or review flags based on scan outcomes

Rationale:  A scan result (CONFIRMED / NOT_VULNERABLE) belongs to a specific
target at a specific point in time.  Storing it globally would cause results
from machine A to silently influence the confidence used when scanning machine B
— a fundamentally different system with different patch levels and services.
The script selection (which NSE to use for CVE-XXXX) is universal and correct
to cache.  The vulnerability outcome is not.

Privacy:
  The database stores only CVE IDs and script names — never IP addresses,
  hostnames, scan results, or any target-specific data.
"""

from __future__ import annotations

import os
import re
import sqlite3
import threading
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Database location
# ─────────────────────────────────────────────────────────────────────────────
_PROJECT_ROOT = Path(__file__).parent.parent.parent
DB_PATH       = str(_PROJECT_ROOT / "data" / "cve_scripts.db")
NSE_DIR       = "/usr/share/nmap/scripts"

_init_lock  = threading.Lock()
_initialized = False


# ─────────────────────────────────────────────────────────────────────────────
# Connection helper
# ─────────────────────────────────────────────────────────────────────────────

def _connect() -> sqlite3.Connection:
    """Open a connection to the CVE database, creating it if needed."""
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # WAL allows concurrent reads
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


# ─────────────────────────────────────────────────────────────────────────────
# Schema
# ─────────────────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cve_script_cache (
    cve_id               TEXT PRIMARY KEY,
    script_name          TEXT,          -- NULL = confirmed no script exists for this CVE
    product_keywords     TEXT,          -- comma-sep, e.g. "vsftpd,ftp"
    confidence           INTEGER DEFAULT 75,
    source               TEXT DEFAULT 'unknown',
                                        -- manual | nse_parse | gemini | nvd
    verified             INTEGER DEFAULT 0,   -- 1 = human-confirmed mapping
    gemini_reasoning     TEXT,
    used_count           INTEGER DEFAULT 0,   -- how many times this mapping was selected
    created_at           TEXT DEFAULT (datetime('now')),
    updated_at           TEXT DEFAULT (datetime('now'))
);

-- REMOVED columns (were storing target-specific scan outcomes — wrong):
--   confirmed_count      INTEGER  -- how many targets were CONFIRMED vulnerable
--   consecutive_failures INTEGER  -- how many scans returned UNCONFIRMED
--   needs_review         INTEGER  -- flag set after repeated scan failures
--
-- These columns caused scan results from machine A to corrupt confidence
-- scores used when scanning machine B.  Scan outcomes belong in per-scan
-- reports, never in the shared script-selection cache.

CREATE TABLE IF NOT EXISTS version_ranges (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id          TEXT NOT NULL,
    product_keyword TEXT NOT NULL,
    min_version     TEXT NOT NULL,
    max_version     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cve_script ON cve_script_cache(cve_id);
CREATE INDEX IF NOT EXISTS idx_source     ON cve_script_cache(source);
CREATE INDEX IF NOT EXISTS idx_vr_cve     ON version_ranges(cve_id);
"""


def _create_schema(conn: sqlite3.Connection):
    conn.executescript(_SCHEMA)
    conn.commit()
    _migrate_schema(conn)


def _migrate_schema(conn: sqlite3.Connection):
    """
    Handle existing databases that still have the removed target-specific
    columns (confirmed_count, consecutive_failures, needs_review).

    SQLite does not support DROP COLUMN on older versions, so we use the
    standard rename-create-copy-drop migration pattern.  This runs once on
    startup; if the old columns don't exist the migration is skipped.
    """
    cols = [row[1] for row in conn.execute("PRAGMA table_info(cve_script_cache)")]
    stale_cols = {"confirmed_count", "consecutive_failures", "needs_review"}
    if not stale_cols.intersection(cols):
        return   # already clean — nothing to do

    logger.info(
        "cve_db: migrating schema — removing stale target-specific columns: %s",
        stale_cols.intersection(cols),
    )
    conn.executescript("""
        -- Step 1: copy into a clean table with only the valid columns
        CREATE TABLE IF NOT EXISTS cve_script_cache_v2 (
            cve_id               TEXT PRIMARY KEY,
            script_name          TEXT,
            product_keywords     TEXT,
            confidence           INTEGER DEFAULT 75,
            source               TEXT DEFAULT 'unknown',
            verified             INTEGER DEFAULT 0,
            gemini_reasoning     TEXT,
            used_count           INTEGER DEFAULT 0,
            created_at           TEXT DEFAULT (datetime('now')),
            updated_at           TEXT DEFAULT (datetime('now'))
        );

        INSERT OR IGNORE INTO cve_script_cache_v2
            (cve_id, script_name, product_keywords, confidence,
             source, verified, gemini_reasoning, used_count,
             created_at, updated_at)
        SELECT
             cve_id, script_name, product_keywords, confidence,
             source, verified, gemini_reasoning, used_count,
             created_at, updated_at
        FROM cve_script_cache;

        -- Step 2: swap
        DROP TABLE cve_script_cache;
        ALTER TABLE cve_script_cache_v2 RENAME TO cve_script_cache;

        -- Step 3: recreate indexes
        CREATE INDEX IF NOT EXISTS idx_cve_script ON cve_script_cache(cve_id);
        CREATE INDEX IF NOT EXISTS idx_source     ON cve_script_cache(source);
    """)
    conn.commit()
    logger.info("cve_db: schema migration complete — stale columns removed")


# ─────────────────────────────────────────────────────────────────────────────
# Seeding helpers
# ─────────────────────────────────────────────────────────────────────────────

def _upsert(conn: sqlite3.Connection, cve_id: str, script_name: Optional[str],
            products: str, confidence: int, source: str, verified: int = 0,
            reasoning: str = "", force: bool = False):
    """
    Insert a CVE→script mapping, updating confidence if the row exists
    and the new confidence is higher than the existing one.

    force=True (used by _seed_hardcoded for manual entries) always
    overwrites existing rows regardless of confidence or verified flag.
    This ensures hand-verified mappings can never be silently replaced by
    wrong auto-seeded (nse_parse) or Gemini-suggested entries in the DB.
    """
    existing = conn.execute(
        "SELECT confidence, verified FROM cve_script_cache WHERE cve_id = ?",
        (cve_id,)
    ).fetchone()

    if existing:
        # force=True: manual entries always win — overwrite wrong DB state
        if not force and (existing["verified"] or existing["confidence"] >= confidence):
            return
        conn.execute("""
            UPDATE cve_script_cache
            SET script_name=?, product_keywords=?, confidence=?,
                source=?, verified=?, updated_at=datetime('now')
            WHERE cve_id=?
        """, (script_name, products, confidence, source, verified, cve_id))
    else:
        conn.execute("""
            INSERT INTO cve_script_cache
              (cve_id, script_name, product_keywords, confidence,
               source, verified, gemini_reasoning)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (cve_id, script_name, products, confidence,
              source, verified, reasoning))


def _seed_hardcoded(conn: sqlite3.Connection) -> int:
    """
    Migrate the 45 hand-verified entries from CVE_NSE_MAP + KNOWN_VULNERABLE_VERSIONS
    into the database with confidence = entry['confidence_base'] and verified = 1.
    """
    try:
        # Lazy import to break potential circular dependency
        from app.scanner.cve_script_mapper import CVE_NSE_MAP, KNOWN_VULNERABLE_VERSIONS
    except ImportError:
        logger.warning("cve_script_mapper not available for seeding")
        return 0

    count = 0
    for cve_id, entry in CVE_NSE_MAP.items():
        _upsert(
            conn, cve_id,
            script_name  = entry.get("script"),
            products     = ",".join(entry.get("products", [])),
            confidence   = entry.get("confidence_base", 90),
            source       = "manual",
            verified     = 1,
            reasoning    = entry.get("notes", ""),
            force        = True,   # manual entries always override wrong DB state
        )
        count += 1

    # Version range fallback table
    for cve_id, ranges in KNOWN_VULNERABLE_VERSIONS.items():
        # Ensure there's a cache row for these CVEs (no script, version-only)
        existing = conn.execute(
            "SELECT 1 FROM cve_script_cache WHERE cve_id=?", (cve_id,)
        ).fetchone()
        if not existing:
            _upsert(conn, cve_id, None, "", 60, "version_range")

        for prod_kw, vmin, vmax in ranges:
            # Avoid duplicates
            dup = conn.execute("""
                SELECT 1 FROM version_ranges
                WHERE cve_id=? AND product_keyword=? AND min_version=? AND max_version=?
            """, (cve_id, prod_kw, vmin, vmax)).fetchone()
            if not dup:
                conn.execute("""
                    INSERT INTO version_ranges (cve_id, product_keyword, min_version, max_version)
                    VALUES (?, ?, ?, ?)
                """, (cve_id, prod_kw, vmin, vmax))

    conn.commit()
    return count


def _extract_cve_from_filename(filename: str) -> Optional[str]:
    """
    Extract a CVE ID from an NSE filename.
    e.g. smb-vuln-cve2009-3103.nse → CVE-2009-3103
         http-vuln-cve2011-3192.nse → CVE-2011-3192
    """
    m = re.search(r'cve[-_]?(\d{4})[-_](\d+)', filename, re.IGNORECASE)
    if m:
        return f"CVE-{m.group(1)}-{m.group(2)}"
    return None


def _extract_cve_from_content(filepath: str) -> list[str]:
    """
    Scan the first 80 lines of an .nse file for CVE references.
    Handles formats:
      IDs = {CVE = "CVE-2014-0160", ...}
      -- IDs: CVE:CVE-2014-0160
      -- @vuln.cve CVE-2014-0160
    """
    cves = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f):
                if i > 80:
                    break
                matches = re.findall(r'CVE-(\d{4})-(\d+)', line, re.IGNORECASE)
                for year, num in matches:
                    cve_id = f"CVE-{year}-{num}"
                    if cve_id not in cves:
                        cves.append(cve_id)
    except OSError:
        pass
    return cves


# Script-name prefix → product keywords.
# Prevents auto-seeded nse_parse entries from running on the wrong service.
_SCRIPT_PREFIX_PRODUCTS: dict[str, str] = {
    "ftp-":         "ftp,vsftpd,proftpd,wu-ftpd",
    "smtp-":        "smtp,exim,postfix,sendmail,mail",
    "http-":        "http,apache,nginx,tomcat,iis,web",
    "smb-":         "smb,samba,netbios,windows,microsoft,cifs",
    "ssl-":         "ssl,tls,openssl,https",
    "mysql-":       "mysql,mariadb",
    "irc-":         "irc,unrealircd",
    "rmi-":         "rmi,java-rmi,classpath,grmiregistry",
    "rdp-":         "rdp,ms-wbt-server",
    "snmp-":        "snmp",
    "distcc-":      "distcc,distccd",
    "vnc-":         "vnc,realvnc",
    "realvnc-":     "vnc,realvnc",
    "telnet-":      "telnet,telnetd",
    "ssh-":         "ssh,openssh",
}


def _product_keywords_for_script(script_name: str) -> str:
    """
    Return a comma-separated product keyword list for an NSE script based on
    its name prefix.  Used when seeding from NSE files so that auto-parsed
    entries don't bypass the product guard in get_confirmation_plan().
    """
    for prefix, keywords in _SCRIPT_PREFIX_PRODUCTS.items():
        if script_name.startswith(prefix):
            return keywords
    return ""


def _seed_from_nse_files(conn: sqlite3.Connection) -> int:
    """
    Auto-scan all .nse files in /usr/share/nmap/scripts/ and extract
    CVE→script mappings. This gives 600+ entries automatically.
    Only imports vuln/safe/version/discovery category scripts — not brute/exploit.
    """
    if not os.path.isdir(NSE_DIR):
        logger.info("NSE scripts dir not found: %s", NSE_DIR)
        return 0

    count = 0
    try:
        nse_files = [f for f in os.listdir(NSE_DIR) if f.endswith(".nse")]
    except OSError:
        return 0

    # Category blocklist — never auto-import brute force or exploit scripts
    BLOCKED_KEYWORDS = {"brute", "exploit", "fuzzer", "dos", "backdoor-connect"}

    for filename in nse_files:
        script_name = filename[:-4]

        # Block dangerous categories by name pattern
        if any(bk in script_name for bk in BLOCKED_KEYWORDS):
            continue

        filepath = os.path.join(NSE_DIR, filename)

        # Derive product keywords from script-name prefix so the product
        # guard in get_confirmation_plan() prevents cross-service misuse.
        # e.g. smtp-vuln-cve2010-4344 must not run against rpcbind/http/postgres.
        _prod_kw = _product_keywords_for_script(script_name)

        # Try filename first (most reliable)
        cve_id = _extract_cve_from_filename(filename)
        if cve_id:
            _upsert(conn, cve_id, script_name, _prod_kw, 80, "nse_parse")
            count += 1
            continue

        # Fall back to reading script header
        cves_in_content = _extract_cve_from_content(filepath)
        for cve_id in cves_in_content:
            _upsert(conn, cve_id, script_name, _prod_kw, 78, "nse_parse")
            count += 1

    conn.commit()
    logger.info("NSE file scan complete: %d CVE→script mappings extracted", count)
    return count


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def init_db() -> dict:
    """
    Initialize the CVE database:
      1. Create schema (idempotent)
      2. Seed from hardcoded CVE_NSE_MAP (45 verified entries)
      3. Auto-scan /usr/share/nmap/scripts/ for all CVE references

    Safe to call multiple times — uses a lock and idempotent upserts.
    Returns stats dict.
    """
    global _initialized
    with _init_lock:
        if _initialized:
            return get_db_stats()

        logger.info("Initializing CVE database at %s", DB_PATH)
        conn = _connect()
        try:
            _create_schema(conn)
            manual  = _seed_hardcoded(conn)
            from_nse = _seed_from_nse_files(conn)
            total = conn.execute(
                "SELECT COUNT(*) FROM cve_script_cache"
            ).fetchone()[0]
            logger.info(
                "CVE DB ready: %d total (%d manual, %d from NSE files)",
                total, manual, from_nse
            )
            _initialized = True
            return {"total": total, "manual": manual, "nse_parsed": from_nse}
        finally:
            conn.close()


def get_script_for_cve(
    cve_id: str,
    service: str = "",
    product: str = "",
    available_scripts: Optional[list] = None,
) -> dict:
    """
    Look up the best NSE script for a CVE from the database.

    Returns:
    {
        "found"      : bool,
        "script"     : str | None,
        "confidence" : int,
        "source"     : str,
        "has_version_range": bool,
    }
    """
    init_db()
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT * FROM cve_script_cache WHERE cve_id = ?",
            (cve_id,)
        ).fetchone()

        if not row:
            return {"found": False, "script": None, "confidence": 0, "source": ""}

        script = row["script_name"]

        # If we have a script name, verify it's still on disk
        if script and available_scripts is not None:
            if script not in available_scripts:
                logger.debug("DB script %s not on disk, skipping", script)
                script = None

        # Check version ranges
        has_vr = bool(conn.execute(
            "SELECT 1 FROM version_ranges WHERE cve_id = ?", (cve_id,)
        ).fetchone())

        return {
            "found"              : True,
            "script"             : script,
            "confidence"         : row["confidence"],
            "source"             : row["source"],
            "has_version_range"  : has_vr,
            "product_keywords"   : row["product_keywords"] or "",
        }
    finally:
        conn.close()


def get_version_ranges(cve_id: str) -> list:
    """Return version range entries for a CVE."""
    init_db()
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT product_keyword, min_version, max_version FROM version_ranges WHERE cve_id = ?",
            (cve_id,)
        ).fetchall()
        return [(r["product_keyword"], r["min_version"], r["max_version"]) for r in rows]
    finally:
        conn.close()


def save_ai_result(
    cve_id: str,
    script_name: Optional[str],
    service: str = "",
    product: str = "",
    reasoning: str = "",
    source: str = "gemini",
) -> bool:
    """
    Save a Gemini-suggested CVE→script mapping to the database.

    This stores ONLY the script selection (which NSE script to run for this
    CVE) — never whether any target was actually vulnerable.  Confidence
    starts at 72 (below manual=90 and nse_parse=80) because Gemini's answer
    has not yet been human-verified.

    The confidence value here reflects how reliable the CVE→script MAPPING
    is, not whether any specific machine was found vulnerable.  Scan outcomes
    (CONFIRMED / NOT_VULNERABLE / UNCONFIRMED) are never written to this DB.
    """
    init_db()
    conn = _connect()
    try:
        _upsert(
            conn, cve_id, script_name,
            products   = f"{service},{product}".strip(","),
            confidence = 72,
            source     = source,
            verified   = 0,
            reasoning  = reasoning,
        )
        conn.commit()
        logger.debug("save_ai_result: saved script mapping %s → %s (source=%s)",
                     cve_id, script_name, source)
        return True
    except Exception as e:
        logger.warning("save_ai_result failed for %s: %s", cve_id, e)
        return False
    finally:
        conn.close()


def record_script_selection(cve_id: str) -> bool:
    """
    Increment the used_count for a CVE→script mapping.

    This is the ONLY feedback the DB accepts from live scans — a pure usage
    counter that records how many times a mapping was selected.  It carries
    no information about whether the target was vulnerable.

    What is deliberately NOT recorded here:
      - Whether the scan returned CONFIRMED, NOT_VULNERABLE, or UNCONFIRMED
      - Any confidence adjustment based on scan outcome
      - Failure counters or review flags based on target-specific results

    Scan outcomes (CONFIRMED / NOT_VULNERABLE) belong in the per-scan report
    only.  Recording them globally would corrupt confidence scores across
    different targets and scan sessions.
    """
    if not cve_id:
        return False
    init_db()
    conn = _connect()
    try:
        conn.execute("""
            UPDATE cve_script_cache
            SET used_count = used_count + 1,
                updated_at = datetime('now')
            WHERE cve_id = ?
        """, (cve_id,))
        conn.commit()
        return True
    except Exception as e:
        logger.warning("record_script_selection failed for %s: %s", cve_id, e)
        return False
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# record_scan_result() has been REMOVED.
#
# It previously adjusted global confidence and consecutive_failures columns
# based on whether a specific host was vulnerable — mixing script-selection
# quality (universal) with vulnerability outcomes (target-specific).
#
# Example of the bug it caused:
#   1. Scan Samba host A (not vulnerable)  → NOT_VULNERABLE
#      → record_scan_result sets confidence += 2, failures = 0
#   2. Scan Samba host B (IS vulnerable)   → UNCONFIRMED (e.g. timeout)
#      → record_scan_result sets consecutive_failures += 1, confidence -= 3
#   3. Scan Samba host C (IS vulnerable)   → confidence now too low, script
#      may be skipped or flagged needs_review=1 → missed vulnerability
#
# The fix: confidence in this DB represents only how reliable the
# CVE→script MAPPING is (does running smb-vuln-cve-2017-7494 test for
# CVE-2017-7494?  Yes — always).  It must not be influenced by which
# targets happened to be running vulnerable versions.
# ---------------------------------------------------------------------------


def get_db_stats() -> dict:
    """Return database statistics for admin/debug.  No target-specific data."""
    try:
        conn = _connect()
        try:
            total     = conn.execute("SELECT COUNT(*) FROM cve_script_cache").fetchone()[0]
            manual    = conn.execute("SELECT COUNT(*) FROM cve_script_cache WHERE source='manual'").fetchone()[0]
            nse_parse = conn.execute("SELECT COUNT(*) FROM cve_script_cache WHERE source='nse_parse'").fetchone()[0]
            gemini    = conn.execute("SELECT COUNT(*) FROM cve_script_cache WHERE source='gemini'").fetchone()[0]
            verified  = conn.execute("SELECT COUNT(*) FROM cve_script_cache WHERE verified=1").fetchone()[0]
            no_script = conn.execute("SELECT COUNT(*) FROM cve_script_cache WHERE script_name IS NULL").fetchone()[0]
            vr_count  = conn.execute("SELECT COUNT(DISTINCT cve_id) FROM version_ranges").fetchone()[0]
            # NOTE: confirmed_count, needs_review, consecutive_failures columns
            # have been removed — they stored target-specific scan outcomes which
            # must never be persisted in the shared script-selection cache.
            return {
                "total"           : total,
                "manual"          : manual,
                "nse_parsed"      : nse_parse,
                "gemini"          : gemini,
                "human_verified"  : verified,
                "no_script_mapped": no_script,
                "version_ranges"  : vr_count,
            }
        finally:
            conn.close()
    except Exception:
        return {"total": 0, "error": "db not initialized"}


def ensure_initialized():
    """Call this at startup to pre-warm the database."""
    return init_db()
