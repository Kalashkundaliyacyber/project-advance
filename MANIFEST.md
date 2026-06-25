# ThreatWeave Reconstruction — Phases 0–7: Manifest

Supersedes the earlier phase0-changed-files.zip — this is the complete, current
state of every file touched across Phases 0–7. Apply in this order.

## 1. DELETE (Phase 0 — unchanged from before)

```
app/scanner/orchestrator.py
app/api/discovery.py
app/api/scheduled_scans.py
app/multi_scan/
```

## 2. ADD (new files)

```
app/scanner/scanner_core.py        # Phase 0/1 — the one scan
app/scanner/service_prober.py      # Phase 2 — active service probing
app/scanner/cpe_cve_engine.py      # Phase 3 — local CPE/CVE matching
app/scanner/soplib.py              # Phase 4 — script output pattern library
app/scanner/misconfig_checker.py   # Phase 5 — misconfigurations as findings
app/scanner/confirmation_router.py # Phase 6 — tiered confirmation router
app/scanner/auth_scanner.py        # Phase 7 — optional authenticated scanning
```

## 3. OVERWRITE

```
app/main.py
app/api/validators.py
app/api/routes.py
app/recommendation/recommender.py
app/scanner/executor.py
app/scanner/cve_script_mapper.py
requirements.txt
statics/js/chatbot.js
```

---

## Phase-by-phase: what actually needed building vs. what already existed

Before writing anything, I audited the codebase for overlap. Three phases turned
out to be substantially pre-built already — building parallel new systems for
them would have created duplicate, conflicting CVE/confirmation logic instead
of improving anything. Here's exactly what was real work vs. integration:

| Phase | Status | Detail |
|---|---|---|
| 1 | Already done | Phase 0's `scanner_core.py` already locked in the constant + `-sV` + full raw capture. Nothing left to do. |
| 2 | **New** | `service_prober.py` didn't exist. Built from scratch: HTTP/HTTPS GET, SSH/FTP banner read, SMB negotiation (validates `\xffSMB`/`\xfeSMB` magic bytes), raw-socket fallback. 3s timeout everywhere, silent failure, additive-only (never overwrites nmap's reported service/version). |
| 3 | **Mostly existed** | `app/vuln/nvd_client.py` already has `build_cpe()`, the exact NVD REST URL, and a SQLite cache (7-day/24h TTL — tighter than the "weekly" ceiling asked for). `app/cve/mapper.py` already does local version-range matching. The one missing piece — an explicit `confidence: "exact"\|"range"` field — is what `cpe_cve_engine.py` actually adds, as a thin layer over both, not a third CVE database. |
| 4 | **New** | Confirmed by reading `cve_script_mapper.py`'s `analyze_output()` line-by-line: it really did only check for `VULNERABLE:`/`State: VULNERABLE`, nothing else. None of the 8 required scripts were handled. Built `soplib.py` from scratch with all 8. |
| 5 | **New** | No misconfiguration concept existed anywhere in the pipeline. `misconfig_checker.py` is new, but its 5 script-based checks delegate pattern-matching to SOPLib (Phase 4) rather than duplicating regex logic — only `telnet_open`/`snmp_default` (pure port-presence, no script needed) are independent. |
| 6 | **Mostly existed** | `script_selector.py::get_confirmation_plan()` already does a 4-layer cascade (local DB → live Gemini → static fallback → version range) that's *cheaper* than the literal spec (DB-first beats calling Gemini directly). `confirmation_router.py` orchestrates this existing cascade as Steps 1–4, then adds the two genuinely missing pieces: Step 5 (Qwen last-resort) and the unified single-entry-point shape, replacing the confirm-port endpoint's inline logic. |
| 7 | **New** | No authenticated-scanning capability existed. `auth_scanner.py` is new: SSH via paramiko (uname, packages, SUID, /etc/passwd, listening-port cross-check), SMB via pysmb/impacket (share enum, write test). Both degrade to "no findings, clear log line" if their library isn't installed or no credentials are given — never blocks the pipeline. |

## Pipeline wiring (`_run_scan_pipeline` in routes.py)

```
run_full_scan()                              Phase 0/1
  -> service_prober.probe_all_ports()        Phase 2  (additive merge into parsed)
  -> soplib.scan_all_ports()                 Phase 4  (reads scripts already run)
  -> analyze_versions() -> map_cves()
     -> enrich_with_nvd_sync()
     -> cpe_cve_engine.tag_confidence_on_parsed()   Phase 3
  -> analyze_context() -> calculate_risk()
  -> [parallel] recommendation, explanation, ai_analysis, charts,
                misconfig_checker.run_all()         Phase 5
  -> rule_based_analysis, threat_correlation         (unchanged)
  -> [optional] auth_scanner.run_auth_checks()       Phase 7 (only if creds given)
  -> analysis dict (report-ready) -> save_analysis()
```

`confirmation_router.route_confirmation()` (Phase 6) lives on a separate path —
the per-port `/scan/confirm-port` endpoint the frontend's live table already
calls sequentially. It is now the *only* thing that endpoint calls; no inline
confirmation logic remains there.

## Bugs found and fixed while verifying (not introduced by this work)

1. **`executor.py`'s `_simulated_scan()` referenced `_sim_service()`, never
   defined anywhere** — crashed every simulated scan, for every scan type,
   whenever nmap wasn't installed. Fixed last session, still in this drop.
2. **SOPLib/generic-pattern priority conflict, found this session**: the
   existing generic NOT_VULN_PATTERNS includes a bare `disabled` keyword
   (meant for things like *"WebDAV disabled"* = safe). Because SOPLib was
   originally wired in *after* that generic check, `smb-security-mode`'s
   *"message_signing: disabled"* (a bad finding) was being misread as safe.
   **Fixed**: for any script SOPLib has a specific entry for, SOPLib now
   gets first refusal, before the generic patterns run at all. Verified with
   a regression test that the fix doesn't change behavior for any script
   SOPLib doesn't know about.
3. **`nfs-showmount` patterns anchored on line-start whitespace** (`^\s*/...`),
   but real nmap output prefixes every script-output line with `|`/`|_` —
   so the pattern could never match real output. Fixed to match the
   export-path-then-wildcard shape anywhere in the line instead. Caught by
   a unit test against realistic NSE output, not the simulated scan (whose
   fake data doesn't include this script).

## Verification performed

- `py_compile` across the entire `app/` tree, every time something changed
- `node --check` on `chatbot.js`
- Full `import app.main` in a clean venv against your pinned `requirements.txt`
  (now including `paramiko`) — 79 routes, no import errors
- Unit tests against realistic synthetic NSE output for **all 8** SOPLib
  scripts (8/9 passed first try; the 1 failure was the `nfs-showmount` bug
  above, fixed and re-verified)
- `confirmation_router.route_confirmation()` exercised through all 6 steps
  individually: NSE-keyword CONFIRMED, SOPLib CONFIRMED, no-output
  NOT_VALIDATABLE, short-unresolved-output UNCONFIRMED, long-unresolved
  output correctly attempting (and gracefully skipping, Qwen unavailable in
  this sandbox) Step 5, and a CVE-with-no-script case correctly invoking the
  Step 3 plan lookup
- Full `_run_scan_pipeline()` end-to-end run with all 7 phases wired in —
  confirmed `probed_services`, `soplib_findings`, `misconfig_findings`,
  `auth_findings` (empty list, no creds given) all present and correctly
  shaped in the final report-ready `analysis` dict
- `TestClient` HTTP tests: bare-IP chat auto-trigger still works end to end
  with the new stages inserted; `/scan/confirm-port` now returns the
  router's `trace` field showing which method resolved (or didn't resolve)
  the finding

## What's NOT included (by design, matches the original spec)

- Gemini integration untouched (Phase 3 explicitly said not to touch it;
  Phase 6 only changes *which* findings reach it and *when*)
- No SMB library forced into `requirements.txt` — `pysmb` or `impacket` are
  genuinely optional per Phase 7's own wording; install either manually if
  you want SMB authenticated checks. SSH's `paramiko` IS pinned, since SSH
  checks are the more commonly-used half of Phase 7.
- Phase 8 (final integration test / orphaned-code audit) — say the word and
  I'll run it next; it's a verification pass over everything above, not new
  code.
