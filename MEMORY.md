# `logparser-DFIR` — Project State & Memory File

**Last Updated:** 2026-10-31 21:32 UTC  
**Repository Path:** `C:\users\xt\logparser-DFIR`  
**Current Version:** `v0.4.1`  
**Active Branch:** `master`

---

## 1. Executive Summary & Purpose
`logparser-DFIR` is a high-performance desktop Digital Forensics and Incident Response (DFIR) investigation workbench built with **Tauri v2 + Rust + SQLite** backend and a **Tabulator.js / HTML5** frontend. It is designed to ingest and correlate large SIEM/EDR log exports, cloud audit logs (Azure/M365, AWS), Windows Event logs (`.evtx`), and compressed archives (`.jsonl.gz`, `.csv`, `.tsv`) with zero silent drops, high-speed multi-file IOC hunting, and master timeline generation.

---

## 2. Recent Commits & Milestones

| Commit | Version | Description |
| :--- | :--- | :--- |
| `e08ab2b` | **v0.4.0** | **feat(ui):** Streamlined 3-tab forensic layout, universal multi-file IOC inspector, targeted hunting workbench, and contextual Gemini AI integration. |
| `21f2e0a` | **v0.3.9** | **fix(grid):** Completely eliminated black-screen flashing and row dropping on scroll via horizontal virtualization, column widths, and CSS solid container backgrounds. |
| `2404af4` | **v0.3.8** | **feat(report):** Multi-file forensic workbook export across all loaded files, searched IOCs, and findings. |
| `769a47c` | **v0.3.7** | **feat(ioc):** One-click bulk export for all extracted indicators and dynamic category exports. |
| `fcb6f52` | **v0.3.6** | **feat(filter):** Real-time quick search and date/time range filter for unified timeline. |

---

## 3. UI Architecture & Core Workflows (v0.4.1)

The workbench provides **5 purpose-built tabs** with **Evidence Grid** first and active by default:

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│  [Open File] [Open Folder] [Active: All (7 files)]                                     [⌨ Shortcuts] [⚙ Settings] │
├────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│  [ 📊 Evidence Grid ]  [ 🎯 Targeted Hunt & Master Timeline ]  [ 🛡️ Extracted IOCs ]  [ ⚡ Threat Enrichment ]  [ ⚙️ Data Mapping & Rules ] │
└────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Tab 1: Extracted IOCs (Multi-File) (`tab-iocs`)
* **Universal Collection**: Automatically scans and aggregates **all** unique indicators across all loaded evidence files (IPs, domains, URLs, hashes, emails, usernames, correlation IDs, GUIDs).
* **Default View**: Defaults to `All Indicators` (no longer hides single-file indicators behind an "overlap" filter).
* **"Inspect in Grid" on Every Card**:
  * If found across 2+ files: Opens the **Unified Correlated Grid** across all files.
  * If found in 1 file: Immediately switches to that file, sets the Evidence Grid filter to that indicator, and displays the matching records.
* **One-Click Export**: Dedicated buttons to export **All IOCs (.xlsx)** or your active **Filtered View**.

### Tab 2: Targeted Hunt & Forensic Master Timeline (`tab-correlation`)
* **1. Incident Time Window (UTC)**:
  * `From (UTC)` and `To (UTC)` inputs.
  * Quick presets: `[ Full Evidence Range ]`, `[ Last 1 Hour ]`, `[ Last 24 Hours ]`, and `[ Clear Window ]`.
  * Dynamic timeframe indicator displaying the earliest and latest timestamps across loaded evidence.
* **2. Targeted IOC Hunting Set**:
  * Large monospace text area to paste multiline indicator sets (IPs, CIDRs, domains, hashes, usernames, command keywords).
  * Direct file import (`.txt` / `.csv`).
* **3. Master Timeline Output**:
  * Primary action: `[ 🎯 Search Across All Files & Generate Master Timeline ]`.
  * Automatically filters chronological events across all loaded logs matching both the time window and indicator set.
  * Dedicated Action Bar:
    * `[ 📋 View Master Timeline in Grid ]`: Renders the correlated Master Timeline in the Evidence Grid and switches to Tab 3.
    * `[ 📥 Export Forensic Workbook (.xlsx) ]`: Generates a multi-sheet Excel workbook (`MASTER_TIMELINE`, `SEARCHED_IOC_FINDINGS`, `IOC_HUNTING_LIST`, `EVIDENCE_FILES`).
    * `[ ✨ Generate Narrative (Gemini) ]`: Produces an automated executive and technical incident narrative.

### Tab 3: Evidence Grid (`tab-grid`)
* High-performance log browser with virtual horizontal and vertical scrolling.
* **Row Detail Drawer**: Includes an inline `[ ✨ Deobfuscate / Explain (AI) ]` button for analyzing suspicious command lines, Base64 strings, or complex JSON events.

---

## 4. Contextual Gemini AI Integration (Zero-Bloat Design)
* **No Chatbot Tab**: Removed the dedicated chat tab to avoid cognitive and resource clutter.
* **Contextual Helpers**:
  1. **Master Timeline Narrative**: Summarizes chronological timeline events into:
     - Executive Briefing
     - Attack Progression (Initial Access → Execution → Persistence → Lateral Movement → Exfiltration)
     - Identified Threat Entities
     - Mapped MITRE ATT&CK Techniques
  2. **Process & Script Deobfuscator**: Decodes Base64/PowerShell/hex in the detail drawer, explains attacker intent, and extracts hidden IOCs into your hunting set.
* **Settings & 100% Offline Forensic Mode**:
  - Configured via `⚙ Settings` in the top toolbar.
  - API Key and model stored securely in client-side `localStorage`.
  - **If no key is configured**: The tool runs in **100% offline mode** (0 network requests, 0 extra RAM usage).
  - Uses direct HTTPS calls to Google's official Gemini API endpoint (`https://generativelanguage.googleapis.com/v1beta/models/...`), permitted via CSP in `tauri.conf.json`.

---

## 5. Scrolling & Black-Screen Fix Details
* **Problem**: In unified timeline view with 50–120 merged columns, rapid scrolling caused Tabulator virtual DOM desync and Windows WebView2 GPU rasterizer timeouts (turning the screen solid black and dropping rows).
* **Fixes Applied**:
  1. `WIDE_GRID_COLUMN_THRESHOLD` lowered from `400` to `15` in `frontend/app.js`, enabling `renderHorizontal: "virtual"` so offscreen columns are never mounted into the DOM.
  2. Explicit widths (`width: 180`) assigned to all merged custom columns, eliminating synchronous cell measurement on scroll.
  3. Clean lifecycle via `recreateSingleFileTable()` when transitioning between unified and single-file views.
  4. Solid backgrounds (`background-color: var(--panel-bg) !important; contain: content; overflow-anchor: none;`) added to `#grid`, `.tabulator`, and `.tabulator-tableholder` in `frontend/style.css`.
  5. Added `--disable-gpu-rasterization` in `src-tauri/tauri.conf.json`.

---

## 6. How to Run & Verify

* **Binary Location**: `C:\Users\xt\logparser-DFIR\src-tauri\target\debug\log-parser.exe`
* **Compile Backend**:
  ```powershell
  Set-Location "C:\Users\xt\logparser-DFIR\src-tauri"
  cargo build
  ```
* **Quick Check**:
  ```powershell
  Set-Location "C:\Users\xt\logparser-DFIR\src-tauri"
  cargo check
  ```
* **Launch Desktop App**:
  ```powershell
  Start-Process "C:\Users\xt\logparser-DFIR\src-tauri\target\debug\log-parser.exe"
  ```

---

## 7. v0.4.1 Fixes & Enhancements (Ingest, FTS5, Multi-File Correlation & Offline DFIR)
1. **Frontend Initialization & Folder Ingest (`frontend/app.js`, `frontend/index.html`)**:
   - Fixed fatal `SyntaxError`s and IIFE scope leak introduced in `e08ab2b` (lines 9465–10104) where template literals had stripped quotes/backticks and code was appended outside the main IIFE `})();`.
   - Fixed `pickAndOpenFolder()` to register `activeSourceLoad` before calling `loadSheet()` so opening a folder immediately loads the primary evidence file while queuing all remaining files.
   - Restored null guards on removed legacy DOM elements and added the collapsible **Evidence Workspace Files** status bar (`#correlation-files-list`) inside `tab-correlation`.
2. **Backend Universal Ingest & Full-Text Search (`src-tauri/src/universal_import.rs`, `csv_import.rs`, `tabular_import.rs`, `db.rs`)**:
   - Fixed `ColumnSource` mapping in `insert_batch` so nested/punctuated JSON and EVTX fields (`properties.userAgent`, `@timestamp`, `Event.System.EventID`) map by original key instead of sanitized SQL column name (previously imported as `NULL`).
   - Added `db::populate_fts(&conn, &columns)` to `import_stream_into_db` so `rows_fts` is populated for JSON, JSONL, `.gz`, EVTX, and Syslog files.
   - Bumped cache version to `"cache-v2"` in `db::cache_key` to automatically invalidate stale pre-fix `.sqlite3` caches.
   - Added true TSV (`\t`) delimited import, lossy UTF-8 + BOM stripping for CSV/TSV/line streams, `MultiGzDecoder` for multi-member `.gz` archives, streaming EVTX ingestion via bounded channel, `.log.gz` / rotated log (`auth.log.1`, `syslog.2`) support, and JSONL fallback for `.json` files.
3. **On-Demand Cache Resolution & Time-Window Hunting (`src-tauri/src/commands.rs`, `intel/analyst.rs`)**:
   - Added `FileTarget::ensure_cached_db()` so multi-file commands (`cross_search_files`, `cross_search_batch_files`, `cross_ioc_overlap`, `extract_unified_events_for_indicators`, `get_row_raw_details`) automatically resolve default sheet names and build `.sqlite3` caches on the fly.
   - Enabled time-window-only Master Timeline hunts and zero-friction full Master Timeline generation across all loaded files even when the IOC hunting textarea is empty.
4. **Offline Deobfuscator, Offline Incident Narrative & Single-File Drawer (`frontend/app.js`)**:
   - Added deterministic **Offline Forensic Deobfuscator** (`offlineDeobfuscatePayload`) for PowerShell `-EncodedCommand` (UTF-16LE Base64), standard Base64, URL encoding, and backtick/caret obfuscation with automatic MITRE ATT&CK mapping and IOC extraction.
   - Added **Offline Incident Narrative** (`generateOfflineIncidentNarrative`) so `[ ✨ Generate Narrative ]` works 100% offline without a Gemini API key (and combines with Gemini AI when configured).
   - Enabled the Slide-Over Row Detail & Deobfuscation Drawer (`openUnifiedRowDetailDrawer`) and Date/Time range filter across both single-file Evidence Grid mode and Unified Master Timeline mode.


---

## 8. Master Timeline Persistence & Discrepancy Fix (8,273 vs. 5,470 Events)

### Issue Summary
* **Observation**: When loading 34 evidence files without filters or keywords, the Master Timeline initially generated **8,273 correlated events**. After filtering in the Evidence Grid or running threat enrichment, clearing all UI filters, and generating the Master Timeline again, the count dropped to **5,470 events**.
* **Examiner Discrepancy**: One examiner saw 8,273 events, while another saw 5,470 events on the same file set with zero visible UI filters applied.

### Root Cause Analysis
1. In `src-tauri/src/intel/analyst.rs:find_matching_timeline_rows()`, when `keywords.is_empty()`, the function checked `if table_exists(conn, "_intel_match")?`.
2. On fresh file ingestion, `_intel_match` does not exist in the cached SQLite databases on disk. The query fell through to `SELECT row_num FROM rows ORDER BY row_num ASC LIMIT 500`, yielding up to 500 rows per file (totalling **8,273 events** across 34 files).
3. When the examiner applied a filter or executed Threat Enrichment / Intel Scan, `_intel_match` was created and populated with detected MITRE/threat hits inside the SQLite cache database.
4. Clicking "Clear Filters" in the UI cleared the frontend Tabulator state, but **`_intel_match` persisted inside the SQLite database on disk**.
5. When regenerating the Master Timeline, `table_exists(conn, "_intel_match")` evaluated to `true`, causing `find_matching_timeline_rows` to execute `SELECT DISTINCT row_num FROM _intel_match LIMIT 500` instead of querying `rows`. This silently restricted the Master Timeline to threat matches only (**5,470 events**).

### Fixes Applied
1. **Backend Query Determinism (`src-tauri/src/intel/analyst.rs`)**:
   - In `find_matching_timeline_rows()`, removed the conditional branch that prioritized `_intel_match` when `keywords.is_empty()`.
   - Master Timeline without keywords now **always queries `rows` directly**:
     ```rust
     if keywords.is_empty() {
         let mut stmt = conn.prepare("SELECT row_num FROM rows ORDER BY row_num ASC LIMIT 500")?;
         let rows: Vec<i64> = stmt.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
         return Ok(rows);
     }
     ```
   - This guarantees 100% deterministic, bit-for-bit reproducible Master Timeline generation (consistently returning the complete ~8,273 chronological events), immune to prior UI filtering or background Intel scans.
2. **Frontend Refresh Action (`frontend/app.js`)**:
   - Updated `correlation-refresh-btn` (`[ 🔄 Refresh ]` button in `tab-correlation` header) so that when `crossSearchInput` is empty, it invokes `runCrossBatchSearch()`, actively refreshing the Master Timeline and file scope.
3. **Regression Coverage (`src-tauri/src/intel/analyst.rs`)**:
   - Added `empty_timeline_ignores_persisted_intel_matches`, which creates both `rows` and a populated `_intel_match` table and asserts that an empty-keyword timeline still returns the first 500 raw rows.

### Live Verification (2026-11-02)
* Rebuilt `src-tauri/target/debug/log-parser.exe` and loaded the original 34-file `C:\cases\raceX_parsed` evidence set.
* Confirmed all 34 loaded SQLite caches already contained persisted `_intel_match` tables, reproducing the state that previously changed timeline results.
* An empty Master Timeline search returned **8,273 correlated events across 34 files**.
* Clicking the header **Refresh** button reran the search and again returned **8,273 correlated events**, confirming that the result is stable after persisted threat-scan state and through the refresh path.
