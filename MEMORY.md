# `logparser-DFIR` — Comprehensive Project Memory & Architecture Guide

**Last Updated:** 2026-11-11 00:45 UTC  
**Repository Path:** `C:\Users\xt\Documents\Codex\2026-11-02\forensic-memory-master-timeline-event-discrepancy\work\release-gate-git`  
**Current Tag:** `v0.3.9` (Commit `3d029aa`)  
**Active Branch:** `master`  
**Upstream Remote:** `https://github.com/biancanik-art/logparser-DFIR.git`

---

## 1. Executive Summary & Purpose

`logparser-DFIR` is an enterprise-grade desktop Digital Forensics and Incident Response (DFIR) investigation workbench built on **Tauri v2 + Rust 1.80+ + SQLite (bundled with FTS5)** on the backend and a **Tabulator.js / HTML5** virtualized frontend.

It is designed for rapid ingestion, deep timeline reconstruction, full-case cross-file IOC hunting, threat intelligence enrichment (MITRE ATT&CK), and offline/cloud AI-assisted evidence analysis across heterogenous forensic sources:
- Windows Event Logs (`.evtx` via streaming channel decoder)
- Cloud Audit logs (Azure AD/Entra ID, Microsoft 365, AWS CloudTrail)
- EDR and SIEM exports (`.csv`, `.tsv`, `.json`, `.jsonl`, `.log`)
- Compressed multi-stream archives (`.gz`, `.jsonl.gz`, `.log.gz`)

---

## 2. System Architecture & Component Layout

```
logparser-DFIR/
├── src-tauri/                      # Rust Backend (Tauri v2)
│   ├── src/
│   │   ├── main.rs                 # Tauri application entrypoint
│   │   ├── lib.rs                  # Plugin registration & command dispatch
│   │   ├── commands.rs             # Tauri command implementations (~5,000 LOC)
│   │   ├── query.rs                # SQL compilation, AST predicates, rowIds query engine
│   │   ├── db.rs                   # SQLite schema, FTS5 indexing, cache versioning (cache-v2)
│   │   ├── universal_import.rs     # Multi-format streaming parser (EVTX, JSON, GZ, CSV, TSV)
│   │   ├── csv_import.rs           # High-speed CSV parsing with type inference & header sanitization
│   │   ├── tabular_import.rs       # Stream ingestion with synthetic column assignment
│   │   ├── export.rs               # Forensic Excel (.xlsx) & CSV writers, multi-sheet workbooks
│   │   ├── local_ai_manager.rs     # Local llama-server orchestration, model registry, GGUF management
│   │   ├── cloud_ai.rs             # Session-safe Google Gemini API integration
│   │   └── intel/
│   │       ├── chains.rs           # MITRE ATT&CK multi-stage attack chain grouping & scoring
│   │       ├── matcher.rs          # Intel matching engine against ATT&CK keyword library
│   │       ├── analyst.rs          # Timeline extraction, cross-file correlation, narrative generation
│   │       ├── ioc.rs              # Regex-based multi-threaded IOC extraction engine
│   │       ├── time.rs             # Timestamp normalization (epoch_ms) across 40+ date formats
│   │       ├── roles.rs            # Heuristic column role detector (host, user, commandline, etc.)
│   │       └── parser.rs           # Guided natural-language query parser & AST validator
│   ├── Cargo.toml                  # Dependencies (rusqlite, tokio, calamine, rust_xlsxwriter, etc.)
│   └── tauri.conf.json             # Tauri configuration, window policies, CSP
├── frontend/                       # Vanilla JS + CSS Virtualized Frontend
│   ├── index.html                  # Main layout: 6-tab forensic interface, drawers, modals
│   ├── style.css                   # High-contrast DFIR theme, solid virtualized canvas, responsive panels
│   ├── app.js                      # Central frontend logic & state controller (~13,000 LOC)
│   └── tests/                      # Automated test suite (Node.js test runner + JSDOM)
│       ├── ai-evidence-assistant.test.cjs  # 42 unit tests for AI evidence assistant & local runtime
│       └── guided-query-flow.test.cjs      # 36 unit tests for grid filtering, file routing & exports
```

---

## 3. Six-Tab Forensic Interface Specification

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ [Open File...] [Open Folder...] [Active: Security.evtx (1/147 files) — 248,190 rows]    [⌨ Shortcuts] [⚙ Settings] │
├──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ [📊 Evidence Grid] [🤖 AI Assistant] [🎯 Targeted Hunt & Timeline] [🛡️ Extracted IOCs] [⚡ Threat Enrichment] [⚙️ Data Mapping] │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Tab 1: Evidence Grid (`tab-grid`) — *Primary Default Tab*
- **Virtualized Rendering**: Horizontal and vertical virtualization via Tabulator.js (`renderHorizontal: "virtual"`). Columns and cells offscreen are unmounted, preventing memory exhaustion and black-screen rasterizer faults.
- **Single-File vs. Unified Correlated Mode**:
  - *Single-File Mode*: Direct connection to the active file's SQLite database (`rows` table), supporting SQL-level sorting, pagination, search, and compound AST expressions (`rowIds`, `intelTactic`, `intelTechnique`).
  - *Unified Correlated Grid Mode*: In-memory chronological timeline across multiple files with cross-file origin indicators, jumped-row return buttons, and export actions.
- **Row Detail & Deobfuscation Drawer**:
  - Displays all original raw key-value pairs without truncation.
  - Inline **Offline Deobfuscator**: Automatically decodes Base64, UTF-16LE PowerShell (`-EncodedCommand`), URL encoding, and backtick/caret obfuscation. Extracts embedded IOCs and maps MITRE techniques locally.

### Tab 2: AI Evidence Assistant (`tab-ai`)
- **Hybrid Local/Cloud Inference**:
  - **Local Model Registry (`llama-server`)**:
    1. *Mistral 3 8B Instruct* (`mistral-3-8b-instruct`) — High-precision multi-stage reasoning.
    2. *IBM Granite 4.0 Micro 3B* (`granite-4.0-micro-3b`) — Lightweight, ultra-fast 3B model (8k context).
    3. *GPT-OSS 20B* (`gpt-oss-20b`) — Deep forensic analysis with 300s watchdog.
    4. *Qwen 2.5 7B Coder* — Code and script reverse engineering.
  - **Cloud Google Gemini**: Configurable via session-only API keys (zero disk persistence, immediate session clearing).
- **Bounded Ordered Chunking Pipeline**: Large row selections (e.g., 2,000+ rows) are automatically chunked into bounded batches with strict file, sheet, source row number, and timestamp provenance.
- **Export AI Attack Timeline (.xlsx)**: Generates a dedicated forensic timeline workbook containing exclusively the evidence rows cited by the AI model.

### Tab 3: Targeted Hunt & Master Timeline (`tab-correlation`)
- **Incident Time Window (UTC)**:
  - Exact `From (UTC)` and `To (UTC)` boundary filtering. Presets: `Full Evidence Range`, `Last 1 Hour`, `Last 24 Hours`.
- **Targeted IOC Hunting Set**:
  - Bulk multiline input accepting IPs, CIDRs, domains, SHA256/MD5 hashes, usernames, and command keywords.
- **Master Timeline Generation**:
  - Searches across all loaded files on disk using high-speed indexed SQLite queries.
  - Queries raw `rows` directly for deterministic counts (immune to background threat match persistence).
- **Tripartite Decoupled Exports**:
  1. 🎯 **[Export Hunted Timeline (.xlsx)]**: Cross-file chronological event timeline (`export_unified_multisheet_xlsx`).
  2. 📋 **[Export Searched IOCs (.xlsx)]**: Breakdown of searched indicators with hit counts, file provenance, and sample row numbers (`export_batch_iocs_file`).
  3. 🌐 **[Export Full Case (.xlsx)]**: Complete 5-sheet master workbook (`MASTER_TIMELINE`, `SEARCHED_IOC_FINDINGS`, `IOC_HUNTING_LIST`, `EVIDENCE_FILES`, `FORENSIC_SUMMARY`).

### Tab 4: Extracted IOCs (Multi-File) (`tab-iocs`)
- Multi-core IOC extraction engine scanning IPs, URLs, domains, emails, hashes, GUIDs, and Windows SID patterns.
- Shows total occurrences and file overlap across evidence.
- Card actions:
  - *Inspect in Grid*: Switches to single file or opens Unified Correlated Grid.
  - *Export Events (.xlsx)*: Downloads all events for that specific indicator.

### Tab 5: Threat Enrichment (`tab-enrichment`)
- **Automated ATT&CK Mapping**: Evaluates active evidence columns against MITRE ATT&CK techniques and tactics (with optional BEC / Cloud rules).
- **Correlated Attack Chains**:
  - Detects multi-stage progression across distinct tactics within 60-minute host/user windows.
  - Calculates severity progression scores.
  - Displays host, user, file origin, and row spans.
  - Single-click evidence drilldown directly routes to the exact evidence in the Evidence Grid.

### Tab 6: Data Mapping & Rules (`tab-roles`)
- Automatic and manual column role assignment (`timestamp`, `host`, `user`, `command_line`, `process_name`, `ip`, `text_evidence`).
- Custom Ignore Rules: Filters known benign processes, hosts, or service accounts from MITRE scans.

---

## 4. Key Milestones & Recent Commits

| Commit | Version / Tag | Description & Scope |
| :--- | :--- | :--- |
| `3d029aa` | **v0.3.9** *(Current)* | **fix(intel):** Correlated Attack Chains evidence visibility in Evidence Grid, provenance tracking (`filePath`/`fileName`), race condition mitigation, and sample rows expansion to 1,000. |
| `ea76f69` | **v0.3.9** | **feat(export):** Decoupled tripartite export architecture: Hunted Timeline (.xlsx), Searched IOCs (.xlsx), and Full Case Forensic Workbook (.xlsx). |
| `1a94f09` | **v0.3.9** | **feat(ai):** Multi-model local offline AI registry (Mistral, Granite, GPT-OSS), chunked analysis pipeline, uncapped master timeline export. |
| `3b9dbe7` | **v0.3.9** | **test(ai):** Deterministic mock download testing and model registry verification. |
| `ee66cd2` | **v0.3.9** | **ci(release):** Automated GitHub Actions release pipeline with offline AI packaging. |
| `3c5b316` | **v0.3.8** | **feat(ai):** AI Evidence Assistant with grounded provenance and AI Attack Timeline export. |
| `1e6027d` | **v0.3.8** | **fix(timeline):** Guaranteed deterministic Master Timeline row counts (8,273 events) by isolating raw queries from `_intel_match`. |
| `130f909` | **v0.3.7** | **fix(ingest):** Restored Evidence Grid first, fixed universal EVTX/JSON streaming, TSV support, FTS5 population, and offline deobfuscation. |
| `e08ab2b` | **v0.3.6** | **feat(ui):** Multi-file IOC inspector, targeted hunting workbench, and contextual Gemini integration. |
| `21f2e0a` | **v0.3.5** | **fix(grid):** Virtual horizontal rendering to permanently eliminate black screen flashing and dropped rows during scroll. |

---

## 5. Architectural Deep Dives

### A. Correlated Attack Chains & Evidence Grid Routing (`3d029aa`)
- **Problem**: When examiners clicked "View Chain" on an attack chain in Threat Enrichment, the Evidence Grid showed 0 rows.
- **Root Cause**:
  1. `IntelChainSummary` lacked file provenance (`filePath` and `fileName`), so the frontend did not know which file contained the chain.
  2. `filterGridByIntel` had no routing logic for `filterType === "chain"`. It applied `row_num IN (...)` against whatever file happened to be active (e.g. `ConsoleLog.txt` with only 68 rows).
  3. When switching files, `switchLoadedFile` triggered `tableBuilt` which asynchronously ran an unfiltered query, colliding with the intel filter.
  4. `MAX_SAMPLE_ROWS` was hardcoded to 50 in `chains.rs`.
- **Solution**:
  1. Added `filePath: Option<String>` and `fileName: Option<String>` to `IntelChainSummary` in [`src-tauri/src/intel/chains.rs`](file:///C:/Users/xt/Documents/Codex/2026-11-02/forensic-memory-master-timeline-event-discrepancy\work\release-gate-git\src-tauri\src\intel\chains.rs).
  2. Populated file identity during both multi-file scans and single-file scans in [`src-tauri/src/commands.rs`](file:///C:/Users/xt/Documents/Codex/2026-11-02/forensic-memory-master-timeline-event-discrepancy\work\release-gate-git\src-tauri\src\commands.rs).
  3. Increased `MAX_SAMPLE_ROWS` from 50 to 1,000 (matching `MAX_ROW_IDS = 1000` in `query.rs`).
  4. Enhanced `filterGridByIntel` in [`frontend/app.js`](file:///C:/Users/xt/Documents/Codex/2026-11-02/forensic-memory-master-timeline-event-discrepancy\work\release-gate-git\frontend\app.js) to resolve the target file, switch to it, await `activeDataRequest` completion, apply `{ type: "rowIds", values: chainRows }`, and transition to the Evidence Grid.

### B. Master Timeline Determinism & Discrepancy Prevention (`1e6027d`)
- **Problem**: Running Master Timeline initially yielded 8,273 events, but dropped to 5,470 events after running Threat Enrichment.
- **Root Cause**: `find_matching_timeline_rows` in `analyst.rs` checked `if table_exists(conn, "_intel_match")?`. Once threat enrichment ran, `_intel_match` remained in the SQLite cache, causing subsequent empty timeline searches to query threat matches only.
- **Solution**: Removed the branch. Master Timeline with empty keywords **always queries raw `rows` directly**:
  ```rust
  if keywords.is_empty() {
      let mut stmt = conn.prepare("SELECT row_num FROM rows ORDER BY row_num ASC LIMIT 500")?;
      let rows: Vec<i64> = stmt.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
      return Ok(rows);
  }
  ```

### C. Universal Streaming Ingest & FTS5 (`130f909`)
- Handles malformed CSV/TSV with lossy UTF-8 recovery and automatic BOM stripping.
- EVTX files stream through a bounded crossbeam/tokio channel directly into SQLite.
- Multi-member gzip (`.jsonl.gz`) decoded via `flate2::read::MultiGzDecoder`.
- Original JSON/EVTX field paths (e.g. `Event.System.EventID`) preserved in raw metadata.
- Automatic full-text search index (`rows_fts`) created and maintained for all imported datasets.

---

## 6. How to Build, Test, and Verify

### Backend Unit Tests (Rust)
```powershell
Set-Location "C:\Users\xt\Documents\Codex\2026-11-02\forensic-memory-master-timeline-event-discrepancy\work\release-gate-git"
cargo test --manifest-path src-tauri/Cargo.toml --lib
```
*Current test status: 334 passed, 0 failed, 3 ignored.*

### Frontend Automated Unit Tests (Node.js)
```powershell
Set-Location "C:\Users\xt\Documents\Codex\2026-11-02\forensic-memory-master-timeline-event-discrepancy\work\release-gate-git"
node frontend/tests/ai-evidence-assistant.test.cjs
node frontend/tests/guided-query-flow.test.cjs
```
*Current test status: 78 passed, 0 failed.*

### Compile Release Binary
```powershell
# Ensure llama-server is not holding file locks on ggml DLLs:
Stop-Process -Name "llama-server" -Force -ErrorAction SilentlyContinue

Set-Location "C:\Users\xt\Documents\Codex\2026-11-02\forensic-memory-master-timeline-event-discrepancy\work\release-gate-git"
cargo build --manifest-path src-tauri/Cargo.toml --release
```
*Output binary:* `src-tauri/target/release/log-parser.exe` (73 MB).

---

## 7. Common Diagnostic & Operational Tips

1. **DLL Handle Lock (OS Error 32)**:
   - If `cargo build` fails on `resources\llama-cpp-runtime\ggml-base.dll`, an orphaned `llama-server.exe` process is still running.
   - Solution: `Stop-Process -Name "llama-server" -Force`.
2. **SQLite Cache Invalidation**:
   - Cache databases are stored at `%TEMP%\logparser_cache` with a version token (currently `cache-v2`).
   - If schema changes occur, modifying the version token in `src-tauri/src/db.rs:cache_key()` immediately invalidates stale caches safely.
3. **Large Case Memory Footprint**:
   - Tabulator uses horizontal virtualization. When loading datasets with 200+ columns, offscreen cells are never added to the DOM.
   - If inspecting high-column-count files, keep column lock count under 10 for optimal scroll frame rates.
