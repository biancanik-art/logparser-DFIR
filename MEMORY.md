# `logparser-DFIR` — Project State & Memory File

**Last Updated:** 2026-10-28 01:42 UTC  
**Repository Path:** `C:\users\xt\logparser-DFIR`  
**Current Version:** `v0.4.0`  
**Active Branch:** `master` (Clean working tree, 2 commits ahead of remote origin)

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

## 3. UI Architecture & Core Workflows (v0.4.0)

The bloated, heavy multi-tab interface (including the slow local 3B chatbot) was stripped down into **3 clean, purpose-built tabs**:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│  [Open Folder]  [Open File]  [Active: All (7 files)]       [⌨ Shortcuts] [⚙ Settings]  │
├────────────────────────────────────────────────────────────────────────────────────────┤
│  [ 🔍 Extracted IOCs (Multi-File) ]   [ 🎯 Targeted Hunt & Master Timeline ]   [ 📋 Evidence Grid ]
└────────────────────────────────────────────────────────────────────────────────────────┘
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

## 7. Next Actions for Next Session
1. Test targeted hunting and timeline generation with real-world multi-file cases.
2. Optional: Add offline regex-based Base64/PowerShell decoding fallback for environments where no Gemini API key is available.
3. Push commits `21f2e0a` and `e08ab2b` to remote repository when ready (`git push origin master`).
