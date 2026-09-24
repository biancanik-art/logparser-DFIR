# logparser-DFIR

A fast, fully offline desktop forensic log viewer and investigation workbench for large SIEM/EDR log exports (Excel
and CSV) — built for DFIR examiners. Handles 100k+ row files, dynamic
column detection, keyset-paginated filtering/search, multi-file correlation, AI-assisted evidence
retrieval, optional MITRE ATT&CK enrichment, and multi-sheet report export.
**No runtime network calls** — imported evidence and AI inference stay on
your machine.

See the [wiki](../../wiki) for a full user guide.

## Features

- **Multi-File Cross-Log Correlation & Auto-Ingestion**: Ingest dozens or hundreds of disparate logs (e.g. 145 CSVs, M365 UAL, Windows Event Logs, Sysmon, Firewall, VPN) simultaneously without forcing them into a flattened, sparse schema. When multiple files are opened, the first file is displayed immediately while all remaining files are automatically indexed and cached into local SQLite databases in the background with live progress indicators (`⏳`).
- **Resilient Raw & Headerless Log Ingestion**: Never rejects logs lacking a formal header row or single-column raw text/error logs (such as `php-fpm-error.xlsx`). Automatically detects headerless formats, synthesizes clean column names (`Column 1`, `raw_record`), and preserves row 1 as evidentiary data with non-blocking audit notices.
- **Global Pivot Search**: Search entities (IPs, users, hashes, domains) across all open files in parallel with instant snippet previews.
- **Shared Indicator (IOC) Co-occurrence Matrix**: Detect indicators that appear across 2 or more evidence files, with export to Excel, CSV, or JSON.
- **Whole-Picture 1-Click Filter**: Isolate all correlated timeline events directly in the Evidence Grid with a single click.
- **High-Entropy Correlation Entity Extraction**: Automatically extracts Device IDs, Session IDs / AADSessionIDs, App IDs, UniqueTokenIDs, Correlation IDs, Mailbox GUIDs, Message IDs, Hashes, and User-Agents.
- Dynamic column detection — no per-source schema required.
- Fast filtering, full-text search, sorting, and CSV/XLSX export, all keyset-paginated for large files.
- Automatic data mapping for timestamps and common evidence fields, with optional manual overrides. Mapping is metadata for timelines and threat enrichment; it never limits which raw rows the AI can search.
- UTC timestamp normalization, with an explicit prompt when a timestamp's timezone is ambiguous.
- An offline, built-in MITRE ATT&CK-style keyword library, scanned via Aho-Corasick pattern matching, extensible with your own custom categories.
- Local AI evidence search powered by embedded Qwen2.5-1.5B-Instruct and all-MiniLM-L6-v2 models. Describe the evidence in plain language (for example, *"show failed logins followed by PowerShell activity for alice, chronologically"*). Qwen plans a validated, bounded lexical/structured query over the complete raw table. MiniLM can supplement that plan with semantically similar evidence. Neither path is restricted by data mappings or rows found by the optional threat scan.
- One-step AI search: submitting a request validates and executes its bounded plan immediately, and asks for clarification only when a safe search cannot be formed. Returned rows include a `Why matched` explanation. Generated search values must be grounded in the examiner's request. The models cannot execute SQL, read arbitrary files, launch processes, or access the network.
- Interactive Threat Enrichment & Attack Chains: Clickable MITRE ATT&CK tactics, techniques, and correlated attack chains. In multi-file cases, 1-click drilldowns ("View in Table" / "Filter Grid") seamlessly route to the Unified Correlated Grid when matches span multiple files, or auto-switch to the matching evidence file when hits are concentrated in a single log.
- One-click multi-sheet XLSX report export: a case-summary sheet, a chronological MITRE-mapped timeline, and one sheet per matched technique category — every row traceable back to its original source row. Also supports exporting the complete Unified Correlated Grid into multi-sheet Excel workbooks.

## Grid Controls & Keyboard Shortcuts

| Action | Shortcut / Gesture | Description |
| :--- | :--- | :--- |
| **Hide Column** | `Alt` + Click header<br>*or* Right-click header &rarr; `Hide Column` | Immediately hides any column from view. |
| **Multi-Select Columns** | `Ctrl` + Click headers | Select multiple column headers, then press `Delete` to hide them all at once. |
| **Pin / Unpin Column** | Double-click header<br>*or* Right-click header &rarr; `Pin Column` | Freezes column to the left for persistent horizontal scrolling. |
| **Hide Row(s)** | Select row(s) + `Delete` / `Backspace`<br>*or* Right-click row &rarr; `Hide Row` | Suppresses unwanted rows non-destructively from your active investigation session. |
| **Multi-Select Rows** | `Ctrl` + Click / `Shift` + Click | Select discrete rows or a contiguous range of rows for bulk hiding. |
| **Restore Hidden Rows** | Click red `● N hidden` in status bar<br>*or* Press `Esc` | Brings all hidden rows back into view. |
| **Restore Hidden Columns** | Click amber `● N cols hidden` in status bar | Restores all hidden columns to the grid. |
| **Jump to Source File** | Click `📄 filename ↗` badge | Switches to that source file in the Evidence Grid, focused at that exact row. |
| **Return to Unified Timeline** | Click `↩ Return to Unified View`<br>*or* `Alt` + `Left` / `Esc` | Restores your previous position and filter context in the correlated timeline. |
| **Inspect Raw Row Details** | Double-click row<br>*or* Click `👁️ Details` | Opens the slide-over inspector drawer displaying all raw source fields. |
| **In-App Shortcuts Help** | Press `F1` or `?`<br>*or* Click `⌨ Shortcuts` toolbar button | Displays the interactive in-app cheat sheet. |

## Try it

Sample data is included under `testdata/`:

- `sentinel_sample_120k.xlsx` — a 120,000-row synthetic Sentinel-style
  export, for trying the tool at realistic scale.
- `multi_sheet_sample.xlsx` — a small 3-sheet workbook.

## Building from source

Requires [Rust](https://rustup.rs/), Python 3, and the
[Tauri v2 prerequisites](https://v2.tauri.app/start/prerequisites/) for
your platform (Windows, macOS, or Linux). Fetch the checksum-pinned models,
tokenizers, and configuration once before building; this is an explicit
build-time download, not an application runtime download:

```sh
python scripts/fetch_llm_resources.py
cd src-tauri
cargo tauri build
```

This produces a native installer/bundle for your current platform in
`src-tauri/target/release/bundle/`. Cross-compiling for other platforms
follows the standard Tauri process — see the
[Tauri distribution docs](https://v2.tauri.app/distribute/).

To run in development mode:

```sh
python scripts/fetch_llm_resources.py
cd src-tauri
cargo tauri dev
```

The embedded AI resources add about 1.22 GB (1.13 GiB) to an unpacked
application. Current
x86-64 builds require AVX2 and FMA CPU support; Apple Silicon uses its native
ARM SIMD baseline.

## Stack

Rust + [Tauri v2](https://v2.tauri.app/) · [calamine](https://github.com/tafia/calamine)
(Excel parsing) · SQLite via [rusqlite](https://github.com/rusqlite/rusqlite)
(bundled, FTS5 full-text search) · [aho-corasick](https://github.com/BurntSushi/aho-corasick)
(keyword matching) · [rust_xlsxwriter](https://github.com/jmcnamara/rust_xlsxwriter)
(report export) · [Candle](https://github.com/huggingface/candle) with
[Qwen2.5-1.5B-Instruct](https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct)
for local query planning and
[all-MiniLM-L6-v2](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2)
for semantic retrieval · plain HTML/CSS/vanilla JS frontend
([Tabulator.js](https://tabulator.info/) for the grid), no build step.

## Downloads

Pre-built installers for Windows and macOS (Apple Silicon and Intel) are
published on the [Releases](../../releases) page.

**macOS note:** these builds are not yet code-signed/notarized with an
Apple Developer ID, so Gatekeeper will refuse to open them with a
"logparser-DFIR is damaged and should be moved to the Trash" message — the
app isn't actually damaged, this is just Gatekeeper blocking an
unsigned/unnotarized download. After moving `logparser-DFIR.app` to
`/Applications`, clear the quarantine flag once:

```sh
xattr -cr /Applications/logparser-DFIR.app
```

Then it opens normally.

## Credits

logparser-DFIR is a team effort: concept, requirements, and product direction
by [biancanik-art](https://github.com/biancanik-art); engineering by
[Gemini](https://deepmind.google/technologies/gemini/) (Google DeepMind) and
[Codex](https://openai.com/index/introducing-codex/) (OpenAI), working as
independent AI engineers/reviewers throughout the build — implementing
features in parallel, cross-checking each other's work, and running live
end-to-end verification against the real app.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
