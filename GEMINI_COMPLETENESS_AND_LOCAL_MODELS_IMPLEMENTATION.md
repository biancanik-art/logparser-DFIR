# Gemini Implementation Brief: Complete Evidence Timelines, Complete Exports, and Selectable Local Models

Date: 2026-11-08  
Repository: `logparser-DFIR`  
Working tree: this document is part of an in-progress release-gate review. Preserve all pre-existing changes.  
Release authority: **do not commit, push, move a tag, publish a release, or replace release assets. Return the implementation and verification evidence for Codex/user review first.**

## 1. Mission

Implement the next release-gate pass with two outcomes:

1. A Master Timeline and every filter applied to it must operate on the **entire imported evidence set**, not a sample or an early row prefix. The UI may page results for performance, but it must never silently omit matching rows. The examiner decides how to narrow the result.
2. The local AI subsystem must support a model registry and allow the examiner to download and select these offline models:
   - existing `gpt-oss-20b`;
   - IBM Granite 4.0 Micro 3B GGUF;
   - Mistral Ministral 3 8B Instruct GGUF.

This is forensic software. Completeness, provenance, deterministic ordering, and an explicit statement of coverage are release requirements, not optional UX refinements.

## 2. Read before editing

Read the repository, tests, `README.md`, `BUILD_ENGINEERING_REPORT.md`, and this document completely. Inspect `git status` and preserve unrelated/user changes. At minimum, trace these areas before changing code:

- `src-tauri/src/intel/analyst.rs`
- `src-tauri/src/commands.rs`
- `src-tauri/src/lib.rs`
- `src-tauri/src/universal_export.rs`
- `src-tauri/src/local_ai_manager.rs`
- `src-tauri/src/local_ai_runtime.rs`
- `src-tauri/src/intel/llm_parser.rs`
- `frontend/app.js`
- `frontend/index.html`
- `frontend/styles.css`
- `frontend/tests/*.test.cjs`
- `scripts/fetch_llama_runtime.py`
- Tauri configuration/capabilities and the Rust/Node test configuration

Before implementing, run a repository-wide search for evidence-affecting caps and sampling terms. Classify each result as one of:

- a result-set cap that can change forensic meaning;
- a page/batch size that only changes transport/performance;
- a display/narrative cap that is explicitly labeled and cannot change the underlying result;
- a model context/payload safety limit.

Remove or redesign every result-set cap that silently changes forensic meaning. Do not indiscriminately remove safe batch sizes.

## 3. Confirmed defects that must be fixed

### 3.1 Empty Master Timeline is a per-file prefix sample

`find_matching_timeline_rows()` in `src-tauri/src/intel/analyst.rs` currently executes the equivalent of:

```sql
SELECT row_num FROM rows ORDER BY row_num ASC LIMIT 500
```

when there are no keywords. This means a timeline labeled as unified/full can include only the first 500 source rows per file. The previously observed 8,273 events across 34 files were not proof of full coverage; that number was the sum of these bounded per-source prefixes and smaller files.

### 3.2 Keyword fallbacks also truncate matches

The non-FTS/fallback paths contain `LIMIT 200` queries. These can omit valid matches after the first 200 rows or first 200 matches. FTS presence must not determine whether a query is complete.

### 3.3 The time window is applied too late

`runCrossBatchSearch()` currently invokes `get_unified_batch_events` without the requested time range and filters the returned events in JavaScript. Because the backend has already sampled the source rows, a date/time filter cannot recover matching events outside the sample.

All evidence filters, including time, indicators, quick search, dynamic column filters, and sort order, must be evaluated by the backend against the entire logical dataset before result pagination.

### 3.4 Workbook export contains independent 50,000-row caps

`src-tauri/src/universal_export.rs` contains `LIMIT 50000` queries for Master Timeline/report data. A complete grid paired with a truncated workbook is still a forensic completeness defect. Exports must include every row in the selected filtered result and state the exported row count.

### 3.5 Simply deleting SQL limits is not an acceptable fix

The current unified path builds a `Vec<CorrelatedTimelineEvent>`, includes broad `raw_fields`, sorts everything in memory, sends the whole vector across Tauri IPC, maps it again in JavaScript, and gives all objects to a local Tabulator instance. Removing the SQL limit alone can exhaust memory or freeze the UI on million-row cases.

The required fix is **complete backend evaluation plus bounded page delivery**, not unbounded all-at-once materialization in the frontend.

## 4. Non-negotiable forensic invariants

The implementation and tests must enforce all of the following:

1. Every imported source row is eligible for timeline inclusion.
2. Filters are evaluated over all eligible rows, never a loaded page or sample.
3. Pagination changes only how rows are delivered, never the count or membership of the result.
4. Results use a deterministic total order. Timestamp ties require stable source and source-row tie-breakers.
5. Every displayed/exported/AI-staged row retains immutable provenance: source file identity/path, sheet/table identity where relevant, original source row number, normalized timestamp plus timestamp status, and a stable event identifier.
6. A prior Threat Enrichment run or persisted `_intel_match` table cannot change an empty-keyword Master Timeline.
7. FTS availability cannot change result completeness.
8. No mode may be called `Master Timeline`, `Full`, `Unified`, or `Complete` if it is sampled.
9. If an explicit preview/sample mode is ever retained, it must be opt-in, visibly labeled `INCOMPLETE PREVIEW`, display its sampling rule, and never be the default.
10. A source error must be reported with the affected source and coverage state. Do not silently call a partial multi-file result complete.
11. No-timestamp or unresolved-timezone evidence must not disappear. Place it in a clearly labeled undated section/order, or require normalization where chronological semantics demand it. Never silently assume UTC solely to make a row sortable.

## 5. Required timeline architecture

Implement a backend-owned unified timeline query/session layer. Names may follow existing style, but the responsibilities below are mandatory.

### 5.1 Query specification

Define serializable Rust/JavaScript types for a unified query, including:

- selected file targets;
- indicator/keyword terms;
- optional normalized UTC `from` and `to` bounds;
- quick-search expression;
- dynamic column filters and their operators;
- sort specification;
- page size/cursor;
- inclusion policy for rows with missing/unresolved timestamps.

Reject invalid operators and invalid column identifiers. Use bound SQL parameters for values. Never accept raw SQL from the UI or an AI model.

### 5.2 Build/prepare command

Add a command such as `prepare_unified_timeline_query` that:

- examines every requested source cache;
- applies normalization/mapping consistently;
- evaluates the base query across all source rows;
- builds or references a backend-owned query session;
- returns a session/query ID, exact total count, per-source counts, coverage status, source errors, column metadata, and a stable snapshot/version marker;
- emits progress containing sources completed, rows examined, matches found, and current phase;
- supports cancellation.

A practical implementation is a temporary/session SQLite database containing lightweight unified timeline records and appropriate indexes. A correct k-way cursor merge is also acceptable. Choose the design that best fits the existing cache architecture, but do not hold the full wide result in the frontend.

If using a materialized session database:

- write in bounded transactions;
- index normalized timestamp, stable event ID, source identity/source row, and fields required by supported filters;
- keep wide raw evidence out of the primary page records when possible;
- store or resolve full row details on demand;
- create the session atomically;
- clean it on Clear All, explicit close, app shutdown, cancellation, and stale-session cleanup;
- place it only in the app cache/data area, never beside original evidence;
- do not mutate original evidence files.

### 5.3 Exact count and page commands

Add commands such as:

- `query_unified_timeline_page`
- `count_unified_timeline`
- `get_unified_timeline_row_details`
- `cancel_unified_timeline_build`
- `close_unified_timeline_session`

The page command must return a bounded set (default UI size may remain 300) plus cursor/page metadata. This is a transport limit, not a result limit. The exact count must describe all rows matching the active query.

Prefer keyset/cursor pagination over large SQL offsets. The ordering key must be stable, for example:

```text
(timestamp-status, normalized-epoch, source-stable-id, source-row-number, stable-event-id)
```

Define ascending/descending and undated-row behavior explicitly. Pages must contain no duplicates or gaps even when timestamps tie.

### 5.4 Backend filtering over the full session

Move these operations out of post-sample JavaScript filtering and into the backend query:

- incident time window;
- indicators/keywords;
- quick search;
- inline column filters;
- sort changes;
- source-file filters;
- hidden-row exclusions if hidden rows are intended to affect exports/counts.

Changing a filter may reuse the complete session where safe, but the count and page must always reflect all session rows. If a filter cannot be expressed against lightweight session fields, query the relevant source cache or build an indexed normalized representation; do not fall back to filtering only the current page.

### 5.5 Row details and selection

The existing Details drawer and AI staging must work with remote pages:

- use a stable composite event ID, never a transient grid index;
- fetch complete source fields on demand;
- preserve selections across pages and sorts where feasible;
- stage selected IDs by retrieving their exact backend records and provenance;
- do not send a whole million-row timeline to the AI;
- a deliberately selected set can still be bounded/chunked for model context, but the UI must distinguish `selected rows` from `all timeline rows` and must never imply that the model inspected rows it did not receive.

### 5.6 Frontend behavior

Update the unified timeline grid to use remote/backend pagination or equivalent progressive retrieval:

- show build progress and a Cancel control;
- show `N matching events — complete across M/M sources` only after successful complete evaluation;
- show a clear partial/error state if any source failed;
- show page size and navigation without claiming `All rows displayed` unless that is literally true;
- debounce inline filter requests;
- cancel or supersede stale requests;
- do not retain every raw row in `unifiedCorrelatedRows`, `savedUnifiedContext`, or duplicate JS arrays;
- keep Details, jump-to-source, row selection, Clear Filter, and return-to-unified-view working;
- preserve user-visible filters when switching tabs/views unless the user clears them.

Do not add more redundant buttons. Use the existing toolbar and one clear status/progress surface.

## 6. Complete export requirements

Rewrite Master Timeline/workbook exports so the backend streams or iterates the entire active filtered query without `LIMIT 50000` or an equivalent implicit cap.

Requirements:

- export exactly the rows described by the active query/session;
- preserve the same deterministic ordering as the grid;
- use bounded memory; do not accumulate every CSV line in a `Vec<String>`;
- include an export manifest/summary with query description, total matching rows, total exported rows, sources included, source errors, timezone/normalization notes, generation time, and application version;
- surface a hard error if exported count differs from expected count;
- write atomically to a temporary file and rename on success;
- delete incomplete temporary output on cancellation/error;
- emit progress and support cancellation.

Excel has a physical row limit per worksheet. Split a large Master Timeline across deterministically named sheets such as `MASTER TIMELINE`, `MASTER TIMELINE 2`, and so on, leaving room for headers. Record sheet ranges/counts in the manifest. Do not truncate at the first sheet.

If CSV is supported, it must also be complete. If a single file would be impractical, produce numbered parts plus a manifest, but never silently omit rows.

Audit other export limits (`LIMIT 200`, `LIMIT 500`, `LIMIT 2000`, one-million-row constants, and similar). A top-N summary may remain bounded only if its title and manifest clearly say it is a top-N summary and the bound does not affect the Master Timeline or raw evidence export.

## 7. Selectable local-model architecture

### 7.1 Replace gpt-oss constants with a model registry

Refactor `local_ai_manager.rs`, `local_ai_runtime.rs`, commands, and UI around a typed registry. Each model entry must contain at least:

- stable internal ID;
- display name and family;
- exact pinned download URL using an immutable full revision, not `/main/`;
- exact artifact filename;
- exact byte length and SHA-256;
- quantization;
- license and official model-card URL;
- minimum/recommended RAM and free disk guidance;
- model-specific context and output-token defaults;
- chat template/reasoning format/runtime arguments;
- supported capabilities;
- local directory name and migration aliases.

Do not duplicate download/runtime code per model. All validation, resumable download, checksum verification, partial-file handling, removal, and status reporting must use the registry.

### 7.2 Required model entries

Keep the existing pinned gpt-oss entry and add:

#### IBM Granite 4.0 Micro 3B

- Official repository: `ibm-granite/granite-4.0-micro-GGUF`
- Artifact/quantization: `granite-4.0-micro-Q4_K_M.gguf`
- Display label: `Granite 4.0 Micro 3B (Local)`
- License: Apache-2.0, verified from the official card/repository
- Official reference: <https://huggingface.co/ibm-granite/granite-4.0-micro-GGUF>

#### Mistral Ministral 3 8B Instruct

- Official repository: `mistralai/Ministral-3-8B-Instruct-2512-GGUF`
- Artifact/quantization: `Ministral-3-8B-Instruct-2512-Q4_K_M.gguf`
- Display label: `Ministral 3 8B Instruct (Local)`
- License: Apache-2.0, verified from the official card/repository
- Official reference: <https://huggingface.co/mistralai/Ministral-3-8B-Instruct-2512-GGUF>

Before enabling either entry, query the official Hugging Face repository metadata and record the **full immutable commit SHA, exact file byte count, and exact SHA-256**. Do not copy abbreviated browser SHAs and do not guess hashes or sizes. A registry entry without verified immutable metadata must remain disabled with a developer-visible reason.

The Ministral text assistant does not require a vision projector. Do not download multimodal projector artifacts unless a separately designed image-evidence feature needs them.

### 7.3 Runtime compatibility

The application currently bundles llama.cpp release `b12080`. Validate the exact three model artifacts against the bundled Windows runtime and the runtime on every supported release platform. Current upstream documentation is not proof that the older bundled binary supports a newer template.

Official llama.cpp references:

- <https://github.com/ggml-org/llama.cpp/blob/master/docs/autoparser.md>
- <https://github.com/ggml-org/llama.cpp/blob/master/docs/function-calling.md>

If either model fails with `b12080`, upgrade the pinned llama.cpp runtime deliberately:

- pin one exact upstream release/revision;
- update all platform asset URLs, exact byte sizes, and SHA-256 values;
- update cache keys/fetch scripts;
- run runtime-integrity and startup tests on supported platforms;
- document the change and third-party notices.

### 7.4 Model management UX

Keep the main AI conversation simple:

- one selected-model dropdown near the conversation/provider control;
- one `Manage local models` entry opening a modal/panel;
- cards/rows showing Installed, Downloading, Corrupt, or Not installed;
- download progress, size, license, hardware guidance, Verify, Remove, and Select;
- only one active llama-server process at a time;
- switching model stops the old runtime cleanly, verifies the new artifact, starts it with model-specific settings, and updates all labels;
- the app remains fully usable without any downloaded generative model;
- labels must say `gpt-oss Local`, `Granite Local`, or `Ministral Local`, never cloud GPT/OpenAI API.

Do not bundle multi-gigabyte model weights in the installer. Downloads must be explicit examiner actions.

### 7.5 Existing installation migration

Detect the existing gpt-oss artifact in its current directory and register it without forcing a re-download. Migration must be idempotent and must not move/delete a valid artifact until the destination and checksum are verified.

Each model must use an exact, sanitized, app-owned directory. Removal must resolve and validate the target path and may delete only that model's final and partial artifacts. Test traversal, symlink/reparse-point, and wrong-directory rejection.

## 8. Inference timeout and reliability fix

The current behavior conflates startup, connection, authentication, generation, and wall-clock timeouts, and can automatically restart/retry work that was already processing. Fix this while adding model selection.

Required behavior:

- stream llama.cpp SSE/token output to the frontend, or implement a progress/idle watchdog that resets when valid output/progress arrives;
- separate errors for model verification, runtime startup, health check, authentication, request connection, first-token timeout, idle-generation timeout, total safety timeout, cancellation, and process exit;
- show model loading/startup progress and first-token/generation state;
- provide explicit Cancel;
- capture bounded/redacted llama-server diagnostics instead of running with all useful logging disabled;
- never expose the loopback API token in UI, URL, browser navigation, or logs;
- do not restart and repeat a completed/partially completed generation after tokens have arrived;
- do not automatically retry a full AI evidence chunk on an ambiguous timeout;
- at most retry once for a proven pre-request connection failure where no request body was accepted and no token/output was received;
- assign a request ID and suppress stale chunks/results after cancellation or a newer request;
- use model-specific context/output settings and validate the staged payload before sending;
- keep citation/provenance verification outside the model and reject invented source references.

A slow CPU is not evidence loss and must not be handled by silently reducing selected rows. If the selected evidence exceeds a model context, use transparent deterministic chunking and synthesis with coverage counts. State exactly how many selected rows/chunks were processed and whether any field was truncated.

## 9. Required regression and acceptance tests

Do not declare completion without automated tests for the following.

### 9.1 Timeline completeness

1. One source with 1,205 rows, no keywords: exact count and complete page traversal return all 1,205 stable IDs.
2. Persist `_intel_match` containing a subset, then run empty-keyword timeline: still returns all 1,205 rows.
3. Place time-window matches only after source row 500: the backend time query finds them.
4. Create more than 200 keyword matches with FTS enabled: all are counted/pageable.
5. Repeat with FTS absent/disabled: membership and count are identical.
6. Multi-file sources with identical timestamps: traversal has deterministic order, no duplicates, no gaps.
7. Dynamic column filter matches records only on later pages: count/page includes them.
8. Quick search and source filter operate across all sources, not the loaded page.
9. Cancel a build: no session is labeled complete and temporary artifacts are cleaned.
10. One source fails: UI/API reports the source and partial coverage; it does not claim complete.
11. Clear filters restores the exact full count independent of prior threat scans and prior queries.
12. Rows with unresolved timestamps are retained and visibly classified according to the documented policy.

Update the existing 600-row test that currently expects 500. It must expect all 600 and prove the persisted threat table is ignored for empty-keyword scope.

### 9.2 Frontend remote paging

1. `from`/`to` and all active filters are sent to the backend query.
2. The frontend does not post-filter a sampled timeline.
3. Page size changes do not change total count.
4. Rapid filter changes cancel/supersede stale responses.
5. Details/jump-to-source resolve the correct row after sorts/pages.
6. Selection uses stable IDs and AI staging retrieves exactly the selected records.
7. Status text never says `All rows displayed` for a partial page.
8. A complete status is shown only after all sources succeed.

### 9.3 Export completeness

1. Export 50,001 rows and verify all 50,001 plus headers/manifest.
2. Export enough synthetic rows to cross an Excel worksheet limit and verify multiple timeline sheets and exact aggregate count. This test may use a fast generated fixture/stream rather than committing a huge binary.
3. Verify first, boundary, and last stable event IDs and deterministic ordering.
4. Simulate write/cancel failure and verify no completed-looking partial file remains.
5. Verify exported count must equal the active query's expected count.

### 9.4 Model registry and runtime

1. Registry IDs are unique and artifact metadata are complete.
2. Pinned URLs use full immutable revisions.
3. Download resume, checksum failure, wrong byte count, cancellation, corrupt file, and atomic promotion work per model.
4. Existing gpt-oss artifact migration works without re-download.
5. Concurrent download requests cannot corrupt artifacts.
6. Selecting each installed model starts it with its own arguments and exact model identity.
7. Switching models terminates the previous child process and leaves one runtime.
8. Missing model produces a clear Manage Models action; the rest of the app still works.
9. Path traversal/symlink/reparse-point and broad-delete attempts are rejected.
10. Streaming cancellation produces no late UI output.
11. Slow but progressing generation does not hit a fixed wall-clock timeout.
12. A crashed server is reported accurately; no blind duplicate inference occurs.
13. Loopback token remains absent from URLs/logs/frontend state.
14. No local-model flow makes a cloud request.

### 9.5 Existing regression suites

Run all existing Rust, frontend, resource, AI, export, and release-integrity tests. Fix regressions rather than weakening assertions. Run formatting and lint/check steps used by the repository. Record exact commands and outcomes.

## 10. Performance verification

Use generated data to test at least:

- 34 sources with the shape of the original case;
- one million total rows;
- wide/dynamic columns;
- high timestamp collision rates;
- a filter returning very few late rows;
- an unfiltered result returning every row.

Report:

- build duration;
- peak backend and frontend memory;
- time to first page;
- time to exact count/complete status;
- filter latency after session build;
- export throughput and output size;
- cancellation latency.

The UI must remain responsive. Performance is solved with batching, indexing, paging, streaming, and progress—not by hiding rows.

## 11. Documentation updates

Update README/wiki-facing text so it truthfully explains:

- Master Timeline queries and filters cover all imported evidence;
- the grid is paged even though the result is complete;
- how incomplete source errors are displayed;
- how undated/unresolved-timezone rows are handled;
- export splitting for Excel's sheet limit;
- local model choices, download sizes, licenses, hardware guidance, and offline behavior;
- model output is assistance, not evidentiary fact, and citations remain examiner-verifiable;
- AI context/chunk coverage is reported separately from timeline completeness.

Remove obsolete statements that imply a single hardcoded model or that every visible page is the entire result.

## 12. Forbidden shortcuts

Do not:

- only delete `LIMIT 500` and return a giant vector;
- replace 500 with a larger hidden number;
- filter only the first page in JavaScript;
- call sampling `full`, `master`, `unified`, or `complete`;
- silently skip source errors, undated rows, oversized cells, or export rows;
- use Excel's sheet limit as permission to truncate;
- guess model hashes, sizes, revisions, licenses, or template flags;
- use `/main/` for a released model registry entry;
- add one-off duplicated model download implementations;
- automatically retry ambiguous inference failures and risk duplicate work;
- weaken tests that expose omitted rows;
- change existing evidence files or caches in a way that destroys prior examiner state;
- commit, push, tag, publish, or upload release assets.

## 13. Delivery format for review

When implementation is complete, return:

1. concise summary of architecture and user-visible changes;
2. complete list of changed files;
3. exact caps removed/redesigned and any remaining caps with classification/justification;
4. model registry table with IDs, pinned full revisions, filenames, byte sizes, SHA-256, licenses, context/runtime settings, and official sources;
5. exact test/check commands with pass/fail counts;
6. performance results and test hardware;
7. screenshots of complete timeline status, remote paging/filtering, split export manifest, model manager, model switching, streaming/cancellation, and clear error states;
8. known limitations or unverified platforms;
9. `git status --short` and a focused diff summary.

Stop for Codex/user code review. Do not publish the release.

## 14. Definition of done

This work is done only when an examiner can import a large multi-file case, generate an unfiltered Master Timeline, see an exact complete count, filter any field or time range against the entire evidence set, traverse every matching event through pages, export every matching event without truncation, stage chosen events to the AI with exact provenance, select any installed supported local model, receive streaming/progress-aware analysis, and verify through automated tests that no forensic result depends on a hidden prefix/sample limit.
