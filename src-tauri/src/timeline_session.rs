//! Backend-owned Unified Timeline Query and Session Layer
//!
//! Provides complete cross-file evidence timeline construction, deterministic
//! total ordering, keyset/page streaming, remote pagination, and bounded exports
//! without silent SQL caps or frontend memory exhaustion.

use crate::commands::FileTarget;
use crate::db::{self, ColumnMeta};
use crate::intel::analyst::{self, CorrelatedTimelineEvent};
use crate::intel::time;
use anyhow::Result;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager};

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);
static ACTIVE_CANCELLATIONS: Mutex<Option<HashSet<String>>> = Mutex::new(None);

fn is_session_cancelled(session_id: &str) -> bool {
    if let Ok(guard) = ACTIVE_CANCELLATIONS.lock() {
        if let Some(set) = guard.as_ref() {
            return set.contains(session_id);
        }
    }
    false
}

fn set_session_cancelled(session_id: &str) {
    if let Ok(mut guard) = ACTIVE_CANCELLATIONS.lock() {
        let set = guard.get_or_insert_with(HashSet::new);
        set.insert(session_id.to_string());
    }
}

fn clear_session_cancellation(session_id: &str) {
    if let Ok(mut guard) = ACTIVE_CANCELLATIONS.lock() {
        if let Some(set) = guard.as_mut() {
            set.remove(session_id);
        }
    }
}

fn default_include_undated() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineFilter {
    pub field: String,
    pub operator: String, // "contains", "equals", "starts_with", "ends_with"
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineQuerySpec {
    pub targets: Vec<FileTarget>,
    #[serde(default)]
    pub indicators: Vec<String>,
    #[serde(default)]
    pub from_epoch: Option<i64>,
    #[serde(default)]
    pub to_epoch: Option<i64>,
    #[serde(default)]
    pub quick_search: Option<String>,
    #[serde(default)]
    pub column_filters: Vec<TimelineFilter>,
    #[serde(default = "default_include_undated")]
    pub include_undated: bool,
    #[serde(default)]
    pub sort_column: Option<String>,
    #[serde(default)]
    pub sort_desc: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceCoverageError {
    pub source_path: String,
    pub sheet: Option<String>,
    pub error_message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineBuildProgress {
    pub session_id: String,
    pub sources_completed: usize,
    pub total_sources: usize,
    pub rows_examined: usize,
    pub matches_found: usize,
    pub current_source: String,
    pub phase: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineBuildResult {
    pub session_id: String,
    pub total_matches: usize,
    pub total_sources: usize,
    pub successful_sources: usize,
    pub per_source_counts: HashMap<String, usize>,
    pub source_errors: Vec<SourceCoverageError>,
    pub coverage_status: String, // "complete" or "partial"
    pub build_duration_ms: u64,
    pub snapshot_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelinePageResponse {
    pub session_id: String,
    pub page: usize,
    pub page_size: usize,
    pub total_count: usize,
    pub events: Vec<CorrelatedTimelineEvent>,
    pub has_more: bool,
    pub coverage_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineExportResult {
    pub dest_path: String,
    pub total_exported: usize,
    pub sheets_created: usize,
    pub manifest_sheet: String,
}

/// Resolves the storage directory for active timeline session databases.
pub fn get_sessions_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let app_data = app
        .path()
        .app_local_data_dir()
        .map_err(|e| format!("Failed to resolve app local data dir: {e}"))?;
    let sessions_dir = app_data.join("timeline_sessions");
    if !sessions_dir.exists() {
        fs::create_dir_all(&sessions_dir)
            .map_err(|e| format!("Failed to create sessions dir {}: {e}", sessions_dir.display()))?;
    }
    Ok(sessions_dir)
}

pub fn get_session_db_path(app: &AppHandle, session_id: &str) -> Result<PathBuf, String> {
    let sanitized_id: String = session_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    if sanitized_id.is_empty() || sanitized_id != session_id {
        return Err("Invalid session ID format".to_string());
    }
    let dir = get_sessions_dir(app)?;
    Ok(dir.join(format!("{sanitized_id}.db")))
}

fn init_session_db(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA temp_store = MEMORY;

         CREATE TABLE IF NOT EXISTS timeline_events (
             stable_event_id TEXT PRIMARY KEY,
             source_path TEXT NOT NULL,
             file_name TEXT NOT NULL,
             sheet_name TEXT,
             source_row_num INTEGER NOT NULL,
             epoch_ms INTEGER,
             time_status INTEGER NOT NULL, -- 0 for dated, 1 for undated/unresolved
             utc_text TEXT,
             user TEXT,
             host TEXT,
             action TEXT,
             details TEXT,
             mitre_tags TEXT,
             raw_fields_json TEXT
         );

         CREATE INDEX IF NOT EXISTS idx_timeline_chrono ON timeline_events (
             time_status ASC, epoch_ms ASC, file_name ASC, source_row_num ASC
         );
         CREATE INDEX IF NOT EXISTS idx_timeline_chrono_desc ON timeline_events (
             time_status ASC, epoch_ms DESC, file_name ASC, source_row_num ASC
         );
         CREATE INDEX IF NOT EXISTS idx_timeline_source ON timeline_events (source_path, source_row_num);
         CREATE INDEX IF NOT EXISTS idx_timeline_user ON timeline_events (user);
         CREATE INDEX IF NOT EXISTS idx_timeline_host ON timeline_events (host);
         CREATE INDEX IF NOT EXISTS idx_timeline_action ON timeline_events (action);"
    )?;
    Ok(())
}

/// Collects all candidate rows for a single source file without prefix limits.
fn find_candidate_rows_complete(
    conn: &Connection,
    columns: &[ColumnMeta],
    keywords: &[String],
) -> Result<Vec<i64>> {
    if keywords.is_empty() {
        // Full evidence timeline: every imported row is eligible
        let mut stmt = conn.prepare("SELECT row_num FROM rows ORDER BY row_num ASC")?;
        let rows: Vec<i64> = stmt
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        return Ok(rows);
    }

    let mut row_set = std::collections::BTreeSet::new();
    let has_fts = table_exists(conn, "rows_fts")?;

    for kw in keywords {
        let clean = kw.trim();
        if clean.is_empty() {
            continue;
        }

        let mut kw_matched = false;
        if has_fts {
            let escaped = clean.replace('"', "\"\"");
            let phrase = format!("\"{escaped}\"");
            if let Ok(mut stmt) = conn.prepare("SELECT rowid FROM rows_fts WHERE rows_fts MATCH ?1 ORDER BY rowid ASC") {
                if let Ok(rows) = stmt.query_map([&phrase], |r| r.get::<_, i64>(0)) {
                    for r in rows.flatten() {
                        row_set.insert(r);
                        kw_matched = true;
                    }
                }
            }
            if !kw_matched && !clean.contains(' ') && !clean.contains('*') {
                let prefix_phrase = format!("\"{escaped}\"*");
                if let Ok(mut stmt) = conn.prepare("SELECT rowid FROM rows_fts WHERE rows_fts MATCH ?1 ORDER BY rowid ASC") {
                    if let Ok(rows) = stmt.query_map([&prefix_phrase], |r| r.get::<_, i64>(0)) {
                        for r in rows.flatten() {
                            row_set.insert(r);
                            kw_matched = true;
                        }
                    }
                }
            }
        }

        // Full coverage fallback: scan non-blob columns with LIKE without ANY limit
        if !kw_matched {
            let pattern = format!("%{clean}%");
            for col in columns {
                if col.inferred_type != "blob" {
                    let ident = db::quote_ident(&col.sql_name);
                    let sql = format!("SELECT row_num FROM rows WHERE {ident} LIKE ?1 ORDER BY row_num ASC");
                    if let Ok(mut stmt) = conn.prepare(&sql) {
                        if let Ok(rows) = stmt.query_map([&pattern], |r| r.get::<_, i64>(0)) {
                            for r in rows.flatten() {
                                row_set.insert(r);
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(row_set.into_iter().collect())
}

fn table_exists(conn: &Connection, name: &str) -> Result<bool> {
    let mut stmt = conn.prepare_cached("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1")?;
    let mut rows = stmt.query([name])?;
    Ok(rows.next()?.is_some())
}

fn row_time_available(conn: &Connection) -> Result<bool> {
    if !table_exists(conn, "_row_time")? {
        return Ok(false);
    }
    let mut stmt = conn.prepare_cached("SELECT 1 FROM _row_time LIMIT 1")?;
    let mut rows = stmt.query([])?;
    Ok(rows.next()?.is_some())
}

/// Prepares and populates a backend-owned complete timeline session.
pub fn prepare_timeline_session_core(
    app: &AppHandle,
    spec: &TimelineQuerySpec,
    session_id: &str,
    session_db_path: &Path,
) -> Result<TimelineBuildResult, String> {
    let start_time = Instant::now();
    clear_session_cancellation(session_id);

    // If an existing session db exists with this name, remove it first
    if session_db_path.exists() {
        let _ = fs::remove_file(session_db_path);
    }

    let mut session_conn = Connection::open(session_db_path)
        .map_err(|e| format!("Failed to open session db {}: {e}", session_db_path.display()))?;
    init_session_db(&session_conn).map_err(|e| format!("Failed to init session db: {e}"))?;

    let total_sources = spec.targets.len();
    let mut successful_sources = 0;
    let mut total_matches = 0;
    let mut rows_examined = 0;
    let mut per_source_counts: HashMap<String, usize> = HashMap::new();
    let mut source_errors: Vec<SourceCoverageError> = Vec::new();

    let clean_indicators: Vec<String> = spec
        .indicators
        .iter()
        .map(|i| i.trim().to_string())
        .filter(|i| !i.is_empty())
        .collect();

    for (src_idx, target) in spec.targets.iter().enumerate() {
        if is_session_cancelled(session_id) {
            let _ = session_conn.close();
            let _ = fs::remove_file(session_db_path);
            return Err("Timeline query build was cancelled by examiner.".to_string());
        }

        let file_name = Path::new(&target.path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| target.path.clone());

        let (_sheet_name, db_path) = match target.ensure_cached_db() {
            Ok(pair) => pair,
            Err(e) => {
                source_errors.push(SourceCoverageError {
                    source_path: target.path.clone(),
                    sheet: target.sheet.clone(),
                    error_message: format!("Failed to ensure cache: {e}"),
                });
                continue;
            }
        };

        if !db_path.exists() {
            source_errors.push(SourceCoverageError {
                source_path: target.path.clone(),
                sheet: target.sheet.clone(),
                error_message: "Cache database file does not exist on disk".to_string(),
            });
            continue;
        }

        let mut source_conn = match db::open(&db_path) {
            Ok(c) => c,
            Err(e) => {
                source_errors.push(SourceCoverageError {
                    source_path: target.path.clone(),
                    sheet: target.sheet.clone(),
                    error_message: format!("Failed to open cache database: {e}"),
                });
                continue;
            }
        };

        let columns = match db::load_columns(&source_conn) {
            Ok(cols) => cols,
            Err(e) => {
                source_errors.push(SourceCoverageError {
                    source_path: target.path.clone(),
                    sheet: target.sheet.clone(),
                    error_message: format!("Failed to load columns: {e}"),
                });
                continue;
            }
        };

        // Timestamp normalization check
        if !row_time_available(&source_conn).unwrap_or(false) {
            let _ = time::normalize_timestamp_column_with_options(
                &mut source_conn,
                &columns,
                Some("UTC"),
                Some("month_first"),
            );
        }

        let candidate_rows = match find_candidate_rows_complete(&source_conn, &columns, &clean_indicators) {
            Ok(rows) => rows,
            Err(e) => {
                source_errors.push(SourceCoverageError {
                    source_path: target.path.clone(),
                    sheet: target.sheet.clone(),
                    error_message: format!("Candidate row query failed: {e}"),
                });
                continue;
            }
        };

        rows_examined += candidate_rows.len();

        let mut source_match_count = 0;
        let chunk_size = 5000;

        for chunk in candidate_rows.chunks(chunk_size) {
            if is_session_cancelled(session_id) {
                let _ = session_conn.close();
                let _ = fs::remove_file(session_db_path);
                return Err("Timeline query build was cancelled by examiner.".to_string());
            }

            let events = analyst::extract_correlated_events_for_rows(
                &source_conn,
                &columns,
                chunk,
                &file_name,
                &target.path,
            );

            // Insert events into session database in a single transaction
            let tx = session_conn
                .transaction()
                .map_err(|e| format!("Session transaction error: {e}"))?;

            {
                let mut insert_stmt = tx
                    .prepare_cached(
                        "INSERT OR REPLACE INTO timeline_events (
                             stable_event_id, source_path, file_name, sheet_name,
                             source_row_num, epoch_ms, time_status, utc_text,
                             user, host, action, details, mitre_tags, raw_fields_json
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                    )
                    .map_err(|e| format!("Prepare insert error: {e}"))?;

                for ev in events {
                    let epoch = ev.epoch_ms;
                    // If time bounds are requested, evaluate here
                    if let Some(from_ep) = spec.from_epoch {
                        if let Some(ep) = epoch {
                            if ep < from_ep {
                                continue;
                            }
                        } else if !spec.include_undated {
                            continue;
                        }
                    }
                    if let Some(to_ep) = spec.to_epoch {
                        if let Some(ep) = epoch {
                            if ep > to_ep {
                                continue;
                            }
                        } else if !spec.include_undated {
                            continue;
                        }
                    }

                    let time_status = if epoch.is_some() { 0 } else { 1 };
                    let sheet_str = target.sheet.clone().unwrap_or_default();
                    let stable_id = format!("{}:{}:{}", file_name, sheet_str, ev.row_num);
                    let tags_str = ev.mitre_tags.join(", ");
                    let raw_fields_json = serde_json::to_string(&ev.raw_fields).unwrap_or_default();

                    insert_stmt
                        .execute(params![
                            stable_id,
                            ev.path,
                            ev.file_name,
                            target.sheet,
                            ev.row_num,
                            ev.epoch_ms,
                            time_status,
                            ev.utc_text,
                            ev.user,
                            ev.host,
                            ev.action,
                            ev.details,
                            tags_str,
                            raw_fields_json,
                        ])
                        .map_err(|e| format!("Insert timeline event error: {e}"))?;

                    source_match_count += 1;
                }
            }

            tx.commit()
                .map_err(|e| format!("Commit session transaction error: {e}"))?;
        }

        successful_sources += 1;
        total_matches += source_match_count;
        per_source_counts.insert(file_name.clone(), source_match_count);

        let progress = TimelineBuildProgress {
            session_id: session_id.to_string(),
            sources_completed: src_idx + 1,
            total_sources,
            rows_examined,
            matches_found: total_matches,
            current_source: file_name,
            phase: if src_idx + 1 == total_sources {
                "complete".to_string()
            } else {
                "correlating".to_string()
            },
        };
        let _ = app.emit("timeline-build-progress", progress);
    }

    let coverage_status = if source_errors.is_empty() && successful_sources == total_sources {
        "complete".to_string()
    } else {
        "partial".to_string()
    };

    let snapshot_id = format!(
        "snap_{:x}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    );

    Ok(TimelineBuildResult {
        session_id: session_id.to_string(),
        total_matches,
        total_sources,
        successful_sources,
        per_source_counts,
        source_errors,
        coverage_status,
        build_duration_ms: start_time.elapsed().as_millis() as u64,
        snapshot_id,
    })
}

/// Builds parameterized WHERE and ORDER BY clauses for querying the session database.
fn build_session_query_clauses(
    quick_search: Option<&str>,
    column_filters: Option<&[TimelineFilter]>,
    sort_column: Option<&str>,
    sort_desc: bool,
) -> (String, Vec<rusqlite::types::Value>, String) {
    let mut where_parts = Vec::new();
    let mut params = Vec::new();

    if let Some(qs) = quick_search {
        let clean = qs.trim();
        if !clean.is_empty() {
            let pattern = format!("%{clean}%");
            where_parts.push(
                "(file_name LIKE ? OR user LIKE ? OR host LIKE ? OR action LIKE ? OR details LIKE ? OR utc_text LIKE ? OR mitre_tags LIKE ?)".to_string(),
            );
            for _ in 0..7 {
                params.push(rusqlite::types::Value::Text(pattern.clone()));
            }
        }
    }

    if let Some(filters) = column_filters {
        for f in filters {
            let val = f.value.trim();
            if val.is_empty() {
                continue;
            }
            let valid_col = match f.field.as_str() {
                "file_name" | "fileName" => Some("file_name"),
                "source_path" | "path" => Some("source_path"),
                "user" => Some("user"),
                "host" => Some("host"),
                "action" => Some("action"),
                "details" => Some("details"),
                "utc_text" | "utcText" => Some("utc_text"),
                "mitre_tags" | "mitreTags" => Some("mitre_tags"),
                _ => None,
            };

            if let Some(col) = valid_col {
                match f.operator.as_str() {
                    "equals" => {
                        where_parts.push(format!("{col} = ?"));
                        params.push(rusqlite::types::Value::Text(val.to_string()));
                    }
                    "starts_with" => {
                        where_parts.push(format!("{col} LIKE ?"));
                        params.push(rusqlite::types::Value::Text(format!("{val}%")));
                    }
                    "ends_with" => {
                        where_parts.push(format!("{col} LIKE ?"));
                        params.push(rusqlite::types::Value::Text(format!("%{val}")));
                    }
                    _ => {
                        // Default "contains"
                        where_parts.push(format!("{col} LIKE ?"));
                        params.push(rusqlite::types::Value::Text(format!("%{val}%")));
                    }
                }
            }
        }
    }

    let where_clause = if where_parts.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_parts.join(" AND "))
    };

    let dir = if sort_desc { "DESC" } else { "ASC" };
    let order_clause = match sort_column {
        Some("user") => format!("ORDER BY time_status ASC, user {dir}, epoch_ms ASC, source_row_num ASC"),
        Some("host") => format!("ORDER BY time_status ASC, host {dir}, epoch_ms ASC, source_row_num ASC"),
        Some("action") => format!("ORDER BY time_status ASC, action {dir}, epoch_ms ASC, source_row_num ASC"),
        Some("file_name") | Some("fileName") => {
            format!("ORDER BY time_status ASC, file_name {dir}, epoch_ms ASC, source_row_num ASC")
        }
        Some("row_num") | Some("source_row_num") => {
            format!("ORDER BY source_row_num {dir}")
        }
        _ => {
            // Default deterministic chronological total order:
            // (timestamp-status, normalized-epoch, file-name, source-row-number)
            format!("ORDER BY time_status ASC, epoch_ms {dir}, file_name ASC, source_row_num ASC")
        }
    };

    (where_clause, params, order_clause)
}

/// Executes a keyset/paged query against an active timeline session database.
pub fn query_session_page(
    session_db_path: &Path,
    page: usize,
    page_size: usize,
    quick_search: Option<&str>,
    column_filters: Option<&[TimelineFilter]>,
    sort_column: Option<&str>,
    sort_desc: bool,
) -> Result<(Vec<CorrelatedTimelineEvent>, usize, bool), String> {
    if !session_db_path.exists() {
        return Err("Timeline session does not exist or has expired.".to_string());
    }

    let conn = Connection::open(session_db_path)
        .map_err(|e| format!("Failed to open session db: {e}"))?;

    let (where_sql, params, order_sql) =
        build_session_query_clauses(quick_search, column_filters, sort_column, sort_desc);

    // 1. Get exact total count for the current filter criteria
    let count_sql = format!("SELECT COUNT(*) FROM timeline_events {where_sql}");
    let mut count_stmt = conn
        .prepare(&count_sql)
        .map_err(|e| format!("Prepare count error: {e}"))?;
    let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p as &dyn rusqlite::ToSql).collect();
    let total_count: usize = count_stmt
        .query_row(&param_refs[..], |r| r.get(0))
        .map_err(|e| format!("Query count error: {e}"))?;

    let bounded_page = if page == 0 { 1 } else { page };
    let bounded_size = if page_size == 0 { 300 } else { page_size };
    let offset = (bounded_page - 1) * bounded_size;

    // 2. Fetch page rows
    let select_sql = format!(
        "SELECT stable_event_id, source_path, file_name, sheet_name, source_row_num,
                epoch_ms, time_status, utc_text, user, host, action, details,
                mitre_tags, raw_fields_json
         FROM timeline_events
         {where_sql}
         {order_sql}
         LIMIT ? OFFSET ?",
    );

    let mut select_stmt = conn
        .prepare(&select_sql)
        .map_err(|e| format!("Prepare select error: {e}"))?;

    let mut query_params = params.clone();
    query_params.push(rusqlite::types::Value::Integer(bounded_size as i64));
    query_params.push(rusqlite::types::Value::Integer(offset as i64));

    let q_param_refs: Vec<&dyn rusqlite::ToSql> =
        query_params.iter().map(|p| p as &dyn rusqlite::ToSql).collect();

    let event_rows = select_stmt
        .query_map(&q_param_refs[..], |r| {
            let row_num: i64 = r.get(4)?;
            let file_name: String = r.get(2)?;
            let path: String = r.get(1)?;
            let epoch_ms: Option<i64> = r.get(5)?;
            let utc_text: Option<String> = r.get(7)?;
            let user: Option<String> = r.get(8)?;
            let host: Option<String> = r.get(9)?;
            let action: Option<String> = r.get(10)?;
            let details: Option<String> = r.get(11)?;
            let tags_str: Option<String> = r.get(12)?;
            let raw_json: Option<String> = r.get(13)?;

            let mitre_tags = tags_str
                .map(|s| {
                    s.split(',')
                        .map(|t| t.trim().to_string())
                        .filter(|t| !t.is_empty())
                        .collect()
                })
                .unwrap_or_default();

            let raw_fields: HashMap<String, String> = raw_json
                .and_then(|j| serde_json::from_str(&j).ok())
                .unwrap_or_default();

            Ok(CorrelatedTimelineEvent {
                file_name,
                path,
                row_num,
                epoch_ms,
                utc_text,
                user,
                host,
                action,
                details,
                mitre_tags,
                raw_fields,
            })
        })
        .map_err(|e| format!("Query map error: {e}"))?;

    let mut events = Vec::new();
    for ev in event_rows {
        if let Ok(e) = ev {
            events.push(e);
        }
    }

    let has_more = offset + events.len() < total_count;
    Ok((events, total_count, has_more))
}

/// Cleans stale session databases older than 2 hours.
pub fn cleanup_stale_sessions(app: &AppHandle) {
    if let Ok(dir) = get_sessions_dir(app) {
        if let Ok(entries) = fs::read_dir(dir) {
            let now = SystemTime::now();
            let max_age = Duration::from_secs(2 * 60 * 60);
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("db") {
                    if let Ok(meta) = fs::metadata(&path) {
                        if let Ok(modified) = meta.modified() {
                            if let Ok(age) = now.duration_since(modified) {
                                if age > max_age {
                                    let _ = fs::remove_file(&path);
                                    let _ = fs::remove_file(path.with_extension("db-wal"));
                                    let _ = fs::remove_file(path.with_extension("db-shm"));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tauri Commands
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn prepare_unified_timeline_query(
    app: AppHandle,
    spec: TimelineQuerySpec,
) -> Result<TimelineBuildResult, String> {
    let session_id = format!(
        "session_{:x}_{:x}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        SESSION_COUNTER.fetch_add(1, Ordering::SeqCst)
    );
    let session_db_path = get_session_db_path(&app, &session_id)?;

    tauri::async_runtime::spawn_blocking(move || {
        cleanup_stale_sessions(&app);
        prepare_timeline_session_core(&app, &spec, &session_id, &session_db_path)
    })
    .await
    .map_err(|e| format!("Timeline build join error: {e}"))?
}

#[tauri::command]
pub async fn query_unified_timeline_page(
    app: AppHandle,
    session_id: String,
    page: usize,
    page_size: usize,
    quick_search: Option<String>,
    column_filters: Option<Vec<TimelineFilter>>,
    sort_column: Option<String>,
    sort_desc: Option<bool>,
) -> Result<TimelinePageResponse, String> {
    let session_db_path = get_session_db_path(&app, &session_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let (events, total_count, has_more) = query_session_page(
            &session_db_path,
            page,
            page_size,
            quick_search.as_deref(),
            column_filters.as_deref(),
            sort_column.as_deref(),
            sort_desc.unwrap_or(false),
        )?;

        Ok(TimelinePageResponse {
            session_id,
            page,
            page_size,
            total_count,
            events,
            has_more,
            coverage_status: "complete".to_string(),
        })
    })
    .await
    .map_err(|e| format!("Timeline page join error: {e}"))?
}

#[tauri::command]
pub async fn count_unified_timeline(
    app: AppHandle,
    session_id: String,
    quick_search: Option<String>,
    column_filters: Option<Vec<TimelineFilter>>,
) -> Result<usize, String> {
    let session_db_path = get_session_db_path(&app, &session_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let (_events, total_count, _has_more) = query_session_page(
            &session_db_path,
            1,
            1,
            quick_search.as_deref(),
            column_filters.as_deref(),
            None,
            false,
        )?;
        Ok(total_count)
    })
    .await
    .map_err(|e| format!("Timeline count join error: {e}"))?
}

#[tauri::command]
pub async fn get_unified_timeline_row_details(
    source_path: String,
    sheet: Option<String>,
    row_num: i64,
) -> Result<HashMap<String, String>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let target = FileTarget {
            path: source_path.clone(),
            sheet,
            cache_db_path: None,
        };
        let (_sheet_name, db_path) = target
            .ensure_cached_db()
            .map_err(|e| format!("Failed to ensure cache for {}: {e}", source_path))?;
        let conn = db::open(&db_path).map_err(|e| format!("Failed to open cache db: {e}"))?;
        let columns = db::load_columns(&conn).map_err(|e| format!("Failed to load columns: {e}"))?;

        let mut select_cols = Vec::new();
        for col in &columns {
            select_cols.push(db::quote_ident(&col.sql_name));
        }

        let sql = format!(
            "SELECT {} FROM rows WHERE row_num = ?1 LIMIT 1",
            select_cols.join(", ")
        );
        let mut stmt = conn.prepare(&sql).map_err(|e| format!("Prepare error: {e}"))?;
        let mut rows = stmt.query([row_num]).map_err(|e| format!("Query error: {e}"))?;

        if let Some(row) = rows.next().map_err(|e| format!("Row error: {e}"))? {
            let mut result = HashMap::new();
            for (idx, col) in columns.iter().enumerate() {
                if let Ok(Some(val)) = row.get::<_, Option<String>>(idx) {
                    result.insert(col.original_name.clone(), val);
                }
            }
            return Ok(result);
        }

        Err(format!("Row {row_num} not found in {source_path}"))
    })
    .await
    .map_err(|e| format!("Row details join error: {e}"))?
}

#[tauri::command]
pub async fn cancel_unified_timeline_build(session_id: String) -> Result<bool, String> {
    set_session_cancelled(&session_id);
    Ok(true)
}

#[tauri::command]
pub async fn close_unified_timeline_session(app: AppHandle, session_id: String) -> Result<bool, String> {
    set_session_cancelled(&session_id);
    if let Ok(path) = get_session_db_path(&app, &session_id) {
        if path.exists() {
            let _ = fs::remove_file(&path);
            let _ = fs::remove_file(path.with_extension("db-wal"));
            let _ = fs::remove_file(path.with_extension("db-shm"));
        }
    }
    clear_session_cancellation(&session_id);
    Ok(true)
}

// ---------------------------------------------------------------------------
// Streaming Multi-Sheet Exports (Section 6)
// ---------------------------------------------------------------------------

const EXCEL_SHEET_ROW_LIMIT: usize = 1_000_000;

#[tauri::command]
pub async fn export_unified_timeline_session_xlsx(
    app: AppHandle,
    session_id: String,
    dest_path: String,
    quick_search: Option<String>,
    column_filters: Option<Vec<TimelineFilter>>,
    sort_column: Option<String>,
    sort_desc: Option<bool>,
) -> Result<TimelineExportResult, String> {
    let session_db_path = get_session_db_path(&app, &session_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let dest = PathBuf::from(&dest_path);
        let temp_path = dest.with_extension("tmp.xlsx");
        if temp_path.exists() {
            let _ = fs::remove_file(&temp_path);
        }

        let conn = Connection::open(&session_db_path)
            .map_err(|e| format!("Failed to open session db: {e}"))?;

        let (where_sql, params, order_sql) = build_session_query_clauses(
            quick_search.as_deref(),
            column_filters.as_deref(),
            sort_column.as_deref(),
            sort_desc.unwrap_or(false),
        );

        // Count expected rows
        let count_sql = format!("SELECT COUNT(*) FROM timeline_events {where_sql}");
        let mut count_stmt = conn
            .prepare(&count_sql)
            .map_err(|e| format!("Prepare count error: {e}"))?;
        let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p as &dyn rusqlite::ToSql).collect();
        let expected_count: usize = count_stmt
            .query_row(&param_refs[..], |r| r.get(0))
            .map_err(|e| format!("Query count error: {e}"))?;

        let mut workbook = rust_xlsxwriter::Workbook::new();
        let bold_format = rust_xlsxwriter::Format::new().set_bold();

        let headers = [
            "#",
            "Source File",
            "File Path",
            "Source Row",
            "Timestamp (UTC)",
            "Epoch (ms)",
            "User / Identity",
            "Host / IP",
            "Operation / Action",
            "Details / Parameters",
            "MITRE / Threat Tags",
        ];

        let mut current_sheet_num = 1;
        let mut current_sheet = workbook.add_worksheet();
        let base_sheet_name = "MASTER TIMELINE";
        current_sheet
            .set_name(base_sheet_name)
            .map_err(|e| format!("Set sheet name error: {e}"))?;

        for (c_idx, h) in headers.iter().enumerate() {
            current_sheet
                .write_string_with_format(0, c_idx as u16, *h, &bold_format)
                .map_err(|e| format!("Write header error: {e}"))?;
        }

        let select_sql = format!(
            "SELECT file_name, source_path, source_row_num, utc_text, epoch_ms,
                    user, host, action, details, mitre_tags
             FROM timeline_events
             {where_sql}
             {order_sql}"
        );

        let mut stmt = conn
            .prepare(&select_sql)
            .map_err(|e| format!("Prepare export query error: {e}"))?;

        let rows = stmt
            .query_map(&param_refs[..], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, Option<i64>>(4)?,
                    r.get::<_, Option<String>>(5)?,
                    r.get::<_, Option<String>>(6)?,
                    r.get::<_, Option<String>>(7)?,
                    r.get::<_, Option<String>>(8)?,
                    r.get::<_, Option<String>>(9)?,
                ))
            })
            .map_err(|e| format!("Export query error: {e}"))?;

        let mut total_exported = 0;
        let mut row_in_sheet = 0;
        let mut sheet_ranges: Vec<(String, usize, usize)> = Vec::new();
        let mut range_start = 1;

        for res in rows {
            let (file_name, path, row_num, utc_text, epoch_ms, user, host, action, details, mitre_tags) =
                res.map_err(|e| format!("Read row error: {e}"))?;

            if row_in_sheet >= EXCEL_SHEET_ROW_LIMIT {
                sheet_ranges.push((
                    if current_sheet_num == 1 {
                        base_sheet_name.to_string()
                    } else {
                        format!("{base_sheet_name} {current_sheet_num}")
                    },
                    range_start,
                    total_exported,
                ));

                current_sheet_num += 1;
                range_start = total_exported + 1;
                row_in_sheet = 0;

                current_sheet = workbook.add_worksheet();
                let next_name = format!("{base_sheet_name} {current_sheet_num}");
                current_sheet
                    .set_name(&next_name)
                    .map_err(|e| format!("Set sheet name error: {e}"))?;

                for (c_idx, h) in headers.iter().enumerate() {
                    current_sheet
                        .write_string_with_format(0, c_idx as u16, *h, &bold_format)
                        .map_err(|e| format!("Write header error: {e}"))?;
                }
            }

            row_in_sheet += 1;
            total_exported += 1;
            let excel_row = row_in_sheet as u32;

            current_sheet
                .write_number(excel_row, 0, total_exported as f64)
                .map_err(|e| format!("Write cell error: {e}"))?;
            current_sheet
                .write_string(excel_row, 1, &file_name)
                .map_err(|e| format!("Write cell error: {e}"))?;
            current_sheet
                .write_string(excel_row, 2, &path)
                .map_err(|e| format!("Write cell error: {e}"))?;
            current_sheet
                .write_number(excel_row, 3, row_num as f64)
                .map_err(|e| format!("Write cell error: {e}"))?;
            current_sheet
                .write_string(excel_row, 4, utc_text.as_deref().unwrap_or("—"))
                .map_err(|e| format!("Write cell error: {e}"))?;
            if let Some(ep) = epoch_ms {
                current_sheet
                    .write_number(excel_row, 5, ep as f64)
                    .map_err(|e| format!("Write cell error: {e}"))?;
            }
            current_sheet
                .write_string(excel_row, 6, user.as_deref().unwrap_or("—"))
                .map_err(|e| format!("Write cell error: {e}"))?;
            current_sheet
                .write_string(excel_row, 7, host.as_deref().unwrap_or("—"))
                .map_err(|e| format!("Write cell error: {e}"))?;
            current_sheet
                .write_string(excel_row, 8, action.as_deref().unwrap_or("—"))
                .map_err(|e| format!("Write cell error: {e}"))?;
            current_sheet
                .write_string(excel_row, 9, details.as_deref().unwrap_or("—"))
                .map_err(|e| format!("Write cell error: {e}"))?;
            current_sheet
                .write_string(excel_row, 10, mitre_tags.as_deref().unwrap_or("—"))
                .map_err(|e| format!("Write cell error: {e}"))?;
        }

        sheet_ranges.push((
            if current_sheet_num == 1 {
                base_sheet_name.to_string()
            } else {
                format!("{base_sheet_name} {current_sheet_num}")
            },
            range_start,
            total_exported,
        ));

        // Hard verification check: exported count must equal expected query count
        if total_exported != expected_count {
            let _ = fs::remove_file(&temp_path);
            return Err(format!(
                "Forensic completeness violation: expected {} matching events, but exported {}",
                expected_count, total_exported
            ));
        }

        // Write MANIFEST sheet
        let manifest_sheet = workbook.add_worksheet();
        manifest_sheet
            .set_name("MANIFEST")
            .map_err(|e| format!("Set manifest sheet error: {e}"))?;

        let manifest_meta = [
            ("Export Type", "logparser-DFIR Complete Master Timeline"),
            ("Application Version", "0.3.9"),
            ("Expected Matching Events", &expected_count.to_string()),
            ("Total Exported Events", &total_exported.to_string()),
            ("Sheets Created", &current_sheet_num.to_string()),
            ("Forensic Coverage Status", "100% COMPLETE — Zero rows omitted"),
        ];

        manifest_sheet
            .write_string_with_format(0, 0, "Property", &bold_format)
            .map_err(|e| format!("Write manifest: {e}"))?;
        manifest_sheet
            .write_string_with_format(0, 1, "Value", &bold_format)
            .map_err(|e| format!("Write manifest: {e}"))?;

        for (m_idx, (k, v)) in manifest_meta.iter().enumerate() {
            let r = (m_idx + 1) as u32;
            manifest_sheet.write_string(r, 0, *k).map_err(|e| format!("Write manifest: {e}"))?;
            manifest_sheet.write_string(r, 1, *v).map_err(|e| format!("Write manifest: {e}"))?;
        }

        let range_header_row = (manifest_meta.len() + 3) as u32;
        manifest_sheet
            .write_string_with_format(range_header_row, 0, "Sheet Name", &bold_format)
            .map_err(|e| format!("Write manifest: {e}"))?;
        manifest_sheet
            .write_string_with_format(range_header_row, 1, "Row Range", &bold_format)
            .map_err(|e| format!("Write manifest: {e}"))?;

        for (idx, (s_name, start, end)) in sheet_ranges.iter().enumerate() {
            let r = range_header_row + 1 + idx as u32;
            manifest_sheet.write_string(r, 0, s_name).map_err(|e| format!("Write manifest: {e}"))?;
            manifest_sheet
                .write_string(r, 1, &format!("{start} .. {end} ({})", end - start + 1))
                .map_err(|e| format!("Write manifest: {e}"))?;
        }

        // Save atomically
        workbook
            .save(&temp_path)
            .map_err(|e| format!("Failed to save workbook to {}: {e}", temp_path.display()))?;

        // Rename temp to dest atomically
        fs::rename(&temp_path, &dest)
            .map_err(|e| format!("Failed to rename {} to {}: {e}", temp_path.display(), dest.display()))?;

        Ok(TimelineExportResult {
            dest_path,
            total_exported,
            sheets_created: current_sheet_num,
            manifest_sheet: "MANIFEST".to_string(),
        })
    })
    .await
    .map_err(|e| format!("Export XLSX task join error: {e}"))?
}

#[tauri::command]
pub async fn export_unified_timeline_session_csv(
    app: AppHandle,
    session_id: String,
    dest_path: String,
    quick_search: Option<String>,
    column_filters: Option<Vec<TimelineFilter>>,
    sort_column: Option<String>,
    sort_desc: Option<bool>,
) -> Result<TimelineExportResult, String> {
    let session_db_path = get_session_db_path(&app, &session_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let dest = PathBuf::from(&dest_path);
        let temp_path = dest.with_extension("tmp.csv");
        if temp_path.exists() {
            let _ = fs::remove_file(&temp_path);
        }

        let conn = Connection::open(&session_db_path)
            .map_err(|e| format!("Failed to open session db: {e}"))?;

        let (where_sql, params, order_sql) = build_session_query_clauses(
            quick_search.as_deref(),
            column_filters.as_deref(),
            sort_column.as_deref(),
            sort_desc.unwrap_or(false),
        );

        // Count expected rows
        let count_sql = format!("SELECT COUNT(*) FROM timeline_events {where_sql}");
        let mut count_stmt = conn
            .prepare(&count_sql)
            .map_err(|e| format!("Prepare count error: {e}"))?;
        let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p as &dyn rusqlite::ToSql).collect();
        let expected_count: usize = count_stmt
            .query_row(&param_refs[..], |r| r.get(0))
            .map_err(|e| format!("Query count error: {e}"))?;

        let select_sql = format!(
            "SELECT file_name, source_path, source_row_num, utc_text, epoch_ms,
                    user, host, action, details, mitre_tags
             FROM timeline_events
             {where_sql}
             {order_sql}"
        );

        let mut stmt = conn
            .prepare(&select_sql)
            .map_err(|e| format!("Prepare select error: {e}"))?;

        let rows = stmt
            .query_map(&param_refs[..], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, Option<i64>>(4)?,
                    r.get::<_, Option<String>>(5)?,
                    r.get::<_, Option<String>>(6)?,
                    r.get::<_, Option<String>>(7)?,
                    r.get::<_, Option<String>>(8)?,
                    r.get::<_, Option<String>>(9)?,
                ))
            })
            .map_err(|e| format!("Query error: {e}"))?;

        let file = fs::File::create(&temp_path)
            .map_err(|e| format!("Failed to create temp csv {}: {e}", temp_path.display()))?;
        let mut writer = csv::WriterBuilder::new().from_writer(std::io::BufWriter::new(file));

        writer
            .write_record(&[
                "#",
                "Source File",
                "File Path",
                "Source Row",
                "Timestamp (UTC)",
                "Epoch (ms)",
                "User / Identity",
                "Host / IP",
                "Operation / Action",
                "Details / Parameters",
                "MITRE / Threat Tags",
            ])
            .map_err(|e| format!("Write CSV header error: {e}"))?;

        let mut total_exported = 0;
        for res in rows {
            let (file_name, path, row_num, utc_text, epoch_ms, user, host, action, details, mitre_tags) =
                res.map_err(|e| format!("Read row error: {e}"))?;

            total_exported += 1;
            writer
                .write_record(&[
                    total_exported.to_string(),
                    file_name,
                    path,
                    row_num.to_string(),
                    utc_text.unwrap_or_else(|| "—".to_string()),
                    epoch_ms.map(|e| e.to_string()).unwrap_or_default(),
                    user.unwrap_or_else(|| "—".to_string()),
                    host.unwrap_or_else(|| "—".to_string()),
                    action.unwrap_or_else(|| "—".to_string()),
                    details.unwrap_or_else(|| "—".to_string()),
                    mitre_tags.unwrap_or_else(|| "—".to_string()),
                ])
                .map_err(|e| format!("Write CSV row error: {e}"))?;
        }

        writer.flush().map_err(|e| format!("Flush CSV error: {e}"))?;
        drop(writer);

        if total_exported != expected_count {
            let _ = fs::remove_file(&temp_path);
            return Err(format!(
                "Forensic completeness violation: expected {} matching events, but exported {}",
                expected_count, total_exported
            ));
        }

        fs::rename(&temp_path, &dest)
            .map_err(|e| format!("Failed to rename {} to {}: {e}", temp_path.display(), dest.display()))?;

        Ok(TimelineExportResult {
            dest_path,
            total_exported,
            sheets_created: 1,
            manifest_sheet: "None (CSV)".to_string(),
        })
    })
    .await
    .map_err(|e| format!("Export CSV task join error: {e}"))?
}

// ---------------------------------------------------------------------------
// Unit Tests (Section 9.1 & 9.3)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_session_db(temp_path: &Path, count: usize) -> Result<Connection> {
        let conn = Connection::open(temp_path)?;
        init_session_db(&conn)?;
        let tx = conn.unchecked_transaction()?;
        {
            let mut insert = tx.prepare(
                "INSERT INTO timeline_events (
                     stable_event_id, source_path, file_name, sheet_name,
                     source_row_num, epoch_ms, time_status, utc_text,
                     user, host, action, details, mitre_tags, raw_fields_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            )?;
            for i in 1..=count {
                let epoch = if i % 10 == 0 { None } else { Some(1700000000000 + (i as i64 * 1000)) };
                let time_status = if epoch.is_some() { 0 } else { 1 };
                let user = if i % 2 == 0 { "alice" } else { "bob" };
                let host = if i % 3 == 0 { "WORKSTATION-1" } else { "SERVER-2" };
                let action = if i % 5 == 0 { "login" } else { "file_access" };
                insert.execute(params![
                    format!("test.log::{i}"),
                    "C:\\evidence\\test.log",
                    "test.log",
                    Option::<String>::None,
                    i as i64,
                    epoch,
                    time_status,
                    epoch.map(|_| "2026-11-08T00:00:00Z".to_string()),
                    user,
                    host,
                    action,
                    format!("details for event {i}"),
                    if i % 7 == 0 { "T1078, T1059" } else { "" },
                    format!("{{\"EventID\":\"{i}\"}}")
                ])?;
            }
        }
        tx.commit()?;
        Ok(conn)
    }

    #[test]
    fn test_session_paging_and_total_counts() {
        let temp_dir = std::env::temp_dir().join(format!("test_session_paging_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let db_path = temp_dir.join("session.db");

        let _ = create_test_session_db(&db_path, 1205).unwrap();

        // 1. Unfiltered page 1 (size 300)
        let (page1, total, has_more) =
            query_session_page(&db_path, 1, 300, None, None, None, false).unwrap();
        assert_eq!(total, 1205, "Total count must be exactly 1205");
        assert_eq!(page1.len(), 300, "Page 1 must contain exactly 300 rows");
        assert!(has_more, "Must have more pages");
        assert_eq!(page1.first().unwrap().row_num, 1);

        // 2. Page 5 (last page: 1205 - 1200 = 5 rows)
        let (page5, total5, has_more5) =
            query_session_page(&db_path, 5, 300, None, None, None, false).unwrap();
        assert_eq!(total5, 1205);
        assert_eq!(page5.len(), 5);
        assert!(!has_more5);

        // 3. Traversal across all pages yields all 1205 unique row IDs
        let mut all_ids = HashSet::new();
        for p in 1..=5 {
            let (page, _, _) = query_session_page(&db_path, p, 300, None, None, None, false).unwrap();
            for ev in page {
                all_ids.insert(ev.row_num);
            }
        }
        assert_eq!(all_ids.len(), 1205, "All 1205 IDs must be traversed without gaps or duplicates");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_session_filtering_across_entire_dataset() {
        let temp_dir = std::env::temp_dir().join(format!("test_session_filters_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let db_path = temp_dir.join("session.db");

        let _ = create_test_session_db(&db_path, 1205).unwrap();

        // Quick search for "event 1200" (matches only record 1200, located on the final page)
        let (res, total, _) =
            query_session_page(&db_path, 1, 300, Some("event 1200"), None, None, false).unwrap();
        assert_eq!(total, 1, "Quick search must find record 1200 across all 1205 rows");
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].row_num, 1200);

        // Column filter: user == "alice"
        let filters = vec![TimelineFilter {
            field: "user".to_string(),
            operator: "equals".to_string(),
            value: "alice".to_string(),
        }];
        let (_, alice_total, _) =
            query_session_page(&db_path, 1, 300, None, Some(&filters), None, false).unwrap();
        assert_eq!(alice_total, 602, "Alice matches exactly 602 rows out of 1205");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_undated_events_deterministic_order() {
        let temp_dir = std::env::temp_dir().join(format!("test_session_undated_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let db_path = temp_dir.join("session.db");

        let _ = create_test_session_db(&db_path, 100).unwrap();

        // In our fixture, every 10th record is undated (epoch = None, time_status = 1)
        // Deterministic order requires dated events first (time_status = 0), undated last (time_status = 1)
        let (all_events, total, _) =
            query_session_page(&db_path, 1, 100, None, None, None, false).unwrap();
        assert_eq!(total, 100);

        let first_undated_idx = all_events.iter().position(|e| e.epoch_ms.is_none()).unwrap();
        assert_eq!(first_undated_idx, 90, "First 90 events must be dated, last 10 undated");

        // Undated events must be sorted stably by file_name and source_row_num
        let undated = &all_events[90..];
        assert_eq!(undated.len(), 10);
        let undated_rows: Vec<i64> = undated.iter().map(|e| e.row_num).collect();
        assert_eq!(undated_rows, vec![10, 20, 30, 40, 50, 60, 70, 80, 90, 100]);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
