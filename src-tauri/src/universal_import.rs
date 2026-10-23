use crate::db::{self, ColumnMeta};
use crate::header_utils::sanitize_headers;
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use evtx::EvtxParser;
use flate2::read::GzDecoder;
use rusqlite::Connection;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

const BATCH_SIZE: usize = 5000;
const INITIAL_SCHEMA_SAMPLE_SIZE: usize = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UniversalFormat {
    Csv,
    Tsv,
    Json,
    JsonLines,
    CompressedJsonLines,
    Evtx,
    Syslog,
    Xml,
    Excel,
}

pub struct UniversalImportResult {
    pub columns: Vec<ColumnMeta>,
    pub row_count: i64,
    pub failure_count: i64,
    pub warning: Option<String>,
}

pub fn detect_format(path: &Path) -> Result<UniversalFormat> {
    let file_name = path
        .file_name()
        .and_then(|f| f.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    if file_name.ends_with(".jsonl.gz") || file_name.ends_with(".log.gz") || file_name.ends_with(".gz") {
        return Ok(UniversalFormat::CompressedJsonLines);
    }

    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
        .as_deref()
    {
        Some("csv") => Ok(UniversalFormat::Csv),
        Some("tsv" | "tab") => Ok(UniversalFormat::Tsv),
        Some("json") => Ok(UniversalFormat::Json),
        Some("jsonl" | "ndjson") => Ok(UniversalFormat::JsonLines),
        Some("evtx") => Ok(UniversalFormat::Evtx),
        Some("log" | "syslog" | "txt") => Ok(UniversalFormat::Syslog),
        Some("xml") => Ok(UniversalFormat::Xml),
        Some("xls" | "xlsx" | "xlsm" | "xlsb" | "ods") => Ok(UniversalFormat::Excel),
        Some(ext) => bail!("unsupported file extension .{ext}"),
        None => bail!("unsupported file type with no extension"),
    }
}

pub fn create_audit_tables_if_needed(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS _parse_failures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_path TEXT NOT NULL,
            record_num INTEGER NOT NULL,
            raw_payload TEXT,
            error_message TEXT NOT NULL,
            occurred_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS _ingest_audit (
            source_path TEXT PRIMARY KEY,
            total_records INTEGER NOT NULL,
            parse_failures INTEGER NOT NULL,
            columns_count INTEGER NOT NULL,
            format TEXT NOT NULL,
            imported_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS _universal_iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_type TEXT NOT NULL,
            value TEXT NOT NULL UNIQUE,
            description TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            is_exclusion INTEGER NOT NULL DEFAULT 0,
            added_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS _ioc_matches (
            match_id INTEGER PRIMARY KEY AUTOINCREMENT,
            row_num INTEGER NOT NULL,
            ioc_id INTEGER,
            ioc_type TEXT NOT NULL,
            ioc_value TEXT NOT NULL,
            matched_field TEXT NOT NULL,
            matched_value TEXT NOT NULL,
            match_kind TEXT NOT NULL,
            is_suppressed INTEGER NOT NULL DEFAULT 0,
            timestamp_utc TEXT,
            source_file TEXT NOT NULL,
            event_summary TEXT,
            raw_evidence TEXT,
            created_at TEXT NOT NULL
        );",
    )?;
    Ok(())
}

fn record_failure(
    conn: &Connection,
    source_path: &str,
    record_num: i64,
    raw_payload: &str,
    error_message: &str,
) {
    let now = Utc::now().to_rfc3339();
    let _ = conn.execute(
        "INSERT INTO _parse_failures (source_path, record_num, raw_payload, error_message, occurred_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![source_path, record_num, raw_payload, error_message, now],
    );
}

pub fn flatten_json_value(prefix: &str, value: &Value, out: &mut HashMap<String, String>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten_json_value(&key, v, out);
            }
        }
        Value::Array(arr) => {
            if !prefix.is_empty() {
                out.insert(prefix.to_string(), serde_json::to_string(arr).unwrap_or_default());
            }
            // For compact arrays (<= 5 elements), also allow leaf indexing
            if arr.len() <= 5 {
                for (idx, item) in arr.iter().enumerate() {
                    let key = format!("{prefix}[{idx}]");
                    flatten_json_value(&key, item, out);
                }
            }
        }
        Value::String(s) => {
            out.insert(prefix.to_string(), s.clone());
        }
        Value::Number(n) => {
            out.insert(prefix.to_string(), n.to_string());
        }
        Value::Bool(b) => {
            out.insert(prefix.to_string(), b.to_string());
        }
        Value::Null => {
            out.insert(prefix.to_string(), String::new());
        }
    }
}

pub fn extract_normalized_fields(
    raw_fields: &HashMap<String, String>,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    let mut norm_time = None;
    let mut norm_ip = None;
    let mut norm_user = None;
    let mut norm_host = None;
    let mut norm_process = None;
    let mut norm_req_id = None;

    for (k, v) in raw_fields {
        let lk = k.to_ascii_lowercase();
        let val = v.trim();
        if val.is_empty() {
            continue;
        }

        if norm_time.is_none()
            && (lk.contains("time")
                || lk.contains("timestamp")
                || lk == "date"
                || lk.ends_with("_at")
                || lk.contains("utctime")
                || lk.contains("timegenerated"))
        {
            if let Ok(dt) = DateTime::parse_from_rfc3339(val) {
                norm_time = Some(dt.with_timezone(&Utc).to_rfc3339());
            } else if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(val, "%Y-%m-%d %H:%M:%S") {
                norm_time = Some(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc).to_rfc3339());
            } else {
                norm_time = Some(val.to_string());
            }
        }

        if norm_ip.is_none()
            && (lk == "ip"
                || lk.ends_with(".ip")
                || lk.ends_with("_ip")
                || lk.contains("clientip")
                || lk.contains("sourceip")
                || lk.contains("remoteip")
                || lk.contains("src_ip")
                || lk.contains("dst_ip")
                || lk.contains("destinationip")
                || lk.contains("ipaddress")
                || lk.contains("callerip")
                || lk.contains("ip_address"))
        {
            norm_ip = Some(val.to_string());
        }

        if norm_user.is_none()
            && (lk.contains("userprincipalname")
                || lk.contains("targetusername")
                || lk.contains("subjectusername")
                || lk.contains("accountname")
                || lk == "user"
                || lk == "username"
                || lk.ends_with(".user")
                || lk.ends_with(".username")
                || lk.contains("account")
                || (lk.contains("actor") && (lk.ends_with(".name") || lk.ends_with("_name") || lk == "actor"))
                || lk.contains("principalid")
                || lk.contains("aadprincipalid"))
        {
            norm_user = Some(val.to_string());
        }

        if norm_host.is_none()
            && (lk.contains("computer")
                || lk.contains("hostname")
                || lk == "host"
                || lk.ends_with(".host")
                || lk.ends_with("_host")
                || lk.contains("devicename")
                || lk.contains("workstation")
                || lk.contains("resourcename")
                || lk.contains("databasename")
                || lk.contains("collectionname"))
        {
            norm_host = Some(val.to_string());
        }

        if norm_process.is_none()
            && (lk.contains("commandline")
                || lk.contains("processname")
                || lk.contains("newprocessname")
                || lk.contains("image")
                || lk == "process"
                || lk.ends_with(".command")
                || lk.ends_with("_command")
                || lk.contains("operationname")
                || lk == "operation")
        {
            norm_process = Some(val.to_string());
        }

        if norm_req_id.is_none()
            && (lk.contains("correlationid")
                || lk.contains("activityid")
                || lk.contains("requestid")
                || lk.contains("sessionid")
                || lk.contains("requestresourceid"))
        {
            norm_req_id = Some(val.to_string());
        }
    }

    (
        norm_time,
        norm_ip,
        norm_user,
        norm_host,
        norm_process,
        norm_req_id,
    )
}

pub fn import_stream_into_db(
    source_path: &Path,
    db_path: &Path,
    format: UniversalFormat,
    mut on_progress: impl FnMut(u64, u64),
) -> Result<UniversalImportResult> {
    let source_str = source_path.to_string_lossy().to_string();

    let (mut discovered_columns, _sample_rows) = sample_records(source_path, format)?;

    if discovered_columns.is_empty() {
        discovered_columns.push("message".to_string());
    }

    let canonical_cols = [
        ("norm_time", "Event Time (UTC)"),
        ("norm_ip", "IP Address"),
        ("norm_user", "User / Identity"),
        ("norm_host", "Host / Device"),
        ("norm_process", "Process / Command"),
        ("norm_req_id", "Request / Correlation ID"),
        ("raw_evidence", "Original Evidence"),
    ];

    let mut all_headers = Vec::new();
    for (sql, _) in &canonical_cols {
        all_headers.push(sql.to_string());
    }
    for col in &discovered_columns {
        if !all_headers.contains(col) {
            all_headers.push(col.clone());
        }
    }

    // Safety: Cap SQL table columns to prevent SQLite column overflow (SQLITE_MAX_COLUMN)
    const MAX_TABLE_COLUMNS: usize = 350;
    if all_headers.len() > MAX_TABLE_COLUMNS {
        all_headers.truncate(MAX_TABLE_COLUMNS);
    }

    let columns = sanitize_headers(&all_headers);

    let mut conn = db::open(db_path)?;
    db::set_import_pragmas(&conn)?;
    db::create_schema(&conn, &columns)?;
    create_audit_tables_if_needed(&conn)?;

    let col_idents: Vec<String> = columns
        .iter()
        .map(|c| db::quote_ident(&c.sql_name))
        .collect();
    let placeholders: Vec<String> = (1..=columns.len() + 1).map(|i| format!("?{i}")).collect();
    let insert_sql = format!(
        "INSERT INTO rows (row_num, {}) VALUES ({})",
        col_idents.join(", "),
        placeholders.join(", ")
    );

    let mut row_count: i64 = 0;
    let mut failure_count: i64 = 0;

    let mut stream_reader = open_record_stream(source_path, format)?;
    let mut batch: Vec<(i64, HashMap<String, String>, String)> = Vec::with_capacity(BATCH_SIZE);
    let mut current_record_num: i64 = 0;

    while let Some(record_res) = stream_reader.next_record() {
        current_record_num += 1;
        match record_res {
            Ok((parsed_fields, raw_str)) => {
                row_count += 1;
                batch.push((row_count, parsed_fields, raw_str));
                if batch.len() >= BATCH_SIZE {
                    insert_batch(&mut conn, &insert_sql, &columns, &batch)?;
                    batch.clear();
                    on_progress(row_count as u64, 0);
                }
            }
            Err((err_msg, raw_payload)) => {
                failure_count += 1;
                record_failure(
                    &conn,
                    &source_str,
                    current_record_num,
                    &raw_payload,
                    &err_msg,
                );
            }
        }
    }

    if !batch.is_empty() {
        insert_batch(&mut conn, &insert_sql, &columns, &batch)?;
        batch.clear();
        on_progress(row_count as u64, row_count as u64);
    }

    let now = Utc::now().to_rfc3339();
    let format_name = format!("{format:?}");
    let _ = conn.execute(
        "INSERT OR REPLACE INTO _ingest_audit (source_path, total_records, parse_failures, columns_count, format, imported_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![source_str, row_count, failure_count, columns.len(), format_name, now],
    );

    db::restore_normal_pragmas(&conn)?;

    let warning = if failure_count > 0 {
        Some(format!(
            "Ingestion completed with {failure_count} parsing failures logged to audit table (0 discarded)."
        ))
    } else {
        None
    };

    Ok(UniversalImportResult {
        columns,
        row_count,
        failure_count,
        warning,
    })
}

fn insert_batch(
    conn: &mut Connection,
    insert_sql: &str,
    columns: &[ColumnMeta],
    batch: &[(i64, HashMap<String, String>, String)],
) -> Result<()> {
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare(insert_sql)?;
        for (row_num, fields, raw_str) in batch {
            let (norm_time, norm_ip, norm_user, norm_host, norm_process, norm_req_id) =
                extract_normalized_fields(fields);

            let mut values: Vec<Option<String>> = Vec::with_capacity(columns.len() + 1);
            values.push(Some(row_num.to_string()));

            for col in columns {
                match col.sql_name.as_str() {
                    "norm_time" => values.push(norm_time.clone()),
                    "norm_ip" => values.push(norm_ip.clone()),
                    "norm_user" => values.push(norm_user.clone()),
                    "norm_host" => values.push(norm_host.clone()),
                    "norm_process" => values.push(norm_process.clone()),
                    "norm_req_id" => values.push(norm_req_id.clone()),
                    "raw_evidence" => values.push(Some(raw_str.clone())),
                    other => {
                        let val = fields.get(other).cloned().or_else(|| {
                            fields
                                .iter()
                                .find(|(k, _)| k.eq_ignore_ascii_case(other))
                                .map(|(_, v)| v.clone())
                        });
                        values.push(val);
                    }
                }
            }

            let params = rusqlite::params_from_iter(values.iter().map(|v| match v {
                Some(s) => rusqlite::types::Value::Text(s.clone()),
                None => rusqlite::types::Value::Null,
            }));
            stmt.execute(params)?;
        }
    }
    tx.commit()?;
    Ok(())
}

trait RecordStream {
    fn next_record(&mut self) -> Option<Result<(HashMap<String, String>, String), (String, String)>>;
}

struct LineRecordStream<R: Read> {
    reader: BufReader<R>,
    format: UniversalFormat,
    line_buf: String,
}

impl<R: Read> LineRecordStream<R> {
    fn new(reader: R, format: UniversalFormat) -> Self {
        Self {
            reader: BufReader::new(reader),
            format,
            line_buf: String::new(),
        }
    }
}

impl<R: Read> RecordStream for LineRecordStream<R> {
    fn next_record(&mut self) -> Option<Result<(HashMap<String, String>, String), (String, String)>> {
        self.line_buf.clear();
        match self.reader.read_line(&mut self.line_buf) {
            Ok(0) => None,
            Ok(_) => {
                let raw = self.line_buf.trim();
                if raw.is_empty() {
                    return self.next_record();
                }

                match self.format {
                    UniversalFormat::JsonLines | UniversalFormat::CompressedJsonLines => {
                        match serde_json::from_str::<Value>(raw) {
                            Ok(val) => {
                                let mut fields = HashMap::new();
                                flatten_json_value("", &val, &mut fields);
                                Some(Ok((fields, raw.to_string())))
                            }
                            Err(e) => Some(Err((format!("JSONL parse error: {e}"), raw.to_string()))),
                        }
                    }
                    UniversalFormat::Syslog => {
                        let mut fields = HashMap::new();
                        parse_syslog_line(raw, &mut fields);
                        Some(Ok((fields, raw.to_string())))
                    }
                    _ => {
                        let mut fields = HashMap::new();
                        fields.insert("message".to_string(), raw.to_string());
                        Some(Ok((fields, raw.to_string())))
                    }
                }
            }
            Err(e) => Some(Err((format!("I/O read error: {e}"), String::new()))),
        }
    }
}

struct EvtxRecordStream {
    records: Box<dyn Iterator<Item = Result<(HashMap<String, String>, String), (String, String)>> + Send>,
}

impl EvtxRecordStream {
    fn new(path: &Path) -> Result<Self> {
        let mut parser = EvtxParser::from_path(path).context("opening EVTX file")?;
        let mut items = Vec::new();
        for record_res in parser.records_json_value() {
            match record_res {
                Ok(rec) => {
                    let mut fields = HashMap::new();
                    fields.insert("event_record_id".to_string(), rec.event_record_id.to_string());
                    fields.insert("timestamp".to_string(), rec.timestamp.to_rfc3339());
                    flatten_json_value("", &rec.data, &mut fields);
                    let raw = rec.data.to_string();
                    items.push(Ok((fields, raw)));
                }
                Err(e) => {
                    items.push(Err((format!("EVTX parse error: {e}"), String::new())));
                }
            }
        }
        Ok(Self {
            records: Box::new(items.into_iter()),
        })
    }
}

impl RecordStream for EvtxRecordStream {
    fn next_record(&mut self) -> Option<Result<(HashMap<String, String>, String), (String, String)>> {
        self.records.next()
    }
}

struct JsonArrayRecordStream {
    elements: Box<dyn Iterator<Item = Value> + Send>,
}

impl RecordStream for JsonArrayRecordStream {
    fn next_record(&mut self) -> Option<Result<(HashMap<String, String>, String), (String, String)>> {
        match self.elements.next() {
            Some(val) => {
                let raw = val.to_string();
                let mut fields = HashMap::new();
                flatten_json_value("", &val, &mut fields);
                Some(Ok((fields, raw)))
            }
            None => None,
        }
    }
}

fn open_record_stream(
    source_path: &Path,
    format: UniversalFormat,
) -> Result<Box<dyn RecordStream>> {
    match format {
        UniversalFormat::CompressedJsonLines => {
            let file = File::open(source_path)?;
            let gz = GzDecoder::new(file);
            Ok(Box::new(LineRecordStream::new(gz, format)))
        }
        UniversalFormat::JsonLines | UniversalFormat::Syslog => {
            let file = File::open(source_path)?;
            Ok(Box::new(LineRecordStream::new(file, format)))
        }
        UniversalFormat::Evtx => Ok(Box::new(EvtxRecordStream::new(source_path)?)),
        UniversalFormat::Json => {
            let file = File::open(source_path)?;
            let reader = BufReader::new(file);
            let root_val: Value = serde_json::from_reader(reader)?;
            let items: Vec<Value> = match root_val {
                Value::Array(arr) => arr,
                Value::Object(map) => {
                    let candidate_keys = [
                        "value", "records", "events", "data", "items", "logs",
                        "logentries", "entries", "rows", "results", "hits", "messages",
                    ];
                    let mut found_arr = None;
                    for (k, v) in &map {
                        let lk = k.to_ascii_lowercase();
                        if candidate_keys.contains(&lk.as_str()) {
                            if let Value::Array(arr) = v {
                                found_arr = Some(arr.clone());
                                break;
                            } else if let Value::Object(submap) = v {
                                for (_, sv) in submap {
                                    if let Value::Array(subarr) = sv {
                                        found_arr = Some(subarr.clone());
                                        break;
                                    }
                                }
                                if found_arr.is_some() {
                                    break;
                                }
                            }
                        }
                    }

                    if found_arr.is_none() {
                        for (_, v) in &map {
                            if let Value::Array(arr) = v {
                                if !arr.is_empty() && arr.iter().any(|item| item.is_object()) {
                                    found_arr = Some(arr.clone());
                                    break;
                                }
                            }
                        }
                    }

                    found_arr.unwrap_or_else(|| vec![Value::Object(map)])
                }
                other => vec![other],
            };
            Ok(Box::new(JsonArrayRecordStream {
                elements: Box::new(items.into_iter()),
            }))
        }
        _ => {
            let file = File::open(source_path)?;
            Ok(Box::new(LineRecordStream::new(file, format)))
        }
    }
}

fn sample_records(
    source_path: &Path,
    format: UniversalFormat,
) -> Result<(Vec<String>, Vec<HashMap<String, String>>)> {
    let mut columns_set = HashSet::new();
    let mut sample_rows = Vec::new();
    let mut stream = open_record_stream(source_path, format)?;

    let mut count = 0;
    while let Some(res) = stream.next_record() {
        if let Ok((fields, _)) = res {
            for k in fields.keys() {
                columns_set.insert(k.clone());
            }
            sample_rows.push(fields);
            count += 1;
            if count >= INITIAL_SCHEMA_SAMPLE_SIZE {
                break;
            }
        }
    }

    let mut sorted_cols: Vec<String> = columns_set.into_iter().collect();
    sorted_cols.sort();
    Ok((sorted_cols, sample_rows))
}

fn parse_syslog_line(line: &str, fields: &mut HashMap<String, String>) {
    fields.insert("raw_line".to_string(), line.to_string());

    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 4 {
        let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
        if months.contains(&parts[0]) && parts[2].contains(':') {
            fields.insert("timestamp".to_string(), format!("{} {} {}", parts[0], parts[1], parts[2]));
            fields.insert("hostname".to_string(), parts[3].to_string());
            let msg = parts[4..].join(" ");
            fields.insert("message".to_string(), msg);
            return;
        }

        if parts[0].contains('T') || parts[0].contains('-') {
            fields.insert("timestamp".to_string(), parts[0].to_string());
            fields.insert("hostname".to_string(), parts[1].to_string());
            fields.insert("message".to_string(), parts[2..].join(" "));
            return;
        }
    }

    fields.insert("message".to_string(), line.to_string());
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LogAnalyticsSummary {
    pub total_records: i64,
    pub parse_failures: i64,
    pub min_time: Option<String>,
    pub max_time: Option<String>,
    pub total_request_charge_ru: Option<f64>,
    pub max_request_charge_ru: Option<f64>,
    pub total_duration_ms: Option<f64>,
    pub max_duration_ms: Option<f64>,
    pub top_ips: Vec<(String, i64)>,
    pub top_operations: Vec<(String, i64)>,
    pub status_codes: Vec<(String, i64)>,
    pub hourly_distribution: Vec<(String, i64)>,
    pub top_users: Vec<(String, i64)>,
}

pub fn compute_log_analytics_summary(conn: &Connection) -> Result<LogAnalyticsSummary> {
    let total_records: i64 = conn
        .query_row("SELECT COUNT(*) FROM rows", [], |r| r.get(0))
        .unwrap_or(0);

    let parse_failures: i64 = conn
        .query_row("SELECT COUNT(*) FROM _parse_failures", [], |r| r.get(0))
        .unwrap_or(0);

    let (min_time, max_time) = conn
        .query_row(
            "SELECT MIN(norm_time), MAX(norm_time) FROM rows WHERE norm_time IS NOT NULL AND norm_time != ''",
            [],
            |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, Option<String>>(1)?)),
        )
        .unwrap_or((None, None));

    let mut table_cols: Vec<String> = Vec::new();
    let mut pragma_stmt = conn.prepare("PRAGMA table_info(rows)")?;
    let rows = pragma_stmt.query_map([], |r| r.get::<_, String>(1))?;
    for c in rows.flatten() {
        table_cols.push(c.to_ascii_lowercase());
    }

    let mut total_ru = None;
    let mut max_ru = None;
    for col in &table_cols {
        if col.contains("requestcharge") || col == "ru" {
            let sql = format!("SELECT SUM(CAST(\"{col}\" AS REAL)), MAX(CAST(\"{col}\" AS REAL)) FROM rows WHERE \"{col}\" IS NOT NULL");
            if let Ok(res) = conn.query_row(&sql, [], |r| Ok((r.get::<_, Option<f64>>(0)?, r.get::<_, Option<f64>>(1)?))) {
                total_ru = res.0;
                max_ru = res.1;
                break;
            }
        }
    }

    let mut total_duration = None;
    let mut max_duration = None;
    for col in &table_cols {
        if col == "duration" || col.ends_with("_duration") {
            let sql = format!("SELECT SUM(CAST(\"{col}\" AS REAL)), MAX(CAST(\"{col}\" AS REAL)) FROM rows WHERE \"{col}\" IS NOT NULL");
            if let Ok(res) = conn.query_row(&sql, [], |r| Ok((r.get::<_, Option<f64>>(0)?, r.get::<_, Option<f64>>(1)?))) {
                total_duration = res.0;
                max_duration = res.1;
                break;
            }
        }
    }

    let mut top_ips = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT norm_ip, COUNT(*) FROM rows WHERE norm_ip IS NOT NULL AND norm_ip != '' GROUP BY norm_ip ORDER BY COUNT(*) DESC, norm_ip ASC LIMIT 20",
    ) {
        if let Ok(rows) = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))) {
            for item in rows.flatten() {
                top_ips.push(item);
            }
        }
    }

    let mut top_operations = Vec::new();
    let op_col = table_cols.iter().find(|c| c.contains("operationname") || *c == "operation").cloned();
    let op_sql = if let Some(ref col) = op_col {
        format!("SELECT \"{col}\", COUNT(*) FROM rows WHERE \"{col}\" IS NOT NULL AND \"{col}\" != '' GROUP BY \"{col}\" ORDER BY COUNT(*) DESC LIMIT 20")
    } else {
        "SELECT norm_process, COUNT(*) FROM rows WHERE norm_process IS NOT NULL AND norm_process != '' GROUP BY norm_process ORDER BY COUNT(*) DESC LIMIT 20".to_string()
    };
    if let Ok(mut stmt) = conn.prepare(&op_sql) {
        if let Ok(rows) = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))) {
            for item in rows.flatten() {
                top_operations.push(item);
            }
        }
    }

    let mut status_codes = Vec::new();
    if let Some(sc_col) = table_cols.iter().find(|c| c.contains("statuscode") || *c == "status").cloned() {
        let sc_sql = format!("SELECT \"{sc_col}\", COUNT(*) FROM rows WHERE \"{sc_col}\" IS NOT NULL AND \"{sc_col}\" != '' GROUP BY \"{sc_col}\" ORDER BY COUNT(*) DESC LIMIT 20");
        if let Ok(mut stmt) = conn.prepare(&sc_sql) {
            if let Ok(rows) = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))) {
                for item in rows.flatten() {
                    status_codes.push(item);
                }
            }
        }
    }

    let mut hourly_distribution = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT substr(norm_time, 1, 13) AS hr, COUNT(*) FROM rows WHERE norm_time IS NOT NULL AND length(norm_time) >= 13 GROUP BY hr ORDER BY hr ASC LIMIT 100",
    ) {
        if let Ok(rows) = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))) {
            for item in rows.flatten() {
                hourly_distribution.push(item);
            }
        }
    }

    let mut top_users = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT norm_user, COUNT(*) FROM rows WHERE norm_user IS NOT NULL AND norm_user != '' GROUP BY norm_user ORDER BY COUNT(*) DESC LIMIT 20",
    ) {
        if let Ok(rows) = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))) {
            for item in rows.flatten() {
                top_users.push(item);
            }
        }
    }

    Ok(LogAnalyticsSummary {
        total_records,
        parse_failures,
        min_time,
        max_time,
        total_request_charge_ru: total_ru,
        max_request_charge_ru: max_ru,
        total_duration_ms: total_duration,
        max_duration_ms: max_duration,
        top_ips,
        top_operations,
        status_codes,
        hourly_distribution,
        top_users,
    })
}
