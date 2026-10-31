//! Regression tests for file/folder ingestion bugs:
//! nested JSON fields importing as NULL, empty full-text index for non-CSV evidence,
//! `.json` files that are really JSON-lines, BOMs, TSV, non-UTF-8 bytes, plain-text `.gz`,
//! extensionless/rotated syslog files and lazy EVTX streaming.

use flate2::write::GzEncoder;
use flate2::Compression;
use log_parser_lib::commands::is_forensic_evidence_file;
use log_parser_lib::db;
use log_parser_lib::tabular_import;
use log_parser_lib::universal_import::{detect_format, UniversalFormat};
use std::io::Write;
use std::path::{Path, PathBuf};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "logparser_ingest_{name}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn import(path: &Path) -> (rusqlite::Connection, tabular_import::ImportResult) {
    let sheets = tabular_import::list_sheet_names(path).expect("list sheets");
    let db_path = path.with_extension("test.sqlite3");
    let _ = std::fs::remove_file(&db_path);
    let result = tabular_import::import_into_db(path, &sheets[0], &db_path, |_, _| {})
        .unwrap_or_else(|e| panic!("import of {} failed: {e:#}", path.display()));
    (db::open(&db_path).unwrap(), result)
}

fn sql_name_for(result: &tabular_import::ImportResult, original: &str) -> String {
    result
        .columns
        .iter()
        .find(|c| c.original_name == original)
        .unwrap_or_else(|| panic!("column {original} missing"))
        .sql_name
        .clone()
}

fn non_null_count(conn: &rusqlite::Connection, sql_name: &str) -> i64 {
    conn.query_row(
        &format!("SELECT COUNT(*) FROM rows WHERE {} IS NOT NULL AND {} != ''", db::quote_ident(sql_name), db::quote_ident(sql_name)),
        [],
        |r| r.get(0),
    )
    .unwrap()
}

fn fts_hits(conn: &rusqlite::Connection, term: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM rows_fts WHERE rows_fts MATCH ?1",
        [term],
        |r| r.get(0),
    )
    .unwrap()
}

#[test]
fn nested_json_fields_are_populated_and_full_text_indexed() {
    let dir = temp_dir("nested");
    let path = dir.join("signin.jsonl");
    std::fs::write(
        &path,
        concat!(
            r#"{"@timestamp":"2026-10-01T10:00:00Z","properties":{"userAgent":"curl/8.0","ipAddress":"203.0.113.9"},"process.command_line":"mimikatz.exe sekurlsa"}"#,
            "\n",
            r#"{"@timestamp":"2026-10-01T10:01:00Z","properties":{"userAgent":"Mozilla/5.0","ipAddress":"198.51.100.4"},"process.command_line":"whoami"}"#,
            "\n"
        ),
    )
    .unwrap();

    let (conn, result) = import(&path);
    assert_eq!(result.row_count, 2);
    for original in ["properties.userAgent", "properties.ipAddress", "@timestamp", "process.command_line"] {
        let sql = sql_name_for(&result, original);
        assert_eq!(non_null_count(&conn, &sql), 2, "column {original} ({sql}) imported as NULL");
    }
    assert_eq!(fts_hits(&conn, "mimikatz"), 1, "FTS index must be populated for JSON evidence");
}

#[test]
fn json_file_containing_json_lines_falls_back_instead_of_failing() {
    let dir = temp_dir("jsonl_as_json");
    let path = dir.join("export.json");
    std::fs::write(&path, "{\"a\":1,\"user\":\"alice\"}\n{\"a\":2,\"user\":\"bob\"}\n").unwrap();
    assert_eq!(detect_format(&path).unwrap(), UniversalFormat::Json);
    let (conn, result) = import(&path);
    assert_eq!(result.row_count, 2);
    assert_eq!(non_null_count(&conn, &sql_name_for(&result, "user")), 2);
}

#[test]
fn json_array_with_utf8_bom_imports() {
    let dir = temp_dir("bom");
    let path = dir.join("bom.json");
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(br#"{"value":[{"op":"Login"},{"op":"Logout"},{"op":"Delete"}]}"#);
    std::fs::write(&path, bytes).unwrap();
    let (_conn, result) = import(&path);
    assert_eq!(result.row_count, 3);
}

#[test]
fn log_file_with_json_lines_is_detected_as_jsonl() {
    let dir = temp_dir("log_json");
    let path = dir.join("app.log");
    std::fs::write(&path, "\n{\"level\":\"warn\",\"msg\":\"disk\"}\n").unwrap();
    assert_eq!(detect_format(&path).unwrap(), UniversalFormat::JsonLines);
    let (conn, result) = import(&path);
    assert_eq!(non_null_count(&conn, &sql_name_for(&result, "msg")), 1);
}

#[test]
fn tsv_is_split_into_columns() {
    let dir = temp_dir("tsv");
    let path = dir.join("events.tsv");
    std::fs::write(&path, "TimeCreated\tEventID\tAccount\n2026-10-01 10:00:00\t4624\talice\n").unwrap();
    let (conn, result) = import(&path);
    assert_eq!(result.row_count, 1);
    assert_eq!(result.columns.len(), 3, "TSV must not collapse into a single message column");
    assert_eq!(non_null_count(&conn, &sql_name_for(&result, "Account")), 1);
}

#[test]
fn csv_with_non_utf8_bytes_imports_lossily() {
    let dir = temp_dir("latin1");
    let path = dir.join("latin1.csv");
    // 0xE9 = 'é' in Windows-1252, invalid as UTF-8.
    std::fs::write(&path, b"User,Action\nren\xE9,login\nbob,logout\n").unwrap();
    let (_conn, result) = import(&path);
    assert_eq!(result.row_count, 2);
}

#[test]
fn plain_text_gzip_is_not_parsed_as_jsonl() {
    let dir = temp_dir("gz_text");
    let path = dir.join("auth.log.2.gz");
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(b"Oct  1 10:00:00 web01 sshd[1]: Failed password for root from 203.0.113.9\nOct  1 10:00:05 web01 sshd[1]: Accepted password for bob\n").unwrap();
    std::fs::write(&path, enc.finish().unwrap()).unwrap();

    assert_eq!(detect_format(&path).unwrap(), UniversalFormat::CompressedSyslog);
    let (conn, result) = import(&path);
    assert_eq!(result.row_count, 2);
    assert!(result.warning.is_none(), "unexpected warning: {:?}", result.warning);
    assert_eq!(fts_hits(&conn, "\"203.0.113.9\""), 1);
}

#[test]
fn multi_member_gzip_reads_all_members() {
    let dir = temp_dir("gz_multi");
    let path = dir.join("events.jsonl.gz");
    let mut bytes = Vec::new();
    for line in [b"{\"n\":1}\n".as_slice(), b"{\"n\":2}\n".as_slice()] {
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(line).unwrap();
        bytes.extend(enc.finish().unwrap());
    }
    std::fs::write(&path, bytes).unwrap();
    let (_conn, result) = import(&path);
    assert_eq!(result.row_count, 2);
}

#[test]
fn extensionless_and_rotated_syslog_are_supported() {
    let dir = temp_dir("syslog");
    let messages = dir.join("messages");
    std::fs::write(&messages, "Oct  1 10:00:00 host1 kernel: boot\n").unwrap();
    assert_eq!(detect_format(&messages).unwrap(), UniversalFormat::Syslog);
    let (_conn, result) = import(&messages);
    assert_eq!(result.row_count, 1);

    let rotated = dir.join("auth.log.1");
    std::fs::write(&rotated, "Oct  1 10:00:00 host1 sshd: hi\n").unwrap();
    assert_eq!(detect_format(&rotated).unwrap(), UniversalFormat::Syslog);

    assert!(is_forensic_evidence_file("auth.log.1"));
    assert!(is_forensic_evidence_file("syslog.3"));
    assert!(!is_forensic_evidence_file("library.so.1"));
}

#[test]
fn late_appearing_fields_are_reported_not_silently_dropped() {
    let dir = temp_dir("late_fields");
    let path = dir.join("late.jsonl");
    let mut content = String::new();
    for i in 0..10_050 {
        if i == 10_040 {
            content.push_str("{\"i\":1,\"surprise_field\":\"x\"}\n");
        } else {
            content.push_str(&format!("{{\"i\":{i}}}\n"));
        }
    }
    std::fs::write(&path, content).unwrap();
    let (_conn, result) = import(&path);
    assert_eq!(result.row_count, 10_050);
    let warning = result.warning.expect("expected a late-field warning");
    assert!(warning.contains("surprise_field"), "{warning}");
}

#[test]
fn file_target_auto_caches_and_extracts_unified_events_with_or_without_indicators() {
    let dir = temp_dir("auto_cache_unified");
    let path1 = dir.join("fw.jsonl");
    let path2 = dir.join("auth.csv");
    std::fs::write(
        &path1,
        "{\"timestamp\":\"2026-10-02T13:40:00Z\",\"user\":\"alice\",\"src_ip\":\"198.51.100.77\",\"action\":\"ALLOW\"}\n",
    )
    .unwrap();
    std::fs::write(
        &path2,
        "timestamp,user,client_ip,action\n2026-10-02T13:41:00Z,alice,198.51.100.77,LOGIN_FAIL\n",
    )
    .unwrap();

    let targets = vec![
        log_parser_lib::commands::FileTarget {
            path: path1.to_string_lossy().to_string(),
            sheet: None,
            cache_db_path: None,
        },
        log_parser_lib::commands::FileTarget {
            path: path2.to_string_lossy().to_string(),
            sheet: None,
            cache_db_path: None,
        },
    ];

    // 1. Empty indicators (time-window-only / full master timeline across un-cached files)
    let all_events =
        log_parser_lib::intel::analyst::extract_unified_events_for_indicators(&targets, &[]);
    assert_eq!(all_events.len(), 2);

    // 2. Specific indicator across both files
    let indicator_events = log_parser_lib::intel::analyst::extract_unified_events_for_indicators(
        &targets,
        &["198.51.100.77".to_string()],
    );
    assert_eq!(indicator_events.len(), 2);
}
