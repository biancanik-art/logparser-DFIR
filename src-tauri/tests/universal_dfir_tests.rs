use log_parser_lib::db;
use log_parser_lib::intel::universal_ioc::{
    auto_detect_ioc_type, execute_universal_ioc_scan, insert_bulk_iocs, CidrMatcher,
    UniversalIocType,
};
use log_parser_lib::universal_export::export_forensic_workbook;
use log_parser_lib::universal_import::{
    compute_log_analytics_summary, detect_format, extract_normalized_fields, flatten_json_value,
    import_stream_into_db, UniversalFormat,
};
use serde_json::json;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;

#[test]
fn test_universal_ioc_auto_detection() {
    assert_eq!(auto_detect_ioc_type("192.168.1.1"), UniversalIocType::Ip);
    assert_eq!(auto_detect_ioc_type("2001:db8::1"), UniversalIocType::Ip);
    assert_eq!(auto_detect_ioc_type("10.0.0.0/8"), UniversalIocType::Cidr);
    assert_eq!(auto_detect_ioc_type("fe80::/64"), UniversalIocType::Cidr);
    assert_eq!(auto_detect_ioc_type("evil-c2.darknet.org"), UniversalIocType::Domain);
    assert_eq!(auto_detect_ioc_type("https://phishing.site/login.php?id=9"), UniversalIocType::Url);
    assert_eq!(auto_detect_ioc_type("badactor@threat.com"), UniversalIocType::Email);
    assert_eq!(auto_detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e"), UniversalIocType::Hash);
    assert_eq!(
        auto_detect_ioc_type("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        UniversalIocType::Hash
    );
    assert_eq!(
        auto_detect_ioc_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        UniversalIocType::Hash
    );
    assert_eq!(
        auto_detect_ioc_type("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        UniversalIocType::RegistryKey
    );
    assert_eq!(auto_detect_ioc_type("C:\\Windows\\System32\\cmd.exe"), UniversalIocType::Path);
    assert_eq!(auto_detect_ioc_type("mimikatz.exe"), UniversalIocType::ProcessName);
    assert_eq!(auto_detect_ioc_type("evil_document.docx"), UniversalIocType::Filename);
    assert_eq!(
        auto_detect_ioc_type("6ba7b810-9dad-11d1-80b4-00c04fd430c8"),
        UniversalIocType::Guid
    );
    assert_eq!(auto_detect_ioc_type("regex:^admin_.*"), UniversalIocType::Regex);
    assert_eq!(auto_detect_ioc_type("powershell.exe -enc AAAA"), UniversalIocType::CommandLine);
}

#[test]
fn test_cidr_matching_logic() {
    let cidr = CidrMatcher::parse("192.168.0.0/16").expect("valid cidr");
    assert!(cidr.contains_str("192.168.1.50"));
    assert!(cidr.contains_str("192.168.254.1"));
    assert!(!cidr.contains_str("192.169.0.1"));
    assert!(!cidr.contains_str("10.0.0.1"));
}

#[test]
fn test_json_leaf_flattening() {
    let raw = json!({
        "time": "2026-10-23T20:00:00Z",
        "actor": {
            "name": "attacker_user",
            "ip": "198.51.100.42"
        },
        "details": {
            "command": "powershell.exe -enc AAAA",
            "flags": [1, 2]
        }
    });

    let mut out = HashMap::new();
    flatten_json_value("", &raw, &mut out);

    assert_eq!(out.get("time").unwrap(), "2026-10-23T20:00:00Z");
    assert_eq!(out.get("actor.name").unwrap(), "attacker_user");
    assert_eq!(out.get("actor.ip").unwrap(), "198.51.100.42");
    assert_eq!(out.get("details.command").unwrap(), "powershell.exe -enc AAAA");
    assert_eq!(out.get("details.flags[0]").unwrap(), "1");

    let (norm_time, norm_ip, norm_user, _, norm_process, _) = extract_normalized_fields(&out);
    assert!(norm_time.is_some());
    assert_eq!(norm_ip.as_deref(), Some("198.51.100.42"));
    assert_eq!(norm_user.as_deref(), Some("attacker_user"));
    assert_eq!(norm_process.as_deref(), Some("powershell.exe -enc AAAA"));
}

#[test]
fn test_cosmos_jsonl_analytics_and_completeness() {
    let temp_dir = std::env::temp_dir().join(format!("dfir_cosmos_test_{}", std::process::id()));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let jsonl_path = temp_dir.join("cosmos_audit.jsonl");
    {
        let mut f = File::create(&jsonl_path).unwrap();
        // 5 valid Cosmos DB JSONL records
        writeln!(
            f,
            r#"{{"time":"2026-10-23T10:00:00Z","activityId":"act-001","clientIpAddress":"203.0.113.10","operationName":"Read","databaseName":"AuditDb","collectionName":"EventsA","statusCode":200,"requestCharge":3.5,"duration":12.4,"userAgent":"AzureCosmos/3.0"}}"#
        ).unwrap();
        writeln!(
            f,
            r#"{{"time":"2026-10-23T10:15:00Z","activityId":"act-002","clientIpAddress":"203.0.113.10","operationName":"Create","databaseName":"AuditDb","collectionName":"EventsA","statusCode":201,"requestCharge":14.2,"duration":45.1,"userAgent":"AzureCosmos/3.0"}}"#
        ).unwrap();
        writeln!(
            f,
            r#"{{"time":"2026-10-23T11:00:00Z","activityId":"act-003","clientIpAddress":"198.51.100.88","operationName":"Query","databaseName":"AuditDb","collectionName":"EventsB","statusCode":403,"requestCharge":2.1,"duration":8.0,"userAgent":"curl/7.68.0"}}"#
        ).unwrap();
        writeln!(
            f,
            r#"{{"time":"2026-10-23T11:30:00Z","activityId":"act-004","clientIpAddress":"198.51.100.88","operationName":"Query","databaseName":"AuditDb","collectionName":"EventsB","statusCode":200,"requestCharge":8.0,"duration":19.2,"userAgent":"curl/7.68.0"}}"#
        ).unwrap();
        writeln!(
            f,
            r#"{{"time":"2026-10-23T12:00:00Z","activityId":"act-005","clientIpAddress":"192.0.2.1","operationName":"Delete","databaseName":"AuditDb","collectionName":"EventsC","statusCode":204,"requestCharge":9.5,"duration":22.0,"userAgent":"PostmanRuntime/7.28"}}"#
        ).unwrap();
        // 1 deliberately corrupted line to verify non-silent drop
        writeln!(f, r#"{{"time": "2026-10-23T12:05:00Z", INVALID_JSON_LINE_HERE}}"#).unwrap();
    }

    let db_path = temp_dir.join("cosmos.sqlite3");
    let ingest_res = import_stream_into_db(
        &jsonl_path,
        &db_path,
        UniversalFormat::JsonLines,
        |_, _| {},
    )
    .expect("ingestion succeeds");

    assert_eq!(ingest_res.row_count, 5);
    assert_eq!(ingest_res.failure_count, 1);

    let conn = db::open(&db_path).unwrap();

    // Verify _parse_failures has the exact line recorded
    let raw_payload: String = conn
        .query_row(
            "SELECT raw_payload FROM _parse_failures WHERE record_num = 6",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(raw_payload.contains("INVALID_JSON_LINE_HERE"));

    // Verify analytics summary
    let summary = compute_log_analytics_summary(&conn).expect("analytics succeeds");
    assert_eq!(summary.total_records, 5);
    assert_eq!(summary.parse_failures, 1);
    assert_eq!(summary.min_time.as_deref(), Some("2026-10-23T10:00:00+00:00"));
    assert_eq!(summary.max_time.as_deref(), Some("2026-10-23T12:00:00+00:00"));

    // RU charge sum: 3.5 + 14.2 + 2.1 + 8.0 + 9.5 = 37.3
    assert!((summary.total_request_charge_ru.unwrap() - 37.3).abs() < 0.001);
    assert_eq!(summary.max_request_charge_ru.unwrap(), 14.2);

    // Verify Top IPs
    assert_eq!(summary.top_ips.len(), 3);
    assert!(summary.top_ips.iter().any(|(ip, count)| ip == "203.0.113.10" && *count == 2));
    assert!(summary.top_ips.iter().any(|(ip, count)| ip == "198.51.100.88" && *count == 2));

    // Verify status codes
    assert!(summary.status_codes.iter().any(|(sc, count)| sc == "200" && *count == 2));
    assert!(summary.status_codes.iter().any(|(sc, count)| sc == "403" && *count == 1));

    // Verify hourly distribution
    assert_eq!(summary.hourly_distribution.len(), 3);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_universal_e2e_flow() {
    let temp_dir = std::env::temp_dir().join(format!("dfir_test_{}", std::process::id()));
    std::fs::create_dir_all(&temp_dir).unwrap();

    // 1. Create synthetic JSONL log file with heterogeneous events
    let jsonl_path = temp_dir.join("test_evidence.jsonl");
    {
        let mut f = File::create(&jsonl_path).unwrap();
        // Record 1: Cloud Auth event
        writeln!(
            f,
            r#"{{"time":"2026-10-23T20:00:00Z","client_ip":"198.51.100.55","user":"admin@example.org","action":"Sign-in","status":"SUCCESS"}}"#
        )
        .unwrap();
        // Record 2: Windows Process Creation event
        writeln!(
            f,
            r#"{{"time":"2026-10-23T20:05:00Z","host":"HOST-01","process":"C:\\Windows\\System32\\powershell.exe -enc AAAA","user":"domain\\user"}}"#
        )
        .unwrap();
        // Record 3: Firewall flow event
        writeln!(
            f,
            r#"{{"timestamp":"2026-10-23T21:10:00Z","src_ip":"10.240.10.88","dst_ip":"198.51.100.55","action":"ACCEPT"}}"#
        )
        .unwrap();
        // Record 4: Deliberately malformed JSON line to test non-silent failure recording
        writeln!(f, r#"{{"corrupt": true, INVALID_JSON_PAYLOAD"#).unwrap();
    }

    assert_eq!(detect_format(&jsonl_path).unwrap(), UniversalFormat::JsonLines);

    // 2. Ingest into disk-backed SQLite database
    let db_path = temp_dir.join("cache.sqlite3");
    let ingest_res = import_stream_into_db(
        &jsonl_path,
        &db_path,
        UniversalFormat::JsonLines,
        |_, _| {},
    )
    .expect("ingestion succeeds");

    assert_eq!(ingest_res.row_count, 3);
    assert_eq!(ingest_res.failure_count, 1); // Never silently dropped!

    // Verify failures table
    let mut conn = db::open(&db_path).unwrap();
    let failures_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM _parse_failures", [], |r| r.get(0))
        .unwrap();
    assert_eq!(failures_count, 1);

    // 3. Add IOCs via universal input (paste & typed)
    let paste_input = "198.51.100.55\n10.0.0.0/8\npowershell.exe\nregex:.*-enc\\s+.*";
    let (added, skipped) =
        insert_bulk_iocs(&mut conn, paste_input, Some("Test Threat IOCs")).unwrap();
    assert_eq!(added, 4);
    assert_eq!(skipped, 0);

    // 4. Run Universal IOC Scan across all columns & nested JSON fields
    let scan_summary =
        execute_universal_ioc_scan(&mut conn, |_, _| {}).expect("scan succeeds");

    assert_eq!(scan_summary.total_rows_scanned, 3);
    assert!(scan_summary.total_matches >= 3);
    assert_eq!(scan_summary.unique_matched_rows, 3);
    assert_eq!(scan_summary.parse_failures_count, 1);

    // Verify multi-pivot correlation: 198.51.100.55 appeared in both Cloud Auth and Firewall logs!
    let ip_pivot = scan_summary
        .correlated_pivots
        .iter()
        .find(|p| p.pivot_value == "198.51.100.55");
    assert!(ip_pivot.is_some(), "IP 198.51.100.55 was correlated across multiple log types");

    // 5. Export to 4-sheet Forensic Reporting Workbook
    let export_xlsx = temp_dir.join("DFIR_Master_Timeline.xlsx");
    let export_res = export_forensic_workbook(&conn, &export_xlsx, "Forensic Analyst")
        .expect("export succeeds");

    assert!(export_res.total_exported_records >= 3);
    assert!(export_xlsx.exists());
    assert!(temp_dir.join("DFIR_Master_Timeline.csv").exists());
    assert!(temp_dir.join("DFIR_Master_Timeline_PARSE_FAILURES.csv").exists());

    // Cleanup
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_large_scale_jsonl_and_compressed_gz_stress() {
    use calamine::{open_workbook, Reader, Xlsx};
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::BufWriter;

    let temp_dir = std::env::temp_dir().join(format!("dfir_stress_{}", std::process::id()));
    std::fs::create_dir_all(&temp_dir).unwrap();

    // 1. Generate 5,000 JSONL lines with 20 intentional corrupted lines
    let jsonl_path = temp_dir.join("large_cloud_audit.jsonl");
    let total_generated = 5000;
    let corrupted_count = 20;
    {
        let file = File::create(&jsonl_path).unwrap();
        let mut writer = BufWriter::new(file);

        for i in 1..=total_generated {
            if i % 250 == 0 {
                // Intentionally corrupted line
                writeln!(writer, r#"{{"bad_record_id": {i}, "corrupt": true, UNCLOSED_JSON"#).unwrap();
            } else {
                let hour = (i % 24) as u8;
                let ip_octet = (i % 250) as u8;
                let status = if i % 10 == 0 { 403 } else if i % 25 == 0 { 500 } else { 200 };
                let ru = ((i % 15) as f64) * 1.5 + 1.0;
                let duration = (i % 120) as f64;
                writeln!(
                    writer,
                    r#"{{"time":"2026-10-23T{:02}:15:00Z","activityId":"act-{:05}","clientIpAddress":"198.51.100.{}","operationName":"DataQuery","databaseName":"AuditDb","collectionName":"Events","statusCode":{},"requestCharge":{},"duration":{},"userAgent":"AppClient/1.0"}}"#,
                    hour, i, ip_octet, status, ru, duration
                ).unwrap();
            }
        }
        writer.flush().unwrap();
    }

    // 2. Generate 1,000 compressed JSONL.gz records
    let gz_path = temp_dir.join("streamed_events.jsonl.gz");
    {
        let file = File::create(&gz_path).unwrap();
        let gz = GzEncoder::new(file, Compression::default());
        let mut writer = BufWriter::new(gz);
        for i in 1..=1000 {
            writeln!(
                writer,
                r#"{{"time":"2026-10-23T14:{:02}:00Z","event_id":{},"client_ip":"203.0.113.{}","user":"analyst@example.org","action":"ExportReport"}}"#,
                i % 60, i, i % 200
            ).unwrap();
        }
        writer.flush().unwrap();
    }

    assert_eq!(detect_format(&jsonl_path).unwrap(), UniversalFormat::JsonLines);
    assert_eq!(detect_format(&gz_path).unwrap(), UniversalFormat::CompressedJsonLines);

    // 3. Ingest large JSONL into disk-backed SQLite
    let db_path = temp_dir.join("stress.sqlite3");
    let t0 = std::time::Instant::now();
    let ingest_res = import_stream_into_db(
        &jsonl_path,
        &db_path,
        UniversalFormat::JsonLines,
        |_, _| {},
    )
    .expect("ingest large JSONL succeeds");
    let ingest_duration = t0.elapsed();
    println!("Ingested {} records in {:?}", ingest_res.row_count, ingest_duration);

    let expected_valid = total_generated - corrupted_count;
    assert_eq!(ingest_res.row_count, expected_valid);
    assert_eq!(ingest_res.failure_count, corrupted_count);

    let mut conn = db::open(&db_path).unwrap();

    // Verify mathematical completeness invariant: total = valid + failures
    let failures_in_db: i64 = conn
        .query_row("SELECT COUNT(*) FROM _parse_failures", [], |r| r.get(0))
        .unwrap();
    assert_eq!(failures_in_db, corrupted_count);

    // 4. Ingest compressed GZ directly
    let db_gz_path = temp_dir.join("gz_test.sqlite3");
    let gz_res = import_stream_into_db(
        &gz_path,
        &db_gz_path,
        UniversalFormat::CompressedJsonLines,
        |_, _| {},
    )
    .expect("ingest GZ succeeds");
    assert_eq!(gz_res.row_count, 1000);
    assert_eq!(gz_res.failure_count, 0);

    // 5. Test Bulk IOC Input with 10 diverse indicators
    let ioc_payload = "198.51.100.0/24\n198.51.100.42\nDataQuery\nAuditDb\nregex:^act-000[0-9]{2}$\n203.0.113.50";
    let (added, _) = insert_bulk_iocs(&mut conn, ioc_payload, Some("Stress IOC Set")).unwrap();
    assert_eq!(added, 6);

    // 6. Benchmark Universal IOC Scan
    let t_scan = std::time::Instant::now();
    let scan_res = execute_universal_ioc_scan(&mut conn, |_, _| {}).expect("scan succeeds");
    let scan_duration = t_scan.elapsed();
    println!("Scanned {} rows against IOCs in {:?}", scan_res.total_rows_scanned, scan_duration);

    assert_eq!(scan_res.total_rows_scanned, expected_valid);
    assert!(scan_res.total_matches > 0);
    assert!(scan_duration.as_secs() < 5, "Scan must complete in under 5 seconds");

    // 7. Test Analytics Summary
    let summary = compute_log_analytics_summary(&conn).expect("analytics succeeds");
    assert_eq!(summary.total_records, expected_valid);
    assert_eq!(summary.parse_failures, corrupted_count);
    assert!(summary.total_request_charge_ru.unwrap() > 0.0);
    assert!(!summary.top_ips.is_empty());
    assert!(!summary.status_codes.is_empty());
    assert!(!summary.hourly_distribution.is_empty());

    // 8. Export to 5-Sheet Excel Workbook & Verify via Calamine (Master Timeline Alignment)
    let workbook_path = temp_dir.join("Stress_Forensic_Report.xlsx");
    let export_res = export_forensic_workbook(&conn, &workbook_path, "Forensic Examiner")
        .expect("workbook export succeeds");
    assert!(export_res.total_exported_records > 0);

    let mut xl: Xlsx<_> = open_workbook(&workbook_path).expect("open exported workbook");
    let sheet_names = xl.sheet_names();
    assert!(sheet_names.contains(&"MASTER TIMELINE".to_string()));
    assert!(sheet_names.contains(&"IOC".to_string()));
    assert!(sheet_names.contains(&"INVENTORY".to_string()));
    assert!(sheet_names.contains(&"SUSPICIOUS ACCOUNTS".to_string()));
    assert!(sheet_names.contains(&"List".to_string()));

    let master_range = xl.worksheet_range("MASTER TIMELINE").expect("read MASTER TIMELINE");
    assert!(master_range.height() > 1, "Must have header and data rows");
    assert_eq!(master_range.get((0, 0)).unwrap().to_string(), "Input Date");
    assert_eq!(master_range.get((0, 1)).unwrap().to_string(), "Analyst");
    assert_eq!(master_range.get((0, 2)).unwrap().to_string(), "Date/Time (UTC)");
    assert_eq!(master_range.get((0, 4)).unwrap().to_string(), "Event Type & MITRE ATT&CK ID");

    let ioc_range = xl.worksheet_range("IOC").expect("read IOC sheet");
    assert!(ioc_range.height() > 1);
    assert_eq!(ioc_range.get((0, 0)).unwrap().to_string(), "Type");
    assert_eq!(ioc_range.get((0, 1)).unwrap().to_string(), "Indicator");

    let inv_range = xl.worksheet_range("INVENTORY").expect("read INVENTORY sheet");
    assert!(inv_range.height() >= 1);
    assert_eq!(inv_range.get((0, 0)).unwrap().to_string(), "Evidence Type");

    let acc_range = xl.worksheet_range("SUSPICIOUS ACCOUNTS").expect("read SUSPICIOUS ACCOUNTS sheet");
    assert!(acc_range.height() >= 1);
    assert_eq!(acc_range.get((0, 0)).unwrap().to_string(), "Account Name");

    let list_range = xl.worksheet_range("List").expect("read List sheet");
    assert!(list_range.height() >= 100, "List must contain master MITRE reference rows");

    // Clean up
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cross_file_batch_ioc_and_analyst_prompts() {
    use log_parser_lib::intel::analyst::{
        classify_ask, resolve_hunt_patterns, AnalystIntent,
    };

    // 1. Verify analyst prompt classification
    assert_eq!(
        classify_ask("show me exfiltration in all files"),
        AnalystIntent::Hunt
    );
    assert_eq!(
        classify_ask("show me communication in all files"),
        AnalystIntent::Hunt
    );
    assert_eq!(
        classify_ask("find c2 communication and external connections"),
        AnalystIntent::Hunt
    );
    assert_eq!(
        classify_ask("detect beaconing"),
        AnalystIntent::Hunt
    );
    assert_eq!(
        classify_ask("detect beaconing across files"),
        AnalystIntent::Chains
    );
    assert_eq!(
        classify_ask("detect breaches across files"),
        AnalystIntent::Chains
    );

    // 2. Verify resolve_hunt_patterns covers generic exfiltration and communication
    let (exfil_topic, exfil_patterns) = resolve_hunt_patterns("show me exfiltration in all files");
    assert!(exfil_topic.contains("Exfiltration"));
    assert!(exfil_patterns.iter().any(|p| p.eq_ignore_ascii_case("upload")));
    assert!(exfil_patterns.iter().any(|p| p.eq_ignore_ascii_case("rclone")));
    assert!(exfil_patterns.iter().any(|p| p.eq_ignore_ascii_case("curl")));
    assert!(exfil_patterns.iter().any(|p| p.eq_ignore_ascii_case("T1048")));

    let (comm_topic, comm_patterns) = resolve_hunt_patterns("show me communication in all files");
    assert!(comm_topic.contains("Communication"));
    assert!(comm_patterns.iter().any(|p| p.eq_ignore_ascii_case("network")));
    assert!(comm_patterns.iter().any(|p| p.eq_ignore_ascii_case("connection")));
    assert!(comm_patterns.iter().any(|p| p.eq_ignore_ascii_case("beacon")));
    assert!(comm_patterns.iter().any(|p| p.eq_ignore_ascii_case("c2")));
    assert!(comm_patterns.iter().any(|p| p.eq_ignore_ascii_case("T1071")));
}

#[test]
fn test_multi_file_real_correlation_exfiltration_and_communication() {
    use log_parser_lib::commands::FileTarget;
    use log_parser_lib::intel::analyst::{
        extract_unified_events_for_indicators, multi_file_hunt,
    };

    let temp_dir = std::env::temp_dir().join("dfir_test_multifile");
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();

    let file_a_path = temp_dir.join("auth_logs.jsonl");
    let file_b_path = temp_dir.join("network_traffic.jsonl");

    let file_a_data = concat!(
        "{\"time\": \"2026-10-24T01:00:00Z\", \"user\": \"alice\", \"ip\": \"198.51.100.45\", \"action\": \"UserLogin\", \"tool\": \"powershell.exe\"}\n",
        "{\"time\": \"2026-10-24T01:05:00Z\", \"user\": \"alice\", \"ip\": \"198.51.100.45\", \"action\": \"Exfiltration upload\", \"command\": \"rclone copy secret.zip remote:bucket\"}\n"
    );
    let file_b_data = concat!(
        "{\"time\": \"2026-10-24T01:02:00Z\", \"user\": \"bob\", \"client_ip\": \"198.51.100.45\", \"protocol\": \"HTTPS\", \"detail\": \"Outbound connection C2 beaconing to external IP\"}\n",
        "{\"time\": \"2026-10-24T01:10:00Z\", \"user\": \"charlie\", \"client_ip\": \"203.0.113.88\", \"protocol\": \"DNS\", \"detail\": \"Standard DNS query\"}\n"
    );

    std::fs::write(&file_a_path, file_a_data).unwrap();
    std::fs::write(&file_b_path, file_b_data).unwrap();

    let db_a_path = temp_dir.join("auth_logs.db");
    let db_b_path = temp_dir.join("network_traffic.db");

    let stats_a = import_stream_into_db(&file_a_path, &db_a_path, UniversalFormat::JsonLines, |_, _| {}).unwrap();
    assert_eq!(stats_a.row_count, 2);

    let stats_b = import_stream_into_db(&file_b_path, &db_b_path, UniversalFormat::JsonLines, |_, _| {}).unwrap();
    assert_eq!(stats_b.row_count, 2);

    let targets = vec![
        FileTarget {
            path: file_a_path.to_string_lossy().to_string(),
            sheet: None,
            cache_db_path: Some(db_a_path.to_string_lossy().to_string()),
        },
        FileTarget {
            path: file_b_path.to_string_lossy().to_string(),
            sheet: None,
            cache_db_path: Some(db_b_path.to_string_lossy().to_string()),
        },
    ];

    // 1. Test AI Exfiltration hunt across files
    let exfil_ans = multi_file_hunt(&targets, "show me exfiltration in all files").unwrap();
    let exfil_events = exfil_ans.correlated_events.as_ref().expect("exfil events present");
    assert!(!exfil_events.is_empty(), "Must find exfiltration events");
    assert!(
        exfil_events.iter().any(|e| e.file_name.contains("auth_logs")),
        "Exfiltration upload must be found in auth_logs"
    );

    // 2. Test AI Communication hunt across files
    let comm_ans = multi_file_hunt(&targets, "show me communication in all files").unwrap();
    let comm_events = comm_ans.correlated_events.as_ref().expect("comm events present");
    assert!(!comm_events.is_empty(), "Must find communication events");
    assert!(
        comm_events.iter().any(|e| e.file_name.contains("network_traffic")),
        "C2 communication must be found in network_traffic"
    );

    // 3. Test Batch indicator extraction across files (shared IP 198.51.100.45)
    let indicators = vec!["198.51.100.45".to_string()];
    let unified_events = extract_unified_events_for_indicators(&targets, &indicators);
    assert_eq!(unified_events.len(), 3, "198.51.100.45 appears in 2 events in file A and 1 event in file B");

    let file_names: Vec<String> = unified_events.iter().map(|e| e.file_name.clone()).collect();
    assert!(file_names.iter().any(|f| f.contains("auth_logs")));
    assert!(file_names.iter().any(|f| f.contains("network_traffic")));

    // Verify chronological ordering across files: 01:00:00 -> 01:02:00 -> 01:05:00
    if let (Some(t0), Some(t1), Some(t2)) = (
        unified_events[0].epoch_ms,
        unified_events[1].epoch_ms,
        unified_events[2].epoch_ms,
    ) {
        assert!(t0 <= t1, "Timeline order t0 <= t1");
        assert!(t1 <= t2, "Timeline order t1 <= t2");
    }

    // Clean up
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_single_json_document_with_large_arrays_and_many_keys() {
    let temp_dir = std::env::temp_dir().join(format!("dfir_json_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();

    let json_file_path = temp_dir.join("single_export.json");
    let db_path = temp_dir.join("single_export.db");

    // Create a JSON document with a collection key ("Records") containing 25 records,
    // plus arrays with multiple items and dozens of fields.
    let mut records = Vec::new();
    for i in 0..25 {
        let mut rec = serde_json::Map::new();
        rec.insert("EventTime".to_string(), serde_json::json!("2026-10-24T02:00:00Z"));
        rec.insert("SourceIP".to_string(), serde_json::json!(format!("198.51.100.{}", i + 10)));
        rec.insert("User".to_string(), serde_json::json!("admin_user"));
        rec.insert("Tags".to_string(), serde_json::json!(["tagA", "tagB", "tagC", "tagD", "tagE", "tagF", "tagG"]));
        for k in 0..40 {
            rec.insert(format!("Attribute_{k}"), serde_json::json!(format!("val_{}_{k}", i)));
        }
        records.push(serde_json::Value::Object(rec));
    }

    let root_doc = serde_json::json!({
        "Records": records,
        "format_version": "1.0",
        "description": "Enterprise cloud security export"
    });

    std::fs::write(&json_file_path, root_doc.to_string()).unwrap();

    let format = detect_format(&json_file_path).unwrap();
    assert_eq!(format, UniversalFormat::Json);

    // Ingest into SQLite database - MUST NOT fail with "too many columns on rows"
    let ingest_res = import_stream_into_db(
        &json_file_path,
        &db_path,
        format,
        |_, _| {},
    ).expect("Single JSON import must succeed without exceeding SQLite column limit");

    assert_eq!(ingest_res.row_count, 25, "All 25 records must be unpacked as separate rows");
    assert_eq!(ingest_res.failure_count, 0);
    assert!(ingest_res.columns.len() <= 350, "Columns must be safely bounded");

    // Clean up
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_compressed_json_gz_cloudtrail_and_auto_fallback() {
    use flate2::{write::GzEncoder, Compression};
    let temp_dir = std::env::temp_dir().join(format!("dfir_jsongz_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();

    // 1. Create a compressed AWS CloudTrail style .json.gz file (single root JSON with Records array)
    let gz_path = temp_dir.join("AWSLogs_123456789012_CloudTrail.json.gz");
    {
        let f = File::create(&gz_path).unwrap();
        let mut encoder = GzEncoder::new(f, Compression::default());
        let cloudtrail_doc = json!({
            "Records": [
                {
                    "eventTime": "2026-10-24T02:30:00Z",
                    "eventName": "ConsoleLogin",
                    "sourceIPAddress": "198.51.100.89",
                    "userIdentity": { "type": "IAMUser", "userName": "alice" }
                },
                {
                    "eventTime": "2026-10-24T02:35:00Z",
                    "eventName": "GetObject",
                    "sourceIPAddress": "198.51.100.89",
                    "userIdentity": { "type": "IAMUser", "userName": "alice" }
                }
            ]
        });
        encoder.write_all(cloudtrail_doc.to_string().as_bytes()).unwrap();
        encoder.finish().unwrap();
    }

    assert_eq!(detect_format(&gz_path).unwrap(), UniversalFormat::CompressedJson);

    let db_path = temp_dir.join("cloudtrail.sqlite3");
    let ingest_res = import_stream_into_db(
        &gz_path,
        &db_path,
        UniversalFormat::CompressedJson,
        |_, _| {},
    ).expect("ingest .json.gz cloudtrail stream");

    assert_eq!(ingest_res.row_count, 2, "Unpacked 2 CloudTrail records from .json.gz");
    assert_eq!(ingest_res.failure_count, 0);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_recursive_folder_scan_and_batch_evidence_discovery() {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use log_parser_lib::commands::scan_evidence_directory;
    use std::fs::{create_dir_all, File};
    use std::io::Write;

    let temp_root = std::env::temp_dir().join(format!("dfir_folder_scan_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_root);
    create_dir_all(&temp_root).unwrap();

    let ep1 = temp_root.join("endpoints").join("dc01");
    let ep2 = temp_root.join("cloud").join("aws");
    let git_dir = temp_root.join(".git");
    create_dir_all(&ep1).unwrap();
    create_dir_all(&ep2).unwrap();
    create_dir_all(&git_dir).unwrap();

    // 1. Create .jsonl.gz in ep1
    let jsonl_gz_path = ep1.join("endpoint_activity.jsonl.gz");
    {
        let f = File::create(&jsonl_gz_path).unwrap();
        let mut enc = GzEncoder::new(f, Compression::default());
        enc.write_all(b"{\"timestamp\":\"2026-10-24T01:00:00Z\",\"user\":\"analyst\"}\n").unwrap();
        enc.finish().unwrap();
    }

    // 2. Create .evtx dummy file in ep1
    let evtx_path = ep1.join("Security.evtx");
    {
        let mut f = File::create(&evtx_path).unwrap();
        f.write_all(b"dummy evtx data").unwrap();
    }

    // 3. Create .json.gz in ep2
    let json_gz_path = ep2.join("cloudtrail.json.gz");
    {
        let f = File::create(&json_gz_path).unwrap();
        let mut enc = GzEncoder::new(f, Compression::default());
        enc.write_all(b"{\"Records\":[{\"event\":\"login\"}]}").unwrap();
        enc.finish().unwrap();
    }

    // 4. Create .csv in root
    let csv_path = temp_root.join("firewall_traffic.csv");
    {
        let mut f = File::create(&csv_path).unwrap();
        f.write_all(b"src,dst,action\n10.0.0.1,10.0.0.2,ALLOW\n").unwrap();
    }

    // 5. Create ignored files (.tmp and in .git)
    let tmp_path = temp_root.join("temp_buffer.tmp");
    {
        let mut f = File::create(&tmp_path).unwrap();
        f.write_all(b"temporary cache").unwrap();
    }
    let git_file = git_dir.join("HEAD");
    {
        let mut f = File::create(&git_file).unwrap();
        f.write_all(b"ref: refs/heads/master").unwrap();
    }

    // 6. Execute scan_evidence_directory via tauri async_runtime
    let summary = tauri::async_runtime::block_on(scan_evidence_directory(
        temp_root.to_string_lossy().to_string(),
        Some(true),
    ))
    .expect("recursive scan succeeds");

    assert_eq!(summary.total_files_found, 4, "Must find exactly 4 forensic files and skip .tmp/.git");
    assert!(summary.total_bytes > 0);

    let found_names: Vec<String> = summary.files.iter().map(|f| f.name.clone()).collect();
    assert!(found_names.contains(&"endpoint_activity.jsonl.gz".to_string()));
    assert!(found_names.contains(&"Security.evtx".to_string()));
    assert!(found_names.contains(&"cloudtrail.json.gz".to_string()));
    assert!(found_names.contains(&"firewall_traffic.csv".to_string()));
    assert!(!found_names.contains(&"temp_buffer.tmp".to_string()));
    assert!(!found_names.contains(&"HEAD".to_string()));

    let jsonl_gz_entry = summary.files.iter().find(|f| f.name == "endpoint_activity.jsonl.gz").unwrap();
    assert!(jsonl_gz_entry.is_compressed);

    let _ = std::fs::remove_dir_all(&temp_root);
}

#[test]
fn test_export_from_tabular_cache_without_raw_evidence() {
    let temp_dir = std::env::temp_dir().join(format!("dfir_export_no_raw_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();

    let db_path = temp_dir.join("tabular_cache.db");
    let xlsx_path = temp_dir.join("Forensic_Report.xlsx");

    let conn = db::open(&db_path).unwrap();

    // Create table rows with dynamic columns (NO raw_evidence column, exactly like Excel/CSV import)
    conn.execute_batch(
        "CREATE TABLE rows (
            row_num INTEGER PRIMARY KEY,
            CreationDate TEXT,
            UserId TEXT,
            Operation TEXT,
            Workload TEXT,
            ClientIP TEXT,
            ObjectId TEXT,
            AuditData TEXT
        );
        CREATE TABLE _import_info (
            source_path TEXT NOT NULL,
            sheet_name TEXT NOT NULL,
            row_count INTEGER NOT NULL,
            imported_at TEXT NOT NULL
        );
        INSERT INTO _import_info VALUES ('C:\\cases\\evidence.xlsx', 'Sheet1', 2, '2026-10-24 10:00:00');
        INSERT INTO rows VALUES (
            1,
            '2026-10-24T08:15:30Z',
            'analyst_user@enterprise.com',
            'MailItemsAccessed',
            'Exchange',
            '198.51.100.45',
            'Inbox/Confidential.eml',
            '{\"ClientInfoString\":\"Outlook\",\"OperationProperties\":[{\"Name\":\"MailboxOwnerUPN\",\"Value\":\"victim@enterprise.com\"}]}'
        );
        INSERT INTO rows VALUES (
            2,
            '2026-10-24T08:20:12Z',
            'admin@enterprise.com',
            'UserLoggedIn',
            'AzureActiveDirectory',
            '203.0.113.88',
            'UserAccount',
            '{\"ResultStatus\":\"Success\",\"LogonError\":\"None\"}'
        );",
    )
    .unwrap();

    // Export forensic report - MUST succeed cleanly and NOT panic or fail with "no such column: raw_evidence"
    let result = export_forensic_workbook(&conn, &xlsx_path, "Lead DFIR Examiner")
        .expect("Export forensic workbook must succeed for tabular imports without raw_evidence");

    assert_eq!(result.total_exported_records, 2);
    assert!(xlsx_path.exists());
    assert!(std::fs::metadata(&xlsx_path).unwrap().len() > 1000);

    let csv_path = std::path::PathBuf::from(&result.csv_timeline_path);
    assert!(csv_path.exists());
    let csv_content = std::fs::read_to_string(&csv_path).unwrap();
    assert!(csv_content.contains("MailItemsAccessed"));
    assert!(csv_content.contains("analyst_user@enterprise.com"));
    assert!(csv_content.contains("198.51.100.45"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cross_ioc_overlap_handles_unicode_smart_quotes_without_panic() {
    let temp_dir = std::env::temp_dir().join(format!("dfir_unicode_ioc_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();

    let db_path = temp_dir.join("unicode_audit.db");
    let conn = db::open(&db_path).unwrap();

    // Create table with multi-byte smart quotes ” and “
    conn.execute_batch(
        "CREATE TABLE rows (
            row_num INTEGER PRIMARY KEY,
            AuditData TEXT
        );
        CREATE TABLE _meta (
            sql_name TEXT NOT NULL,
            original_name TEXT NOT NULL,
            col_index INTEGER NOT NULL,
            inferred_type TEXT NOT NULL
        );
        INSERT INTO _meta VALUES ('AuditData', 'AuditData', 1, 'text');
        INSERT INTO rows VALUES (
            1,
            'Examiner note: ”suspect@external-domain.org” logged in from 198.51.100.99 via “https://c2.phishing-hub.net/gateway?token=secure”'
        );",
    )
    .unwrap();

    let columns = db::load_columns(&conn).unwrap();

    // extract_iocs must NOT panic with "start byte index ... is not a char boundary; it is inside '”'"
    let summary = log_parser_lib::intel::ioc::extract_iocs(&conn, &columns, |_, _, _| {})
        .expect("extract_iocs must succeed on non-ASCII text with smart quotes");

    assert!(summary.ip_indicators.iter().any(|ip| ip.ip == "198.51.100.99"));
    assert!(summary.email_indicators.iter().any(|em| em.email == "suspect@external-domain.org"));
    assert!(summary.url_indicators.iter().any(|u| u.url.contains("phishing-hub.net")));

    let _ = std::fs::remove_dir_all(&temp_dir);
}