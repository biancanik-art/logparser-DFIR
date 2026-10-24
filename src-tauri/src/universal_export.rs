use crate::intel::universal_ioc::IocMatchItem;
use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::Connection;
use rust_xlsxwriter::{Format, Workbook};
use serde_json::Value;
use std::collections::HashSet;
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub struct UniversalExportResult {
    pub xlsx_path: String,
    pub csv_timeline_path: String,
    pub total_exported_records: usize,
}

fn json_find_str(val: &Value, candidates: &[&str]) -> Option<String> {
    if let Value::Object(map) = val {
        for key in candidates {
            if let Some(v) = map.get(*key) {
                if let Some(s) = v.as_str() {
                    let st = s.trim();
                    if !st.is_empty() {
                        return Some(st.to_string());
                    }
                } else if v.is_number() || v.is_boolean() {
                    let s = v.to_string();
                    if !s.is_empty() {
                        return Some(s);
                    }
                }
            }
        }
        for (k, v) in map {
            let k_low = k.to_ascii_lowercase();
            for key in candidates {
                if &k_low == key {
                    if let Some(s) = v.as_str() {
                        let st = s.trim();
                        if !st.is_empty() {
                            return Some(st.to_string());
                        }
                    } else if v.is_number() || v.is_boolean() {
                        return Some(v.to_string());
                    }
                }
            }
        }
    }
    None
}

fn map_mitre_event_type(
    ioc_type: &str,
    match_kind: &str,
    matched_field: &str,
    ioc_value: &str,
    raw_val: Option<&Value>,
) -> String {
    // Check if raw log already specifies a MITRE technique or event type
    if let Some(val) = raw_val {
        if let Some(t) = json_find_str(val, &["event_type", "mitre", "technique", "attack_id", "threat_category"]) {
            if !t.is_empty() {
                return t;
            }
        }
    }

    let field_lower = matched_field.to_ascii_lowercase();
    let val_lower = ioc_value.to_ascii_lowercase();

    if ioc_type == "hash" {
        return "Execution - Malware Infection (T1204)".to_string();
    }
    if ioc_type == "command_line" || field_lower.contains("cmd") || field_lower.contains("command") {
        return "Execution - Command Execution (cmd.exe) (T1059.003)".to_string();
    }
    if field_lower.contains("powershell") || val_lower.ends_with(".ps1") {
        return "Execution - PowerShell Execution (T1059.001)".to_string();
    }
    if ioc_type == "registry_key" || field_lower.contains("registry") || field_lower.contains("reg_") {
        return "Persistence - Registry Run Key Modification (T1547.001)".to_string();
    }
    if field_lower.contains("rdp") || field_lower.contains("remoteconnection") || field_lower.contains("terminal") {
        return "Lateral Movement - RDP Connection (T1021.001)".to_string();
    }
    if field_lower.contains("sched") || field_lower.contains("task") {
        return "Persistence - Scheduled Task Creation (T1053)".to_string();
    }
    if field_lower.contains("service") {
        return "Persistence - Service Installation (T1543)".to_string();
    }
    if ioc_type == "username" || field_lower.contains("user") || field_lower.contains("logon") {
        return "Initial Access - Valid Accounts (T1078)".to_string();
    }
    if field_lower.contains("share") || field_lower.contains("smb") {
        return "Lateral Movement - SMB/Admin Share Access (T1021.002)".to_string();
    }
    if ioc_type == "domain" || ioc_type == "url" {
        return "Command and Control - Beaconing Activity (T1071)".to_string();
    }
    if ioc_type == "ip" {
        if field_lower.contains("dst") || field_lower.contains("dest") || field_lower.contains("server") {
            return "Command and Control - C2 Over HTTPS (T1071.001)".to_string();
        } else {
            return "Initial Access - External Remote Service (T1133)".to_string();
        }
    }

    format!("IOC [{}] {}", ioc_type, match_kind)
}

fn map_ioc_display_type(ioc_type: &str, value: &str) -> &'static str {
    match ioc_type {
        "ip" => {
            if value.contains(':') {
                "IP Address (IPv6)"
            } else {
                "IP Address (IPv4)"
            }
        }
        "cidr" => "CIDR Subnet",
        "domain" => "Domain Name",
        "url" => "URL",
        "email" => "Email Address",
        "username" => "Username",
        "hostname" => "Host / Device",
        "filename" => "File Name",
        "path" => "File Path",
        "hash" => {
            if value.len() == 32 {
                "MD5 Hash"
            } else if value.len() == 40 {
                "SHA1 Hash"
            } else {
                "SHA256 Hash"
            }
        }
        "registry_key" => "Registry Key",
        "process_name" => "Process Name",
        "command_line" => "Command Line Arguments",
        _ => "Custom String",
    }
}

pub fn export_forensic_workbook(
    conn: &Connection,
    dest_xlsx: &Path,
    analyst_name: &str,
) -> Result<UniversalExportResult> {
    let mut workbook = Workbook::new();
    let header_fmt = Format::new().set_bold();

    let input_date = Utc::now().format("%Y-%m-%d").to_string();

    // ==========================================
    // 1. MASTER TIMELINE Sheet
    // ==========================================
    let master_sheet = workbook.add_worksheet();
    master_sheet.set_name("MASTER TIMELINE")?;

    let master_headers = [
        "Input Date",
        "Analyst",
        "Date/Time (UTC)",
        "Host/Device",
        "Event Type & MITRE ATT&CK ID",
        "File/Artifact Information",
        "Is This Malicious?",
        "User Account",
        "Source Host",
        "Source IP Address",
        "Destination Host",
        "Destination IP Address",
        "Evidence Source",
        "Event ID",
        "Notes",
    ];

    for (col_idx, header) in master_headers.iter().enumerate() {
        master_sheet.write_string_with_format(0, col_idx as u16, *header, &header_fmt)?;
    }

    // Set Column Widths matching Master Template
    let master_col_widths = [
        22.0, // A: Input Date
        16.0, // B: Analyst
        28.0, // C: Date/Time (UTC)
        26.0, // D: Host/Device
        55.0, // E: Event Type & MITRE ATT&CK ID
        65.0, // F: File/Artifact Information
        20.0, // G: Is This Malicious?
        32.0, // H: User Account
        24.0, // I: Source Host
        24.0, // J: Source IP Address
        24.0, // K: Destination Host
        24.0, // L: Destination IP Address
        30.0, // M: Evidence Source
        18.0, // N: Event ID
        70.0, // O: Notes
    ];
    for (col_idx, width) in master_col_widths.iter().enumerate() {
        master_sheet.set_column_width(col_idx as u16, *width)?;
    }

    let mut row_idx: u32 = 1;
    let mut csv_lines = Vec::new();
    csv_lines.push(master_headers.join(","));

    // Check count of _ioc_matches
    let match_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM _ioc_matches", [], |r| r.get(0))
        .unwrap_or(0);

    let mut total_exported = 0;

    if match_count > 0 {
        // Query matched records
        let mut stmt = conn.prepare(
            "SELECT match_id, row_num, ioc_type, ioc_value, matched_field, matched_value, match_kind,
                    is_suppressed, timestamp_utc, source_file, event_summary, raw_evidence
             FROM _ioc_matches ORDER BY timestamp_utc ASC, row_num ASC",
        )?;

        let rows = stmt.query_map([], |r| {
            Ok(IocMatchItem {
                match_id: r.get(0)?,
                row_num: r.get(1)?,
                ioc_id: 0,
                ioc_type: r.get(2)?,
                ioc_value: r.get(3)?,
                matched_field: r.get(4)?,
                matched_value: r.get(5)?,
                match_kind: r.get(6)?,
                is_suppressed: r.get::<_, i64>(7)? != 0,
                timestamp_utc: r.get(8)?,
                source_file: r.get(9)?,
                event_summary: r.get(10)?,
                raw_evidence: r.get(11)?,
            })
        })?;

        for res in rows {
            let item = res?;
            total_exported += 1;

            let raw_obj: Option<Value> = serde_json::from_str(&item.raw_evidence).ok();

            let time_str = item
                .timestamp_utc
                .clone()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| {
                    raw_obj.as_ref().and_then(|o| {
                        json_find_str(
                            o,
                            &[
                                "time",
                                "timestamp",
                                "@timestamp",
                                "datetime",
                                "date_time",
                                "eventtime",
                                "timecreated",
                                "date",
                                "norm_time",
                                "created_at",
                            ],
                        )
                    })
                })
                .unwrap_or_else(|| "Unknown".to_string());

            let host = raw_obj
                .as_ref()
                .and_then(|o| {
                    json_find_str(
                        o,
                        &[
                            "host",
                            "norm_host",
                            "computer",
                            "computername",
                            "hostname",
                            "device",
                            "devicename",
                            "workstationname",
                            "workstation",
                            "system",
                            "dvc",
                        ],
                    )
                })
                .unwrap_or_default();

            let event_type = map_mitre_event_type(
                &item.ioc_type,
                &item.match_kind,
                &item.matched_field,
                &item.ioc_value,
                raw_obj.as_ref(),
            );

            let artifact_info = raw_obj
                .as_ref()
                .and_then(|o| {
                    json_find_str(
                        o,
                        &[
                            "file",
                            "filename",
                            "filepath",
                            "path",
                            "process",
                            "process_name",
                            "image",
                            "commandline",
                            "targetfilename",
                            "sourceimage",
                            "norm_process",
                            "request",
                            "uri",
                            "url",
                        ],
                    )
                })
                .unwrap_or_else(|| {
                    if !item.matched_value.is_empty() {
                        item.matched_value.clone()
                    } else {
                        item.matched_field.clone()
                    }
                });

            let malicious_flag = if item.is_suppressed {
                "Legitimate"
            } else {
                "TBD - Suspicious"
            };

            let user_account = raw_obj
                .as_ref()
                .and_then(|o| {
                    json_find_str(
                        o,
                        &[
                            "user",
                            "norm_user",
                            "username",
                            "targetusername",
                            "subjectusername",
                            "accountname",
                            "account",
                            "user_name",
                            "identity",
                            "account_id",
                        ],
                    )
                })
                .or_else(|| {
                    if item.ioc_type == "username" {
                        Some(item.ioc_value.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_default();

            let source_host = raw_obj
                .as_ref()
                .and_then(|o| {
                    json_find_str(
                        o,
                        &[
                            "source_host",
                            "src_host",
                            "sourcehost",
                            "client_host",
                            "workstation",
                            "workstationname",
                        ],
                    )
                })
                .unwrap_or_default();

            let source_ip = raw_obj
                .as_ref()
                .and_then(|o| {
                    json_find_str(
                        o,
                        &[
                            "src_ip",
                            "source_ip",
                            "sourceip",
                            "ipaddress",
                            "c-ip",
                            "clientip",
                            "norm_ip",
                            "src_addr",
                            "sourceaddress",
                            "remote_addr",
                        ],
                    )
                })
                .or_else(|| {
                    if item.ioc_type == "ip"
                        && !item.matched_field.to_ascii_lowercase().contains("dst")
                        && !item.matched_field.to_ascii_lowercase().contains("dest")
                    {
                        Some(item.ioc_value.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_default();

            let dest_host = raw_obj
                .as_ref()
                .and_then(|o| {
                    json_find_str(
                        o,
                        &[
                            "dest_host",
                            "destination_host",
                            "desthost",
                            "targethost",
                            "servername",
                            "destinationhostname",
                            "targetcomputer",
                        ],
                    )
                })
                .unwrap_or_default();

            let dest_ip = raw_obj
                .as_ref()
                .and_then(|o| {
                    json_find_str(
                        o,
                        &[
                            "dest_ip",
                            "dst_ip",
                            "destination_ip",
                            "destip",
                            "targetip",
                            "destinationip",
                            "s-ip",
                            "serverip",
                            "dst_addr",
                            "destinationaddress",
                        ],
                    )
                })
                .or_else(|| {
                    if item.ioc_type == "ip"
                        && (item.matched_field.to_ascii_lowercase().contains("dst")
                            || item.matched_field.to_ascii_lowercase().contains("dest"))
                    {
                        Some(item.ioc_value.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_default();

            let evidence_source = format!("{}#row={}", item.source_file, item.row_num);

            let event_id = raw_obj
                .as_ref()
                .and_then(|o| {
                    json_find_str(
                        o,
                        &[
                            "event_id",
                            "eventid",
                            "id",
                            "recordid",
                            "eventrecordid",
                            "status_code",
                            "status",
                        ],
                    )
                })
                .unwrap_or_default();

            let notes = if !item.event_summary.is_empty() {
                item.event_summary.as_str()
            } else {
                "Forensic correlation hit"
            };

            let cols = [
                input_date.as_str(),
                analyst_name,
                time_str.as_str(),
                host.as_str(),
                event_type.as_str(),
                artifact_info.as_str(),
                malicious_flag,
                user_account.as_str(),
                source_host.as_str(),
                source_ip.as_str(),
                dest_host.as_str(),
                dest_ip.as_str(),
                evidence_source.as_str(),
                event_id.as_str(),
                notes,
            ];

            for (col_idx, val) in cols.iter().enumerate() {
                master_sheet.write_string(row_idx, col_idx as u16, *val)?;
            }

            let csv_row = cols
                .iter()
                .map(|s| format!("\"{}\"", s.replace('"', "\"\"")))
                .collect::<Vec<_>>()
                .join(",");
            csv_lines.push(csv_row);

            row_idx += 1;
        }
    } else {
        // Fallback: If no IOC matches are stored yet, populate from `rows` evidence table
        let has_rows: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='rows')",
                [],
                |r| r.get(0),
            )
            .unwrap_or(false);

        if has_rows {
            let mut stmt = conn.prepare(
                "SELECT row_num, raw_evidence FROM rows ORDER BY row_num ASC LIMIT 50000",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?))
            })?;

            for res in rows {
                let (r_num, raw_ev) = res?;
                total_exported += 1;

                let raw_obj: Option<Value> = raw_ev.as_ref().and_then(|s| serde_json::from_str(s).ok());

                let time_str = raw_obj
                    .as_ref()
                    .and_then(|o| {
                        json_find_str(
                            o,
                            &[
                                "time",
                                "timestamp",
                                "@timestamp",
                                "datetime",
                                "date_time",
                                "eventtime",
                                "timecreated",
                                "date",
                                "norm_time",
                                "created_at",
                            ],
                        )
                    })
                    .unwrap_or_else(|| "Unknown".to_string());

                let host = raw_obj
                    .as_ref()
                    .and_then(|o| {
                        json_find_str(
                            o,
                            &[
                                "host",
                                "norm_host",
                                "computer",
                                "computername",
                                "hostname",
                                "device",
                                "devicename",
                                "workstationname",
                                "system",
                            ],
                        )
                    })
                    .unwrap_or_default();

                let artifact_info = raw_obj
                    .as_ref()
                    .and_then(|o| {
                        json_find_str(
                            o,
                            &[
                                "file",
                                "filename",
                                "filepath",
                                "path",
                                "process",
                                "process_name",
                                "image",
                                "commandline",
                                "targetfilename",
                                "norm_process",
                                "request",
                                "uri",
                            ],
                        )
                    })
                    .unwrap_or_default();

                let user_account = raw_obj
                    .as_ref()
                    .and_then(|o| {
                        json_find_str(
                            o,
                            &[
                                "user",
                                "norm_user",
                                "username",
                                "targetusername",
                                "subjectusername",
                                "accountname",
                                "account",
                                "identity",
                            ],
                        )
                    })
                    .unwrap_or_default();

                let source_ip = raw_obj
                    .as_ref()
                    .and_then(|o| {
                        json_find_str(
                            o,
                            &[
                                "src_ip",
                                "source_ip",
                                "sourceip",
                                "ipaddress",
                                "c-ip",
                                "clientip",
                                "norm_ip",
                                "remote_addr",
                            ],
                        )
                    })
                    .unwrap_or_default();

                let dest_ip = raw_obj
                    .as_ref()
                    .and_then(|o| {
                        json_find_str(
                            o,
                            &[
                                "dest_ip",
                                "dst_ip",
                                "destination_ip",
                                "destip",
                                "targetip",
                                "s-ip",
                                "serverip",
                            ],
                        )
                    })
                    .unwrap_or_default();

                let event_id = raw_obj
                    .as_ref()
                    .and_then(|o| {
                        json_find_str(
                            o,
                            &["event_id", "eventid", "id", "recordid", "status_code", "status"],
                        )
                    })
                    .unwrap_or_default();

                let evidence_source = format!("imported_evidence#row={r_num}");

                let cols = [
                    input_date.as_str(),
                    analyst_name,
                    time_str.as_str(),
                    host.as_str(),
                    "System Event - Log Entry",
                    artifact_info.as_str(),
                    "Undetermined",
                    user_account.as_str(),
                    "",
                    source_ip.as_str(),
                    "",
                    dest_ip.as_str(),
                    evidence_source.as_str(),
                    event_id.as_str(),
                    "Log record imported from evidence",
                ];

                for (col_idx, val) in cols.iter().enumerate() {
                    master_sheet.write_string(row_idx, col_idx as u16, *val)?;
                }

                let csv_row = cols
                    .iter()
                    .map(|s| format!("\"{}\"", s.replace('"', "\"\"")))
                    .collect::<Vec<_>>()
                    .join(",");
                csv_lines.push(csv_row);

                row_idx += 1;
            }
        }
    }

    // Auto-filter on MASTER TIMELINE
    if row_idx > 1 {
        master_sheet.autofilter(0, 0, row_idx - 1, 14)?;
    }

    // ==========================================
    // 2. IOC Sheet
    // ==========================================
    let ioc_sheet = workbook.add_worksheet();
    ioc_sheet.set_name("IOC")?;
    let ioc_headers = [
        "Type",
        "Indicator",
        "Description",
        "MD5 Hash",
        "SHA1 Hash",
        "SHA256 Hash",
        "Notes",
    ];
    for (col_idx, header) in ioc_headers.iter().enumerate() {
        ioc_sheet.write_string_with_format(0, col_idx as u16, *header, &header_fmt)?;
    }

    let ioc_col_widths = [22.0, 45.0, 50.0, 35.0, 42.0, 66.0, 55.0];
    for (col_idx, width) in ioc_col_widths.iter().enumerate() {
        ioc_sheet.set_column_width(col_idx as u16, *width)?;
    }

    let has_iocs_tbl: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='_universal_iocs')",
            [],
            |r| r.get(0),
        )
        .unwrap_or(false);

    let mut ioc_row_idx: u32 = 1;
    if has_iocs_tbl {
        let mut ioc_stmt = conn.prepare(
            "SELECT ioc_type, value, description, enabled, is_exclusion FROM _universal_iocs",
        )?;
        let ioc_rows = ioc_stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                r.get::<_, i64>(3)? != 0,
                r.get::<_, i64>(4)? != 0,
            ))
        })?;

        for r in ioc_rows {
            let (ioc_type, val, desc, enabled, is_ex) = r?;
            let status = if !enabled {
                "Disabled"
            } else if is_ex {
                "Exclusion / Allowlist"
            } else {
                "Active"
            };

            let display_type = map_ioc_display_type(&ioc_type, &val);

            let mut md5_str = "";
            let mut sha1_str = "";
            let mut sha256_str = "";

            if ioc_type == "hash" {
                if val.len() == 32 {
                    md5_str = &val;
                } else if val.len() == 40 {
                    sha1_str = &val;
                } else if val.len() == 64 {
                    sha256_str = &val;
                }
            }

            ioc_sheet.write_string(ioc_row_idx, 0, display_type)?;
            ioc_sheet.write_string(ioc_row_idx, 1, &val)?;
            ioc_sheet.write_string(ioc_row_idx, 2, &desc)?;
            ioc_sheet.write_string(ioc_row_idx, 3, md5_str)?;
            ioc_sheet.write_string(ioc_row_idx, 4, sha1_str)?;
            ioc_sheet.write_string(ioc_row_idx, 5, sha256_str)?;
            ioc_sheet.write_string(ioc_row_idx, 6, status)?;
            ioc_row_idx += 1;
        }
    }

    if ioc_row_idx > 1 {
        ioc_sheet.autofilter(0, 0, ioc_row_idx - 1, 6)?;
    }

    // ==========================================
    // 3. INVENTORY Sheet
    // ==========================================
    let inv_sheet = workbook.add_worksheet();
    inv_sheet.set_name("INVENTORY")?;
    let inv_headers = [
        "Evidence Type",
        "Device Name",
        "IP Address",
        "File Name",
        "Analyzed",
        "Assigned",
        "Compromised",
        "Notes",
    ];
    for (col_idx, header) in inv_headers.iter().enumerate() {
        inv_sheet.write_string_with_format(0, col_idx as u16, *header, &header_fmt)?;
    }

    let inv_col_widths = [28.0, 26.0, 22.0, 42.0, 14.0, 18.0, 18.0, 65.0];
    for (col_idx, width) in inv_col_widths.iter().enumerate() {
        inv_sheet.set_column_width(col_idx as u16, *width)?;
    }

    let mut inv_row_idx: u32 = 1;

    // Check _ingest_audit table
    let has_ingest_audit: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='_ingest_audit')",
            [],
            |r| r.get(0),
        )
        .unwrap_or(false);

    if has_ingest_audit {
        let mut audit_stmt = conn.prepare(
            "SELECT source_path, total_records, parse_failures, format, imported_at FROM _ingest_audit",
        )?;
        let audit_rows = audit_stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
            ))
        })?;

        for a in audit_rows {
            let (source_path, total, fails, fmt_name, imp_at) = a?;
            let path_obj = Path::new(&source_path);
            let fname = path_obj
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&source_path);

            let evidence_type = if fmt_name.contains("Compressed") {
                "Compressed Archive / Log (.gz)"
            } else if fmt_name.contains("Json") {
                "JSON Log File"
            } else if fmt_name.contains("Evtx") {
                "Windows - Event Log (.evtx)"
            } else if fmt_name.contains("Csv") {
                "CSV / TSV Log Export"
            } else {
                "Forensic Evidence File"
            };

            let notes = format!(
                "Ingested {} records ({} parse failures). Format: {}. Imported at {}",
                total, fails, fmt_name, imp_at
            );

            inv_sheet.write_string(inv_row_idx, 0, evidence_type)?;
            inv_sheet.write_string(inv_row_idx, 1, "")?; // Device Name
            inv_sheet.write_string(inv_row_idx, 2, "")?; // IP Address
            inv_sheet.write_string(inv_row_idx, 3, fname)?;
            inv_sheet.write_string(inv_row_idx, 4, "Yes")?;
            inv_sheet.write_string(inv_row_idx, 5, analyst_name)?;
            inv_sheet.write_string(inv_row_idx, 6, "Undetermined")?;
            inv_sheet.write_string(inv_row_idx, 7, &notes)?;
            inv_row_idx += 1;
        }
    }

    // Also check if any hosts were discovered across rows
    let has_norm_host: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('rows') WHERE name='norm_host')",
            [],
            |r| r.get(0),
        )
        .unwrap_or(false);

    if has_norm_host {
        let mut host_stmt = conn.prepare(
            "SELECT DISTINCT norm_host FROM rows WHERE norm_host IS NOT NULL AND norm_host != '' LIMIT 50",
        )?;
        let host_rows = host_stmt.query_map([], |r| r.get::<_, String>(0))?;
        for h in host_rows {
            if let Ok(hostname) = h {
                inv_sheet.write_string(inv_row_idx, 0, "Host / Triage")?;
                inv_sheet.write_string(inv_row_idx, 1, &hostname)?;
                inv_sheet.write_string(inv_row_idx, 2, "")?;
                inv_sheet.write_string(inv_row_idx, 3, "")?;
                inv_sheet.write_string(inv_row_idx, 4, "Yes")?;
                inv_sheet.write_string(inv_row_idx, 5, analyst_name)?;
                inv_sheet.write_string(inv_row_idx, 6, "Undetermined")?;
                inv_sheet.write_string(
                    inv_row_idx,
                    7,
                    "Device identified in ingested log evidence",
                )?;
                inv_row_idx += 1;
            }
        }
    }

    if inv_row_idx > 1 {
        inv_sheet.autofilter(0, 0, inv_row_idx - 1, 7)?;
    }

    // ==========================================
    // 4. SUSPICIOUS ACCOUNTS Sheet
    // ==========================================
    let acc_sheet = workbook.add_worksheet();
    acc_sheet.set_name("SUSPICIOUS ACCOUNTS")?;
    let acc_headers = [
        "Account Name",
        "Account Type",
        "Admin Rights?",
        "Compromised",
        "SID",
        "Notes",
    ];
    for (col_idx, header) in acc_headers.iter().enumerate() {
        acc_sheet.write_string_with_format(0, col_idx as u16, *header, &header_fmt)?;
    }

    let acc_col_widths = [30.0, 25.0, 18.0, 18.0, 25.0, 65.0];
    for (col_idx, width) in acc_col_widths.iter().enumerate() {
        acc_sheet.set_column_width(col_idx as u16, *width)?;
    }

    let mut acc_row_idx: u32 = 1;
    let mut seen_accounts = HashSet::new();

    // Accounts from _ioc_matches
    if match_count > 0 {
        let mut acc_stmt = conn.prepare(
            "SELECT DISTINCT ioc_value, matched_field FROM _ioc_matches 
             WHERE ioc_type = 'username' OR matched_field LIKE '%user%' OR matched_field LIKE '%account%'",
        )?;
        let acc_rows = acc_stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;

        for a in acc_rows {
            let (account, field) = a?;
            if account.trim().is_empty() || seen_accounts.contains(&account) {
                continue;
            }
            seen_accounts.insert(account.clone());

            let acc_type = if account.ends_with('$') {
                "Computer Account"
            } else if account.contains('\\') || account.contains('@') {
                "Domain Account"
            } else {
                "Local Account"
            };

            let is_admin = if account.to_ascii_lowercase().contains("admin")
                || account.to_ascii_lowercase() == "root"
            {
                "Yes"
            } else {
                "Undetermined"
            };

            let note = format!("Identified in correlation hit ({field})");

            acc_sheet.write_string(acc_row_idx, 0, &account)?;
            acc_sheet.write_string(acc_row_idx, 1, acc_type)?;
            acc_sheet.write_string(acc_row_idx, 2, is_admin)?;
            acc_sheet.write_string(acc_row_idx, 3, "Undetermined")?;
            acc_sheet.write_string(acc_row_idx, 4, "")?;
            acc_sheet.write_string(acc_row_idx, 5, &note)?;
            acc_row_idx += 1;
        }
    }

    // Also check norm_user in rows if available
    let has_norm_user: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('rows') WHERE name='norm_user')",
            [],
            |r| r.get(0),
        )
        .unwrap_or(false);

    if has_norm_user {
        let mut u_stmt = conn.prepare(
            "SELECT DISTINCT norm_user FROM rows 
             WHERE norm_user IS NOT NULL AND norm_user != '' 
               AND (norm_user LIKE '%admin%' OR norm_user LIKE '%root%' OR norm_user LIKE '%svc%') 
             LIMIT 50",
        )?;
        let u_rows = u_stmt.query_map([], |r| r.get::<_, String>(0))?;
        for u in u_rows {
            if let Ok(account) = u {
                if account.trim().is_empty() || seen_accounts.contains(&account) {
                    continue;
                }
                seen_accounts.insert(account.clone());

                let acc_type = if account.ends_with('$') {
                    "Computer Account"
                } else if account.contains('\\') || account.contains('@') {
                    "Domain Account"
                } else {
                    "Local Account"
                };

                let note = "High-privilege account observed in evidence records";

                acc_sheet.write_string(acc_row_idx, 0, &account)?;
                acc_sheet.write_string(acc_row_idx, 1, acc_type)?;
                acc_sheet.write_string(acc_row_idx, 2, "Yes")?;
                acc_sheet.write_string(acc_row_idx, 3, "Undetermined")?;
                acc_sheet.write_string(acc_row_idx, 4, "")?;
                acc_sheet.write_string(acc_row_idx, 5, note)?;
                acc_row_idx += 1;
            }
        }
    }

    if acc_row_idx > 1 {
        acc_sheet.autofilter(0, 0, acc_row_idx - 1, 5)?;
    }

    // ==========================================
    // 5. List Sheet (Master Forensic Taxonomy & ATT&CK Reference)
    // ==========================================
    let list_sheet = workbook.add_worksheet();
    list_sheet.set_name("List")?;

    let list_col_widths = [60.0, 20.0, 12.0, 60.0, 30.0, 30.0, 15.0, 25.0];
    for (col_idx, width) in list_col_widths.iter().enumerate() {
        list_sheet.set_column_width(col_idx as u16, *width)?;
    }

    // Embed and parse master taxonomy dataset
    let taxonomy_json = include_str!("list_sheet_data.json");
    if let Ok(tax_val) = serde_json::from_str::<Value>(taxonomy_json) {
        let col_a = tax_val.get("A").and_then(|v| v.as_array());
        let col_b = tax_val.get("B").and_then(|v| v.as_array());
        let col_c = tax_val.get("C").and_then(|v| v.as_array());
        let col_d = tax_val.get("D").and_then(|v| v.as_array());
        let col_e = tax_val.get("E").and_then(|v| v.as_array());
        let col_f = tax_val.get("F").and_then(|v| v.as_array());
        let col_g = tax_val.get("G").and_then(|v| v.as_array());
        let col_h = tax_val.get("H").and_then(|v| v.as_array());

        let max_len = [
            col_a.map_or(0, |a| a.len()),
            col_b.map_or(0, |a| a.len()),
            col_c.map_or(0, |a| a.len()),
            col_d.map_or(0, |a| a.len()),
            col_e.map_or(0, |a| a.len()),
            col_f.map_or(0, |a| a.len()),
            col_g.map_or(0, |a| a.len()),
            col_h.map_or(0, |a| a.len()),
        ]
        .into_iter()
        .max()
        .unwrap_or(0);

        for row_i in 0..max_len {
            if let Some(val) = col_a.and_then(|a| a.get(row_i)).and_then(|v| v.as_str()) {
                list_sheet.write_string(row_i as u32, 0, val)?;
            }
            if let Some(val) = col_b.and_then(|a| a.get(row_i)).and_then(|v| v.as_str()) {
                list_sheet.write_string(row_i as u32, 1, val)?;
            }
            if let Some(val) = col_c.and_then(|a| a.get(row_i)).and_then(|v| v.as_str()) {
                list_sheet.write_string(row_i as u32, 2, val)?;
            }
            if let Some(val) = col_d.and_then(|a| a.get(row_i)).and_then(|v| v.as_str()) {
                list_sheet.write_string(row_i as u32, 3, val)?;
            }
            if let Some(val) = col_e.and_then(|a| a.get(row_i)).and_then(|v| v.as_str()) {
                list_sheet.write_string(row_i as u32, 4, val)?;
            }
            if let Some(val) = col_f.and_then(|a| a.get(row_i)).and_then(|v| v.as_str()) {
                list_sheet.write_string(row_i as u32, 5, val)?;
            }
            if let Some(val) = col_g.and_then(|a| a.get(row_i)).and_then(|v| v.as_str()) {
                list_sheet.write_string(row_i as u32, 6, val)?;
            }
            if let Some(val) = col_h.and_then(|a| a.get(row_i)).and_then(|v| v.as_str()) {
                list_sheet.write_string(row_i as u32, 7, val)?;
            }
        }
    }

    // Save workbook
    workbook
        .save(dest_xlsx)
        .with_context(|| format!("saving workbook to {}", dest_xlsx.display()))?;

    // Also write CSV version of MASTER TIMELINE
    let parent_dir = dest_xlsx.parent().unwrap_or_else(|| Path::new("."));
    let stem = dest_xlsx
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("MASTER_TIMELINE");
    let csv_path = parent_dir.join(format!("{stem}.csv"));
    let mut csv_file = File::create(&csv_path)?;
    csv_file.write_all(csv_lines.join("\n").as_bytes())?;

    // Also write PARSE_FAILURES.csv if failures exist
    let has_failures_tbl: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='_parse_failures')",
            [],
            |r| r.get(0),
        )
        .unwrap_or(false);

    if has_failures_tbl {
        let mut fail_stmt = conn.prepare(
            "SELECT id, source_path, record_num, raw_payload, error_message, occurred_at FROM _parse_failures",
        )?;
        let fail_rows = fail_stmt.query_map([], |r| {
            Ok(format!(
                "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"",
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?.replace('"', "\"\""),
                r.get::<_, i64>(2)?,
                r.get::<_, Option<String>>(3)?.unwrap_or_default().replace('"', "\"\""),
                r.get::<_, String>(4)?.replace('"', "\"\""),
                r.get::<_, String>(5)?
            ))
        })?;

        let fail_csv_path = parent_dir.join(format!("{stem}_PARSE_FAILURES.csv"));
        let mut fail_file = File::create(&fail_csv_path)?;
        fail_file.write_all(
            b"\"id\",\"source_path\",\"record_num\",\"raw_payload\",\"error_message\",\"occurred_at\"\n",
        )?;
        for line in fail_rows {
            fail_file.write_all(line?.as_bytes())?;
            fail_file.write_all(b"\n")?;
        }
    }

    Ok(UniversalExportResult {
        xlsx_path: dest_xlsx.to_string_lossy().to_string(),
        csv_timeline_path: csv_path.to_string_lossy().to_string(),
        total_exported_records: total_exported,
    })
}
