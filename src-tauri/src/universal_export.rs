use crate::intel::universal_ioc::IocMatchItem;
use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::Connection;
use rust_xlsxwriter::{Format, Workbook};
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub struct UniversalExportResult {
    pub xlsx_path: String,
    pub csv_timeline_path: String,
    pub total_exported_records: usize,
}

pub fn export_forensic_workbook(
    conn: &Connection,
    dest_xlsx: &Path,
    analyst_name: &str,
) -> Result<UniversalExportResult> {
    let mut workbook = Workbook::new();
    let header_fmt = Format::new().set_bold();

    let input_date = Utc::now().format("%Y-%m-%d").to_string();

    // 1. MASTER TIMELINE Sheet
    let master_sheet = workbook.add_worksheet();
    master_sheet.set_name("MASTER TIMELINE")?;

    let master_headers = [
        "Input Date",
        "Analyst",
        "Date/Time (UTC)",
        "Host/Device",
        "Event Type & MITRE ATT&CK",
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

    // Query all matches
    let mut stmt = conn.prepare(
        "SELECT match_id, row_num, ioc_type, ioc_value, matched_field, matched_value, match_kind,
                is_suppressed, timestamp_utc, source_file, event_summary, raw_evidence
         FROM _ioc_matches ORDER BY timestamp_utc ASC, row_num ASC",
    )?;

    let mut row_idx: u32 = 1;
    let mut csv_lines = Vec::new();
    csv_lines.push(master_headers.join(","));

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

    let mut total_exported = 0;
    for res in rows {
        let item = res?;
        total_exported += 1;

        let time_str = item.timestamp_utc.unwrap_or_else(|| "Unknown".to_string());
        let event_type = format!("IOC [{}] {}", item.ioc_type, item.match_kind);
        let evidence_source = format!("{}#row={}", item.source_file, item.row_num);
        let malicious_flag = if item.is_suppressed { "Benign / Allowlist" } else { "Suspicious" };

        let cols = [
            input_date.as_str(),
            analyst_name,
            time_str.as_str(),
            "", // Host/Device
            event_type.as_str(),
            item.matched_field.as_str(),
            malicious_flag,
            "", // User
            "", // Source Host
            if item.ioc_type == "ip" { item.ioc_value.as_str() } else { "" },
            "", // Destination Host
            "", // Destination IP
            evidence_source.as_str(),
            "", // Event ID
            item.event_summary.as_str(),
        ];

        for (col_idx, val) in cols.iter().enumerate() {
            master_sheet.write_string(row_idx, col_idx as u16, *val)?;
        }

        // CSV line
        let csv_row = cols
            .iter()
            .map(|s| format!("\"{}\"", s.replace('"', "\"\"")))
            .collect::<Vec<_>>()
            .join(",");
        csv_lines.push(csv_row);

        row_idx += 1;
    }

    // 2. IOC Sheet
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

    let mut ioc_row_idx: u32 = 1;
    for r in ioc_rows {
        let (ioc_type, val, desc, enabled, is_ex) = r?;
        let status = if !enabled {
            "Disabled"
        } else if is_ex {
            "Exclusion / Allowlist"
        } else {
            "Active"
        };
        ioc_sheet.write_string(ioc_row_idx, 0, &ioc_type)?;
        ioc_sheet.write_string(ioc_row_idx, 1, &val)?;
        ioc_sheet.write_string(ioc_row_idx, 2, &desc)?;
        ioc_sheet.write_string(ioc_row_idx, 6, status)?;
        ioc_row_idx += 1;
    }

    // 3. INVENTORY Sheet
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

    // 4. SUSPICIOUS ACCOUNTS Sheet
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

    // Save workbook
    workbook.save(dest_xlsx).with_context(|| format!("saving workbook to {}", dest_xlsx.display()))?;

    // Also write CSV version
    let parent_dir = dest_xlsx.parent().unwrap_or_else(|| Path::new("."));
    let stem = dest_xlsx
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("MASTER_TIMELINE");
    let csv_path = parent_dir.join(format!("{stem}.csv"));
    let mut csv_file = File::create(&csv_path)?;
    csv_file.write_all(csv_lines.join("\n").as_bytes())?;

    // Also write PARSE_FAILURES.csv if failures exist
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
    fail_file.write_all(b"\"id\",\"source_path\",\"record_num\",\"raw_payload\",\"error_message\",\"occurred_at\"\n")?;
    for line in fail_rows {
        fail_file.write_all(line?.as_bytes())?;
        fail_file.write_all(b"\n")?;
    }

    Ok(UniversalExportResult {
        xlsx_path: dest_xlsx.to_string_lossy().to_string(),
        csv_timeline_path: csv_path.to_string_lossy().to_string(),
        total_exported_records: total_exported,
    })
}
