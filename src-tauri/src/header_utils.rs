use crate::db::ColumnMeta;
use std::collections::HashSet;

/// Turns raw header cells into SQL-safe, deduplicated, non-empty identifiers. `row_num` is
/// reserved for the synthetic primary key so a source column literally named "row_num" won't
/// collide with it.
pub fn sanitize_headers(raw: &[String]) -> Vec<ColumnMeta> {
    let mut used: HashSet<String> = HashSet::new();
    used.insert("row_num".to_string());

    raw.iter()
        .enumerate()
        .map(|(idx, original)| {
            let mut base = sanitize_one(original);
            if base.is_empty() {
                base = format!("column_{idx}");
            }
            if base.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                base = format!("c_{base}");
            }

            let mut candidate = base.clone();
            let mut n = 2;
            while used.contains(&candidate) {
                candidate = format!("{base}_{n}");
                n += 1;
            }
            used.insert(candidate.clone());

            ColumnMeta {
                sql_name: candidate,
                original_name: if original.trim().is_empty() {
                    format!("Column {}", idx + 1)
                } else {
                    original.clone()
                },
                col_index: idx,
                inferred_type: infer_type(original),
            }
        })
        .collect()
}

fn sanitize_one(header: &str) -> String {
    let mut out = String::new();
    let mut last_was_underscore = false;
    for c in header.chars() {
        let lower = c.to_ascii_lowercase();
        if lower.is_ascii_alphanumeric() {
            out.push(lower);
            last_was_underscore = false;
        } else if !last_was_underscore {
            out.push('_');
            last_was_underscore = true;
        }
    }
    out.trim_matches('_').to_string()
}

/// Header-name-only heuristic used solely to pick sensible default filter operators in the UI.
/// Never enforced at the storage layer and never used to normalize/rename columns across sources.
fn infer_type(header: &str) -> String {
    let h = header.to_ascii_lowercase();
    if h.contains("time")
        || h.contains("date")
        || h.contains("generated")
        || h.contains("createdat")
    {
        "timestamp"
    } else if h.contains("ip") || h.contains("address") {
        "ip"
    } else if h.contains("id") || h.contains("guid") {
        "identifier"
    } else {
        "text"
    }
    .to_string()
}

/// Generates synthetic column metadata when a file or sheet has no explicit headers.
/// For single-column logs (e.g. php-fpm-error, syslog, raw text logs), the column is
/// named `raw_record` with display label `Column 1`, ensuring downstream analytics and
/// MITRE/Intel matching automatically detect it as descriptive evidence text.
pub fn generate_synthetic_columns(count: usize) -> Vec<ColumnMeta> {
    if count <= 1 {
        vec![ColumnMeta {
            sql_name: "raw_record".to_string(),
            original_name: "Column 1".to_string(),
            col_index: 0,
            inferred_type: "text".to_string(),
        }]
    } else {
        (0..count)
            .map(|i| ColumnMeta {
                sql_name: format!("column_{i}"),
                original_name: format!("Column {}", i + 1),
                col_index: i,
                inferred_type: "text".to_string(),
            })
            .collect()
    }
}

/// Robust heuristic to check if the first row of cells looks like a table header or raw data.
/// Forensic exports frequently include headerless logs (such as single-column raw logs, syslogs,
/// or firewall CSV dumps). Rejecting them or misinterpreting row 1 as a header leads to loss of
/// evidence.
pub fn is_likely_header_row(cells: &[String]) -> bool {
    if cells.is_empty() {
        return false;
    }
    // If all cells are completely empty or whitespace, it's not a header row
    if cells.iter().all(|c| c.trim().is_empty()) {
        return false;
    }

    if cells.len() == 1 {
        let val = cells[0].trim();
        if val.is_empty() {
            return false;
        }
        let lower = val.to_ascii_lowercase();

        // Exact known single-column header tokens
        const KNOWN_SINGLE_HEADERS: &[&str] = &[
            "message", "msg", "log", "raw", "raw_record", "raw_log", "record", "line",
            "text", "event", "data", "column_1", "column 1", "entry", "payload",
            "content", "description", "details", "log_entry", "log_message",
        ];
        if KNOWN_SINGLE_HEADERS.contains(&lower.as_str()) {
            return true;
        }

        // If it starts with common log markers: `[`, `{`, log levels, or is long
        if val.starts_with('[')
            || val.starts_with('{')
            || val.starts_with("GET ")
            || val.starts_with("POST ")
            || val.starts_with("NOTICE:")
            || val.starts_with("ERROR:")
            || val.starts_with("INFO:")
            || val.starts_with("WARN")
            || val.starts_with("DEBUG:")
            || val.starts_with("CRITICAL:")
            || val.starts_with("FATAL:")
            || val.contains("PHP Fatal")
            || val.contains("PHP Warning")
            || val.contains("PHP Notice")
        {
            return false;
        }

        // Check if it contains timestamps or date patterns
        if contains_date_or_time_pattern(val) {
            return false;
        }

        // If it's longer than 35 characters or contains spaces and punctuation, it's data
        if val.len() > 35 || (val.contains(' ') && (val.contains(':') || val.contains('/') || val.contains('\\'))) {
            return false;
        }

        // Default for single column: treat as data to preserve forensic evidence
        return false;
    }

    // For multi-column rows:
    // Check if any cells exhibit strong data indicators (numbers, timestamps, IP addresses, JSON, long text)
    let mut data_indicator_count = 0;
    for cell in cells {
        let trimmed = cell.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Pure numbers (integer or float) are almost never headers
        if trimmed.parse::<i64>().is_ok() || trimmed.parse::<f64>().is_ok() {
            data_indicator_count += 1;
            continue;
        }
        // Date or timestamp patterns
        if contains_date_or_time_pattern(trimmed) {
            data_indicator_count += 1;
            continue;
        }
        // IP address patterns
        if looks_like_ip_addr(trimmed) {
            data_indicator_count += 1;
            continue;
        }
        // JSON or URL or HTTP request
        if trimmed.starts_with('{')
            || trimmed.starts_with("http://")
            || trimmed.starts_with("https://")
            || trimmed.starts_with("GET ")
            || trimmed.starts_with("POST ")
        {
            data_indicator_count += 1;
            continue;
        }
        // Very long cells (> 60 chars) or newlines
        if trimmed.len() > 60 || trimmed.contains('\n') || trimmed.contains('\r') {
            data_indicator_count += 1;
            continue;
        }
    }

    // If any strong data indicators are present, row 1 is DATA, not a header
    if data_indicator_count > 0 {
        return false;
    }

    true
}

fn contains_date_or_time_pattern(s: &str) -> bool {
    let bytes = s.as_bytes();
    for window in bytes.windows(4) {
        if window[0] == b'2' && window[1] == b'0' && window[2].is_ascii_digit() && window[3].is_ascii_digit() {
            return true;
        }
    }
    for window in bytes.windows(5) {
        if window[0].is_ascii_digit()
            && window[1].is_ascii_digit()
            && window[2] == b':'
            && window[3].is_ascii_digit()
            && window[4].is_ascii_digit()
        {
            return true;
        }
    }
    false
}

fn looks_like_ip_addr(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_headers_dedupes_and_handles_edge_cases() {
        let raw = vec![
            "TimeGenerated".to_string(),
            "".to_string(),
            "Account".to_string(),
            "Account".to_string(),
            "1stThing".to_string(),
            "row_num".to_string(),
            "Weird!! Header--Name".to_string(),
        ];
        let cols = sanitize_headers(&raw);
        let names: Vec<&str> = cols.iter().map(|c| c.sql_name.as_str()).collect();

        assert_eq!(names[0], "timegenerated");
        assert_eq!(names[1], "column_1");
        assert_eq!(names[2], "account");
        assert_eq!(names[3], "account_2");
        assert_eq!(names[4], "c_1stthing");
        assert_eq!(names[5], "row_num_2"); // collides with reserved row_num
        assert_eq!(names[6], "weird_header_name");

        let unique: HashSet<&str> = names.iter().copied().collect();
        assert_eq!(unique.len(), names.len());
    }

    #[test]
    fn infer_type_heuristics() {
        assert_eq!(infer_type("TimeGenerated"), "timestamp");
        assert_eq!(infer_type("EventDate"), "timestamp");
        assert_eq!(infer_type("SrcIpAddress"), "ip");
        assert_eq!(infer_type("EventID"), "identifier");
        assert_eq!(infer_type("CommandLine"), "text");
    }

    #[test]
    fn header_detection_single_column_log_vs_header() {
        // Raw log lines should NOT be treated as headers
        assert!(!is_likely_header_row(&["[24-Sep-2026 10:12:01] NOTICE: fpm is running, pid 1234".to_string()]));
        assert!(!is_likely_header_row(&["2026-09-24T10:12:01Z mysqld started".to_string()]));
        assert!(!is_likely_header_row(&["PHP Fatal error:  Uncaught Exception in /var/www/index.php:42".to_string()]));
        assert!(!is_likely_header_row(&["192.168.1.50 - - [24/Sep/2026:10:12:01 +0000] \"GET /api HTTP/1.1\" 200".to_string()]));

        // Legitimate single-column headers SHOULD be treated as headers
        assert!(is_likely_header_row(&["message".to_string()]));
        assert!(is_likely_header_row(&["raw_record".to_string()]));
        assert!(is_likely_header_row(&["Log".to_string()]));
        assert!(is_likely_header_row(&["Event".to_string()]));

        // Empty row is not a header
        assert!(!is_likely_header_row(&[]));
        assert!(!is_likely_header_row(&["   ".to_string()]));
    }

    #[test]
    fn header_detection_multi_column_data_vs_header() {
        // Legitimate column headers
        assert!(is_likely_header_row(&[
            "Timestamp".to_string(),
            "EventID".to_string(),
            "Source".to_string(),
            "User".to_string(),
            "Message".to_string(),
        ]));

        // Data rows without headers (e.g. firewall logs, timestamps, numbers, IPs)
        assert!(!is_likely_header_row(&[
            "2026-09-24 10:00:00".to_string(),
            "4624".to_string(),
            "Security".to_string(),
            "alice".to_string(),
            "192.168.1.100".to_string(),
        ]));
    }

    #[test]
    fn synthetic_columns_generation() {
        let single = generate_synthetic_columns(1);
        assert_eq!(single.len(), 1);
        assert_eq!(single[0].sql_name, "raw_record");
        assert_eq!(single[0].original_name, "Column 1");

        let multi = generate_synthetic_columns(3);
        assert_eq!(multi.len(), 3);
        assert_eq!(multi[0].sql_name, "column_0");
        assert_eq!(multi[0].original_name, "Column 1");
        assert_eq!(multi[1].sql_name, "column_1");
        assert_eq!(multi[1].original_name, "Column 2");
        assert_eq!(multi[2].sql_name, "column_2");
        assert_eq!(multi[2].original_name, "Column 3");
    }
}
