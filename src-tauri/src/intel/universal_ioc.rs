use crate::db;
use anyhow::Result;
use chrono::Utc;
use regex::Regex;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum UniversalIocType {
    Ip,
    Cidr,
    Domain,
    Url,
    Email,
    Username,
    Hostname,
    Filename,
    Path,
    Hash,
    RegistryKey,
    ProcessName,
    CommandLine,
    Guid,
    ResourceName,
    CustomString,
    Regex,
}

impl UniversalIocType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Cidr => "cidr",
            Self::Domain => "domain",
            Self::Url => "url",
            Self::Email => "email",
            Self::Username => "username",
            Self::Hostname => "hostname",
            Self::Filename => "filename",
            Self::Path => "path",
            Self::Hash => "hash",
            Self::RegistryKey => "registry_key",
            Self::ProcessName => "process_name",
            Self::CommandLine => "command_line",
            Self::Guid => "guid",
            Self::ResourceName => "resource_name",
            Self::CustomString => "custom_string",
            Self::Regex => "regex",
        }
    }

    pub fn from_str_loose(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "ip" | "ipv4" | "ipv6" | "ip_address" => Self::Ip,
            "cidr" | "subnet" | "range" => Self::Cidr,
            "domain" | "domain_name" => Self::Domain,
            "url" | "uri" => Self::Url,
            "email" | "mail" => Self::Email,
            "username" | "user" | "account" => Self::Username,
            "hostname" | "host" | "computer" => Self::Hostname,
            "filename" | "file" => Self::Filename,
            "path" | "filepath" => Self::Path,
            "hash" | "md5" | "sha1" | "sha256" => Self::Hash,
            "registry" | "reg" | "registry_key" => Self::RegistryKey,
            "process" | "process_name" | "proc" => Self::ProcessName,
            "command" | "command_line" | "cmd" => Self::CommandLine,
            "guid" | "uuid" => Self::Guid,
            "resource" | "resource_name" => Self::ResourceName,
            "regex" | "pattern" => Self::Regex,
            _ => Self::CustomString,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UniversalIocEntry {
    pub id: i64,
    pub ioc_type: String,
    pub value: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub is_exclusion: bool,
    pub added_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IocMatchItem {
    pub match_id: i64,
    pub row_num: i64,
    pub ioc_id: i64,
    pub ioc_type: String,
    pub ioc_value: String,
    pub matched_field: String,
    pub matched_value: String,
    pub match_kind: String,
    pub is_suppressed: bool,
    pub timestamp_utc: Option<String>,
    pub source_file: String,
    pub event_summary: String,
    pub raw_evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorrelationPivot {
    pub pivot_type: String,
    pub pivot_value: String,
    pub event_count: i64,
    pub related_iocs: Vec<String>,
    pub earliest_time: Option<String>,
    pub latest_time: Option<String>,
    pub sample_events: Vec<IocMatchItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UniversalScanSummary {
    pub total_rows_scanned: i64,
    pub total_matches: i64,
    pub unique_matched_rows: i64,
    pub unique_iocs_hit: i64,
    pub suppressed_matches: i64,
    pub parse_failures_count: i64,
    pub matches: Vec<IocMatchItem>,
    pub correlated_pivots: Vec<CorrelationPivot>,
}

pub fn auto_detect_ioc_type(indicator: &str) -> UniversalIocType {
    let s = indicator.trim();

    if s.starts_with("regex:") {
        return UniversalIocType::Regex;
    }

    if let Some((ip_str, prefix_str)) = s.split_once('/') {
        if ip_str.parse::<IpAddr>().is_ok() && prefix_str.parse::<u8>().is_ok() {
            return UniversalIocType::Cidr;
        }
    }

    if s.parse::<IpAddr>().is_ok() {
        return UniversalIocType::Ip;
    }

    if s.starts_with("http://") || s.starts_with("https://") || s.starts_with("ftp://") {
        return UniversalIocType::Url;
    }

    if s.contains('@') && !s.contains('/') && !s.contains('\\') && s.split('@').count() == 2 {
        let parts: Vec<&str> = s.split('@').collect();
        if parts[1].contains('.') {
            return UniversalIocType::Email;
        }
    }

    if s.len() == 36 && s.matches('-').count() == 4 {
        let clean = s.replace('-', "");
        if clean.chars().all(|c| c.is_ascii_hexdigit()) {
            return UniversalIocType::Guid;
        }
    }

    if (s.len() == 32 || s.len() == 40 || s.len() == 64) && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return UniversalIocType::Hash;
    }

    let upper = s.to_ascii_uppercase();
    if upper.starts_with("HKLM\\")
        || upper.starts_with("HKCU\\")
        || upper.starts_with("HKEY_")
        || upper.starts_with("HKCR\\")
    {
        return UniversalIocType::RegistryKey;
    }

    if (s.len() >= 3 && s.chars().nth(1) == Some(':') && (s.contains('\\') || s.contains('/')))
        || s.starts_with('/')
        || s.starts_with("\\\\")
    {
        return UniversalIocType::Path;
    }

    if s.ends_with(".exe") || s.ends_with(".dll") || s.ends_with(".ps1") || s.ends_with(".bat") || s.ends_with(".sh") {
        return UniversalIocType::ProcessName;
    }

    if s.contains(' ')
        && (s.contains('-') || s.contains('/') || s.contains('\\'))
        && (s.to_ascii_lowercase().contains(".exe")
            || s.to_ascii_lowercase().contains("cmd")
            || s.to_ascii_lowercase().contains("powershell")
            || s.to_ascii_lowercase().contains("bash")
            || s.to_ascii_lowercase().contains("sh"))
    {
        return UniversalIocType::CommandLine;
    }

    let file_exts = [
        ".docx", ".doc", ".xlsx", ".xls", ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar",
        ".txt", ".csv", ".json", ".xml", ".evtx", ".sys", ".drv", ".vbs", ".js", ".py", ".tmp",
    ];
    if file_exts.iter().any(|ext| s.to_ascii_lowercase().ends_with(ext)) {
        return UniversalIocType::Filename;
    }

    if !s.contains(' ')
        && s.contains('.')
        && !s.ends_with('.')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return UniversalIocType::Domain;
    }

    UniversalIocType::CustomString
}

pub struct CidrMatcher {
    network_u32: u32,
    mask_u32: u32,
    original_str: String,
}

impl CidrMatcher {
    pub fn parse(cidr_str: &str) -> Option<Self> {
        let (ip_part, prefix_part) = cidr_str.split_once('/')?;
        let ip: Ipv4Addr = ip_part.trim().parse().ok()?;
        let prefix: u32 = prefix_part.trim().parse().ok()?;
        if prefix > 32 {
            return None;
        }

        let mask: u32 = if prefix == 0 {
            0
        } else {
            !0u32 << (32 - prefix)
        };

        let ip_u32 = u32::from(ip);
        Some(Self {
            network_u32: ip_u32 & mask,
            mask_u32: mask,
            original_str: cidr_str.to_string(),
        })
    }

    pub fn contains_ip(&self, ip: Ipv4Addr) -> bool {
        (u32::from(ip) & self.mask_u32) == self.network_u32
    }

    pub fn contains_str(&self, ip_str: &str) -> bool {
        if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
            self.contains_ip(ip)
        } else {
            false
        }
    }
}

pub struct CompiledUniversalIocs {
    pub exact_tokens: HashMap<String, (i64, String, bool)>,
    pub substrings: Vec<(String, i64, String, bool)>,
    pub cidrs: Vec<(CidrMatcher, i64, bool)>,
    pub regexes: Vec<(Regex, i64, String, bool)>,
}

impl CompiledUniversalIocs {
    pub fn load_active(conn: &Connection) -> Result<Self> {
        let mut exact_tokens = HashMap::new();
        let mut substrings = Vec::new();
        let mut cidrs = Vec::new();
        let mut regexes = Vec::new();

        let mut stmt = conn.prepare(
            "SELECT id, ioc_type, value, is_exclusion FROM _universal_iocs WHERE enabled = 1",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)? != 0,
            ))
        })?;

        for r in rows {
            let (id, ioc_type, val, is_exclusion) = r?;
            let trimmed = val.trim();
            if trimmed.is_empty() {
                continue;
            }

            match ioc_type.as_str() {
                "cidr" => {
                    if let Some(matcher) = CidrMatcher::parse(trimmed) {
                        cidrs.push((matcher, id, is_exclusion));
                    }
                }
                "regex" => {
                    let pat = if let Some(stripped) = trimmed.strip_prefix("regex:") {
                        stripped
                    } else {
                        trimmed
                    };
                    if let Ok(re) = Regex::new(pat) {
                        regexes.push((re, id, ioc_type, is_exclusion));
                    }
                }
                "url" | "path" | "command_line" | "custom_string" => {
                    substrings.push((trimmed.to_ascii_lowercase(), id, ioc_type, is_exclusion));
                }
                _ => {
                    exact_tokens.insert(
                        trimmed.to_ascii_lowercase(),
                        (id, ioc_type.clone(), is_exclusion),
                    );
                    if ioc_type == "domain" || ioc_type == "filename" {
                        substrings.push((trimmed.to_ascii_lowercase(), id, ioc_type, is_exclusion));
                    }
                }
            }
        }

        Ok(Self {
            exact_tokens,
            substrings,
            cidrs,
            regexes,
        })
    }

    pub fn match_value(
        &self,
        raw_val: &str,
    ) -> Vec<(i64, String, String, String, bool)> {
        let mut results = Vec::new();
        let val_lower = raw_val.to_ascii_lowercase();
        let trimmed_val = raw_val.trim();

        if let Some((id, ioc_type, is_ex)) = self.exact_tokens.get(&val_lower) {
            results.push((*id, ioc_type.clone(), raw_val.to_string(), "exact".to_string(), *is_ex));
        }

        if let Ok(ip) = trimmed_val.parse::<Ipv4Addr>() {
            for (cidr, id, is_ex) in &self.cidrs {
                if cidr.contains_ip(ip) {
                    results.push((
                        *id,
                        "cidr".to_string(),
                        format!("{} in {}", ip, cidr.original_str),
                        "cidr".to_string(),
                        *is_ex,
                    ));
                }
            }
        }

        for (needle, id, ioc_type, is_ex) in &self.substrings {
            if val_lower.contains(needle) {
                results.push((*id, ioc_type.clone(), needle.clone(), "substring".to_string(), *is_ex));
            }
        }

        for (re, id, ioc_type, is_ex) in &self.regexes {
            if let Some(m) = re.find(raw_val) {
                results.push((
                    *id,
                    ioc_type.clone(),
                    m.as_str().to_string(),
                    "regex".to_string(),
                    *is_ex,
                ));
            }
        }

        results
    }
}

pub fn execute_universal_ioc_scan(
    conn: &mut Connection,
    mut on_progress: impl FnMut(i64, i64),
) -> Result<UniversalScanSummary> {
    let compiled = CompiledUniversalIocs::load_active(conn)?;
    let columns = db::load_columns(conn)?;

    conn.execute_batch("DELETE FROM _ioc_matches")?;

    let count_sql = "SELECT COUNT(*) FROM rows";
    let total_rows: i64 = conn.query_row(count_sql, [], |r| r.get(0)).unwrap_or(0);

    let col_names: Vec<String> = columns.iter().map(|c| c.sql_name.clone()).collect();
    let select_cols: Vec<String> = col_names.iter().map(|c| db::quote_ident(c)).collect();
    let query = format!(
        "SELECT row_num, {} FROM rows ORDER BY row_num",
        select_cols.join(", ")
    );

    let mut matches = Vec::new();
    let mut unique_rows = HashSet::new();
    let mut unique_iocs = HashSet::new();
    let mut suppressed_count = 0;
    let mut insert_batch: Vec<IocMatchItem> = Vec::with_capacity(1000);

    let now = Utc::now().to_rfc3339();

    // Query rows block (scoped so stmt & rows are dropped before transaction)
    {
        let mut stmt = conn.prepare(&query)?;
        let mut rows = stmt.query([])?;
        let mut scanned_rows: i64 = 0;

        while let Some(row) = rows.next()? {
            scanned_rows += 1;
            let row_num: i64 = row.get(0)?;

            let mut row_values: Vec<(String, String)> = Vec::with_capacity(columns.len());
            for (idx, col) in columns.iter().enumerate() {
                let val: Option<String> = row.get(idx + 1)?;
                if let Some(v) = val {
                    if !v.trim().is_empty() {
                        row_values.push((col.sql_name.clone(), v));
                    }
                }
            }

            let time_val = row_values
                .iter()
                .find(|(k, _)| k == "norm_time" || k.contains("time"))
                .map(|(_, v)| v.clone());
            let raw_evidence = row_values
                .iter()
                .find(|(k, _)| k == "raw_evidence")
                .map(|(_, v)| v.clone())
                .unwrap_or_default();

            for (col_name, val_str) in &row_values {
                if col_name == "raw_evidence" {
                    continue;
                }

                let hits = compiled.match_value(val_str);
                for (ioc_id, ioc_type, matched_val, match_kind, is_exclusion) in hits {
                    unique_rows.insert(row_num);
                    unique_iocs.insert(ioc_id);
                    if is_exclusion {
                        suppressed_count += 1;
                    }

                    let summary = format!(
                        "[{}] Hit in column `{col_name}`: {matched_val}",
                        ioc_type.to_ascii_uppercase()
                    );

                    let item = IocMatchItem {
                        match_id: 0,
                        row_num,
                        ioc_id,
                        ioc_type: ioc_type.clone(),
                        ioc_value: matched_val.clone(),
                        matched_field: col_name.clone(),
                        matched_value: val_str.clone(),
                        match_kind,
                        is_suppressed: is_exclusion,
                        timestamp_utc: time_val.clone(),
                        source_file: "imported_log".to_string(),
                        event_summary: summary,
                        raw_evidence: raw_evidence.clone(),
                    };
                    insert_batch.push(item.clone());
                    matches.push(item);
                }
            }

            if scanned_rows % 5000 == 0 {
                on_progress(scanned_rows, total_rows);
            }
        }
    }

    // Flush batch into SQLite in transaction
    let tx = conn.transaction()?;
    {
        let mut ins_stmt = tx.prepare(
            "INSERT INTO _ioc_matches (
                row_num, ioc_id, ioc_type, ioc_value, matched_field, matched_value, match_kind,
                is_suppressed, timestamp_utc, source_file, event_summary, raw_evidence, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        )?;
        for m in &insert_batch {
            ins_stmt.execute(rusqlite::params![
                m.row_num,
                m.ioc_id,
                m.ioc_type,
                m.ioc_value,
                m.matched_field,
                m.matched_value,
                m.match_kind,
                if m.is_suppressed { 1 } else { 0 },
                m.timestamp_utc,
                m.source_file,
                m.event_summary,
                m.raw_evidence,
                now
            ])?;
        }
    }
    tx.commit()?;

    let correlated_pivots = build_correlated_pivots(conn, &matches)?;

    let parse_failures_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM _parse_failures", [], |r| r.get(0))
        .unwrap_or(0);

    Ok(UniversalScanSummary {
        total_rows_scanned: total_rows,
        total_matches: matches.len() as i64,
        unique_matched_rows: unique_rows.len() as i64,
        unique_iocs_hit: unique_iocs.len() as i64,
        suppressed_matches: suppressed_count,
        parse_failures_count,
        matches,
        correlated_pivots,
    })
}

fn build_correlated_pivots(
    _conn: &Connection,
    matches: &[IocMatchItem],
) -> Result<Vec<CorrelationPivot>> {
    let mut pivots = Vec::new();
    let mut ip_groups: HashMap<String, Vec<IocMatchItem>> = HashMap::new();
    let mut user_groups: HashMap<String, Vec<IocMatchItem>> = HashMap::new();

    for m in matches {
        if m.is_suppressed {
            continue;
        }

        if m.ioc_type == "ip" {
            ip_groups
                .entry(m.ioc_value.clone())
                .or_default()
                .push(m.clone());
        } else if m.ioc_type == "username" || m.ioc_type == "email" {
            user_groups
                .entry(m.ioc_value.clone())
                .or_default()
                .push(m.clone());
        }
    }

    for (ip, events) in ip_groups {
        if events.len() >= 2 {
            let earliest = events.iter().filter_map(|e| e.timestamp_utc.as_deref()).min().map(String::from);
            let latest = events.iter().filter_map(|e| e.timestamp_utc.as_deref()).max().map(String::from);
            pivots.push(CorrelationPivot {
                pivot_type: "ip".to_string(),
                pivot_value: ip.clone(),
                event_count: events.len() as i64,
                related_iocs: vec![ip],
                earliest_time: earliest,
                latest_time: latest,
                sample_events: events.into_iter().take(5).collect(),
            });
        }
    }

    for (user, events) in user_groups {
        if events.len() >= 2 {
            let earliest = events.iter().filter_map(|e| e.timestamp_utc.as_deref()).min().map(String::from);
            let latest = events.iter().filter_map(|e| e.timestamp_utc.as_deref()).max().map(String::from);
            pivots.push(CorrelationPivot {
                pivot_type: "user".to_string(),
                pivot_value: user.clone(),
                event_count: events.len() as i64,
                related_iocs: vec![user],
                earliest_time: earliest,
                latest_time: latest,
                sample_events: events.into_iter().take(5).collect(),
            });
        }
    }

    Ok(pivots)
}

pub fn insert_bulk_iocs(
    conn: &mut Connection,
    raw_content: &str,
    default_description: Option<&str>,
) -> Result<(usize, usize)> {
    let now = Utc::now().to_rfc3339();
    let mut added = 0;
    let mut skipped = 0;

    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare(
            "INSERT OR IGNORE INTO _universal_iocs (ioc_type, value, description, enabled, is_exclusion, added_at)
             VALUES (?1, ?2, ?3, 1, 0, ?4)",
        )?;

        for line in raw_content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let (ioc_type_str, val, desc) = if trimmed.contains(',') {
                let parts: Vec<&str> = trimmed.splitn(3, ',').collect();
                if parts.len() >= 2 {
                    let inferred_type = UniversalIocType::from_str_loose(parts[0]);
                    let d = if parts.len() == 3 {
                        parts[2].trim().to_string()
                    } else {
                        default_description.unwrap_or("Imported IOC").to_string()
                    };
                    (inferred_type.as_str().to_string(), parts[1].trim().to_string(), d)
                } else {
                    let inferred = auto_detect_ioc_type(trimmed);
                    (inferred.as_str().to_string(), trimmed.to_string(), default_description.unwrap_or("Pasted IOC").to_string())
                }
            } else {
                let inferred = auto_detect_ioc_type(trimmed);
                (inferred.as_str().to_string(), trimmed.to_string(), default_description.unwrap_or("Pasted IOC").to_string())
            };

            let changes = stmt.execute(rusqlite::params![ioc_type_str, val, desc, now])?;
            if changes > 0 {
                added += 1;
            } else {
                skipped += 1;
            }
        }
    }
    tx.commit()?;
    Ok((added, skipped))
}
