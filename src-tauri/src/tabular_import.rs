use crate::csv_import;
use crate::db::ColumnMeta;
use crate::excel_import;
use crate::universal_import::{self, UniversalFormat};
use anyhow::Result;
use std::path::Path;

pub struct ImportResult {
    pub columns: Vec<ColumnMeta>,
    pub row_count: i64,
    pub warning: Option<String>,
}

impl From<csv_import::ImportResult> for ImportResult {
    fn from(result: csv_import::ImportResult) -> Self {
        Self {
            columns: result.columns,
            row_count: result.row_count,
            warning: result.warning,
        }
    }
}

impl From<excel_import::ImportResult> for ImportResult {
    fn from(result: excel_import::ImportResult) -> Self {
        Self {
            columns: result.columns,
            row_count: result.row_count,
            warning: result.warning,
        }
    }
}

impl From<universal_import::UniversalImportResult> for ImportResult {
    fn from(result: universal_import::UniversalImportResult) -> Self {
        Self {
            columns: result.columns,
            row_count: result.row_count,
            warning: result.warning,
        }
    }
}

fn generic_sheet_name(path: &Path) -> String {
    path.file_stem()
        .map(|stem| stem.to_string_lossy().trim().to_string())
        .filter(|stem| !stem.is_empty())
        .unwrap_or_else(|| "LOG".to_string())
}

pub fn list_sheet_names(path: &Path) -> Result<Vec<String>> {
    match universal_import::detect_format(path)? {
        UniversalFormat::Excel => excel_import::list_sheet_names(path),
        _ => Ok(vec![generic_sheet_name(path)]),
    }
}

pub fn import_into_db(
    source_path: &Path,
    sheet_name: &str,
    db_path: &Path,
    on_progress: impl FnMut(u64, u64),
) -> Result<ImportResult> {
    let fmt = universal_import::detect_format(source_path)?;
    match fmt {
        UniversalFormat::Excel => {
            excel_import::import_into_db(source_path, sheet_name, db_path, on_progress)
                .map(Into::into)
        }
        UniversalFormat::Csv => {
            // Still using fast csv_import for standard CSVs, but initialize audit tables
            let res = csv_import::import_into_db(source_path, db_path, on_progress)?;
            if let Ok(conn) = crate::db::open(db_path) {
                let _ = universal_import::create_audit_tables_if_needed(&conn);
            }
            Ok(res.into())
        }
        _ => {
            universal_import::import_stream_into_db(source_path, db_path, fmt, on_progress)
                .map(Into::into)
        }
    }
}
