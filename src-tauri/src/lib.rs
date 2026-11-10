pub mod cloud_ai;
pub mod commands;
pub mod csv_import;
pub mod db;
pub mod excel_import;
pub mod export;
pub mod header_utils;
pub mod intel;
pub mod local_ai_manager;
pub mod local_ai_runtime;
pub mod query;
pub mod report;
pub mod semantic;
pub mod tabular_import;
pub mod universal_export;
pub mod timeline_session;
pub mod universal_import;

#[cfg(not(test))]
use commands::AppState;
#[cfg(not(test))]
use tauri::{path::BaseDirectory, Manager};

#[cfg(not(test))]
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .setup(|app| {
            let library_path = app
                .path()
                .resolve("intel/mitre_core.v1.json", BaseDirectory::Resource)?;
            intel::library::configure_builtin_library_path(library_path)?;
            let bec_library_path = app
                .path()
                .resolve("intel/bec_library.v1.json", BaseDirectory::Resource)?;
            intel::library::configure_builtin_bec_library_path(bec_library_path)?;
            let ignore_rules_path = app
                .path()
                .resolve("intel/ignore_rules.v1.json", BaseDirectory::Resource)?;
            intel::ignore_rules::configure_builtin_ignore_rules_path(ignore_rules_path)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::list_sheets,
            commands::import_sheet,
            commands::query_rows,
            commands::count_rows,
            commands::semantic_index_status,
            commands::build_semantic_index,
            commands::parse_guided_query,
            commands::accept_guided_query,
            commands::run_guided_query,
            commands::set_guided_parse_decision,
            commands::clear_loaded_file,
            commands::detect_column_roles,
            commands::set_column_role_status,
            commands::list_ignore_rules,
            commands::add_custom_ignore_rule,
            commands::delete_custom_ignore_rule,
            commands::set_ignore_rule_enabled,
            commands::analyze_timestamp_column,
            commands::normalize_timestamp_column,
            commands::export_data,
            commands::export_guided_data,
            commands::scan_intel_matches,
            commands::get_intel_matching_rows,
            commands::extract_iocs,
            commands::ask_analyst,
            commands::export_report,
            commands::cross_search_files,
            commands::cross_search_batch_files,
            commands::cross_ioc_overlap,
            commands::export_ioc_overlap_file,
            commands::export_batch_iocs_file,
            commands::export_text_file,
            commands::get_unified_ioc_events,
            commands::get_unified_batch_events,
            commands::export_unified_multisheet_xlsx,
            commands::get_row_raw_details,
            commands::scan_all_files_intel_matches,
            commands::batch_ensure_cached,
            commands::add_universal_iocs,
            commands::list_universal_iocs,
            commands::toggle_universal_ioc,
            commands::remove_universal_ioc,
            commands::run_universal_ioc_scan,
            commands::get_universal_ioc_matches,
            commands::get_ingest_audit,
            commands::get_log_analytics_summary,
            commands::export_forensic_workbook,
            commands::scan_evidence_directory,
            cloud_ai::gemini_generate,
            cloud_ai::gemini_test_connection,
            cloud_ai::gemini_list_models,
            local_ai_manager::local_ai_model_status,
            local_ai_manager::local_ai_download_model,
            local_ai_manager::local_ai_cancel_download,
            local_ai_manager::local_ai_remove_model,
            local_ai_manager::local_ai_list_models,
            local_ai_manager::local_ai_select_model,
            local_ai_manager::local_ai_get_selected_model,
            local_ai_runtime::local_ai_runtime_status,
            local_ai_runtime::local_ai_runtime_start,
            local_ai_runtime::local_ai_runtime_stop,
            local_ai_runtime::local_ai_cancel_analysis,
            local_ai_runtime::local_ai_runtime_diagnostics,
            local_ai_runtime::local_ai_analyze_evidence,
            timeline_session::prepare_unified_timeline_query,
            timeline_session::query_unified_timeline_page,
            timeline_session::count_unified_timeline,
            timeline_session::get_unified_timeline_row_details,
            timeline_session::cancel_unified_timeline_build,
            timeline_session::close_unified_timeline_session,
            timeline_session::export_unified_timeline_session_xlsx,
            timeline_session::export_unified_timeline_session_csv,
        ])
        .build(tauri::generate_context!())
        .expect("error while running tauri application");

    app.run(|_app_handle, event| {
        if matches!(event, tauri::RunEvent::Exit) {
            let _ = local_ai_runtime::GLOBAL_SUPERVISOR.stop();
        }
    });
}
