//! GX Linter desktop shell (GX-015/GX-016).

pub mod commands;

use commands::DesktopState;

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(DesktopState::default())
        .invoke_handler(tauri::generate_handler![
            commands::ping,
            commands::scan,
            commands::cancel_scan,
            commands::pick_source_files,
            commands::list_rules,
            commands::set_rule_enabled,
            commands::get_settings,
            commands::set_settings,
            commands::list_audit_runs,
            commands::get_audit_issues,
            commands::render_text_summary,
            commands::read_object_source,
            commands::save_pdf,
        ])
        .run(tauri::generate_context!())
        .expect("error al iniciar la aplicación Tauri");
}
