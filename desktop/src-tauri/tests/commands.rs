//! GX-016: tests del contrato de comandos desktop.
//!
//! Cubren la frontera Rust (validación de solicitudes), la paridad
//! CLI↔desktop vía el contrato compartido y el comando `scan` con su canal
//! de progreso (mismo `AnalysisRequest` → mismo `AnalysisResult`).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use gx_core::models::{AnalysisRequest, QgPolicy, QgVerdict};
use gx_engine::runtime;
use gx_linter_desktop_lib::commands::{
    read_object_source, run_scan, validate_request, DesktopState, ScanProgressEvent,
};
use gx_storage::dao::{audit_dao, rules_dao};
use tauri::ipc::{Channel, InvokeResponseBody};

fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(rel)
}

/// Solicitud con el MISMO set que carga el CLI por defecto (la base local
/// recién sembrada) y la política porcentual de la GUI legada.
fn gui_request(inputs: Vec<PathBuf>, record_history: bool) -> AnalysisRequest {
    let conn = gx_storage::db::init_memory_db().expect("memory db");
    let enabled_rule_ids = rules_dao::get_enabled_ids(&conn).expect("enabled ids");
    AnalysisRequest {
        schema_version: 1,
        inputs,
        enabled_rule_ids,
        policy: QgPolicy::Percentage {
            max_error_pct: 10.0,
        },
        record_history,
    }
}

fn capture_channel() -> (
    Channel<ScanProgressEvent>,
    Arc<Mutex<Vec<ScanProgressEvent>>>,
) {
    let events: Arc<Mutex<Vec<ScanProgressEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = events.clone();
    let channel = Channel::new(move |body| {
        if let InvokeResponseBody::Json(json) = body {
            if let Ok(event) = serde_json::from_str::<ScanProgressEvent>(&json) {
                sink.lock().unwrap().push(event);
            }
        }
        Ok(())
    });
    (channel, events)
}

fn temp_state(name: &str) -> (DesktopState, PathBuf) {
    let dir = std::env::temp_dir().join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let state = DesktopState::with_db_path(dir.join("gx_linter.db"));
    (state, dir)
}

/// El set habilitado del GUI (base local) es idéntico al default del CLI y
/// reproduce el golden adjudicado: 22 hallazgos (14 ERROR / 8 WARNING).
#[test]
fn gui_rule_set_matches_cli_default_and_golden() {
    let conn = gx_storage::db::init_memory_db().unwrap();
    let gui_ids = rules_dao::get_enabled_ids(&conn).unwrap();
    let mut expected: Vec<String> = gx_storage::seed::default_enabled_ids()
        .into_iter()
        .collect();
    expected.sort();
    assert_eq!(gui_ids, expected, "GUI y CLI parten del mismo set");

    let request = gui_request(vec![fixture("sources/ejemplo_codigo.txt")], false);
    let result = runtime::analyze(&request);
    assert!(result.failures.is_empty());
    assert_eq!(result.metrics.total_findings, 22);
    assert_eq!(result.metrics.errors, 14);
    assert_eq!(result.metrics.warnings, 8);
    assert_eq!(result.verdict, QgVerdict::Reject);
}

/// Mismo `AnalysisRequest` → mismo `AnalysisResult` con o sin historial, y
/// el comando `scan` del desktop produce exactamente el resultado directo
/// del engine (no hay lógica duplicada en TypeScript).
#[test]
fn desktop_scan_matches_direct_engine_analysis() {
    let (state, dir) = temp_state("gx_desktop_parity");
    let request = gui_request(vec![fixture("sources/ejemplo_codigo.txt")], false);
    let (channel, _events) = capture_channel();

    let via_command =
        tauri::async_runtime::block_on(run_scan(request.clone(), channel, &state)).unwrap();
    let direct = runtime::analyze(&request);

    assert_eq!(via_command, direct);
    let _ = std::fs::remove_dir_all(&dir);
}

/// El comando `scan` emite Pending + Ok con el conteo de hallazgos y
/// persiste la corrida completa cuando `record_history` está activo.
#[test]
fn scan_emits_progress_and_persists_history() {
    let (state, dir) = temp_state("gx_desktop_scan_progress");
    let request = gui_request(vec![fixture("sources/ejemplo_codigo.txt")], true);
    let (channel, events) = capture_channel();

    let result = tauri::async_runtime::block_on(run_scan(request, channel, &state)).unwrap();
    assert_eq!(result.metrics.total_findings, 22);
    assert_eq!(result.verdict, QgVerdict::Reject);

    let events = events.lock().unwrap();
    assert_eq!(events.len(), 2, "un Pending + un Ok: {events:?}");
    assert!(matches!(events[0], ScanProgressEvent::Pending { .. }));
    match &events[1] {
        ScanProgressEvent::Ok { findings_count, .. } => assert_eq!(*findings_count, 22),
        other => panic!("se esperaba Ok, llegó {other:?}"),
    }
    drop(events);

    // La base inyectada conserva la corrida y sus hallazgos con identidad.
    let conn = gx_storage::db::init_db_at(&dir.join("gx_linter.db")).unwrap();
    let runs = audit_dao::list_runs(&conn, 10).unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].total_findings, 22);
    assert_eq!(runs[0].verdict.as_deref(), Some("reject"));
    assert!(!runs[0].qg_passed);
    let issues = audit_dao::get_issues_for_run(&conn, runs[0].id).unwrap();
    assert_eq!(issues.len(), 22);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Un input no soportado se reporta como Error (evento + failure + veredicto
/// Error), jamás como escaneo limpio.
#[test]
fn scan_reports_unsupported_input_as_error_never_clean() {
    let (state, dir) = temp_state("gx_desktop_scan_error");
    let request = gui_request(vec![fixture("sources/unusable_package.xpz")], false);
    let (channel, events) = capture_channel();

    let result = tauri::async_runtime::block_on(run_scan(request, channel, &state)).unwrap();
    assert_eq!(result.verdict, QgVerdict::Error);
    assert_eq!(result.metrics.total_findings, 0);
    assert!(!result.failures.is_empty());

    let events = events.lock().unwrap();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ScanProgressEvent::Error { .. })),
        "debe haber un evento Error: {events:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Validación de frontera: schema, paths inexistentes, set vacío y reglas
/// desconocidas devuelven códigos estructurados (nunca panic).
#[test]
fn boundary_validation_rejects_bad_requests() {
    let base = gui_request(vec![fixture("sources/ejemplo_codigo.txt")], false);

    let mut missing = base.clone();
    missing.inputs = vec![PathBuf::from("ruta/que/no/existe.txt")];
    assert_eq!(
        validate_request(&missing).unwrap_err().code,
        "invalid_input"
    );

    let mut no_rules = base.clone();
    no_rules.enabled_rule_ids = Vec::new();
    assert_eq!(
        validate_request(&no_rules).unwrap_err().code,
        "invalid_rules"
    );

    let mut unknown = base.clone();
    unknown.enabled_rule_ids = vec!["GX.9.9".to_string()];
    assert_eq!(
        validate_request(&unknown).unwrap_err().code,
        "invalid_rules"
    );

    let mut bad_schema = base.clone();
    bad_schema.schema_version = 2;
    assert_eq!(
        validate_request(&bad_schema).unwrap_err().code,
        "invalid_input"
    );

    let mut no_inputs = base;
    no_inputs.inputs = Vec::new();
    assert_eq!(
        validate_request(&no_inputs).unwrap_err().code,
        "invalid_input"
    );
}

/// GX-018: una base local existente (instalación previa) conserva flags de
/// reglas y historial al reabrirse con la versión nueva.
#[test]
fn existing_user_db_preserves_rules_and_history_on_upgrade() {
    let (state, dir) = temp_state("gx_desktop_upgrade");
    let db = dir.join("gx_linter.db");

    // "Instalación previa": el usuario deshabilitó una regla.
    {
        let conn = gx_storage::db::init_db_at(&db).unwrap();
        rules_dao::set_enabled(&conn, "GX.2.3", false).unwrap();
    }

    // La versión nueva persiste una corrida sobre esa misma base.
    let request = gui_request(vec![fixture("sources/ejemplo_codigo.txt")], true);
    let (channel, _) = capture_channel();
    let _ = tauri::async_runtime::block_on(run_scan(request, channel, &state)).unwrap();

    // Reapertura: ni el flag del usuario ni el historial se pierden.
    let conn = gx_storage::db::init_db_at(&db).unwrap();
    assert!(
        !rules_dao::is_rule_enabled(&conn, "GX.2.3").unwrap(),
        "el flag del usuario debe sobrevivir"
    );
    let runs = audit_dao::list_runs(&conn, 10).unwrap();
    assert_eq!(runs.len(), 1, "el historial debe sobrevivir");
    let _ = std::fs::remove_dir_all(&dir);
}

/// El visor obtiene el texto del miembro correcto con su línea base
/// (ProcMalo en el XPZ multi-objeto).
#[test]
fn read_object_source_returns_member_local_text() {
    let xpz = fixture("sources/sample_package.xpz");
    let source = read_object_source(
        xpz.to_string_lossy().to_string(),
        "PkgDemo/ProcMalo.xml".to_string(),
        Some("ProcMalo".to_string()),
    )
    .unwrap();
    assert_eq!(source.id, "ProcMalo");
    assert_eq!(source.object_type, "Procedure");
    assert_eq!(source.package, "PkgDemo");
    assert_eq!(source.member, "PkgDemo/ProcMalo.xml");
    assert!(source.text.contains("sub 'Inicializar'"));
    // text line 3 = "sub 'Inicializar'" → línea 6 del miembro.
    assert_eq!(source.code_start_line + 3 - 1, 6);

    let missing = read_object_source(
        xpz.to_string_lossy().to_string(),
        "PkgDemo/NoExiste.xml".to_string(),
        None,
    )
    .unwrap_err();
    assert_eq!(missing.code, "not_found");
}
