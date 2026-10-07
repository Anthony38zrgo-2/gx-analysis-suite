//! GX-016/C01: tests del contrato de comandos desktop.
//!
//! Cubren la frontera Rust (validación de solicitudes), la paridad
//! CLI↔desktop vía el contrato compartido, el comando `scan` con su canal de
//! progreso y el acceso paginado a resultados/historial (C01).

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use gx_core::budget::ExecutionBudget;
use gx_core::models::{AnalysisRequest, QgPolicy, QgVerdict, ScanCompletion};
use gx_engine::runtime;
use gx_linter_desktop_lib::commands::{
    findings_page, history_issues_page, history_object_window, object_window, persist_history_for,
    read_object_source, run_scan, text_summary_for, validate_request, DesktopState,
    ScanProgressEvent,
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
        retain_sensitive_evidence: false,
        discovery: Default::default(),
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
/// reproduce el golden adjudicado: 23 hallazgos (15 ERROR / 8 WARNING).
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
    assert_eq!(result.metrics.total_findings, 23);
    assert_eq!(result.metrics.errors, 15);
    assert_eq!(result.metrics.warnings, 8);
    assert_eq!(result.verdict, QgVerdict::Reject);
}

/// C01: el comando `scan` devuelve un resumen y las páginas reconstruyen
/// exactamente los findings del engine directo (sin lógica en TypeScript).
#[test]
fn desktop_scan_matches_direct_engine_analysis() {
    let (state, dir) = temp_state("gx_desktop_parity");
    let request = gui_request(vec![fixture("sources/ejemplo_codigo.txt")], false);
    let (channel, _events) = capture_channel();

    let summary =
        tauri::async_runtime::block_on(run_scan(request.clone(), channel, &state)).unwrap();
    let direct = runtime::analyze(&request);

    assert_eq!(summary.metrics, direct.metrics);
    assert_eq!(summary.verdict, direct.verdict);
    assert_eq!(summary.failures, direct.failures);
    assert_eq!(summary.findings_total, direct.findings.len());
    assert_eq!(summary.scanned_files, direct.scanned_files);
    assert!(summary.history_error.is_none());

    let page = findings_page(
        &state,
        summary.session_id,
        None,
        Some(500),
        None,
        None,
        None,
    )
    .unwrap();
    assert_eq!(page.total, direct.findings.len());
    assert_eq!(page.items, direct.findings, "misma evidencia, mismo orden");
    let _ = std::fs::remove_dir_all(&dir);
}

/// El comando `scan` emite Pending + Ok con el conteo de hallazgos y
/// persiste la corrida completa cuando `record_history` está activo.
#[test]
fn scan_emits_progress_and_persists_history() {
    let (state, dir) = temp_state("gx_desktop_scan_progress");
    let request = gui_request(vec![fixture("sources/ejemplo_codigo.txt")], true);
    let (channel, events) = capture_channel();

    let summary = tauri::async_runtime::block_on(run_scan(request, channel, &state)).unwrap();
    assert_eq!(summary.metrics.total_findings, 23);
    assert_eq!(summary.verdict, QgVerdict::Reject);
    assert!(summary.history_error.is_none(), "la persistencia fue OK");

    let events = events.lock().unwrap();
    assert_eq!(events.len(), 2, "un Pending + un Ok: {events:?}");
    assert!(matches!(events[0], ScanProgressEvent::Pending { .. }));
    match &events[1] {
        ScanProgressEvent::Ok { findings_count, .. } => assert_eq!(*findings_count, 23),
        other => panic!("se esperaba Ok, llegó {other:?}"),
    }
    drop(events);

    // La base inyectada conserva la corrida y sus hallazgos con identidad.
    let conn = gx_storage::db::init_db_at(&dir.join("gx_linter.db")).unwrap();
    let runs = audit_dao::list_runs(&conn, 10).unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].total_findings, 23);
    assert_eq!(runs[0].verdict.as_deref(), Some("reject"));
    assert!(!runs[0].qg_passed);
    let issues = audit_dao::get_issues_for_run(&conn, runs[0].id).unwrap();
    assert_eq!(issues.len(), 23);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Un input no soportado se reporta como Error (evento + failure + veredicto
/// Error), jamás como escaneo limpio.
#[test]
fn scan_reports_unsupported_input_as_error_never_clean() {
    let (state, dir) = temp_state("gx_desktop_scan_error");
    let request = gui_request(vec![fixture("sources/unusable_package.xpz")], false);
    let (channel, events) = capture_channel();

    let summary = tauri::async_runtime::block_on(run_scan(request, channel, &state)).unwrap();
    assert_eq!(summary.verdict, QgVerdict::Error);
    assert_eq!(summary.metrics.total_findings, 0);
    assert_eq!(summary.findings_total, 0);
    assert!(!summary.failures.is_empty());

    let events = events.lock().unwrap();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ScanProgressEvent::Error { .. })),
        "debe haber un evento Error: {events:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// C01/C03: la página se acota al `limit` pedido y los filtros se resuelven
/// en la frontera Rust (el frontend nunca recibe el resultado completo).
#[test]
fn findings_page_is_bounded_and_filters_server_side() {
    let (state, dir) = temp_state("gx_desktop_page");
    let request = gui_request(vec![fixture("sources/ejemplo_codigo.txt")], false);
    let (channel, _) = capture_channel();
    let summary = tauri::async_runtime::block_on(run_scan(request, channel, &state)).unwrap();

    let page = findings_page(
        &state,
        summary.session_id,
        Some(0),
        Some(5),
        None,
        None,
        None,
    )
    .unwrap();
    assert_eq!(page.items.len(), 5, "página acotada");
    assert_eq!(page.total, 23);
    assert_eq!(page.filtered_total, 23);
    assert!(!page.rules.is_empty(), "reglas para el filtro");

    let errors = findings_page(
        &state,
        summary.session_id,
        None,
        Some(500),
        Some("ERROR".to_string()),
        None,
        None,
    )
    .unwrap();
    assert_eq!(errors.filtered_total, 15);
    assert!(errors.items.iter().all(|i| i.severity.as_str() == "ERROR"));

    let hardcode = findings_page(
        &state,
        summary.session_id,
        None,
        Some(500),
        None,
        Some("GX.2.5".to_string()),
        None,
    )
    .unwrap();
    assert_eq!(hardcode.filtered_total, 3);
    assert!(hardcode.items.iter().all(|i| i.rule_id == "GX.2.5"));

    let search = findings_page(
        &state,
        summary.session_id,
        None,
        Some(500),
        None,
        None,
        Some("vip".to_string()),
    )
    .unwrap();
    assert!(search.filtered_total >= 1, "búsqueda server-side");
    let _ = std::fs::remove_dir_all(&dir);
}

/// C01: un fallo de persistencia NO descarta los diagnostics; el resumen
/// expone `history_error` y las páginas siguen disponibles.
#[test]
fn persistence_failure_keeps_diagnostics_and_reports_warning() {
    let dir = std::env::temp_dir().join("gx_desktop_history_fail");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let blocker = dir.join("not_a_db.bin");
    std::fs::write(&blocker, b"esto no es sqlite").unwrap();
    let state = DesktopState::with_db_path(blocker);

    let request = gui_request(vec![fixture("sources/ejemplo_codigo.txt")], true);
    let (channel, _) = capture_channel();
    let summary = tauri::async_runtime::block_on(run_scan(request, channel, &state)).unwrap();

    assert!(
        summary.history_error.is_some(),
        "debe reportar el fallo de historial como warning"
    );
    assert_eq!(summary.findings_total, 23, "los diagnostics se conservan");
    let page = findings_page(
        &state,
        summary.session_id,
        None,
        Some(500),
        None,
        None,
        None,
    )
    .unwrap();
    assert_eq!(page.items.len(), 23);
    let _ = std::fs::remove_dir_all(&dir);
}

/// C01: las corridas canceladas no se persisten (limpieza explícita).
#[test]
fn cancelled_runs_are_not_persisted() {
    let (state, dir) = temp_state("gx_desktop_cancelled_history");
    let request = gui_request(vec![fixture("sources/ejemplo_codigo.txt")], true);
    let cancel = AtomicBool::new(true);
    let cancelled =
        runtime::analyze_with_options(&request, None, Some(&cancel), &ExecutionBudget::default());
    assert_eq!(cancelled.completion, ScanCompletion::Cancelled);

    persist_history_for(&state, &request, &cancelled).unwrap();
    let conn = gx_storage::db::init_db_at(&dir.join("gx_linter.db")).unwrap();
    assert_eq!(
        audit_dao::list_runs(&conn, 10).unwrap().len(),
        0,
        "una corrida cancelada no deja historial"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// C01: el historial pagina por cursor keyset y los handles inválidos fallan
/// de forma predecible (nunca panic ni resultado equivocado).
#[test]
fn history_keyset_pagination_and_invalid_handles() {
    let (state, dir) = temp_state("gx_desktop_history_page");
    {
        let mut conn = gx_storage::db::init_db_at(&dir.join("gx_linter.db")).unwrap();
        let run = audit_dao::AuditRun {
            file_path: "x.xpz".to_string(),
            file_name: "x.xpz".to_string(),
            triggered_by: "test".to_string(),
            total_findings: 5,
            errors: 5,
            qg_passed: false,
            engine_version: "test".to_string(),
            ..Default::default()
        };
        let issues: Vec<_> = (0..5)
            .map(|i| gx_core::models::Issue {
                rule_id: "GX.2.6".to_string(),
                severity: gx_core::models::Severity::Error,
                line_number: i,
                line_content: format!("linea {i}"),
                description: "desc".to_string(),
                file_path: PathBuf::from("x.xpz"),
                object: None,
                category: None,
                confidence: None,
                cwe: None,
                trace: None,
            })
            .collect();
        audit_dao::persist_run(&mut conn, &run, &issues).unwrap();
    }

    let first = history_issues_page(&state, 1, None, Some(2)).unwrap();
    assert_eq!(first.items.len(), 2);
    let cursor = first.next_cursor.expect("hay más páginas");
    let second = history_issues_page(&state, 1, Some(cursor), Some(2)).unwrap();
    assert_eq!(second.items.len(), 2);
    let third = history_issues_page(&state, 1, second.next_cursor, Some(2)).unwrap();
    assert_eq!(third.items.len(), 1);
    assert!(third.next_cursor.is_none());

    let invalid = history_issues_page(&state, 1, Some("basura".to_string()), Some(2)).unwrap_err();
    assert_eq!(invalid.code, "invalid_input");

    let missing = findings_page(&state, 999, None, None, None, None, None).unwrap_err();
    assert_eq!(missing.code, "not_found");
    let _ = std::fs::remove_dir_all(&dir);
}

/// C01: el resumen textual se renderiza desde la sesión (sin reenviar el
/// resultado desde Vue).
#[test]
fn text_summary_renders_from_session() {
    let (state, dir) = temp_state("gx_desktop_summary");
    let request = gui_request(vec![fixture("sources/ejemplo_codigo.txt")], false);
    let (channel, _) = capture_channel();
    let summary = tauri::async_runtime::block_on(run_scan(request, channel, &state)).unwrap();

    let text = text_summary_for(&state, summary.session_id).unwrap();
    assert!(text.contains("quality gate: REJECT"));
    assert!(text_summary_for(&state, 12345).is_err());
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
        "unsupported_schema"
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

/// C02: la ventana del visor está acotada, mapea a líneas físicas del
/// miembro, usa caché y rechaza ids/sesiones/handles inválidos.
#[test]
fn object_window_is_bounded_cached_and_strict() {
    let (state, dir) = temp_state("gx_desktop_window");
    let xpz = fixture("sources/sample_package.xpz");
    let request = gui_request(vec![xpz.clone()], false);
    let (channel, _) = capture_channel();
    let summary = tauri::async_runtime::block_on(run_scan(request, channel, &state)).unwrap();

    let container = xpz.to_string_lossy().to_string();
    let first = object_window(
        &state,
        summary.session_id,
        &container,
        "PkgDemo/ProcMalo.xml",
        "ProcMalo",
        Some(1),
        Some(5),
    )
    .unwrap();
    assert_eq!(first.lines.len(), 5, "ventana acotada");
    assert!(!first.cached, "primera lectura extrae");
    let line3 = first.lines.iter().find(|l| l.text_line == 3).unwrap();
    assert_eq!(line3.member_line, 6, "texto 3 → miembro 6");
    assert_eq!(
        first.lines.first().unwrap().member_line,
        first.code_start_line,
        "la ventana arranca en la línea física del CDATA"
    );

    let second = object_window(
        &state,
        summary.session_id,
        &container,
        "PkgDemo/ProcMalo.xml",
        "ProcMalo",
        Some(1),
        Some(5),
    )
    .unwrap();
    assert!(second.cached, "segunda lectura desde caché");
    assert!(!second.source_modified);

    let unknown = object_window(
        &state,
        summary.session_id,
        &container,
        "PkgDemo/ProcMalo.xml",
        "NoExiste",
        None,
        None,
    )
    .unwrap_err();
    assert_eq!(unknown.code, "not_found");

    let foreign = fixture("sources/clean_object.txt");
    let forbidden = object_window(
        &state,
        summary.session_id,
        foreign.to_str().unwrap(),
        "clean_object.txt",
        "clean_object",
        None,
        None,
    )
    .unwrap_err();
    assert_eq!(forbidden.code, "forbidden", "fuera de la sesión aprobada");

    let bad_session = object_window(
        &state,
        999,
        &container,
        "PkgDemo/ProcMalo.xml",
        "ProcMalo",
        None,
        None,
    )
    .unwrap_err();
    assert_eq!(bad_session.code, "not_found");
    let _ = std::fs::remove_dir_all(&dir);
}

/// C04: la ventana histórica sólo acepta contenedores registrados por la
/// corrida (nunca paths arbitrarios).
#[test]
fn history_window_is_scoped_to_recorded_containers() {
    let (state, dir) = temp_state("gx_desktop_history_window");
    let xpz = fixture("sources/sample_package.xpz");
    let request = gui_request(vec![xpz.clone()], true);
    let (channel, _) = capture_channel();
    let _ = tauri::async_runtime::block_on(run_scan(request, channel, &state)).unwrap();

    let container = xpz.to_string_lossy().to_string();
    let window = history_object_window(
        &state,
        1,
        &container,
        "PkgDemo/ProcMalo.xml",
        "ProcMalo",
        Some(1),
        Some(3),
    )
    .unwrap();
    assert_eq!(window.lines.len(), 3);
    assert_eq!(window.session_id, 0, "ventana histórica sin sesión");

    let foreign = fixture("sources/clean_object.txt");
    let forbidden = history_object_window(
        &state,
        1,
        foreign.to_str().unwrap(),
        "clean_object.txt",
        "clean_object",
        None,
        None,
    )
    .unwrap_err();
    assert_eq!(forbidden.code, "forbidden");
    let _ = std::fs::remove_dir_all(&dir);
}

/// C02: si el contenedor cambia entre lecturas, la ventana lo reporta y
/// re-extrae (nunca evidencia vieja silenciosa).
#[test]
fn object_window_detects_modified_source() {
    let (state, dir) = temp_state("gx_desktop_window_modified");
    let source_file = dir.join("copia.txt");
    std::fs::copy(fixture("sources/ejemplo_codigo.txt"), &source_file).unwrap();
    let request = gui_request(vec![source_file.clone()], false);
    let (channel, _) = capture_channel();
    let summary = tauri::async_runtime::block_on(run_scan(request, channel, &state)).unwrap();

    let container = source_file.to_string_lossy().to_string();
    let first = object_window(
        &state,
        summary.session_id,
        &container,
        "copia.txt",
        "copia",
        Some(1),
        Some(10),
    )
    .unwrap();
    assert!(!first.source_modified);

    std::thread::sleep(std::time::Duration::from_millis(20));
    let original = std::fs::read_to_string(&source_file).unwrap();
    std::fs::write(&source_file, format!("{original}\n// cambio\n")).unwrap();

    let second = object_window(
        &state,
        summary.session_id,
        &container,
        "copia.txt",
        "copia",
        Some(1),
        Some(10),
    )
    .unwrap();
    assert!(second.source_modified, "el cambio debe ser visible");
    assert!(!second.cached, "se re-extrae la fuente");
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

    // C02: un id desconocido en un miembro existente NO cae al primer
    // candidato.
    let wrong_id = read_object_source(
        xpz.to_string_lossy().to_string(),
        "PkgDemo/ProcMalo.xml".to_string(),
        Some("OtroObjeto".to_string()),
    )
    .unwrap_err();
    assert_eq!(wrong_id.code, "not_found");
}
