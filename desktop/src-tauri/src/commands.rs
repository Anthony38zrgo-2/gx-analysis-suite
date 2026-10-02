//! Comandos Tauri del desktop (GX-016).
//!
//! Capa FINA sobre el contrato compartido `AnalysisRequest`/`AnalysisResult`:
//! el frontend construye la solicitud y muestra el resultado, pero NUNCA
//! duplica lógica de lint. Toda entrada se valida en la frontera Rust y los
//! errores se devuelven estructurados (`CommandError`), nunca como panic.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::ipc::Channel;
use tauri::State;

use gx_core::filesystem::is_source_extension;
use gx_core::models::{AnalysisRequest, AnalysisResult, Issue};
use gx_engine::runtime::{self, FileProgress, FileProgressState};
use gx_storage::dao::{audit_dao, rules_dao, settings_dao};

/// Estado compartido: flag de cancelación y base local (inyectable en tests).
pub struct DesktopState {
    cancel: Arc<AtomicBool>,
    db_path: Option<PathBuf>,
}

impl Default for DesktopState {
    fn default() -> Self {
        Self {
            cancel: Arc::new(AtomicBool::new(false)),
            db_path: None,
        }
    }
}

impl DesktopState {
    /// Estado con una base local alternativa (tests / usos avanzados).
    pub fn with_db_path(db_path: PathBuf) -> Self {
        Self {
            cancel: Arc::new(AtomicBool::new(false)),
            db_path: Some(db_path),
        }
    }

    fn conn(&self) -> Result<rusqlite::Connection, CommandError> {
        open_db(self.db_path.as_deref())
    }
}

fn open_db(db_path: Option<&Path>) -> Result<rusqlite::Connection, CommandError> {
    let result = match db_path {
        Some(path) => gx_storage::db::init_db_at(path),
        None => gx_storage::db::init_db(),
    };
    result.map_err(|e| CommandError::new("database", format!("base de datos: {e}")))
}

/// Error estructurado Rust → frontend (nunca panic/500).
#[derive(Debug, Clone, Serialize, thiserror::Error)]
#[error("{message}")]
pub struct CommandError {
    pub code: String,
    pub message: String,
}

impl CommandError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

fn map_storage(context: &str, e: impl std::fmt::Display) -> CommandError {
    eprintln!("[desktop] {context}: {e}");
    CommandError::new("database", format!("{context}: {e}"))
}

/// Evento de progreso enviado al frontend por el canal del scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ScanProgressEvent {
    Pending { path: String },
    Ok { path: String, findings_count: usize },
    Error { path: String, error: String },
}

impl From<FileProgress> for ScanProgressEvent {
    fn from(progress: FileProgress) -> Self {
        let path = progress.path.to_string_lossy().to_string();
        match progress.state {
            FileProgressState::Pending => ScanProgressEvent::Pending { path },
            FileProgressState::Ok { findings } => ScanProgressEvent::Ok {
                path,
                findings_count: findings,
            },
            FileProgressState::Error { message } => ScanProgressEvent::Error {
                path,
                error: message,
            },
        }
    }
}

/// Stub del shell (GX-015): confirma que el puente Rust↔Vue está vivo.
#[tauri::command]
pub fn ping() -> String {
    "pong".to_string()
}

/// Validación de frontera de una solicitud de análisis (GX-016).
pub fn validate_request(request: &AnalysisRequest) -> Result<(), CommandError> {
    if request.schema_version != 1 {
        return Err(CommandError::new(
            "invalid_input",
            format!(
                "schema_version {} no soportada (esperada 1).",
                request.schema_version
            ),
        ));
    }
    if request.inputs.is_empty() {
        return Err(CommandError::new(
            "invalid_input",
            "No hay archivos ni directorios seleccionados.",
        ));
    }
    for input in &request.inputs {
        if !input.exists() {
            return Err(CommandError::new(
                "invalid_input",
                format!("La ruta '{}' no existe.", input.display()),
            ));
        }
    }
    if request.enabled_rule_ids.is_empty() {
        return Err(CommandError::new(
            "invalid_rules",
            "No hay reglas habilitadas: el escaneo no produciría hallazgos.",
        ));
    }
    for id in &request.enabled_rule_ids {
        if !runtime::is_known_rule(id) {
            return Err(CommandError::new(
                "invalid_rules",
                format!("Regla desconocida: '{id}'."),
            ));
        }
    }
    Ok(())
}

/// Escaneo asíncrono con progreso por archivo y cancelación (GX-016).
#[tauri::command]
pub async fn scan(
    request: AnalysisRequest,
    on_progress: Channel<ScanProgressEvent>,
    state: State<'_, DesktopState>,
) -> Result<AnalysisResult, CommandError> {
    run_scan(request, on_progress, state.inner()).await
}

/// Implementación testeable del comando `scan`.
pub async fn run_scan(
    request: AnalysisRequest,
    on_progress: Channel<ScanProgressEvent>,
    state: &DesktopState,
) -> Result<AnalysisResult, CommandError> {
    validate_request(&request)?;
    let cancel = state.cancel.clone();
    cancel.store(false, Ordering::SeqCst);
    let db_path = state.db_path.clone();

    tauri::async_runtime::spawn_blocking(move || {
        let emit = |progress: FileProgress| {
            // Un frontend cerrado no debe romper el escaneo.
            let _ = on_progress.send(ScanProgressEvent::from(progress));
        };
        let result = runtime::analyze_with_progress(&request, Some(&emit), Some(&cancel));
        if request.record_history {
            persist_history(db_path.as_deref(), &request, &result)?;
        }
        Ok::<AnalysisResult, CommandError>(result)
    })
    .await
    .map_err(|e| CommandError::new("internal", format!("la tarea de escaneo falló: {e}")))?
}

fn persist_history(
    db_path: Option<&Path>,
    request: &AnalysisRequest,
    result: &AnalysisResult,
) -> Result<(), CommandError> {
    let mut conn = open_db(db_path)?;
    let run = audit_dao::AuditRun::from_analysis(request, result, "desktop");
    audit_dao::persist_run(&mut conn, &run, &result.findings)
        .map_err(|e| map_storage("no se pudo guardar el historial", e))?;
    Ok(())
}

/// Solicita la cancelación del scan en curso (idempotente).
#[tauri::command]
pub fn cancel_scan(state: State<'_, DesktopState>) -> bool {
    state.cancel.store(true, Ordering::SeqCst);
    true
}

/// Diálogo nativo de selección de fuentes GeneXus (valida extensiones).
#[tauri::command]
pub async fn pick_source_files(app: tauri::AppHandle) -> Result<Vec<String>, CommandError> {
    use tauri_plugin_dialog::DialogExt;

    let picked = app
        .dialog()
        .file()
        .add_filter(
            "Fuentes GeneXus",
            &["xpz", "zip", "rar", "xml", "txt", "prg", "gxd", "src"],
        )
        .blocking_pick_files();

    let Some(files) = picked else {
        return Ok(Vec::new());
    };

    let mut paths = Vec::with_capacity(files.len());
    for file in files {
        let path = file.into_path().map_err(|e| {
            CommandError::new("invalid_input", format!("Ruta seleccionada no válida: {e}"))
        })?;
        if !is_source_extension(&path) {
            return Err(CommandError::new(
                "invalid_input",
                format!("Extensión no soportada: '{}'.", path.display()),
            ));
        }
        paths.push(path.to_string_lossy().to_string());
    }
    Ok(paths)
}

/// Catálogo de reglas concretas (base local, u opcionalmente Reglas.csv).
#[tauri::command]
pub fn list_rules(
    rules_csv: Option<String>,
    state: State<'_, DesktopState>,
) -> Result<Vec<rules_dao::RuleRecord>, CommandError> {
    let conn = match rules_csv.as_deref() {
        Some(csv) => {
            let conn = gx_storage::db::init_memory_db()
                .map_err(|e| map_storage("catálogo en memoria", e))?;
            gx_storage::seed::import_reglas_csv(&conn, Path::new(csv))
                .map_err(|e| map_storage("importando Reglas.csv", e))?;
            conn
        }
        None => state.conn()?,
    };
    let mut records = rules_dao::get_all(&conn).map_err(|e| map_storage("leyendo catálogo", e))?;
    records.retain(|r| !r.is_abstract);
    Ok(records)
}

/// Habilita/deshabilita una regla en la base local del usuario.
#[tauri::command]
pub fn set_rule_enabled(
    id: String,
    enabled: bool,
    state: State<'_, DesktopState>,
) -> Result<(), CommandError> {
    let conn = state.conn()?;
    let exists = rules_dao::exists(&conn, &id).map_err(|e| map_storage("validando regla", e))?;
    if !exists {
        return Err(CommandError::new(
            "not_found",
            format!("La regla '{id}' no existe en el catálogo."),
        ));
    }
    rules_dao::set_enabled(&conn, &id, enabled).map_err(|e| map_storage("guardando la regla", e))
}

/// Preferencias del desktop (mismos defaults que la base local).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SettingsDto {
    pub qg_threshold_pct: f32,
    pub max_errors: u32,
    pub max_warnings: u32,
}

#[tauri::command]
pub fn get_settings(state: State<'_, DesktopState>) -> Result<SettingsDto, CommandError> {
    let conn = state.conn()?;
    Ok(SettingsDto {
        qg_threshold_pct: settings_dao::get_qg_threshold(&conn),
        max_errors: settings_dao::get_max_errors(&conn),
        max_warnings: settings_dao::get_max_warnings(&conn),
    })
}

#[tauri::command]
pub fn set_settings(
    settings: SettingsDto,
    state: State<'_, DesktopState>,
) -> Result<(), CommandError> {
    let conn = state.conn()?;
    settings_dao::set(
        &conn,
        "qg_threshold_pct",
        &settings.qg_threshold_pct.to_string(),
    )
    .map_err(|e| map_storage("guardando settings", e))?;
    settings_dao::set(&conn, "max_errors", &settings.max_errors.to_string())
        .map_err(|e| map_storage("guardando settings", e))?;
    settings_dao::set(&conn, "max_warnings", &settings.max_warnings.to_string())
        .map_err(|e| map_storage("guardando settings", e))
}

/// Corridas de auditoría más recientes (nuevas primero).
#[tauri::command]
pub fn list_audit_runs(
    limit: Option<i64>,
    state: State<'_, DesktopState>,
) -> Result<Vec<audit_dao::AuditRunSummary>, CommandError> {
    let conn = state.conn()?;
    let limit = limit.unwrap_or(50).clamp(1, 1000);
    audit_dao::list_runs(&conn, limit).map_err(|e| map_storage("leyendo historial", e))
}

/// Hallazgos históricos de una corrida (con identidad de objeto).
#[tauri::command]
pub fn get_audit_issues(
    run_id: i64,
    state: State<'_, DesktopState>,
) -> Result<Vec<Issue>, CommandError> {
    let conn = state.conn()?;
    audit_dao::get_issues_for_run(&conn, run_id)
        .map_err(|e| map_storage("leyendo hallazgos históricos", e))
}

/// Resumen textual idéntico al de `gx scan --format text` (GX-016).
#[tauri::command]
pub fn render_text_summary(result: AnalysisResult) -> String {
    gx_core::summary::text_summary(&result)
}

/// GX-019: exporta el resultado a PDF con diálogo nativo (sin re-ejecutar el
/// engine). Devuelve la ruta elegida; cancelar devuelve cadena vacía.
#[tauri::command]
pub async fn save_pdf(
    result: AnalysisResult,
    app: tauri::AppHandle,
) -> Result<String, CommandError> {
    use tauri_plugin_dialog::DialogExt;

    let picked = app
        .dialog()
        .file()
        .add_filter("PDF", &["pdf"])
        .set_file_name("gx-informe.pdf")
        .blocking_save_file();

    let Some(file) = picked else {
        return Ok(String::new());
    };
    let path = file.into_path().map_err(|e| {
        CommandError::new("invalid_input", format!("Ruta de guardado no válida: {e}"))
    })?;

    let result_path = path.clone();
    tauri::async_runtime::spawn_blocking(move || {
        gx_report::render(&result, &result_path)
            .map_err(|e| CommandError::new("report", format!("no se pudo generar el PDF: {e:#}")))
    })
    .await
    .map_err(|e| CommandError::new("internal", format!("la tarea de PDF falló: {e}")))??;

    Ok(path.to_string_lossy().to_string())
}

/// Texto fuente de un objeto concreto del artefacto (visor GX-017).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectSourceDto {
    pub id: String,
    pub object_type: String,
    pub package: String,
    pub member: String,
    pub container_path: String,
    pub text: String,
    pub code_start_line: u32,
}

#[tauri::command]
pub fn read_object_source(
    container_path: String,
    member: String,
    id: Option<String>,
) -> Result<ObjectSourceDto, CommandError> {
    let path = PathBuf::from(&container_path);
    if !path.is_file() {
        return Err(CommandError::new(
            "invalid_input",
            format!("El artefacto '{}' no existe.", path.display()),
        ));
    }
    let objects = gx_core::xpz_extractor::extract_source_objects(&path)
        .map_err(|e| CommandError::new("scan", format!("no se pudo abrir el objeto: {e}")))?;
    let candidates: Vec<_> = objects
        .into_iter()
        .filter(|o| o.object.member == member)
        .collect();
    let found = match id.as_deref() {
        Some(want) => candidates
            .iter()
            .find(|o| o.object.id == want)
            .or_else(|| candidates.first()),
        None => candidates.first(),
    };
    let found = found.ok_or_else(|| {
        CommandError::new(
            "not_found",
            format!("El miembro '{member}' no contiene el objeto solicitado."),
        )
    })?;
    Ok(ObjectSourceDto {
        id: found.object.id.clone(),
        object_type: found.object.object_type.clone(),
        package: found.object.package.clone(),
        member: found.object.member.clone(),
        container_path: found.object.container_path.clone(),
        text: found.text.clone(),
        code_start_line: found.code_start_line,
    })
}
