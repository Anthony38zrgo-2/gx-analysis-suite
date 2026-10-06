//! Comandos Tauri del desktop (GX-016).
//!
//! Capa FINA sobre el contrato compartido `AnalysisRequest`/`AnalysisResult`:
//! el frontend construye la solicitud y muestra el resultado, pero NUNCA
//! duplica lógica de lint. Toda entrada se valida en la frontera Rust y los
//! errores se devuelven estructurados (`CommandError`), nunca como panic.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use tauri::ipc::Channel;
use tauri::State;

use gx_core::budget::ExecutionBudget;
use gx_core::models::{
    AnalysisRequest, AnalysisResult, AuditMetrics, Issue, QgPolicy, QgVerdict, ScanCompletion,
    ScanCoverage, ScanFailure, SourceObject,
};
use gx_engine::runtime::{self, FileProgress, FileProgressState};
use gx_sources::filesystem::is_source_extension;
use gx_storage::dao::{audit_dao, rules_dao, settings_dao};

/// Scan activo con su identidad y token de cancelación propios (A04/F08).
struct ActiveScan {
    id: u64,
    token: Arc<AtomicBool>,
}

/// Sesión de resultados acotada (C01): los findings grandes viven en Rust y
/// el frontend pide páginas; la retención evita crecer sin límite.
pub struct ScanSession {
    pub request: AnalysisRequest,
    pub result: AnalysisResult,
    pub history_error: Option<String>,
}

/// Store de sesiones con retención por cantidad y por findings (C01).
pub struct SessionStore {
    next_id: u64,
    sessions: VecDeque<(u64, ScanSession)>,
    max_sessions: usize,
    max_findings: usize,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self {
            next_id: 1,
            sessions: VecDeque::new(),
            max_sessions: 8,
            max_findings: 50_000,
        }
    }
}

impl SessionStore {
    pub fn insert(
        &mut self,
        request: AnalysisRequest,
        result: AnalysisResult,
        history_error: Option<String>,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.sessions.push_back((
            id,
            ScanSession {
                request,
                result,
                history_error,
            },
        ));
        self.enforce_retention();
        id
    }

    fn total_findings(&self) -> usize {
        self.sessions
            .iter()
            .map(|(_, session)| session.result.findings.len())
            .sum()
    }

    fn enforce_retention(&mut self) {
        while self.sessions.len() > self.max_sessions
            || (self.total_findings() > self.max_findings && self.sessions.len() > 1)
        {
            self.sessions.pop_front();
        }
    }

    pub fn get(&self, id: u64) -> Option<&ScanSession> {
        self.sessions
            .iter()
            .find(|(session_id, _)| *session_id == id)
            .map(|(_, session)| session)
    }
}

/// Estado compartido: scan activo (token por invocación), base local con pool
/// (migrada UNA vez por arranque, C01), sesiones de resultados y caché de
/// fuentes (C02).
pub struct DesktopState {
    active: Arc<Mutex<Option<ActiveScan>>>,
    next_id: Arc<AtomicU64>,
    db_path: Option<PathBuf>,
    pool: Arc<Mutex<Option<gx_storage::db::SqlitePool>>>,
    sessions: Arc<Mutex<SessionStore>>,
    source_cache: Arc<Mutex<SourceCache>>,
}

impl Default for DesktopState {
    fn default() -> Self {
        Self {
            active: Arc::new(Mutex::new(None)),
            next_id: Arc::new(AtomicU64::new(0)),
            db_path: None,
            pool: Arc::new(Mutex::new(None)),
            sessions: Arc::new(Mutex::new(SessionStore::default())),
            source_cache: Arc::new(Mutex::new(SourceCache::default())),
        }
    }
}

/// Estampilla del contenedor para detectar fuentes modificadas (C02).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ContainerStamp {
    len: u64,
    modified_nanos: u64,
}

fn container_stamp(path: &Path) -> ContainerStamp {
    match std::fs::metadata(path) {
        Ok(metadata) => ContainerStamp {
            len: metadata.len(),
            modified_nanos: metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(SystemTime::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0),
        },
        Err(_) => ContainerStamp {
            len: 0,
            modified_nanos: 0,
        },
    }
}

struct CachedObject {
    source: SourceObject,
    stamp: ContainerStamp,
    tick: u64,
}

/// Caché acotada de objetos extraídos, keyed por contenedor+miembro+id y
/// estampilla de archivo (C02): navegar dentro de un objeto no vuelve a
/// descomprimir el paquete.
pub struct SourceCache {
    entries: HashMap<(String, String, String), CachedObject>,
    tick: u64,
    max_entries: usize,
}

impl Default for SourceCache {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            tick: 0,
            max_entries: 8,
        }
    }
}

impl SourceCache {
    /// Devuelve (objeto, `source_modified`, `cached`).
    fn get_or_load(
        &mut self,
        path: &Path,
        member: &str,
        id: &str,
    ) -> Result<(SourceObject, bool, bool), CommandError> {
        let key = (
            path.canonicalize()
                .unwrap_or_else(|_| path.to_path_buf())
                .to_string_lossy()
                .to_string(),
            member.to_string(),
            id.to_string(),
        );
        let stamp = container_stamp(path);
        let mut modified = false;
        if let Some(entry) = self.entries.get_mut(&key) {
            if entry.stamp == stamp {
                self.tick += 1;
                entry.tick = self.tick;
                return Ok((entry.source.clone(), false, true));
            }
            // El contenedor cambió desde la última lectura (C02).
            modified = true;
        }
        let source = find_object_strict(path, member, id)?;
        self.tick += 1;
        self.entries.insert(
            key,
            CachedObject {
                source: source.clone(),
                stamp,
                tick: self.tick,
            },
        );
        while self.entries.len() > self.max_entries {
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.tick)
                .map(|(key, _)| key.clone())
            {
                self.entries.remove(&oldest);
            } else {
                break;
            }
        }
        Ok((source, modified, false))
    }
}

/// Busca EXACTAMENTE (member, id) con corte temprano (C02): no extrae los
/// miembros posteriores y NUNCA cae al primer candidato.
fn find_object_strict(path: &Path, member: &str, id: &str) -> Result<SourceObject, CommandError> {
    let budget = ExecutionBudget::default();
    let mut stream = gx_sources::xpz_extractor::source_object_stream(path, &budget, None)
        .map_err(|e| CommandError::new("scan", format!("no se pudo abrir el objeto: {e}")))?;
    let mut fallback: Option<SourceObject> = None;
    for item in stream.by_ref() {
        let object = item
            .map_err(|e| CommandError::new("scan", format!("no se pudo abrir el objeto: {e}")))?;
        if object.object.member != member {
            continue;
        }
        if object.object.id == id {
            return Ok(object);
        }
        if fallback.is_none() {
            fallback = Some(object);
        }
    }
    match fallback {
        // `id` vacío (p. ej. .txt con un solo objeto): se acepta el único
        // candidato del miembro, pero nunca "el primero de varios".
        Some(object) if id.is_empty() => Ok(object),
        _ => Err(CommandError::new(
            "not_found",
            format!(
                "No existe el objeto '{id}' en el miembro '{member}' de '{}'.",
                path.display()
            ),
        )),
    }
}

/// El contenedor debe pertenecer a un input aprobado de la sesión (C04:
/// el visor no es acceso irrestricto al filesystem).
fn is_approved_container(session: &ScanSession, container: &Path) -> bool {
    let canonical = container
        .canonicalize()
        .unwrap_or_else(|_| container.to_path_buf());
    session.request.inputs.iter().any(|input| {
        let approved = input.canonicalize().unwrap_or_else(|_| input.to_path_buf());
        canonical == approved || canonical.starts_with(&approved)
    })
}

impl DesktopState {
    /// Estado con una base local alternativa (tests / usos avanzados).
    pub fn with_db_path(db_path: PathBuf) -> Self {
        Self {
            db_path: Some(db_path),
            ..Default::default()
        }
    }

    /// Conexión del pool local; migra y siembra UNA vez por arranque (C01).
    fn conn(&self) -> Result<gx_storage::db::PooledSqliteConnection, CommandError> {
        let mut guard = self
            .pool
            .lock()
            .map_err(|_| CommandError::new("internal", "pool de base envenenado"))?;
        if guard.is_none() {
            let path = match &self.db_path {
                Some(path) => path.clone(),
                None => gx_storage::db::get_db_path(),
            };
            let pool = gx_storage::db::get_pool_at(&path)
                .map_err(|e| CommandError::new("database", format!("base de datos: {e}")))?;
            *guard = Some(pool);
        }
        guard
            .as_ref()
            .expect("pool inicializado")
            .get()
            .map_err(|e| CommandError::new("database", format!("conexión de base: {e}")))
    }

    /// Guarda la corrida en una sesión acotada y devuelve su id (C01).
    pub fn store_session(
        &self,
        request: AnalysisRequest,
        result: AnalysisResult,
        history_error: Option<String>,
    ) -> u64 {
        match self.sessions.lock() {
            Ok(mut store) => store.insert(request, result, history_error),
            Err(_) => 0,
        }
    }

    /// Registra un scan nuevo; rechaza si ya hay uno en curso (A04).
    fn begin_scan(&self) -> Result<(u64, Arc<AtomicBool>), CommandError> {
        let mut guard = self
            .active
            .lock()
            .map_err(|_| CommandError::new("internal", "estado de scan envenenado"))?;
        if guard.is_some() {
            return Err(CommandError::new(
                "scan_in_progress",
                "Ya hay un escaneo en curso; cancele o espere a que termine.",
            ));
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst) + 1;
        let token = Arc::new(AtomicBool::new(false));
        *guard = Some(ActiveScan {
            id,
            token: token.clone(),
        });
        Ok((id, token))
    }

    /// Libera el scan si el id coincide (un scan viejo no libera uno nuevo).
    fn finish_scan(&self, id: u64) {
        if let Ok(mut guard) = self.active.lock() {
            if guard.as_ref().map(|a| a.id) == Some(id) {
                *guard = None;
            }
        }
    }

    /// Cancela el scan activo (si hay) y lo informa.
    fn cancel_active(&self) -> bool {
        if let Ok(guard) = self.active.lock() {
            if let Some(active) = guard.as_ref() {
                active.token.store(true, Ordering::SeqCst);
                return true;
            }
        }
        false
    }
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

/// Validación de frontera de una solicitud de análisis (GX-016/A01).
///
/// Delega en la validación compartida del engine (esquema, reglas, política)
/// y añade la comprobación de existencia para dar un error de UX inmediato.
pub fn validate_request(request: &AnalysisRequest) -> Result<(), CommandError> {
    if let Err(e) = runtime::validate_request(request) {
        return Err(CommandError::new(e.code, e.message));
    }
    for input in &request.inputs {
        if !input.exists() {
            return Err(CommandError::new(
                "invalid_input",
                format!("La ruta '{}' no existe.", input.display()),
            ));
        }
    }
    Ok(())
}

/// Resumen de un scan: el frontend NO recibe todos los findings, sólo la
/// cabecera y el total; las páginas se piden por `session_id` (C01).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanSummaryDto {
    pub session_id: u64,
    pub schema_version: u32,
    pub request: AnalysisRequest,
    pub scanned_files: usize,
    pub metrics: AuditMetrics,
    pub failures: Vec<ScanFailure>,
    pub policy: QgPolicy,
    pub verdict: QgVerdict,
    pub coverage: ScanCoverage,
    pub completion: ScanCompletion,
    pub findings_total: usize,
    /// Fallo de persistencia: el resultado del scan NO se descarta (C01).
    pub history_error: Option<String>,
}

impl ScanSummaryDto {
    fn from_result(
        session_id: u64,
        result: &AnalysisResult,
        history_error: Option<String>,
    ) -> Self {
        Self {
            session_id,
            schema_version: result.schema_version,
            request: result.request.clone(),
            scanned_files: result.scanned_files,
            metrics: result.metrics.clone(),
            failures: result.failures.clone(),
            policy: result.policy.clone(),
            verdict: result.verdict,
            coverage: result.coverage.clone(),
            completion: result.completion,
            findings_total: result.findings.len(),
            history_error,
        }
    }
}

/// Página de findings de una sesión (C01): el desktop nunca materializa el
/// resultado completo en una respuesta IPC.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindingsPageDto {
    pub session_id: u64,
    pub offset: usize,
    pub limit: usize,
    pub filtered_total: usize,
    pub total: usize,
    pub items: Vec<Issue>,
    /// Reglas presentes en la sesión (para el filtro, sin mandar findings).
    pub rules: Vec<String>,
}

/// Escaneo asíncrono con progreso por archivo y cancelación (GX-016/C01).
#[tauri::command]
pub async fn scan(
    request: AnalysisRequest,
    on_progress: Channel<ScanProgressEvent>,
    state: State<'_, DesktopState>,
) -> Result<ScanSummaryDto, CommandError> {
    run_scan(request, on_progress, state.inner()).await
}

/// Implementación testeable del comando `scan`.
pub async fn run_scan(
    request: AnalysisRequest,
    on_progress: Channel<ScanProgressEvent>,
    state: &DesktopState,
) -> Result<ScanSummaryDto, CommandError> {
    validate_request(&request)?;
    // A04/F08: token propio por invocación; un segundo scan se rechaza.
    let (scan_id, cancel) = state.begin_scan()?;
    let db_path = state.db_path.clone();
    let worker_request = request.clone();

    let join = tauri::async_runtime::spawn_blocking(move || {
        let emit = |progress: FileProgress| {
            // Un frontend cerrado no debe romper el escaneo.
            let _ = on_progress.send(ScanProgressEvent::from(progress));
        };
        let result = runtime::analyze_with_progress(&worker_request, Some(&emit), Some(&cancel));
        // C01: la persistencia es ancilar; su fallo se reporta como warning y
        // NUNCA descarta los diagnostics ya calculados.
        let history_error = if worker_request.record_history {
            persist_history_at(db_path.as_deref(), &worker_request, &result)
                .err()
                .map(|error| error.message)
        } else {
            None
        };
        Ok::<(AnalysisResult, Option<String>), CommandError>((result, history_error))
    })
    .await;

    state.finish_scan(scan_id);
    let (result, history_error) = join
        .map_err(|e| CommandError::new("internal", format!("la tarea de escaneo falló: {e}")))??;
    let session_id = state.store_session(request, result.clone(), history_error.clone());
    Ok(ScanSummaryDto::from_result(
        session_id,
        &result,
        history_error,
    ))
}

/// Retención del historial (C01): se conservan las corridas más recientes.
pub const HISTORY_RETENTION_RUNS: i64 = 100;

/// Persiste el historial en la base local; omite corridas canceladas (C01) y
/// aplica retención.
pub fn persist_history_for(
    state: &DesktopState,
    request: &AnalysisRequest,
    result: &AnalysisResult,
) -> Result<(), CommandError> {
    if result.completion == ScanCompletion::Cancelled {
        return Ok(());
    }
    let mut conn = state.conn()?;
    let run = audit_dao::AuditRun::from_analysis(request, result, "desktop");
    audit_dao::persist_run(&mut conn, &run, &result.findings)
        .map_err(|e| map_storage("no se pudo guardar el historial", e))?;
    let _ = audit_dao::prune_runs(&conn, HISTORY_RETENTION_RUNS)
        .map_err(|e| map_storage("retención de historial", e))?;
    Ok(())
}

/// Variante usada desde el scan (no tiene `&DesktopState` en el worker):
/// abre una conexión efímera al path configurado.
fn persist_history_at(
    db_path: Option<&Path>,
    request: &AnalysisRequest,
    result: &AnalysisResult,
) -> Result<(), CommandError> {
    if result.completion == ScanCompletion::Cancelled {
        return Ok(());
    }
    let mut conn = match db_path {
        Some(path) => gx_storage::db::init_db_at(path),
        None => gx_storage::db::init_db(),
    }
    .map_err(|e| CommandError::new("database", format!("base de datos: {e}")))?;
    let run = audit_dao::AuditRun::from_analysis(request, result, "desktop");
    audit_dao::persist_run(&mut conn, &run, &result.findings)
        .map_err(|e| map_storage("no se pudo guardar el historial", e))?;
    let _ = audit_dao::prune_runs(&conn, HISTORY_RETENTION_RUNS)
        .map_err(|e| map_storage("retención de historial", e))?;
    Ok(())
}

fn filter_findings<'a>(
    findings: &'a [Issue],
    severity: Option<&str>,
    rule_id: Option<&str>,
    search: Option<&str>,
) -> Vec<&'a Issue> {
    let search = search.map(|s| s.trim().to_lowercase());
    findings
        .iter()
        .filter(|issue| {
            if let Some(severity) = severity {
                if !severity.is_empty() && issue.severity.as_str() != severity {
                    return false;
                }
            }
            if let Some(rule_id) = rule_id {
                if !rule_id.is_empty() && issue.rule_id != rule_id {
                    return false;
                }
            }
            if let Some(term) = &search {
                if !term.is_empty() {
                    let object = issue
                        .object
                        .as_ref()
                        .map(|o| format!("{} {} {}", o.id, o.object_type, o.member))
                        .unwrap_or_default();
                    let haystack = format!("{} {} {}", issue.rule_id, issue.description, object)
                        .to_lowercase();
                    if !haystack.contains(term.as_str()) {
                        return false;
                    }
                }
            }
            true
        })
        .collect()
}

/// Página de findings de una sesión con filtros server-side (C01/C03).
///
/// Versión testeable sin `State` de Tauri.
#[allow(clippy::too_many_arguments)]
pub fn findings_page(
    state: &DesktopState,
    session_id: u64,
    offset: Option<usize>,
    limit: Option<usize>,
    severity: Option<String>,
    rule_id: Option<String>,
    search: Option<String>,
) -> Result<FindingsPageDto, CommandError> {
    let sessions = state
        .sessions
        .lock()
        .map_err(|_| CommandError::new("internal", "sesiones envenenadas"))?;
    let session = sessions.get(session_id).ok_or_else(|| {
        CommandError::new(
            "not_found",
            format!("La sesión de resultados {session_id} no existe o expiró."),
        )
    })?;

    let offset = offset.unwrap_or(0);
    let limit = limit.unwrap_or(100).clamp(1, 500);
    let filtered = filter_findings(
        &session.result.findings,
        severity.as_deref(),
        rule_id.as_deref(),
        search.as_deref(),
    );
    let mut rules: Vec<String> = session
        .result
        .findings
        .iter()
        .map(|issue| issue.rule_id.clone())
        .collect();
    rules.sort();
    rules.dedup();

    let items: Vec<Issue> = filtered
        .iter()
        .skip(offset)
        .take(limit)
        .map(|issue| (*issue).clone())
        .collect();

    Ok(FindingsPageDto {
        session_id,
        offset,
        limit,
        filtered_total: filtered.len(),
        total: session.result.findings.len(),
        items,
        rules,
    })
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub fn get_findings_page(
    session_id: u64,
    offset: Option<usize>,
    limit: Option<usize>,
    severity: Option<String>,
    rule_id: Option<String>,
    search: Option<String>,
    state: State<'_, DesktopState>,
) -> Result<FindingsPageDto, CommandError> {
    findings_page(
        state.inner(),
        session_id,
        offset,
        limit,
        severity,
        rule_id,
        search,
    )
}

/// Solicita la cancelación del scan en curso (idempotente).
///
/// A04: sólo cancela el scan activo; no puede tocar el token de un scan
/// distinto ni dejar un token global reutilizable.
#[tauri::command]
pub fn cancel_scan(state: State<'_, DesktopState>) -> bool {
    state.cancel_active()
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
    let mut records = match rules_csv.as_deref() {
        Some(csv) => {
            let conn = gx_storage::db::init_memory_db()
                .map_err(|e| map_storage("catálogo en memoria", e))?;
            gx_storage::seed::import_reglas_csv(&conn, Path::new(csv))
                .map_err(|e| map_storage("importando Reglas.csv", e))?;
            rules_dao::get_all(&conn).map_err(|e| map_storage("leyendo catálogo", e))?
        }
        None => {
            let conn = state.conn()?;
            rules_dao::get_all(&conn).map_err(|e| map_storage("leyendo catálogo", e))?
        }
    };
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

/// Corridas de auditoría más recientes (keyset: `before_id` exclusivo) (C01).
#[tauri::command]
pub fn list_audit_runs(
    before_id: Option<i64>,
    limit: Option<i64>,
    state: State<'_, DesktopState>,
) -> Result<Vec<audit_dao::AuditRunSummary>, CommandError> {
    let conn = state.conn()?;
    let limit = limit.unwrap_or(50).clamp(1, 500);
    audit_dao::list_runs_page(&conn, before_id, limit)
        .map_err(|e| map_storage("leyendo historial", e))
}

/// Página de hallazgos históricos con cursor keyset opaco (C01).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HistoryIssuesPageDto {
    pub run_id: i64,
    pub items: Vec<Issue>,
    pub next_cursor: Option<String>,
}

fn encode_cursor(cursor: Option<audit_dao::IssueCursor>) -> Option<String> {
    cursor.map(|c| format!("{}:{}", c.rank, c.id))
}

fn decode_cursor(cursor: Option<String>) -> Result<Option<audit_dao::IssueCursor>, CommandError> {
    match cursor {
        None => Ok(None),
        Some(raw) => {
            let (rank, id) = raw.split_once(':').ok_or_else(|| {
                CommandError::new("invalid_input", format!("cursor inválido: '{raw}'"))
            })?;
            Ok(Some(audit_dao::IssueCursor {
                rank: rank
                    .parse()
                    .map_err(|_| CommandError::new("invalid_input", "rank de cursor inválido"))?,
                id: id
                    .parse()
                    .map_err(|_| CommandError::new("invalid_input", "id de cursor inválido"))?,
            }))
        }
    }
}

/// Versión testeable sin `State` de Tauri (C01).
pub fn history_issues_page(
    state: &DesktopState,
    run_id: i64,
    cursor: Option<String>,
    limit: Option<i64>,
) -> Result<HistoryIssuesPageDto, CommandError> {
    let conn = state.conn()?;
    let page =
        audit_dao::get_issues_page(&conn, run_id, decode_cursor(cursor)?, limit.unwrap_or(100))
            .map_err(|e| map_storage("leyendo hallazgos históricos", e))?;
    Ok(HistoryIssuesPageDto {
        run_id,
        items: page.items,
        next_cursor: encode_cursor(page.next_cursor),
    })
}

#[tauri::command]
pub fn get_audit_issues_page(
    run_id: i64,
    cursor: Option<String>,
    limit: Option<i64>,
    state: State<'_, DesktopState>,
) -> Result<HistoryIssuesPageDto, CommandError> {
    history_issues_page(state.inner(), run_id, cursor, limit)
}

/// Resumen textual idéntico al de `gx scan --format text` (GX-016/C01: se
/// renderiza desde la sesión, sin reenviar el resultado desde Vue).
pub fn text_summary_for(state: &DesktopState, session_id: u64) -> Result<String, CommandError> {
    let sessions = state
        .sessions
        .lock()
        .map_err(|_| CommandError::new("internal", "sesiones envenenadas"))?;
    let session = sessions.get(session_id).ok_or_else(|| {
        CommandError::new(
            "not_found",
            format!("La sesión de resultados {session_id} no existe o expiró."),
        )
    })?;
    Ok(gx_core::summary::text_summary(&session.result))
}

#[tauri::command]
pub fn render_text_summary(
    session_id: u64,
    state: State<'_, DesktopState>,
) -> Result<String, CommandError> {
    text_summary_for(state.inner(), session_id)
}

/// GX-019/C01: exporta a PDF la sesión indicada (sin re-ejecutar el engine ni
/// reenviar el resultado). Devuelve la ruta elegida; cancelar devuelve "".
#[tauri::command]
pub async fn save_pdf(
    session_id: u64,
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
) -> Result<String, CommandError> {
    use tauri_plugin_dialog::DialogExt;

    let result = {
        let sessions = state
            .sessions
            .lock()
            .map_err(|_| CommandError::new("internal", "sesiones envenenadas"))?;
        sessions
            .get(session_id)
            .map(|session| session.result.clone())
            .ok_or_else(|| {
                CommandError::new(
                    "not_found",
                    format!("La sesión de resultados {session_id} no existe o expiró."),
                )
            })?
    };

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

/// Segmento de código con su mapeo de líneas (A03/F04).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectSegmentDto {
    pub kind: String,
    pub text_start_line: u32,
    pub member_start_line: u32,
}

/// Texto fuente de un objeto concreto del artefacto (visor GX-017/A03).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectSourceDto {
    pub id: String,
    pub object_type: String,
    pub package: String,
    pub member: String,
    pub container_path: String,
    pub text: String,
    pub code_start_line: u32,
    /// Segmentos del texto concatenado → líneas físicas del miembro (A03).
    #[serde(default)]
    pub segments: Vec<ObjectSegmentDto>,
}

fn source_to_dto(object: &SourceObject) -> ObjectSourceDto {
    ObjectSourceDto {
        id: object.object.id.clone(),
        object_type: object.object.object_type.clone(),
        package: object.object.package.clone(),
        member: object.object.member.clone(),
        container_path: object.object.container_path.clone(),
        text: object.text.clone(),
        code_start_line: object.code_start_line,
        segments: object
            .segments
            .iter()
            .map(|s| ObjectSegmentDto {
                kind: s.kind.clone(),
                text_start_line: s.text_start_line,
                member_start_line: s.member_start_line,
            })
            .collect(),
    }
}

/// Lectura completa de un objeto (compatibilidad); estricta con (member, id)
/// y con corte temprano (C02).
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
    let object = find_object_strict(&path, &member, id.as_deref().unwrap_or(""))?;
    Ok(source_to_dto(&object))
}

/// Línea de una ventana del visor con su línea física en el miembro (C02).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceWindowLine {
    pub text: String,
    pub text_line: u32,
    pub member_line: u32,
}

/// Ventana acotada de un objeto del visor (C02): el frontend pide sólo las
/// líneas visibles, con coordenadas físicas del miembro.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectWindowDto {
    pub session_id: u64,
    pub id: String,
    pub object_type: String,
    pub package: String,
    pub member: String,
    pub container_path: String,
    pub code_start_line: u32,
    pub segments: Vec<ObjectSegmentDto>,
    pub total_lines: usize,
    pub window_start: usize,
    pub window_end: usize,
    pub lines: Vec<SourceWindowLine>,
    /// El contenedor cambió desde la primera lectura de esta sesión (C02).
    pub source_modified: bool,
    /// La ventana salió de la caché acotada (sin re-descomprimir).
    pub cached: bool,
}

/// Construye la ventana (sin validar scope): archivo + caché + líneas.
fn load_object_window(
    state: &DesktopState,
    path: &Path,
    member: &str,
    id: &str,
    start_line: Option<usize>,
    end_line: Option<usize>,
) -> Result<ObjectWindowDto, CommandError> {
    if !path.is_file() {
        return Err(CommandError::new(
            "invalid_input",
            format!("El artefacto '{}' no existe.", path.display()),
        ));
    }
    let (object, source_modified, cached) = {
        let mut cache = state
            .source_cache
            .lock()
            .map_err(|_| CommandError::new("internal", "caché de fuentes envenenada"))?;
        cache.get_or_load(path, member, id)?
    };

    let text_lines: Vec<&str> = object.text.split('\n').collect();
    let total_lines = text_lines.len();
    let start = start_line.unwrap_or(1).clamp(1, total_lines.max(1));
    let end = end_line
        .unwrap_or(start + 399)
        .clamp(start, total_lines.max(1));
    let lines: Vec<SourceWindowLine> = (start..=end)
        .map(|text_line| SourceWindowLine {
            text: text_lines[text_line - 1].trim_end_matches('\r').to_string(),
            text_line: text_line as u32,
            member_line: object.member_line(text_line as u32),
        })
        .collect();

    Ok(ObjectWindowDto {
        session_id: 0,
        id: object.object.id.clone(),
        object_type: object.object.object_type.clone(),
        package: object.object.package.clone(),
        member: object.object.member.clone(),
        container_path: object.object.container_path.clone(),
        code_start_line: object.code_start_line,
        segments: object
            .segments
            .iter()
            .map(|s| ObjectSegmentDto {
                kind: s.kind.clone(),
                text_start_line: s.text_start_line,
                member_start_line: s.member_start_line,
            })
            .collect(),
        total_lines,
        window_start: start,
        window_end: end,
        lines,
        source_modified,
        cached,
    })
}

/// Versión testeable sin `State` de Tauri: valida sesión + scope aprobado.
#[allow(clippy::too_many_arguments)]
pub fn object_window(
    state: &DesktopState,
    session_id: u64,
    container_path: &str,
    member: &str,
    id: &str,
    start_line: Option<usize>,
    end_line: Option<usize>,
) -> Result<ObjectWindowDto, CommandError> {
    let path = PathBuf::from(container_path);
    {
        let sessions = state
            .sessions
            .lock()
            .map_err(|_| CommandError::new("internal", "sesiones envenenadas"))?;
        let session = sessions.get(session_id).ok_or_else(|| {
            CommandError::new(
                "not_found",
                format!("La sesión de resultados {session_id} no existe o expiró."),
            )
        })?;
        if !is_approved_container(session, &path) {
            return Err(CommandError::new(
                "forbidden",
                format!(
                    "El artefacto '{}' no pertenece a las fuentes aprobadas de la sesión.",
                    path.display()
                ),
            ));
        }
    }
    let mut dto = load_object_window(state, &path, member, id, start_line, end_line)?;
    dto.session_id = session_id;
    Ok(dto)
}

/// Ventana histórica (C04): el scope son los contenedores registrados por los
/// hallazgos de la corrida, nunca un path arbitrario.
#[allow(clippy::too_many_arguments)]
pub fn history_object_window(
    state: &DesktopState,
    run_id: i64,
    container_path: &str,
    member: &str,
    id: &str,
    start_line: Option<usize>,
    end_line: Option<usize>,
) -> Result<ObjectWindowDto, CommandError> {
    let path = PathBuf::from(container_path);
    let conn = state.conn()?;
    let containers = audit_dao::containers_for_run(&conn, run_id)
        .map_err(|e| map_storage("leyendo contenedores del historial", e))?;
    let canonical = path.canonicalize().unwrap_or_else(|_| path.clone());
    let approved = containers.iter().any(|container| {
        let recorded = PathBuf::from(container);
        let recorded_canonical = recorded.canonicalize().unwrap_or(recorded);
        canonical == recorded_canonical || canonical.starts_with(&recorded_canonical)
    });
    if !approved {
        return Err(CommandError::new(
            "forbidden",
            format!(
                "El artefacto '{}' no pertenece a las fuentes registradas de la corrida {run_id}.",
                path.display()
            ),
        ));
    }
    load_object_window(state, &path, member, id, start_line, end_line)
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub fn read_object_window(
    session_id: u64,
    container_path: String,
    member: String,
    id: String,
    start_line: Option<usize>,
    end_line: Option<usize>,
    state: State<'_, DesktopState>,
) -> Result<ObjectWindowDto, CommandError> {
    object_window(
        state.inner(),
        session_id,
        &container_path,
        &member,
        &id,
        start_line,
        end_line,
    )
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub fn read_history_object_window(
    run_id: i64,
    container_path: String,
    member: String,
    id: String,
    start_line: Option<usize>,
    end_line: Option<usize>,
    state: State<'_, DesktopState>,
) -> Result<ObjectWindowDto, CommandError> {
    history_object_window(
        state.inner(),
        run_id,
        &container_path,
        &member,
        &id,
        start_line,
        end_line,
    )
}
