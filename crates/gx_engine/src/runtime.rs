//! Analysis orchestrator. Port of `gx_linter/app/engine/runtime.py`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use anyhow::Result;
use gx_core::budget::ExecutionBudget;
use gx_core::filesystem::{discover_source_files_with_cancel, is_source_extension};
use gx_core::lexical::mask_block_comments;
use gx_core::models::{
    AnalysisRequest, AnalysisResult, AuditContext, AuditMetrics, Issue, ParsedLine, QgVerdict,
    ScanCompletion, ScanCoverage, ScanFailure, SourceLine,
};
use gx_core::validation::{validate_request_shape, ValidationError};
use gx_core::xpz_extractor::extract_source_objects_with_budget;
use gx_rules::base::Rule;
use gx_storage::dao::rules_dao;

use crate::dispatch::{collect_candidate_rules, plan_dispatch, DispatchPlan};

/// Mensaje canónico de cancelación (usado para clasificar la completitud).
pub const CANCELLED_MESSAGE: &str = "cancelado por el usuario";

/// Load enabled, non-abstract rules and build the dispatch plan.
///
/// Mirrors `runtime.load_rules`: filters abstract rules and disabled rules.
/// GX-009: un id sin fila en el catálogo se considera DESHABILITADO
/// (fail-closed) y los errores de SQL se propagan.
pub fn load_rules(conn: &rusqlite::Connection) -> Result<(Vec<Box<dyn Rule>>, DispatchPlan)> {
    let all = gx_rules::all_rules();
    let mut rules: Vec<Box<dyn Rule>> = Vec::new();

    for rule in all {
        if rule.is_abstract() {
            continue;
        }
        if !rules_dao::is_rule_enabled(conn, rule.id())? {
            continue;
        }
        rules.push(rule);
    }
    let plan = plan_dispatch(&rules).map_err(anyhow::Error::msg)?;
    Ok((rules, plan))
}

/// Evaluate a single artifact: reset → per-object evaluation → per-object
/// finalize.
///
/// Contract (GX-003/GX-006):
/// - Every rule is `reset` with the actual artifact path before any line is
///   evaluated, so diagnostics always carry the real file path and no state
///   leaks between scans.
/// - Each [`SourceObject`] (XPZ member / XML Events block / plain file) is
///   evaluated INDEPENDENTLY: rule state and the "generated subroutines
///   (public)" boundary do not cross objects, and line numbers are
///   member-local (never synthetic concatenated coordinates).
/// - Every issue is stamped with the originating object identity.
///
/// Determinism (GX-005): objects in artifact order, lines in source order,
/// candidate rules in ascending registry order; finalize in registry order.
pub fn run_file(
    rules: &mut [Box<dyn Rule>],
    dispatch: &DispatchPlan,
    path: &Path,
    ctx: &AuditContext,
) -> Result<(Vec<Issue>, u128)> {
    let budget = ExecutionBudget::default();
    let outcome = run_file_with_budget(rules, dispatch, path, ctx, &budget, None)?;
    Ok((outcome.issues, outcome.elapsed_ms))
}

/// Resultado de evaluar un archivo con presupuesto/cancelación (A04).
#[derive(Debug, Clone)]
pub struct FileRunOutcome {
    pub issues: Vec<Issue>,
    pub elapsed_ms: u128,
    /// Corte por presupuesto: la corrida del archivo es parcial.
    pub limit: Option<String>,
    /// Cancelación solicitada durante la extracción o el linteo.
    pub cancelled: bool,
}

/// Checkpoint de cancelación/presupuesto cada N líneas (A04).
const LINE_CHECKPOINT: usize = 512;

/// Evalúa un archivo con presupuesto y token de cancelación (A04).
pub fn run_file_with_budget(
    rules: &mut [Box<dyn Rule>],
    dispatch: &DispatchPlan,
    path: &Path,
    ctx: &AuditContext,
    budget: &ExecutionBudget,
    cancel: Option<&AtomicBool>,
) -> Result<FileRunOutcome> {
    let extraction = extract_source_objects_with_budget(path, budget, cancel)?;
    let objects = extraction.objects;
    gx_core::stats::count_objects(objects.len());
    let mut issues: Vec<Issue> = Vec::new();

    let t_start = Instant::now();
    let mut rules_fired_total: usize = 0;
    let mut limit = extraction.limit.clone();
    let mut cancelled = extraction.cancelled;
    let mut line_checks: usize = 0;

    'objects: for obj in &objects {
        if cancelled || limit.is_some() {
            break;
        }
        if cancel.map(|c| c.load(Ordering::Relaxed)).unwrap_or(false) {
            cancelled = true;
            break;
        }
        if budget.is_expired() {
            limit = Some("deadline de la corrida agotado".to_string());
            break;
        }
        if issues.len() >= budget.max_findings {
            limit = Some(format!(
                "límite de hallazgos retenidos alcanzado ({})",
                budget.max_findings
            ));
            break;
        }
        // Estado por objeto: reset antes de cada objeto (GX-006).
        for r in rules.iter_mut() {
            r.reset(path);
        }
        let obj_start = issues.len();
        // A03/F03: la vista de evaluación enmascara comentarios de bloque
        // (string-aware, preservando bytes/líneas); la EVIDENCIA (`raw`/
        // `content` de cada ParsedLine) conserva el texto original.
        let masked = mask_block_comments(&obj.text);
        let original_lines: Vec<&str> = obj.text.split('\n').collect();
        let masked_lines: Vec<&str> = masked.split('\n').collect();

        for (idx, (raw_line, eval_line)) in
            original_lines.iter().zip(masked_lines.iter()).enumerate()
        {
            // Checkpoint de cancelación/presupuesto dentro del linteo (A04).
            line_checks += 1;
            if line_checks.is_multiple_of(LINE_CHECKPOINT) {
                if cancel.map(|c| c.load(Ordering::Relaxed)).unwrap_or(false) {
                    cancelled = true;
                    break 'objects;
                }
                if budget.is_expired() {
                    limit = Some("deadline de la corrida agotado".to_string());
                    break 'objects;
                }
                if issues.len() >= budget.max_findings {
                    limit = Some(format!(
                        "límite de hallazgos retenidos alcanzado ({})",
                        budget.max_findings
                    ));
                    break 'objects;
                }
            }
            let content = raw_line.trim_end_matches('\r');
            let eval = eval_line.trim_end_matches('\r');
            if eval
                .to_lowercase()
                .contains("generated subroutines (public)")
            {
                break;
            }
            let source = SourceLine {
                number: idx as u32 + 1,
                content: content.to_string(),
            };
            let parsed = ParsedLine::from_source_with_eval(source, eval);
            if parsed.stripped.is_empty() {
                continue;
            }
            gx_core::stats::count_line();
            let candidates = collect_candidate_rules(&parsed, dispatch);
            rules_fired_total += candidates.len();
            gx_core::stats::count_rule_evaluations(candidates.len());
            for idx in candidates {
                let result = rules[idx].evaluate(&parsed, ctx);
                if !result.is_empty() {
                    gx_core::stats::note_first_finding();
                }
                issues.extend(result);
            }
            if issues.len() >= budget.max_findings {
                limit = Some(format!(
                    "límite de hallazgos retenidos alcanzado ({})",
                    budget.max_findings
                ));
                break 'objects;
            }
        }

        // Finalize por objeto: los hallazgos pendientes pertenecen al objeto.
        for r in rules.iter_mut() {
            issues.extend(r.finalize(ctx));
        }

        // Stamp de identidad de objeto (GX-006).
        let object_ref = obj.object.clone();
        for issue in issues[obj_start..].iter_mut() {
            issue.object = Some(object_ref.clone());
        }
    }

    // Si se cortó por cancelación, los hallazgos acumulados se conservan
    // pero el archivo NO cuenta como escaneado con éxito.
    gx_core::stats::count_findings(issues.len());
    let elapsed_ms = t_start.elapsed().as_millis();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    tracing::info!(
        "[ENGINE] {name} — {} objetos | {rules_fired_total} rule-evaluations | {} findings | {elapsed_ms} ms | cancelled={cancelled} limit={limit:?}",
        objects.len(),
        issues.len()
    );
    Ok(FileRunOutcome {
        issues,
        elapsed_ms,
        limit,
        cancelled,
    })
}

/// Convenience wrapper: load rules from `conn` then evaluate `path`.
pub fn evaluate_file(
    path: &Path,
    conn: &rusqlite::Connection,
    ctx: &AuditContext,
) -> Result<(Vec<Issue>, u128)> {
    let (mut rules, dispatch) = load_rules(conn)?;
    run_file(&mut rules, &dispatch, path, ctx)
}

/// Scan `path` with an explicit enabled-rule set (no SQLite involved).
pub fn scan_file(
    path: &Path,
    enabled_ids: &HashSet<String>,
    ctx: &AuditContext,
) -> Result<Vec<Issue>> {
    let (mut rules, dispatch) = build_rules(enabled_ids);
    run_file(&mut rules, &dispatch, path, ctx).map(|(issues, _)| issues)
}

/// Summarize issues into metrics (mirrors `runtime.build_metrics`).
pub fn build_metrics(issues: &[Issue]) -> AuditMetrics {
    AuditMetrics::from_issues(issues)
}

/// Progreso neutral por archivo (GX-016): el engine no conoce tipos de UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileProgressState {
    /// Archivo descubierto, aún sin evaluar.
    Pending,
    /// Escaneado con éxito (posiblemente con 0 hallazgos).
    Ok { findings: usize },
    /// Fallo explícito del archivo (nunca un resultado limpio).
    Error { message: String },
}

/// Evento de progreso por archivo durante un [`analyze_with_progress`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileProgress {
    pub path: PathBuf,
    pub state: FileProgressState,
}

/// Análisis completo según una solicitud serializable (GX-010).
///
/// - Descubre archivos por input (archivo único o directorio recursivo con
///   extensiones fuente explícitas; GX-007: sin fallback).
/// - Evalúa en paralelo compartiendo el mismo contrato que el secuencial.
/// - Un archivo fallido va a `failures` (nunca hallazgos vacíos).
/// - Veredicto: con fallos de scan → `QgVerdict::Error`; sin fallos, el
///   veredicto de la política (`Pass`/`Reject`).
/// - El orden de hallazgos es determinista y estable sin importar SQLite.
pub fn analyze(request: &AnalysisRequest) -> AnalysisResult {
    analyze_with_progress(request, None, None)
}

/// [`analyze`] con hooks opcionales de progreso y cancelación (GX-016).
///
/// - `on_progress` recibe `Pending` por archivo descubierto y `Ok`/`Error`
///   al terminar cada archivo (los callbacks pueden ejecutarse desde hilos
///   de rayon, en cualquier orden de finalización).
/// - `cancel` se consulta antes de evaluar cada archivo; los archivos no
///   iniciados se reportan como `ScanFailure` "cancelado por el usuario", de
///   modo que una cancelación nunca produce un resultado limpio.
pub fn analyze_with_progress(
    request: &AnalysisRequest,
    on_progress: Option<&(dyn Fn(FileProgress) + Sync)>,
    cancel: Option<&AtomicBool>,
) -> AnalysisResult {
    let budget = ExecutionBudget::default();
    analyze_with_options(request, on_progress, cancel, &budget)
}

/// [`analyze_with_progress`] con presupuesto explícito (A04/F07).
pub fn analyze_with_options(
    request: &AnalysisRequest,
    on_progress: Option<&(dyn Fn(FileProgress) + Sync)>,
    cancel: Option<&AtomicBool>,
    budget: &ExecutionBudget,
) -> AnalysisResult {
    // A01/F01: la validación es parte del motor, no una convención del
    // llamador. Un request inválido nunca produce PASS.
    if let Err(e) = validate_request(request) {
        return invalid_result(request, e.message);
    }

    let enabled: HashSet<String> = request.enabled_rule_ids.iter().cloned().collect();
    let mut inputs: Vec<PathBuf> = Vec::new();
    let mut failures: Vec<ScanFailure> = Vec::new();
    let mut coverage = ScanCoverage {
        inputs_declared: request.inputs.len(),
        ..Default::default()
    };
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut discovery_cancelled = false;

    // A01/F02: discovery con dedupe canónico, errores reportados y cobertura.
    for input in &request.inputs {
        if input.is_file() {
            if !is_source_extension(input) {
                failures.push(ScanFailure {
                    path: input.clone(),
                    error: format!(
                        "Extensión no soportada: '{}'. Se esperaban .xpz, .zip, .rar, .xml, .txt, .prg, .gxd o .src.",
                        input.display()
                    ),
                });
                continue;
            }
            push_unique(input.clone(), &mut inputs, &mut seen, &mut coverage);
        } else if input.is_dir() {
            let report = discover_source_files_with_cancel(input, cancel);
            coverage.files_excluded += report.excluded_files;
            if report.cancelled {
                discovery_cancelled = true;
                failures.push(ScanFailure {
                    path: input.clone(),
                    error: CANCELLED_MESSAGE.to_string(),
                });
                break;
            }
            let had_discovery_errors = !report.errors.is_empty();
            for err in report.errors {
                failures.push(ScanFailure {
                    path: err.path,
                    error: err.message,
                });
            }
            if report.files.is_empty() && !had_discovery_errors {
                coverage.source_free_inputs += 1;
                failures.push(ScanFailure {
                    path: input.clone(),
                    error: format!(
                        "El directorio '{}' no contiene archivos fuente GeneXus ({} archivo(s) excluidos).",
                        input.display(),
                        report.excluded_files
                    ),
                });
            }
            for file in report.files {
                push_unique(file, &mut inputs, &mut seen, &mut coverage);
            }
        } else {
            failures.push(ScanFailure {
                path: input.clone(),
                error: "El path no existe".to_string(),
            });
        }
    }
    coverage.inputs_scanned = inputs.len();
    coverage.files_discovered = inputs.len();

    if let Some(cb) = on_progress {
        for path in &inputs {
            cb(FileProgress {
                path: path.clone(),
                state: FileProgressState::Pending,
            });
        }
    }

    // Un contexto por corrida: umbrales desde la política (compatibilidad
    // con reglas que leen ctx).
    let (max_errors, max_warnings, qg_threshold_pct) = match &request.policy {
        gx_core::models::QgPolicy::Absolute {
            max_errors,
            max_warnings,
        } => (*max_errors, *max_warnings, 10.0),
        gx_core::models::QgPolicy::Percentage { max_error_pct } => (0, u32::MAX, *max_error_pct),
    };

    let outcomes = evaluate_files_parallel_with_ctx(
        &inputs,
        &enabled,
        |path| AuditContext {
            project_path: path.to_path_buf(),
            rules_path: path.to_path_buf(),
            max_errors,
            max_warnings,
            qg_threshold_pct,
            extra_settings: Default::default(),
        },
        on_progress,
        cancel,
        budget,
    );

    let mut findings: Vec<Issue> = Vec::new();
    let mut scanned_files: usize = 0;
    let mut any_cancelled = false;
    let mut any_limit = false;
    for outcome in outcomes {
        if outcome.cancelled {
            any_cancelled = true;
            findings.extend(outcome.issues);
            failures.push(ScanFailure {
                path: outcome.path,
                error: CANCELLED_MESSAGE.to_string(),
            });
            continue;
        }
        if let Some(error) = outcome.error {
            failures.push(ScanFailure {
                path: outcome.path,
                error,
            });
            continue;
        }
        scanned_files += 1;
        findings.extend(outcome.issues);
        if let Some(limit) = outcome.limit {
            any_limit = true;
            failures.push(ScanFailure {
                path: outcome.path,
                error: format!("presupuesto agotado: {limit}"),
            });
        }
    }

    // Completitud (A04): una cancelación o un límite de recursos NUNCA es un
    // PASS sin calificar; los hallazgos ya calculados se conservan.
    let completion = if any_cancelled || discovery_cancelled {
        ScanCompletion::Cancelled
    } else if any_limit {
        ScanCompletion::Partial
    } else if failures.is_empty() {
        ScanCompletion::Complete
    } else {
        ScanCompletion::Failed
    };

    let metrics = build_metrics(&findings);
    let verdict = if completion != ScanCompletion::Complete {
        QgVerdict::Error
    } else {
        request.policy.evaluate(&metrics)
    };

    AnalysisResult {
        schema_version: 1,
        request: request.clone(),
        scanned_files,
        findings,
        metrics,
        failures,
        policy: request.policy.clone(),
        verdict,
        coverage,
        completion,
    }
}

/// Agrega un archivo a la lista planificada si su identidad canónica no fue
/// vista (A01/F02: inputs solapados se escanean UNA vez).
fn push_unique(
    candidate: PathBuf,
    inputs: &mut Vec<PathBuf>,
    seen: &mut HashSet<PathBuf>,
    coverage: &mut ScanCoverage,
) {
    let key = candidate
        .canonicalize()
        .unwrap_or_else(|_| candidate.clone());
    if seen.insert(key) {
        inputs.push(candidate);
    } else {
        coverage.files_deduplicated += 1;
    }
}

/// Outcome of scanning one file: either real findings or an explicit error.
///
/// A failed scan is NEVER represented as a clean result (GX-005).
#[derive(Debug, Clone)]
pub struct FileScanOutcome {
    pub path: PathBuf,
    pub issues: Vec<Issue>,
    pub metrics: AuditMetrics,
    pub error: Option<String>,
    /// Corte por presupuesto: el archivo se evaluó parcialmente (A04).
    pub limit: Option<String>,
    /// Cancelación durante la evaluación del archivo (A04).
    pub cancelled: bool,
}

/// Whether `rule_id` is a concrete rule compiled into the registry.
///
/// Frontera del desktop (GX-016): un id desconocido NUNCA se ignora en
/// silencio (a diferencia de `build_rules`, que filtra lo que no conoce).
pub fn is_known_rule(rule_id: &str) -> bool {
    gx_rules::all_rules()
        .iter()
        .any(|r| !r.is_abstract() && r.id() == rule_id)
}

/// Validación compartida del request (A01/F01): forma + reglas conocidas.
///
/// Usada por CLI, desktop y la propia [`analyze`]; un request inválido nunca
/// puede traducirse en un PASS silencioso.
pub fn validate_request(request: &AnalysisRequest) -> Result<(), ValidationError> {
    validate_request_shape(request)?;
    let unknown: Vec<&str> = request
        .enabled_rule_ids
        .iter()
        .map(|id| id.as_str())
        .filter(|id| !is_known_rule(id))
        .collect();
    if !unknown.is_empty() {
        return Err(ValidationError::new(
            "invalid_rules",
            format!(
                "Regla(s) desconocida(s) o abstracta(s): {}.",
                unknown.join(", ")
            ),
        ));
    }
    Ok(())
}

/// Resultado de un request inválido: nunca PASS, nunca archivos escaneados.
fn invalid_result(request: &AnalysisRequest, message: String) -> AnalysisResult {
    let path = request
        .inputs
        .first()
        .cloned()
        .unwrap_or_else(|| PathBuf::from("<request>"));
    AnalysisResult {
        schema_version: 1,
        request: request.clone(),
        scanned_files: 0,
        findings: Vec::new(),
        metrics: AuditMetrics::default(),
        failures: vec![ScanFailure {
            path,
            error: message,
        }],
        policy: request.policy.clone(),
        verdict: QgVerdict::Error,
        coverage: ScanCoverage {
            inputs_declared: request.inputs.len(),
            ..Default::default()
        },
        completion: ScanCompletion::Failed,
    }
}

/// Build rules + dispatch plan from an explicit enabled set, without
/// touching SQLite. Used for deterministic tests, read-only scans and
/// parallelism.
pub fn build_rules(enabled_ids: &HashSet<String>) -> (Vec<Box<dyn Rule>>, DispatchPlan) {
    let all = gx_rules::all_rules();
    let mut rules: Vec<Box<dyn Rule>> = Vec::new();
    for rule in all {
        if rule.is_abstract() {
            continue;
        }
        if !enabled_ids.contains(rule.id()) {
            continue;
        }
        rules.push(rule);
    }
    gx_core::stats::count_rule_factories(rules.len());
    let plan = plan_dispatch(&rules).expect("reglas del registry con triggers válidos");
    (rules, plan)
}

/// Evaluate multiple files in parallel (one rule set per thread).
///
/// Per-file errors are surfaced in the outcome; a failing file can never
/// pass as zero findings (GX-005).
pub fn evaluate_files_parallel(
    paths: &[PathBuf],
    enabled_ids: &HashSet<String>,
    ctx: &AuditContext,
) -> Vec<FileScanOutcome> {
    let budget = ExecutionBudget::default();
    evaluate_files_parallel_with_ctx(paths, enabled_ids, |_p| ctx.clone(), None, None, &budget)
}

/// Variante con contexto por archivo, progreso, cancelación y presupuesto
/// (GX-016/A04).
fn evaluate_files_parallel_with_ctx<F>(
    paths: &[PathBuf],
    enabled_ids: &HashSet<String>,
    ctx_factory: F,
    on_progress: Option<&(dyn Fn(FileProgress) + Sync)>,
    cancel: Option<&AtomicBool>,
    budget: &ExecutionBudget,
) -> Vec<FileScanOutcome>
where
    F: Fn(&Path) -> AuditContext + Sync,
{
    use rayon::prelude::*;
    let evaluate = || {
        paths
            .par_iter()
            .map(|p| {
                let outcome = if cancel.map(|c| c.load(Ordering::Relaxed)).unwrap_or(false) {
                    FileScanOutcome {
                        path: p.clone(),
                        issues: Vec::new(),
                        metrics: AuditMetrics::default(),
                        error: Some(CANCELLED_MESSAGE.to_string()),
                        limit: None,
                        cancelled: true,
                    }
                } else {
                    let (mut rules, dispatch) = build_rules(enabled_ids);
                    let ctx = ctx_factory(p);
                    match run_file_with_budget(&mut rules, &dispatch, p, &ctx, budget, cancel) {
                        Ok(run) => {
                            let metrics = AuditMetrics::from_issues(&run.issues);
                            FileScanOutcome {
                                path: p.clone(),
                                issues: run.issues,
                                metrics,
                                error: None,
                                limit: run.limit,
                                cancelled: run.cancelled,
                            }
                        }
                        Err(e) => FileScanOutcome {
                            path: p.clone(),
                            issues: Vec::new(),
                            metrics: AuditMetrics::default(),
                            error: Some(e.to_string()),
                            limit: None,
                            cancelled: false,
                        },
                    }
                };

                if let Some(cb) = on_progress {
                    cb(FileProgress {
                        path: p.clone(),
                        state: match (&outcome.error, &outcome.limit, outcome.cancelled) {
                            (Some(message), _, _) => FileProgressState::Error {
                                message: message.clone(),
                            },
                            (None, Some(limit), _) => FileProgressState::Error {
                                message: format!("presupuesto agotado: {limit}"),
                            },
                            (None, None, true) => FileProgressState::Error {
                                message: CANCELLED_MESSAGE.to_string(),
                            },
                            (None, None, false) => FileProgressState::Ok {
                                findings: outcome.issues.len(),
                            },
                        },
                    });
                }
                outcome
            })
            .collect::<Vec<FileScanOutcome>>()
    };

    // A04: el presupuesto fija el paralelismo; sin `workers` se usa el pool
    // global de Rayon.
    match budget.workers {
        Some(workers) if workers > 0 => {
            match rayon::ThreadPoolBuilder::new().num_threads(workers).build() {
                Ok(pool) => pool.install(evaluate),
                Err(_) => evaluate(),
            }
        }
        _ => evaluate(),
    }
}
