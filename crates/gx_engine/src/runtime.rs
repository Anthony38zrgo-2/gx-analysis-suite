//! Analysis orchestrator. Port of `gx_linter/app/engine/runtime.py`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use anyhow::Result;
use gx_core::budget::ExecutionBudget;
use gx_core::lexical::{contains_ignore_ascii_case, mask_block_comments};
use gx_core::models::{
    AnalysisRequest, AnalysisResult, AuditContext, AuditMetrics, Issue, PackCoverage, ParsedLine,
    QgVerdict, ScanCompletion, ScanCoverage, ScanFailure, SecuritySummary,
};
use gx_core::semantics::{FactSet, GLOBAL_FACT_CACHE};
use gx_core::validation::{validate_request_shape, ValidationError};
use gx_rules::base::{ObjectFacts, Rule, RuleDescriptor};
use gx_sources::filesystem::{discover_source_files_with_cancel, is_source_extension};

use crate::dispatch::{collect_candidate_rules_into, plan_dispatch_descriptors, DispatchPlan};

/// Mensaje canónico de cancelación (usado para clasificar la completitud).
pub const CANCELLED_MESSAGE: &str = "cancelado por el usuario";

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
    let facts_union = rules.iter().fold(FactSet::NONE, |acc, rule| {
        acc.union(rule.capability().facts)
    });
    let outcome = run_file_with_budget(rules, dispatch, facts_union, path, ctx, &budget, None)?;
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
    /// Cobertura por pack de objeto (D01).
    pub pack_coverage: Vec<PackCoverage>,
}

/// Checkpoint de cancelación/presupuesto cada N líneas (A04).
const LINE_CHECKPOINT: usize = 512;

/// Resultado de evaluar UN objeto (B03/D01).
struct ObjectRun {
    issues: Vec<Issue>,
    limit: Option<String>,
    cancelled: bool,
    pack_coverage: Vec<PackCoverage>,
}

/// Evalúa un objeto completo: reset → líneas → finalize → identidad.
///
/// Compartido por la ruta secuencial y la ruta por chunks paralelos.
#[allow(clippy::too_many_arguments)]
fn evaluate_object(
    rules: &mut [Box<dyn Rule>],
    dispatch: &DispatchPlan,
    facts_union: FactSet,
    path: &Path,
    object: &gx_core::models::SourceObject,
    ctx: &AuditContext,
    budget: &ExecutionBudget,
    cancel: Option<&AtomicBool>,
) -> ObjectRun {
    // Estado por objeto: reset antes de cada objeto (GX-006).
    for rule in rules.iter_mut() {
        rule.reset(path);
    }
    let mut issues: Vec<Issue> = Vec::new();
    let mut limit: Option<String> = None;
    let mut cancelled = false;
    // A03/F03: la vista de evaluación enmascara comentarios de bloque
    // (string-aware, preservando bytes/líneas); la EVIDENCIA (`raw`/
    // `content` de cada ParsedLine) conserva el texto original.
    // B01: sin Vec<&str> ni clones por línea; `ParsedLine` presta el texto.
    let masked = mask_block_comments(&object.text);
    let mut candidates: Vec<usize> = Vec::with_capacity(16);

    'lines: for (index, (raw_line, eval_line)) in
        object.text.split('\n').zip(masked.split('\n')).enumerate()
    {
        // Checkpoint de cancelación/presupuesto dentro del linteo (A04).
        if index != 0 && index.is_multiple_of(LINE_CHECKPOINT) {
            if cancel.map(|c| c.load(Ordering::Relaxed)).unwrap_or(false) {
                cancelled = true;
                break 'lines;
            }
            if budget.is_expired() {
                limit = Some("deadline de la corrida agotado".to_string());
                break 'lines;
            }
        }
        let raw = raw_line.trim_end_matches('\r');
        let eval = eval_line.trim_end_matches('\r');
        if contains_ignore_ascii_case(eval, "generated subroutines (public)") {
            break;
        }
        let parsed = ParsedLine::from_parts(index as u32 + 1, raw, eval);
        if parsed.stripped.is_empty() {
            continue;
        }
        gx_core::stats::count_line();
        collect_candidate_rules_into(&parsed, dispatch, &mut candidates);
        gx_core::stats::count_rule_evaluations(candidates.len());
        for &rule_index in &candidates {
            let result = rules[rule_index].evaluate(&parsed, ctx);
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
            break 'lines;
        }
    }

    // Finalize por objeto: los hallazgos pendientes pertenecen al objeto.
    for rule in rules.iter_mut() {
        issues.extend(rule.finalize(ctx));
    }

    // D01/D02: packs de objeto. Los hechos se calculan UNA vez por objeto y
    // sólo si algún pack seleccionado los requiere; el perfil de estilo común
    // (facts_union vacío) no toca el modelo semántico.
    let mut pack_coverage: Vec<PackCoverage> = Vec::new();
    if !facts_union.is_empty() && !dispatch.object_rules().is_empty() {
        let model = if facts_union.needs_model() {
            gx_core::stats::count_fact_model_request();
            let mut cache = GLOBAL_FACT_CACHE
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let (model, _hit) = cache.get_or_build(&object.text, facts_union);
            model
        } else {
            std::sync::Arc::new(gx_core::semantics::analyze(&object.text))
        };
        let facts = ObjectFacts {
            text: &object.text,
            tokens: Some(&model.tokens),
            model: Some(&model),
        };
        for &rule_index in dispatch.object_rules() {
            let rule = &mut rules[rule_index];
            let capability = rule.capability();
            let mut coverage = PackCoverage {
                id: rule.id().to_string(),
                version: rule.version().to_string(),
                objects_analyzed: 0,
                skipped_unsupported: 0,
                findings: 0,
            };
            if !facts.has(capability.facts) {
                coverage.skipped_unsupported = 1;
            } else {
                let result = rule.analyze_object(&facts, ctx);
                coverage.objects_analyzed = 1;
                coverage.findings = result.len();
                if !result.is_empty() {
                    gx_core::stats::note_first_finding();
                }
                issues.extend(result);
            }
            pack_coverage.push(coverage);
        }
    }

    // Stamp de identidad de objeto (GX-006).
    let object_ref = object.object.clone();
    for issue in issues.iter_mut() {
        issue.object = Some(object_ref.clone());
    }

    ObjectRun {
        issues,
        limit,
        cancelled,
        pack_coverage,
    }
}

/// Evalúa un archivo con presupuesto y token de cancelación (A04/B03).
///
/// Ruta secuencial: objetos en orden, un rule-set provisto por el llamador.
pub fn run_file_with_budget(
    rules: &mut [Box<dyn Rule>],
    dispatch: &DispatchPlan,
    facts_union: FactSet,
    path: &Path,
    ctx: &AuditContext,
    budget: &ExecutionBudget,
    cancel: Option<&AtomicBool>,
) -> Result<FileRunOutcome> {
    let t_start = Instant::now();
    let mut stream = gx_sources::xpz_extractor::source_object_stream(path, budget, cancel)?;
    let mut issues: Vec<Issue> = Vec::new();
    let mut limit: Option<String> = None;
    let mut cancelled = false;
    let mut objects: usize = 0;
    let mut pack_coverage: Vec<PackCoverage> = Vec::new();

    for item in stream.by_ref() {
        let object = item?;
        objects += 1;
        gx_core::stats::count_objects(1);
        let run = evaluate_object(
            rules,
            dispatch,
            facts_union,
            path,
            &object,
            ctx,
            budget,
            cancel,
        );
        issues.extend(run.issues);
        merge_pack_coverage(&mut pack_coverage, run.pack_coverage);
        if run.cancelled {
            cancelled = true;
            break;
        }
        if let Some(reason) = run.limit {
            limit = Some(reason);
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
    }

    let (stream_limit, stream_cancelled) = stream.finish_flags();
    if limit.is_none() {
        limit = stream_limit;
    }
    cancelled |= stream_cancelled;
    finish_file_run(
        path,
        t_start,
        objects,
        issues,
        limit,
        cancelled,
        pack_coverage,
    )
}

/// Chunk de objetos evaluados en paralelo dentro de un paquete (B03).
const OBJECT_CHUNK: usize = 16;

/// Evalúa un archivo con el plan compartido, paralelizando los objetos de un
/// mismo paquete en chunks acotados (B03).
///
/// - La memoria activa queda acotada por `OBJECT_CHUNK` objetos, no por el
///   contenido total del paquete.
/// - Los resultados se recolectan en orden de objeto (chunks secuenciales,
///   `collect` indexado dentro del chunk), así que los hallazgos siguen
///   siendo deterministas.
pub fn run_file_planned(
    plan: &RulePlan,
    path: &Path,
    ctx: &AuditContext,
    budget: &ExecutionBudget,
    cancel: Option<&AtomicBool>,
) -> Result<FileRunOutcome> {
    use rayon::prelude::*;

    let t_start = Instant::now();
    let mut stream = gx_sources::xpz_extractor::source_object_stream(path, budget, cancel)?;
    let mut issues: Vec<Issue> = Vec::new();
    let mut limit: Option<String> = None;
    let mut cancelled = false;
    let mut objects: usize = 0;
    let mut pack_coverage: Vec<PackCoverage> = Vec::new();
    let mut chunk: Vec<gx_core::models::SourceObject> = Vec::with_capacity(OBJECT_CHUNK);

    loop {
        chunk.clear();
        while chunk.len() < OBJECT_CHUNK {
            match stream.next() {
                Some(Ok(object)) => chunk.push(object),
                Some(Err(error)) => return Err(error),
                None => break,
            }
        }
        if chunk.is_empty() {
            break;
        }
        objects += chunk.len();
        let results: Vec<ObjectRun> = chunk
            .par_iter()
            .map(|object| {
                gx_core::stats::count_objects(1);
                with_worker_rules(plan, |rules| {
                    evaluate_object(
                        rules,
                        plan.dispatch(),
                        plan.facts_union(),
                        path,
                        object,
                        ctx,
                        budget,
                        cancel,
                    )
                })
            })
            .collect();

        let mut stop_limit: Option<String> = None;
        let mut stop_cancelled = false;
        for run in results {
            if run.cancelled {
                stop_cancelled = true;
            }
            if run.limit.is_some() {
                stop_limit = run.limit;
            }
            issues.extend(run.issues);
            merge_pack_coverage(&mut pack_coverage, run.pack_coverage);
        }
        if stop_cancelled {
            cancelled = true;
            break;
        }
        if stop_limit.is_some() {
            limit = stop_limit;
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
    }

    let (stream_limit, stream_cancelled) = stream.finish_flags();
    if limit.is_none() {
        limit = stream_limit;
    }
    cancelled |= stream_cancelled;
    finish_file_run(
        path,
        t_start,
        objects,
        issues,
        limit,
        cancelled,
        pack_coverage,
    )
}

/// Suma la cobertura de un objeto a la cobertura acumulada del archivo (D01).
fn merge_pack_coverage(accumulated: &mut Vec<PackCoverage>, from_object: Vec<PackCoverage>) {
    for coverage in from_object {
        match accumulated
            .iter_mut()
            .find(|existing| existing.id == coverage.id)
        {
            Some(existing) => {
                existing.objects_analyzed += coverage.objects_analyzed;
                existing.skipped_unsupported += coverage.skipped_unsupported;
                existing.findings += coverage.findings;
            }
            None => accumulated.push(coverage),
        }
    }
}

/// D03: resumen de seguridad separado del veredicto de estilo; `None` si
/// ningún pack de seguridad aportó hallazgos.
fn build_security_summary(findings: &[Issue]) -> Option<SecuritySummary> {
    let security: Vec<&Issue> = findings
        .iter()
        .filter(|issue| issue.category.as_deref() == Some("security"))
        .collect();
    if security.is_empty() {
        return None;
    }
    let errors = security
        .iter()
        .filter(|issue| issue.severity == gx_core::models::Severity::Error)
        .count();
    Some(SecuritySummary {
        findings: security.len(),
        errors,
        verdict: if errors > 0 {
            QgVerdict::Reject
        } else {
            QgVerdict::Pass
        },
    })
}

/// Rule-set reutilizable por worker para un plan concreto (B02).
struct ThreadRuleSet {
    plan_id: u64,
    rules: Vec<Box<dyn Rule>>,
}

thread_local! {
    static THREAD_RULE_SET: std::cell::RefCell<Option<ThreadRuleSet>> =
        const { std::cell::RefCell::new(None) };
}

/// Ejecuta `f` con el rule-set del worker actual, instanciándolo UNA vez por
/// worker y plan (y reseteándolo por objeto dentro de `evaluate_object`).
fn with_worker_rules<R>(plan: &RulePlan, f: impl FnOnce(&mut [Box<dyn Rule>]) -> R) -> R {
    THREAD_RULE_SET.with(|cell| {
        let mut slot = cell.borrow_mut();
        let needs_new = slot
            .as_ref()
            .map(|set| set.plan_id != plan.id())
            .unwrap_or(true);
        if needs_new {
            *slot = Some(ThreadRuleSet {
                plan_id: plan.id(),
                rules: plan.instantiate(),
            });
        }
        let set = slot.as_mut().expect("rule-set inicializado");
        f(set.rules.as_mut_slice())
    })
}

/// Cierre común de una corrida de archivo: contadores, log y outcome.
fn finish_file_run(
    path: &Path,
    t_start: Instant,
    objects: usize,
    issues: Vec<Issue>,
    limit: Option<String>,
    cancelled: bool,
    pack_coverage: Vec<PackCoverage>,
) -> Result<FileRunOutcome> {
    // Si se cortó por cancelación, los hallazgos acumulados se conservan
    // pero el archivo NO cuenta como escaneado con éxito.
    gx_core::stats::count_findings(issues.len());
    let elapsed_ms = t_start.elapsed().as_millis();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    tracing::info!(
        "[ENGINE] {name} — {objects} objetos | {} findings | {elapsed_ms} ms | cancelled={cancelled} limit={limit:?}",
        issues.len()
    );
    Ok(FileRunOutcome {
        issues,
        elapsed_ms,
        limit,
        cancelled,
        pack_coverage,
    })
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
    let mut pack_coverage: Vec<PackCoverage> = Vec::new();
    for outcome in outcomes {
        if outcome.cancelled {
            any_cancelled = true;
            findings.extend(outcome.issues);
            merge_pack_coverage(&mut pack_coverage, outcome.pack_coverage);
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
        merge_pack_coverage(&mut pack_coverage, outcome.pack_coverage);
        if let Some(limit) = outcome.limit {
            any_limit = true;
            failures.push(ScanFailure {
                path: outcome.path,
                error: format!("presupuesto agotado: {limit}"),
            });
        }
    }
    pack_coverage.sort_by(|a, b| a.id.cmp(&b.id));

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

    // D03: la seguridad se evalúa aparte de la política de estilo; un error
    // de seguridad no se diluye por el porcentaje de hallazgos de estilo.
    let security = build_security_summary(&findings);
    let security_failed = security
        .as_ref()
        .map(|summary| summary.errors > 0)
        .unwrap_or(false);

    let metrics = build_metrics(&findings);
    let verdict = if completion != ScanCompletion::Complete {
        QgVerdict::Error
    } else if security_failed {
        QgVerdict::Reject
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
        pack_coverage,
        security,
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
    /// Cobertura por pack de objeto (D01).
    pub pack_coverage: Vec<PackCoverage>,
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
        pack_coverage: Vec::new(),
        security: None,
    }
}

/// Plan de ejecución inmutable (B02): descriptores seleccionados + dispatch.
///
/// Se compila UNA vez por sesión/corrida. Las reglas se instancian por job
/// (`instantiate`) y se resetean por objeto; nunca se construye el catálogo
/// completo por archivo.
pub struct RulePlan {
    /// Identidad de la compilación: los rule-sets thread-local se invalidan
    /// cuando cambia el plan (B02).
    id: u64,
    descriptors: Vec<&'static RuleDescriptor>,
    dispatch: DispatchPlan,
    /// Unión de hechos requeridos por los packs seleccionados (D01). Vacía
    /// para el perfil de estilo común: no se construye ningún hecho.
    facts_union: FactSet,
}

static NEXT_PLAN_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl RulePlan {
    /// Selecciona descriptores concretos habilitados y compila el dispatch.
    pub fn compile(enabled_ids: &HashSet<String>) -> Result<RulePlan> {
        let descriptors: Vec<&'static RuleDescriptor> = gx_rules::catalog()
            .iter()
            .filter(|descriptor| !descriptor.is_abstract && enabled_ids.contains(descriptor.id))
            .collect();
        let dispatch = plan_dispatch_descriptors(&descriptors).map_err(anyhow::Error::msg)?;
        let facts_union = descriptors.iter().fold(FactSet::NONE, |acc, descriptor| {
            acc.union(descriptor.capability.facts)
        });
        Ok(RulePlan {
            id: NEXT_PLAN_ID.fetch_add(1, Ordering::Relaxed),
            descriptors,
            dispatch,
            facts_union,
        })
    }

    fn id(&self) -> u64 {
        self.id
    }

    /// Hechos requeridos por el plan (D01): vacío ⇒ sin costo semántico.
    pub fn facts_union(&self) -> FactSet {
        self.facts_union
    }

    pub fn rules_len(&self) -> usize {
        self.descriptors.len()
    }

    pub fn dispatch(&self) -> &DispatchPlan {
        &self.dispatch
    }

    /// Instancia SÓLO las reglas seleccionadas (contadores A02/B02).
    pub fn instantiate(&self) -> Vec<Box<dyn Rule>> {
        let rules: Vec<Box<dyn Rule>> = self
            .descriptors
            .iter()
            .map(|descriptor| (descriptor.factory)())
            .collect();
        gx_core::stats::count_rule_set_instantiation();
        gx_core::stats::count_rule_factories(rules.len());
        rules
    }
}

/// Build rules + dispatch plan from an explicit enabled set, without
/// touching SQLite. Used for deterministic tests, read-only scans and
/// sequential consumers.
pub fn build_rules(enabled_ids: &HashSet<String>) -> (Vec<Box<dyn Rule>>, DispatchPlan) {
    let plan = RulePlan::compile(enabled_ids).expect("reglas del registry con triggers válidos");
    let rules = plan.instantiate();
    (rules, plan.dispatch.clone())
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

    // B02: el plan se compila UNA vez; cada job de Rayon instancia sus reglas.
    let plan = match RulePlan::compile(enabled_ids) {
        Ok(plan) => plan,
        Err(error) => {
            let message = error.to_string();
            return paths
                .iter()
                .map(|p| FileScanOutcome {
                    path: p.clone(),
                    issues: Vec::new(),
                    metrics: AuditMetrics::default(),
                    error: Some(message.clone()),
                    limit: None,
                    cancelled: false,
                    pack_coverage: Vec::new(),
                })
                .collect();
        }
    };

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
                        pack_coverage: Vec::new(),
                    }
                } else {
                    let ctx = ctx_factory(p);
                    match run_file_planned(&plan, p, &ctx, budget, cancel) {
                        Ok(run) => {
                            let metrics = AuditMetrics::from_issues(&run.issues);
                            FileScanOutcome {
                                path: p.clone(),
                                issues: run.issues,
                                metrics,
                                error: None,
                                limit: run.limit,
                                cancelled: run.cancelled,
                                pack_coverage: run.pack_coverage,
                            }
                        }
                        Err(e) => FileScanOutcome {
                            path: p.clone(),
                            issues: Vec::new(),
                            metrics: AuditMetrics::default(),
                            error: Some(e.to_string()),
                            limit: None,
                            cancelled: false,
                            pack_coverage: Vec::new(),
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
