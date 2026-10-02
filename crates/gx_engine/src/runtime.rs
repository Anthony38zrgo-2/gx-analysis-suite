//! Analysis orchestrator. Port of `gx_linter/app/engine/runtime.py`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Result;
use gx_core::filesystem::Filesystem;
use gx_core::models::{
    AnalysisRequest, AnalysisResult, AuditContext, AuditMetrics, Issue, ParsedLine, QgVerdict,
    ScanFailure, SourceLine,
};
use gx_core::regex_cache::blank_multiline_block_comments;
use gx_core::xpz_extractor::extract_source_objects;
use gx_rules::base::Rule;
use gx_storage::dao::rules_dao;

use crate::dispatch::{collect_candidate_rules, plan_dispatch, DispatchPlan};

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
    let objects = extract_source_objects(path)?;
    let mut issues: Vec<Issue> = Vec::new();

    let t_start = Instant::now();
    let mut rules_fired_total: usize = 0;

    for obj in &objects {
        // Estado por objeto: reset antes de cada objeto (GX-006).
        for r in rules.iter_mut() {
            r.reset(path);
        }
        let obj_start = issues.len();
        // Bloques /* */ multilínea se enmascaran ANTES del linteo por línea
        // (GX-008: código deshabilitado no se lentea; números de línea
        // preservados).
        let text = blank_multiline_block_comments(&obj.text);
        let lines: Vec<&str> = text.split('\n').collect();

        for (idx, raw_line) in lines.iter().enumerate() {
            let content = raw_line.trim_end_matches('\r');
            if content
                .to_lowercase()
                .contains("generated subroutines (public)")
            {
                break;
            }
            let source = SourceLine {
                number: idx as u32 + 1,
                content: content.to_string(),
            };
            let parsed = ParsedLine::from_source(source);
            if parsed.stripped.is_empty() {
                continue;
            }
            let candidates = collect_candidate_rules(&parsed, dispatch);
            rules_fired_total += candidates.len();
            for idx in candidates {
                let result = rules[idx].evaluate(&parsed, ctx);
                issues.extend(result);
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

    let elapsed_ms = t_start.elapsed().as_millis();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    tracing::info!(
        "[ENGINE] {name} — {} objetos | {rules_fired_total} rule-evaluations | {} findings | {elapsed_ms} ms",
        objects.len(),
        issues.len()
    );
    Ok((issues, elapsed_ms))
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
    let enabled: HashSet<String> = request.enabled_rule_ids.iter().cloned().collect();
    let mut inputs: Vec<PathBuf> = Vec::new();
    let mut failures: Vec<ScanFailure> = Vec::new();

    for input in &request.inputs {
        if input.is_file() {
            inputs.push(input.clone());
        } else if input.is_dir() {
            inputs.extend(Filesystem::find_source_files(input));
        } else {
            failures.push(ScanFailure {
                path: input.clone(),
                error: "El path no existe".to_string(),
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

    let outcomes = evaluate_files_parallel_with_ctx(&inputs, &enabled, |path| AuditContext {
        project_path: path.to_path_buf(),
        rules_path: path.to_path_buf(),
        max_errors,
        max_warnings,
        qg_threshold_pct,
        extra_settings: Default::default(),
    });

    let mut findings: Vec<Issue> = Vec::new();
    let mut scanned_files: usize = 0;
    for outcome in outcomes {
        if let Some(error) = outcome.error {
            failures.push(ScanFailure {
                path: outcome.path,
                error,
            });
        } else {
            scanned_files += 1;
            findings.extend(outcome.issues);
        }
    }

    let metrics = build_metrics(&findings);
    let verdict = if !failures.is_empty() {
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
    evaluate_files_parallel_with_ctx(paths, enabled_ids, |_p| ctx.clone())
}

/// Variante con contexto por archivo (usada por [`analyze`]).
fn evaluate_files_parallel_with_ctx<F>(
    paths: &[PathBuf],
    enabled_ids: &HashSet<String>,
    ctx_factory: F,
) -> Vec<FileScanOutcome>
where
    F: Fn(&Path) -> AuditContext + Sync,
{
    use rayon::prelude::*;
    paths
        .par_iter()
        .map(|p| {
            let (mut rules, dispatch) = build_rules(enabled_ids);
            let ctx = ctx_factory(p);
            match run_file(&mut rules, &dispatch, p, &ctx) {
                Ok((issues, _)) => {
                    let metrics = AuditMetrics::from_issues(&issues);
                    FileScanOutcome {
                        path: p.clone(),
                        issues,
                        metrics,
                        error: None,
                    }
                }
                Err(e) => FileScanOutcome {
                    path: p.clone(),
                    issues: Vec::new(),
                    metrics: AuditMetrics::default(),
                    error: Some(e.to_string()),
                },
            }
        })
        .collect()
}
