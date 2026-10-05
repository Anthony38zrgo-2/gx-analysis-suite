//! A01/A03: frontera de confianza del request, cobertura y evidencia.
//!
//! Reproduce los probes del review: regla desconocida, directorio sin
//! archivos fuente y porcentaje inválido ya NO pueden reportar un PASS sin
//! calificar.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use gx_core::budget::ExecutionBudget;
use gx_core::models::{AnalysisRequest, AuditContext, QgPolicy, QgVerdict, ScanCompletion};
use gx_engine::runtime::{analyze, analyze_with_options, scan_file, validate_request};

fn fixtures(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn default_rules() -> Vec<String> {
    let mut ids: Vec<String> = gx_storage::seed::default_enabled_ids()
        .into_iter()
        .collect();
    ids.sort();
    ids
}

fn request(inputs: Vec<PathBuf>, rules: Vec<String>) -> AnalysisRequest {
    AnalysisRequest {
        schema_version: 1,
        inputs,
        enabled_rule_ids: rules,
        policy: QgPolicy::Absolute {
            max_errors: 999,
            max_warnings: 999,
        },
        record_history: false,
    }
}

fn tmp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn ctx_for(path: &Path) -> AuditContext {
    AuditContext {
        project_path: path.to_path_buf(),
        rules_path: path.to_path_buf(),
        max_errors: 0,
        max_warnings: 999_999,
        qg_threshold_pct: 10.0,
        extra_settings: Default::default(),
    }
}

/// F01: regla desconocida → veredicto Error, nunca PASS silencioso.
#[test]
fn unknown_rule_never_passes() {
    let clean = fixtures("sources/clean_object.txt");
    let req = request(vec![clean], vec!["GX.999".to_string()]);
    assert!(validate_request(&req).is_err());
    let r = analyze(&req);
    assert_eq!(r.verdict, QgVerdict::Error);
    assert_eq!(r.completion, ScanCompletion::Failed);
    assert_eq!(
        r.scanned_files, 0,
        "no se escanea nada con request inválido"
    );
    assert!(r.findings.is_empty());
    assert!(
        r.failures[0].error.contains("desconocida"),
        "failure: {:?}",
        r.failures
    );
}

/// F01: set de reglas vacío es inválido (modo explícito, no PASS).
#[test]
fn empty_rule_set_is_invalid() {
    let clean = fixtures("sources/clean_object.txt");
    let req = request(vec![clean], Vec::new());
    assert!(validate_request(&req).is_err());
    assert_eq!(analyze(&req).verdict, QgVerdict::Error);
}

/// F01: porcentaje fuera de rango o no finito se rechaza.
#[test]
fn invalid_percentage_is_rejected() {
    for pct in [101.0_f32, -1.0, f32::NAN] {
        let clean = fixtures("sources/clean_object.txt");
        let mut req = request(vec![clean], default_rules());
        req.policy = QgPolicy::Percentage { max_error_pct: pct };
        assert!(validate_request(&req).is_err(), "pct={pct}");
        assert_eq!(analyze(&req).verdict, QgVerdict::Error, "pct={pct}");
    }
}

/// F02: un directorio sin archivos fuente es un fallo, no un PASS en cero.
#[test]
fn source_free_directory_is_a_failure() {
    let dir = tmp_dir("gx_engine_source_free");
    std::fs::write(dir.join("datos.csv"), "a,b\n").unwrap();
    let req = request(vec![dir.clone()], default_rules());
    let r = analyze(&req);
    assert_eq!(r.verdict, QgVerdict::Error);
    assert_eq!(r.completion, ScanCompletion::Failed);
    assert_eq!(r.scanned_files, 0);
    assert_eq!(r.coverage.source_free_inputs, 1);
    assert_eq!(r.coverage.files_excluded, 1);
    assert!(
        r.failures[0].error.contains("no contiene archivos fuente"),
        "failure: {:?}",
        r.failures
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// F02: inputs solapados se escanean UNA sola vez, en orden determinista.
#[test]
fn overlapping_inputs_are_scanned_once() {
    let dir = tmp_dir("gx_engine_overlap");
    let file = dir.join("clean_object.txt");
    std::fs::copy(fixtures("sources/clean_object.txt"), &file).unwrap();
    let req = request(vec![dir.clone(), file], default_rules());
    let r = analyze(&req);
    assert_eq!(r.scanned_files, 1, "el archivo se escanea una vez");
    assert_eq!(r.coverage.files_deduplicated, 1);
    assert_eq!(r.verdict, QgVerdict::Pass);
    let _ = std::fs::remove_dir_all(&dir);
}

/// F02: `.zip` es una extensión fuente para discovery y extracción.
#[test]
fn zip_extension_is_discovered_and_scanned() {
    let dir = tmp_dir("gx_engine_zip");
    let zipped = dir.join("paquete.zip");
    std::fs::copy(fixtures("sources/sample_package.xpz"), &zipped).unwrap();
    let req = request(vec![dir.clone()], default_rules());
    let r = analyze(&req);
    assert_eq!(r.scanned_files, 1, "failure: {:?}", r.failures);
    assert_eq!(r.metrics.total_findings, 2, "los 2 hallazgos del paquete");
    assert_eq!(r.verdict, QgVerdict::Pass, "dentro de los umbrales amplios");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A03/F03: GX.2.5 examina el literal del WHERE (antes era invisible).
#[test]
fn gx_2_5_detects_hardcoded_literal() {
    let dir = tmp_dir("gx_engine_hardcode");
    let file = dir.join("where.txt");
    std::fs::write(
        &file,
        "for each Customer\n    where CustomerName = 'Admin'\nendfor\n",
    )
    .unwrap();
    let enabled: HashSet<String> = ["GX.2.5".to_string()].into_iter().collect();
    let issues = scan_file(&file, &enabled, &ctx_for(&file)).unwrap();
    assert_eq!(issues.len(), 1, "issues: {issues:?}");
    assert_eq!(issues[0].rule_id, "GX.2.5");
    assert!(
        issues[0].description.contains("'admin'"),
        "descripción: {}",
        issues[0].description
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A04/F07: un input que supera el presupuesto es `partial`, nunca PASS.
#[test]
fn oversized_input_is_partial() {
    let clean = fixtures("sources/clean_object.txt");
    let req = request(vec![clean], default_rules());
    let budget = ExecutionBudget {
        max_input_bytes: 8,
        ..Default::default()
    };
    let r = analyze_with_options(&req, None, None, &budget);
    assert_eq!(r.completion, ScanCompletion::Partial);
    assert_eq!(r.verdict, QgVerdict::Error);
    assert!(
        r.failures
            .iter()
            .any(|f| f.error.contains("presupuesto agotado")),
        "failures: {:?}",
        r.failures
    );
}

/// A04: deadline agotado → `partial` con diagnostics ya calculados.
#[test]
fn expired_deadline_is_partial() {
    let golden = fixtures("sources/ejemplo_codigo.txt");
    let req = request(vec![golden], default_rules());
    let budget = ExecutionBudget::with_timeout(Duration::from_millis(0));
    let r = analyze_with_options(&req, None, None, &budget);
    assert_eq!(r.completion, ScanCompletion::Partial);
    assert_eq!(r.verdict, QgVerdict::Error);
}

/// A04: límite de findings retenidos acota memoria sin perder lo calculado.
#[test]
fn findings_limit_is_partial_and_bounded() {
    let golden = fixtures("sources/ejemplo_codigo.txt");
    let req = request(vec![golden], default_rules());
    let budget = ExecutionBudget {
        max_findings: 5,
        ..Default::default()
    };
    let r = analyze_with_options(&req, None, None, &budget);
    assert_eq!(r.completion, ScanCompletion::Partial);
    assert_eq!(r.verdict, QgVerdict::Error);
    assert!(
        r.findings.len() < 22,
        "no se retiene el total: {}",
        r.findings.len()
    );
}

/// A04/F08: cancelación previa → `cancelled`, nunca un escaneo limpio.
#[test]
fn preset_cancellation_is_cancelled() {
    let golden = fixtures("sources/ejemplo_codigo.txt");
    let req = request(vec![golden], default_rules());
    let cancel = AtomicBool::new(true);
    let r = analyze_with_options(&req, None, Some(&cancel), &ExecutionBudget::default());
    assert_eq!(r.completion, ScanCompletion::Cancelled);
    assert_eq!(r.verdict, QgVerdict::Error);
    assert_eq!(r.scanned_files, 0);
    assert!(r
        .failures
        .iter()
        .any(|f| f.error.contains("cancelado por el usuario")));
}

/// A03/F03: un string con marcador de comentario conserva la evidencia.
#[test]
fn evidence_preserves_string_with_comment_markers() {
    let dir = tmp_dir("gx_engine_evidence");
    let file = dir.join("evidence.txt");
    std::fs::write(&file, "&lower = '/* no es comentario */'\n").unwrap();
    let enabled: HashSet<String> = ["GX.1.1".to_string()].into_iter().collect();
    let issues = scan_file(&file, &enabled, &ctx_for(&file)).unwrap();
    assert_eq!(issues.len(), 1, "issues: {issues:?}");
    assert_eq!(
        issues[0].line_content, "&lower = '/* no es comentario */'",
        "la evidencia es el texto ORIGINAL, no la vista enmascarada"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
