//! Contrato de análisis: políticas, determinismo y fallos (GX-010).

use gx_core::models::{AnalysisRequest, AuditMetrics, Issue, QgPolicy, QgVerdict, ScanFailure};
use gx_engine::runtime::analyze;
use std::path::PathBuf;

fn request(inputs: &[&str], policy: QgPolicy, record_history: bool) -> AnalysisRequest {
    AnalysisRequest {
        schema_version: 1,
        inputs: inputs.iter().map(PathBuf::from).collect(),
        enabled_rule_ids: gx_storage::seed::default_enabled_ids()
            .into_iter()
            .collect(),
        policy,
        record_history,
    }
}

fn golden() -> String {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    dir.join("../../tests/fixtures/sources/ejemplo_codigo.txt")
        .to_string_lossy()
        .to_string()
}

fn clean() -> String {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    dir.join("../../tests/fixtures/sources/clean_object.txt")
        .to_string_lossy()
        .to_string()
}

/// La misma solicitud produce EXACTAMENTE el mismo resultado con o sin
/// historial habilitado (SQLite no altera hallazgos ni veredicto).
#[test]
fn same_request_same_result_with_or_without_history() {
    let with = request(
        &[&golden()],
        QgPolicy::Absolute {
            max_errors: 999,
            max_warnings: 999,
        },
        true,
    );
    let without = request(
        &[&golden()],
        QgPolicy::Absolute {
            max_errors: 999,
            max_warnings: 999,
        },
        false,
    );

    let a = analyze(&with);
    let b = analyze(&without);
    // La solicitud difiere sólo en record_history: hallazgos, métricas y
    // veredicto deben ser idénticos.
    assert_eq!(
        a.findings, b.findings,
        "hallazgos idénticos con y sin historial"
    );
    assert_eq!(a.metrics, b.metrics);
    assert_eq!(a.verdict, b.verdict);
    assert_eq!(a.metrics.total_findings, 23);
    assert_eq!(a.verdict, QgVerdict::Pass);
}

/// Política absolute: pass / reject.
#[test]
fn absolute_policy_pass_and_reject() {
    let pass = request(
        &[&clean()],
        QgPolicy::Absolute {
            max_errors: 0,
            max_warnings: 999_999,
        },
        false,
    );
    let r = analyze(&pass);
    assert_eq!(r.verdict, QgVerdict::Pass);
    assert_eq!(r.findings.len(), 0, "archivo limpio sin hallazgos");

    let reject = request(
        &[&golden()],
        QgPolicy::Absolute {
            max_errors: 0,
            max_warnings: 999_999,
        },
        false,
    );
    let r = analyze(&reject);
    assert_eq!(r.verdict, QgVerdict::Reject);
    assert_eq!(r.metrics.errors, 15);
}

/// Política percentage (GUI legada): pass / reject y cero hallazgos.
#[test]
fn percentage_policy_pass_reject_and_zero_findings() {
    let zero = request(
        &[&clean()],
        QgPolicy::Percentage {
            max_error_pct: 10.0,
        },
        false,
    );
    assert_eq!(
        analyze(&zero).verdict,
        QgVerdict::Pass,
        "cero hallazgos = pass"
    );

    let pass = request(
        &[&golden()],
        QgPolicy::Percentage {
            max_error_pct: 100.0,
        },
        false,
    );
    assert_eq!(analyze(&pass).verdict, QgVerdict::Pass, "100% admite todo");

    let reject = request(
        &[&golden()],
        QgPolicy::Percentage {
            max_error_pct: 10.0,
        },
        false,
    );
    let r = analyze(&reject);
    // 15 de 23 = 65.2% > 10% → reject.
    assert_eq!(r.verdict, QgVerdict::Reject);
    assert_eq!(r.policy.name(), "percentage");
}

/// Fallos de scan siempre fallan el gate y van a `failures`, no a hallazgos.
#[test]
fn scan_errors_always_fail_the_gate() {
    let req = request(
        &[&clean(), "no_existe_gx.txt"],
        QgPolicy::Absolute {
            max_errors: 0,
            max_warnings: 999_999,
        },
        false,
    );
    let r = analyze(&req);
    assert_eq!(
        r.verdict,
        QgVerdict::Error,
        "fallo de scan = veredicto Error"
    );
    assert_eq!(r.failures.len(), 1);
    assert_eq!(
        r.failures[0],
        ScanFailure {
            path: PathBuf::from("no_existe_gx.txt"),
            error: "El path no existe".to_string()
        }
    );
    // El archivo bueno sí se escaneó; su hallazgo (0) no se pierde.
    assert_eq!(r.scanned_files, 1);
    assert_eq!(r.findings.len(), 0);
}

/// El orden de hallazgos de un análisis multi-archivo es determinista.
#[test]
fn multi_input_findings_are_deterministic() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let xpz = dir
        .join("../../tests/fixtures/sources/sample_package.xpz")
        .to_string_lossy()
        .to_string();
    let req = request(
        &[&golden(), &xpz],
        QgPolicy::Absolute {
            max_errors: 999,
            max_warnings: 999,
        },
        false,
    );
    let a = analyze(&req);
    let b = analyze(&req);
    assert_eq!(a, b);
    // golden (23) + xpz (2) = 25 hallazgos.
    assert_eq!(a.metrics.total_findings, 25);
    assert_eq!(a.scanned_files, 2);
}

/// Referencias de tipos para evitar warnings en configuraciones futuras.
#[allow(dead_code)]
fn _type_refs(_: Vec<Issue>, _: AuditMetrics) {}
