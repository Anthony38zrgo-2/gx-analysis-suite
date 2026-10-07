//! D04: perfil profundo project-wide (grafo + taint interprocedural + caché
//! incremental). Todo el trabajo con contadores globales vive en un test.

use std::path::PathBuf;

use gx_core::models::{AnalysisRequest, QgPolicy, QgVerdict};
use gx_core::stats;
use gx_engine::runtime::analyze;

fn tmp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn request(inputs: Vec<PathBuf>, rules: &[&str]) -> AnalysisRequest {
    AnalysisRequest {
        schema_version: 1,
        inputs,
        enabled_rule_ids: rules.iter().map(|id| id.to_string()).collect(),
        policy: QgPolicy::Percentage {
            max_error_pct: 100.0,
        },
        record_history: false,
        retain_sensitive_evidence: false,
        discovery: Default::default(),
    }
}

/// D04: el perfil profundo es opt-in, encuentra el flujo entre objetos con
/// traza, reutiliza sumarios en la segunda corrida y no toca el presupuesto
/// del perfil estándar.
#[test]
fn project_profile_finds_interprocedural_flow_and_is_opt_in() {
    let dir = tmp_dir("gx_phase_d_deep");
    std::fs::write(
        dir.join("Caller.txt"),
        "parm(in:&Entrada)\ncall('ProcSink', &Entrada)\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("ProcSink.txt"),
        "parm(in:&Valor)\n\
         &sql = 'select * from Cliente where nombre = ' + &Valor\n\
         &sql.Execute()\n",
    )
    .unwrap();

    // Perfil estándar: CERO trabajo de proyecto.
    stats::reset();
    let style = analyze(&request(vec![dir.clone()], &["GX.1.1"]));
    let style_stats = stats::snapshot();
    assert_eq!(style_stats.project_objects, 0);
    assert_eq!(style_stats.project_iterations, 0);
    assert!(style.pack_coverage.is_empty());
    assert!(style
        .findings
        .iter()
        .all(|issue| issue.category.as_deref() != Some("security")));

    // Perfil profundo opt-in: hallazgo con traza source→call→sink.
    stats::reset();
    let deep = analyze(&request(vec![dir.clone()], &["GX.SEC.3"]));
    let deep_stats = stats::snapshot();
    assert_eq!(deep.scanned_files, 2, "failures: {:?}", deep.failures);
    assert_eq!(deep.findings.len(), 1, "findings: {:?}", deep.findings);
    let issue = &deep.findings[0];
    assert_eq!(issue.rule_id, "GX.SEC.3");
    assert_eq!(issue.cwe, Some(89));
    assert_eq!(issue.category.as_deref(), Some("security"));
    assert!(
        issue
            .trace
            .as_ref()
            .unwrap()
            .iter()
            .any(|step| step.kind == "call"),
        "la traza debe cruzar la llamada: {:?}",
        issue.trace
    );
    assert_eq!(issue.object.as_ref().unwrap().id.to_lowercase(), "procsink");
    assert_eq!(deep.verdict, QgVerdict::Reject);
    assert_eq!(deep.pack_coverage.len(), 1);
    assert_eq!(deep.pack_coverage[0].id, "GX.SEC.3");
    assert_eq!(deep.pack_coverage[0].findings, 1);
    assert_eq!(deep_stats.project_objects, 2);
    assert_eq!(deep_stats.project_edges, 1);
    assert!(deep_stats.project_cache_misses >= 2);

    // Segunda corrida: sumarios reutilizados (warm) y mismo resultado.
    stats::reset();
    let again = analyze(&request(vec![dir.clone()], &["GX.SEC.3"]));
    let again_stats = stats::snapshot();
    assert_eq!(again.findings.len(), 1);
    assert!(
        again_stats.project_cache_hits >= 2,
        "warm hits esperados: {again_stats:?}"
    );
    assert_eq!(again.pack_coverage[0].findings, 1);

    let _ = std::fs::remove_dir_all(&dir);
}
