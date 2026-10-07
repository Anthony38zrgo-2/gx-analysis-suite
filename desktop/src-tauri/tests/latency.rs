//! §5 (desktop response): presupuesto de latencia p95 en el boundary IPC.
//!
//! Mide páginas de findings (sin filtro, con filtro de severidad y búsqueda)
//! y la ventana de fuente sobre una sesión de 50k findings (el techo del
//! `SessionStore`). La medición interactiva en WebView2 complementa con
//! `pageLatencyMs`/`windowLatencyMs` (C03); este harness es el gate
//! automatizable en CI.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use gx_core::models::{
    AnalysisRequest, AnalysisResult, AuditMetrics, DiscoveryPolicy, Issue, ObjectRef, QgPolicy,
    QgVerdict, ScanCompletion, ScanCoverage, Severity,
};
use gx_linter_desktop_lib::commands::{findings_page, object_window, DesktopState};

/// §5: p95 objetivo de operaciones de página/filtro/ventana (< 200 ms).
const BUDGET: Duration = Duration::from_millis(200);
/// Techo del `SessionStore` (C01): el peor caso realista de la UI.
const FINDINGS: usize = 50_000;
const ITERATIONS: usize = 20;

fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(rel)
}

fn request(container: &Path) -> AnalysisRequest {
    AnalysisRequest {
        schema_version: 1,
        inputs: vec![container.to_path_buf()],
        enabled_rule_ids: vec!["GX.1.1".to_string(), "GX.2.5".to_string()],
        policy: QgPolicy::Percentage {
            max_error_pct: 10.0,
        },
        record_history: false,
        retain_sensitive_evidence: false,
        discovery: DiscoveryPolicy::default(),
    }
}

fn synthetic_result(request: AnalysisRequest, container: &Path) -> AnalysisResult {
    let container = container.to_string_lossy().to_string();
    let findings: Vec<Issue> = (0..FINDINGS)
        .map(|index| {
            let severity = match index % 4 {
                0 | 1 => Severity::Error,
                2 => Severity::Warning,
                _ => Severity::Info,
            };
            Issue {
                rule_id: format!("GX.2.{}", index % 7),
                severity,
                line_number: (index % 5000) as u32 + 1,
                line_content: "where CustomerType = \"VIP\"".to_string(),
                description: format!(
                    "Hallazgo sintético {index} con una descripción representativa de producción"
                ),
                file_path: PathBuf::from(&container),
                object: Some(ObjectRef {
                    id: "ProcMalo".to_string(),
                    object_type: "Procedure".to_string(),
                    package: "PkgDemo".to_string(),
                    member: "PkgDemo/ProcMalo.xml".to_string(),
                    container_path: container.clone(),
                }),
                category: None,
                confidence: None,
                cwe: None,
                trace: None,
            }
        })
        .collect();
    let metrics = AuditMetrics::from_issues(&findings);
    AnalysisResult {
        schema_version: 1,
        request: request.clone(),
        scanned_files: 1,
        findings,
        metrics,
        failures: Vec::new(),
        policy: request.policy.clone(),
        verdict: QgVerdict::Reject,
        coverage: ScanCoverage {
            inputs_declared: 1,
            inputs_scanned: 1,
            files_discovered: 1,
            files_excluded: 0,
            files_deduplicated: 0,
            source_free_inputs: 0,
        },
        completion: ScanCompletion::Complete,
        pack_coverage: Vec::new(),
        security: None,
    }
}

/// p95 de una muestra (ceil, como el harness de benchmarks).
fn p95(mut samples: Vec<Duration>) -> Duration {
    samples.sort();
    let index = ((samples.len() as f64 - 1.0) * 0.95).ceil() as usize;
    samples[index.min(samples.len() - 1)]
}

#[test]
fn ipc_page_filter_and_window_p95_stay_within_budget() {
    let container = fixture("sources/sample_package.xpz");
    assert!(container.is_file(), "fixture: {}", container.display());
    let request = request(&container);
    let result = synthetic_result(request.clone(), &container);
    let dir = std::env::temp_dir().join("gx_desktop_latency");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let state = DesktopState::with_db_path(dir.join("gx_linter.db"));
    let session_id = state.store_session(request, result, None);
    assert!(session_id > 0, "sesión creada");

    // Página sin filtro: recalcula el índice de reglas sobre 50k findings.
    let mut samples = Vec::with_capacity(ITERATIONS);
    for index in 0..ITERATIONS {
        let start = Instant::now();
        let page = findings_page(
            &state,
            session_id,
            Some(index * 100),
            Some(100),
            None,
            None,
            None,
        )
        .expect("página válida");
        assert_eq!(page.items.len(), 100);
        samples.push(start.elapsed());
    }
    let unfiltered = p95(samples);

    // Filtro por severidad (server-side) sobre 50k.
    let mut samples = Vec::with_capacity(ITERATIONS);
    for index in 0..ITERATIONS {
        let start = Instant::now();
        let page = findings_page(
            &state,
            session_id,
            Some(index * 50),
            Some(100),
            Some("ERROR".to_string()),
            None,
            None,
        )
        .expect("página válida");
        assert!(!page.items.is_empty());
        samples.push(start.elapsed());
    }
    let severity = p95(samples);

    // Búsqueda de texto (el peor caso: normaliza y arma haystack por finding).
    let mut samples = Vec::with_capacity(5);
    for _ in 0..5 {
        let start = Instant::now();
        let page = findings_page(
            &state,
            session_id,
            Some(0),
            Some(100),
            None,
            None,
            Some("ProcMalo".to_string()),
        )
        .expect("página válida");
        assert_eq!(page.filtered_total, FINDINGS);
        samples.push(start.elapsed());
    }
    let search = p95(samples);

    // Ventana de fuente: primera llamada extrae, las siguientes usan caché.
    let container_str = container.to_string_lossy().to_string();
    let mut samples = Vec::with_capacity(ITERATIONS);
    for _ in 0..ITERATIONS {
        let start = Instant::now();
        let window = object_window(
            &state,
            session_id,
            &container_str,
            "PkgDemo/ProcMalo.xml",
            "ProcMalo",
            Some(1),
            Some(200),
        )
        .expect("ventana válida");
        assert!(!window.lines.is_empty());
        samples.push(start.elapsed());
    }
    let window = p95(samples);

    eprintln!(
        "[latency] page p95={unfiltered:?} severity p95={severity:?} \
         search p95={search:?} window p95={window:?} (budget {BUDGET:?})"
    );
    assert!(
        unfiltered < BUDGET,
        "p95 de página {unfiltered:?} >= {BUDGET:?}"
    );
    assert!(
        severity < BUDGET,
        "p95 de filtro por severidad {severity:?} >= {BUDGET:?}"
    );
    assert!(search < BUDGET, "p95 de búsqueda {search:?} >= {BUDGET:?}");
    assert!(
        window < BUDGET,
        "p95 de ventana de fuente {window:?} >= {BUDGET:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
