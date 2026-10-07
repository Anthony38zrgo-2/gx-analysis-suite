//! C04: samples serializados del contrato Rust↔TypeScript.
//!
//! El JSON versionado es el snapshot del schema y `contract_samples.ts`
//! declara los mismos literales con los tipos de `src/api/types.ts`; el
//! type-check de Vue falla si el schema driftea (campo extra/faltante o
//! discriminante cambiado). Regenerar tras un cambio deliberado:
//!
//! ```text
//! cargo test --manifest-path desktop/src-tauri/Cargo.toml \
//!   --test contract_samples -- --ignored write_contract_samples
//! ```

use std::path::{Path, PathBuf};

use gx_core::models::{
    AnalysisRequest, AnalysisResult, AuditMetrics, DiscoveryPolicy, Issue, ObjectRef, PackCoverage,
    QgPolicy, QgVerdict, ScanCompletion, ScanCoverage, SecuritySummary, Severity, TraceStep,
};
use gx_linter_desktop_lib::commands::{
    FindingsPageDto, HistoryIssuesPageDto, ObjectSegmentDto, ObjectWindowDto, ScanSummaryDto,
    SourceWindowLine,
};
use serde_json::{json, Value};

const CONTAINER: &str = "tests/fixtures/sources/sample_package.xpz";

fn sample_request() -> AnalysisRequest {
    AnalysisRequest {
        schema_version: 1,
        inputs: vec![PathBuf::from(CONTAINER)],
        enabled_rule_ids: vec!["GX.1.1".to_string(), "GX.2.5".to_string()],
        policy: QgPolicy::Percentage {
            max_error_pct: 10.0,
        },
        record_history: false,
        retain_sensitive_evidence: false,
        // A01.5: sample no-default para que el contrato fije la política.
        discovery: DiscoveryPolicy {
            include: vec!["**/*.xml".to_string()],
            exclude: vec!["generated/**".to_string()],
            ignore_file: Some(PathBuf::from("gx.ignore")),
            follow_symlinks: true,
            include_hidden: true,
        },
    }
}

fn sample_issue() -> Issue {
    Issue {
        rule_id: "GX.2.5".to_string(),
        severity: Severity::Error,
        line_number: 63,
        line_content: "where CustomerType = \"VIP\"".to_string(),
        description: "Mala práctica de mantenibilidad: valor en código duro.".to_string(),
        file_path: PathBuf::from(CONTAINER),
        object: Some(ObjectRef {
            id: "ProcMalo".to_string(),
            object_type: "Procedure".to_string(),
            container_path: CONTAINER.to_string(),
            member: "PkgDemo/ProcMalo.xml".to_string(),
            package: "PkgDemo".to_string(),
        }),
        category: None,
        confidence: None,
        cwe: None,
        trace: None,
    }
}

/// D03: hallazgo de seguridad con categoría/confianza/CWE y evidencia
/// redactada.
fn sample_security_issue() -> Issue {
    Issue {
        rule_id: "GX.SEC.1".to_string(),
        severity: Severity::Error,
        line_number: 12,
        line_content: "&password = '***'".to_string(),
        description: "Se detectó un valor sensible embebido (CWE-798).".to_string(),
        file_path: PathBuf::from(CONTAINER),
        object: Some(ObjectRef {
            id: "ProcMalo".to_string(),
            object_type: "Procedure".to_string(),
            container_path: CONTAINER.to_string(),
            member: "PkgDemo/ProcMalo.xml".to_string(),
            package: "PkgDemo".to_string(),
        }),
        category: Some("security".to_string()),
        confidence: Some("high".to_string()),
        cwe: Some(798),
        trace: Some(vec![
            TraceStep {
                kind: "source".to_string(),
                line: 10,
                detail: "parm entrada &password".to_string(),
            },
            TraceStep {
                kind: "sink".to_string(),
                line: 12,
                detail: "write".to_string(),
            },
        ]),
    }
}

fn sample_result() -> AnalysisResult {
    AnalysisResult {
        schema_version: 1,
        request: sample_request(),
        scanned_files: 1,
        findings: vec![sample_issue(), sample_security_issue()],
        metrics: AuditMetrics {
            total_findings: 2,
            errors: 2,
            warnings: 0,
            info: 0,
        },
        failures: Vec::new(),
        policy: QgPolicy::Percentage {
            max_error_pct: 10.0,
        },
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
        pack_coverage: vec![PackCoverage {
            id: "GX.SEC.1".to_string(),
            version: "1.0".to_string(),
            objects_analyzed: 1,
            skipped_unsupported: 0,
            findings: 1,
            unsupported_sanitizers: 1,
        }],
        security: Some(SecuritySummary {
            findings: 1,
            errors: 1,
            verdict: QgVerdict::Reject,
        }),
    }
}

fn sample_summary() -> ScanSummaryDto {
    let result = sample_result();
    ScanSummaryDto {
        session_id: 1,
        schema_version: 1,
        request: result.request.clone(),
        scanned_files: result.scanned_files,
        metrics: result.metrics.clone(),
        failures: result.failures.clone(),
        policy: result.policy.clone(),
        verdict: result.verdict,
        coverage: result.coverage.clone(),
        completion: result.completion,
        findings_total: result.findings.len(),
        history_error: None,
        pack_coverage: result.pack_coverage.clone(),
        security: result.security.clone(),
    }
}

fn sample_page() -> FindingsPageDto {
    FindingsPageDto {
        session_id: 1,
        offset: 0,
        limit: 100,
        filtered_total: 1,
        total: 1,
        items: vec![sample_issue()],
        rules: vec!["GX.2.5".to_string()],
    }
}

fn sample_window() -> ObjectWindowDto {
    ObjectWindowDto {
        session_id: 1,
        id: "ProcMalo".to_string(),
        object_type: "Procedure".to_string(),
        package: "PkgDemo".to_string(),
        member: "PkgDemo/ProcMalo.xml".to_string(),
        container_path: CONTAINER.to_string(),
        code_start_line: 4,
        segments: vec![ObjectSegmentDto {
            kind: "Events".to_string(),
            text_start_line: 1,
            member_start_line: 4,
        }],
        total_lines: 8,
        window_start: 1,
        window_end: 3,
        lines: vec![
            SourceWindowLine {
                text: String::new(),
                text_line: 1,
                member_line: 4,
            },
            SourceWindowLine {
                text: "&MiVar = 1".to_string(),
                text_line: 2,
                member_line: 5,
            },
            SourceWindowLine {
                text: "sub 'Inicializar'".to_string(),
                text_line: 3,
                member_line: 6,
            },
        ],
        source_modified: false,
        cached: false,
    }
}

fn sample_history() -> HistoryIssuesPageDto {
    HistoryIssuesPageDto {
        run_id: 1,
        items: vec![sample_issue()],
        next_cursor: Some("0:7".to_string()),
    }
}

fn samples() -> Value {
    json!({
        "request": sample_request(),
        "result": sample_result(),
        "summary": sample_summary(),
        "findings_page": sample_page(),
        "object_window": sample_window(),
        "history_page": sample_history(),
    })
}

/// TypeScript generado: los literales del contrato asignados a los tipos del
/// frontend (el type-check falla ante cualquier drift de schema).
fn generated_typescript() -> String {
    let mut out = String::new();
    out.push_str(
        "// GENERADO por desktop/src-tauri/tests/contract_samples.rs — no editar a mano.\n\
         // El type-check de Vue falla si el schema Rust driftea de estos tipos.\n\n\
         import type {\n\
         \x20 AnalysisRequest,\n\
         \x20 AnalysisResult,\n\
         \x20 FindingsPage,\n\
         \x20 HistoryIssuesPage,\n\
         \x20 ObjectWindow,\n\
         \x20 ScanSummary,\n\
         } from \"./types\";\n\n",
    );
    let entries: [(&str, Value, &str); 6] = [
        ("requestSample", json!(sample_request()), "AnalysisRequest"),
        ("resultSample", json!(sample_result()), "AnalysisResult"),
        ("summarySample", json!(sample_summary()), "ScanSummary"),
        ("findingsPageSample", json!(sample_page()), "FindingsPage"),
        ("objectWindowSample", json!(sample_window()), "ObjectWindow"),
        (
            "historyPageSample",
            json!(sample_history()),
            "HistoryIssuesPage",
        ),
    ];
    for (name, value, ty) in entries {
        out.push_str(&format!(
            "export const {name}: {ty} = {};\n\n",
            serde_json::to_string_pretty(&value).expect("sample serializable")
        ));
    }
    out
}

fn contract_path(relative: &str) -> PathBuf {
    // CARGO_MANIFEST_DIR = desktop/src-tauri → desktop/<relative>.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(relative)
}

#[test]
fn contract_samples_match_committed_files() {
    let json_path = contract_path("src/api/contract_samples.json");
    let committed: Value = serde_json::from_str(
        &std::fs::read_to_string(&json_path).expect("contract_samples.json existe"),
    )
    .expect("JSON válido");
    assert_eq!(
        committed,
        samples(),
        "schema drift: regenerar con `cargo test --test contract_samples -- --ignored write_contract_samples`"
    );

    let ts_path = contract_path("src/api/contract_samples.ts");
    let committed_ts = std::fs::read_to_string(&ts_path).expect("contract_samples.ts existe");
    assert_eq!(
        committed_ts,
        generated_typescript(),
        "el contrato TS quedó desincronizado del schema Rust"
    );
}

#[test]
#[ignore = "escribe los archivos del contrato (regeneración deliberada)"]
fn write_contract_samples() {
    let json_path = contract_path("src/api/contract_samples.json");
    let ts_path = contract_path("src/api/contract_samples.ts");
    std::fs::write(
        &json_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&samples()).expect("sample serializable")
        ),
    )
    .expect("escritura del JSON de contrato");
    std::fs::write(&ts_path, generated_typescript()).expect("escritura del TS de contrato");
    eprintln!(
        "[contract] regenerados {} y {}",
        json_path.display(),
        ts_path.display()
    );
}
