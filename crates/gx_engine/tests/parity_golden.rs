//! Paridad contra el baseline Python + adjudicaciones (GX-001..GX-004).

mod common;

use common::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::Path;

type Row = (u32, String, String, String, String);

fn sha256_file(path: &Path) -> String {
    let bytes = std::fs::read(path).expect("fixture legible");
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02X}")).collect()
}

fn read_json(path: &Path) -> Value {
    let text = std::fs::read_to_string(path).expect("fixture json legible");
    serde_json::from_str(&text).expect("json válido")
}

fn rows_from_json(issues: &[Value]) -> Vec<Row> {
    issues
        .iter()
        .map(|i| {
            (
                i["line_number"].as_u64().unwrap() as u32,
                i["rule_id"].as_str().unwrap().to_string(),
                i["severity"].as_str().unwrap().to_string(),
                i["description"].as_str().unwrap().to_string(),
                i["line_content"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

/// La relación fixture→golden es machine-checked vía SHA-256 (GX-001).
#[test]
fn baseline_manifest_machine_check() {
    let manifest = read_json(&fixtures_dir().join("sources/baseline_manifest.json"));

    assert_eq!(
        sha256_file(&source_fixture("ejemplo_codigo.txt")),
        manifest["source"]["sha256"].as_str().unwrap(),
        "el fixture fuente cambió; actualizar baseline_manifest.json como decisión de regresión"
    );
    assert_eq!(
        sha256_file(&fixtures_dir().join("golden_issues.json")),
        manifest["golden"]["issuesSha256"].as_str().unwrap()
    );
    assert_eq!(
        sha256_file(&fixtures_dir().join("rule_manifest.json")),
        manifest["ruleManifest"]["rulesSha256"].as_str().unwrap()
    );
    assert_eq!(
        sha256_file(&fixtures_dir().join("golden_adjudications.json")),
        manifest["adjudications"]["adjudicationsSha256"]
            .as_str()
            .unwrap()
    );

    let enabled: Vec<String> = manifest["baseline"]["enabledRules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        enabled.len(),
        manifest["baseline"]["enabledCount"].as_u64().unwrap() as usize
    );
    let seed_set: HashSet<String> = default_enabled();
    let manifest_set: HashSet<String> = enabled.into_iter().collect();
    assert_eq!(
        seed_set, manifest_set,
        "el set por defecto del seed y el del manifest difieren"
    );

    let golden = read_json(&fixtures_dir().join("golden_issues.json"));
    let golden_issues = golden["issues"].as_array().unwrap();
    assert_eq!(
        golden_issues.len(),
        manifest["golden"]["issueCount"].as_u64().unwrap() as usize
    );
    let metrics = &manifest["golden"]["metrics"];
    let errors = golden_issues
        .iter()
        .filter(|i| i["severity"] == "ERROR")
        .count();
    let warnings = golden_issues
        .iter()
        .filter(|i| i["severity"] == "WARNING")
        .count();
    assert_eq!(errors, metrics["errors"].as_u64().unwrap() as usize);
    assert_eq!(warnings, metrics["warnings"].as_u64().unwrap() as usize);
}

/// Baseline Python (intacto) + adjudicaciones explícitas de GX-004.
fn expected_baseline() -> Vec<Row> {
    let golden = read_json(&fixtures_dir().join("golden_issues.json"));
    let adjud = read_json(&fixtures_dir().join("golden_adjudications.json"));
    let mut rows = rows_from_json(golden["issues"].as_array().unwrap());
    let deltas: Vec<Row> = adjud["adjudications"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            let f = &a["finding"];
            (
                f["line_number"].as_u64().unwrap() as u32,
                f["rule_id"].as_str().unwrap().to_string(),
                f["severity"].as_str().unwrap().to_string(),
                f["description"].as_str().unwrap().to_string(),
                f["line_content"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    rows.extend(deltas);
    rows.sort();
    rows
}

/// El engine Rust reproduce el baseline adjudicado: el output Python intacto
/// más exactamente los deltas documentados en golden_adjudications.json.
#[test]
fn golden_parity_canonical() {
    let issues = scan(&source_fixture("ejemplo_codigo.txt"), &default_enabled());
    let got = canonical(&issues);
    let expected = expected_baseline();

    assert_eq!(
        got.len(),
        expected.len(),
        "conteo de hallazgos distinto\nesperado: {expected:#?}\nobtenido: {got:#?}"
    );
    for (idx, (exp, got_row)) in expected.iter().zip(got.iter()).enumerate() {
        assert_eq!(got_row, exp, "fila {idx} del baseline adjudicado difiere");
    }
}

/// Contención: TODO hallazgo del Python original sigue presente (el Rust no
/// pierde hallazgos del baseline de compatibilidad).
#[test]
fn python_baseline_is_subset_of_rust_output() {
    let golden = read_json(&fixtures_dir().join("golden_issues.json"));
    let python = rows_from_json(golden["issues"].as_array().unwrap());
    let got = canonical(&scan(
        &source_fixture("ejemplo_codigo.txt"),
        &default_enabled(),
    ));

    let missing: Vec<&Row> = python.iter().filter(|p| !got.contains(p)).collect();
    assert!(
        missing.is_empty(),
        "hallazgos Python perdidos por el Rust: {missing:#?}"
    );
}

/// Métricas del scan sobre el fixture golden (adjudicado).
#[test]
fn golden_metrics_errors_and_warnings() {
    let issues = scan(&source_fixture("ejemplo_codigo.txt"), &default_enabled());
    let metrics = gx_engine::runtime::build_metrics(&issues);
    assert_eq!(metrics.total_findings, GOLDEN_TOTAL);
    assert_eq!(metrics.errors, GOLDEN_ERRORS);
    assert_eq!(metrics.warnings, GOLDEN_WARNINGS);
    assert_eq!(metrics.info, 0);
}

/// Las 24 reglas concretas del registry están en el manifest con su trigger
/// efectivo, y el registry no contiene ids fuera del manifest.
#[test]
fn concrete_rules_are_covered_by_manifest() {
    let manifest = read_json(&fixtures_dir().join("rule_manifest.json"));
    let manifest_ids: HashSet<String> = manifest["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["rule_id"].as_str().unwrap().to_string())
        .collect();

    let registry: Vec<(String, bool)> = gx_rules::all_rules()
        .iter()
        .map(|r| (r.id().to_string(), r.is_abstract()))
        .collect();
    let concrete: Vec<&(String, bool)> = registry.iter().filter(|(_, a)| !a).collect();
    assert_eq!(concrete.len(), 24, "el registry debe tener 24 concretas");

    for (id, _) in &concrete {
        assert!(
            manifest_ids.contains(id),
            "la regla {id} no figura en rule_manifest.json"
        );
    }
}
