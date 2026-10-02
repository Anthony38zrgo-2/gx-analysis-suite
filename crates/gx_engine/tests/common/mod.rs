//! Helpers compartidos por los tests de integración del engine (GX-002).
#![allow(dead_code)]

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use gx_core::models::{AuditContext, Issue};

pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

pub fn source_fixture(name: &str) -> PathBuf {
    fixtures_dir().join("sources").join(name)
}

pub fn case_fixture(name: &str) -> PathBuf {
    fixtures_dir().join("cases").join(name)
}

/// Los 15 ids habilitados por defecto (paridad con `config/rules.json`).
pub fn default_enabled() -> HashSet<String> {
    gx_storage::seed::default_enabled_ids()
}

/// Totales del golden ADJUDICADO (Python + adjudicaciones GX-004) para el
/// fixture golden; ver tests/fixtures/golden_adjudications.json.
pub const GOLDEN_TOTAL: usize = 22;
pub const GOLDEN_ERRORS: usize = 14;
pub const GOLDEN_WARNINGS: usize = 8;

pub fn ctx_for(path: &Path) -> AuditContext {
    AuditContext {
        project_path: path.to_path_buf(),
        rules_path: path.to_path_buf(),
        max_errors: 0,
        max_warnings: 999_999,
        qg_threshold_pct: 10.0,
        extra_settings: Default::default(),
    }
}

/// Escanea un fixture con el set de reglas indicado y falla si el scan
/// reporta error (nunca debe haber éxito vacío silencioso en tests).
pub fn scan(path: &Path, enabled: &HashSet<String>) -> Vec<Issue> {
    gx_engine::runtime::scan_file(path, enabled, &ctx_for(path)).expect("scan must not fail")
}

/// Escanea con una única regla habilitada.
pub fn scan_single(path: &Path, rule_id: &str) -> Vec<Issue> {
    let enabled: HashSet<String> = [rule_id.to_string()].into_iter().collect();
    scan(path, &enabled)
}

/// Escanea con la regla bajo prueba + un ancla DEFAULT (GX.2.3, triggers
/// vacíos). Reproduce el comportamiento del set completo: cuando hay
/// reglas DEFAULT activas, el fallback "todas las reglas" no se activa y
/// los huecos del dispatch por token aislado se manifiestan (GX-004).
pub fn scan_with_anchor(path: &Path, rule_id: &str) -> Vec<Issue> {
    let enabled: HashSet<String> = [rule_id.to_string(), "GX.2.3".to_string()]
        .into_iter()
        .collect();
    scan(path, &enabled)
}

/// Clave canónica: (línea, regla, severidad, descripción, contenido).
/// El orden de emisión intra-línea no es parte del contrato (GX-005).
pub fn canonical(issues: &[Issue]) -> Vec<(u32, String, String, String, String)> {
    let mut rows: Vec<(u32, String, String, String, String)> = issues
        .iter()
        .map(|i| {
            (
                i.line_number,
                i.rule_id.clone(),
                i.severity.as_str().to_string(),
                i.description.clone(),
                i.line_content.clone(),
            )
        })
        .collect();
    rows.sort();
    rows
}

pub fn assert_rule_fires(file: &str, rule_id: &str) {
    let path = case_fixture(file);
    let issues = scan_single(&path, rule_id);
    assert!(
        issues.iter().any(|i| i.rule_id == rule_id),
        "el fixture {file} debería disparar {rule_id}; issues: {:?}",
        issues
    );
}

pub fn assert_rule_silent(file: &str, rule_id: &str) {
    let path = case_fixture(file);
    let issues = scan_single(&path, rule_id);
    assert!(
        issues.is_empty(),
        "el fixture {file} debería estar limpio para {rule_id}; issues: {:?}",
        issues
    );
}

/// Variantes con ancla DEFAULT para los demos de defectos de dispatch.
pub fn assert_rule_fires_with_anchor(file: &str, rule_id: &str) {
    let path = case_fixture(file);
    let issues = scan_with_anchor(&path, rule_id);
    assert!(
        issues.iter().any(|i| i.rule_id == rule_id),
        "el fixture {file} debería disparar {rule_id}; issues: {:?}",
        issues
    );
}

pub fn assert_rule_silent_with_anchor(file: &str, rule_id: &str) {
    let path = case_fixture(file);
    let issues = scan_with_anchor(&path, rule_id);
    assert!(
        issues.iter().all(|i| i.rule_id != rule_id),
        "el fixture {file} debería estar limpio para {rule_id}; issues: {:?}",
        issues
    );
}
