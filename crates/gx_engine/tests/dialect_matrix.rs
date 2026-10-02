//! Matriz de dialectos GeneXus para las 24 reglas concretas (GX-008).
//!
//! Cada fixture dialect_*_clean.txt debe estar LIMPIO con las 24 reglas
//! habilitadas; los fixture *_violation.txt disparan exactamente las reglas
//! esperadas. Las decisiones adjudicadas viven en tests/fixtures/BASELINE.md.

mod common;

use common::*;
use gx_core::models::Issue;
use std::collections::HashSet;
use std::path::Path;

const CLEAN_DIALECTS: &[&str] = &[
    "dialect_nested_blocks_clean.txt",
    "dialect_parm_multiline_clean.txt",
    "dialect_block_comments_clean.txt",
    "dialect_web_panel_clean.txt",
    "dialect_trn_clean.txt",
    "dialect_report_clean.txt",
];

const VIOLATIONS: &[(&str, &[(u32, &str)])] = &[
    // (fixture, [(línea, regla)])
    (
        "dialect_block_comments_violation.txt",
        &[(9, "GX.1.1"), (9, "GX.2.7.2"), (10, "GX.1.1")],
    ),
    (
        "dialect_when_itemized_violation.txt",
        &[(12, "GX.2.1"), (12, "GX.2.5")],
    ),
];

/// Set con TODAS las reglas concretas habilitadas.
fn all_concrete_enabled() -> HashSet<String> {
    gx_rules::all_rules()
        .iter()
        .filter(|r| !r.is_abstract())
        .map(|r| r.id().to_string())
        .collect()
}

fn scan(path: &Path, enabled: &HashSet<String>) -> Vec<Issue> {
    gx_engine::runtime::scan_file(path, enabled, &ctx_for(path)).expect("scan must not fail")
}

#[test]
fn clean_dialects_report_zero_findings() {
    let enabled = all_concrete_enabled();
    let mut failures = Vec::new();
    for name in CLEAN_DIALECTS {
        let path = fixtures_dir().join("dialects").join(name);
        let issues = scan(&path, &enabled);
        if !issues.is_empty() {
            failures.push(format!("{name}: {issues:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "falsos positivos en dialectos limpios:\n{}",
        failures.join("\n")
    );
}

#[test]
fn dialect_violations_fire_exactly_expected_rules() {
    let enabled = all_concrete_enabled();
    for (name, expected) in VIOLATIONS {
        let path = fixtures_dir().join("dialects").join(name);
        let issues = scan(&path, &enabled);
        let mut got: Vec<(u32, String)> = issues
            .iter()
            .map(|i| (i.line_number, i.rule_id.clone()))
            .collect();
        got.sort();
        let mut want: Vec<(u32, String)> =
            expected.iter().map(|(l, r)| (*l, r.to_string())).collect();
        want.sort();
        assert_eq!(
            got, want,
            "fixture {name} difiere del esperado; issues: {issues:?}"
        );
    }
}
