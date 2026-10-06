//! Fixtures positivos/negativos por regla concreta (GX-002).
//!
//! Cada caso corre el engine con UNA sola regla habilitada:
//!  - positivo: el fixture debe disparar la regla,
//!  - negativo: el fixture debe quedar limpio.
//!
//! Los casos marcados como defectos conocidos están en tests `#[ignore]`
//! (ver tests/fixtures/BASELINE.md); se corrigen con GX-004/GX-008.

mod common;

use common::*;
use std::collections::HashSet;

struct Case {
    file: &'static str,
    rule: &'static str,
    expect_fires: bool,
}

const GREEN_CASES: &[Case] = &[
    Case {
        file: "gx_1_1_positive.txt",
        rule: "GX.1.1",
        expect_fires: true,
    },
    Case {
        file: "gx_1_1_negative.txt",
        rule: "GX.1.1",
        expect_fires: false,
    },
    Case {
        file: "gx_1_2_positive.txt",
        rule: "GX.1.2",
        expect_fires: true,
    },
    Case {
        file: "gx_1_2_negative.txt",
        rule: "GX.1.2",
        expect_fires: false,
    },
    Case {
        file: "gx_1_3_positive.txt",
        rule: "GX.1.3",
        expect_fires: true,
    },
    Case {
        file: "gx_1_3_negative.txt",
        rule: "GX.1.3",
        expect_fires: false,
    },
    Case {
        file: "gx_1_3_1_positive.txt",
        rule: "GX.1.3.1",
        expect_fires: true,
    },
    Case {
        file: "gx_1_3_1_negative.txt",
        rule: "GX.1.3.1",
        expect_fires: false,
    },
    Case {
        file: "gx_1_3_2_positive.txt",
        rule: "GX.1.3.2",
        expect_fires: true,
    },
    Case {
        file: "gx_1_3_2_negative.txt",
        rule: "GX.1.3.2",
        expect_fires: false,
    },
    Case {
        file: "gx_1_3_2_nested_positive.txt",
        rule: "GX.1.3.2",
        expect_fires: true,
    },
    Case {
        file: "gx_1_3_3_positive.txt",
        rule: "GX.1.3.3",
        expect_fires: true,
    },
    Case {
        file: "gx_1_4_1_positive.txt",
        rule: "GX.1.4.1",
        expect_fires: true,
    },
    Case {
        file: "gx_1_4_1_negative.txt",
        rule: "GX.1.4.1",
        expect_fires: false,
    },
    Case {
        file: "gx_1_4_1_excluded_negative.txt",
        rule: "GX.1.4.1",
        expect_fires: false,
    },
    Case {
        file: "gx_1_4_2_positive.txt",
        rule: "GX.1.4.2",
        expect_fires: true,
    },
    Case {
        file: "gx_1_4_2_negative.txt",
        rule: "GX.1.4.2",
        expect_fires: false,
    },
    Case {
        file: "gx_1_4_3_positive.txt",
        rule: "GX.1.4.3",
        expect_fires: true,
    },
    Case {
        file: "gx_1_4_3_negative.txt",
        rule: "GX.1.4.3",
        expect_fires: false,
    },
    Case {
        file: "gx_1_4_3_multiline_positive.txt",
        rule: "GX.1.4.3",
        expect_fires: true,
    },
    Case {
        file: "gx_1_5_positive.txt",
        rule: "GX.1.5",
        expect_fires: true,
    },
    Case {
        file: "gx_1_5_negative.txt",
        rule: "GX.1.5",
        expect_fires: false,
    },
    Case {
        file: "gx_1_6_1_positive.txt",
        rule: "GX.1.6.1",
        expect_fires: true,
    },
    Case {
        file: "gx_1_6_1_do_case_negative.txt",
        rule: "GX.1.6.1",
        expect_fires: false,
    },
    Case {
        file: "gx_1_6_2_positive.txt",
        rule: "GX.1.6.2",
        expect_fires: true,
    },
    Case {
        file: "gx_1_7_1_positive.txt",
        rule: "GX.1.7.1",
        expect_fires: true,
    },
    Case {
        file: "gx_1_7_1_negative.txt",
        rule: "GX.1.7.1",
        expect_fires: false,
    },
    Case {
        file: "gx_1_7_2_positive.txt",
        rule: "GX.1.7.2",
        expect_fires: true,
    },
    Case {
        file: "gx_1_7_2_empty_positive.txt",
        rule: "GX.1.7.2",
        expect_fires: true,
    },
    Case {
        file: "gx_1_7_2_negative.txt",
        rule: "GX.1.7.2",
        expect_fires: false,
    },
    Case {
        file: "gx_2_1_positive.txt",
        rule: "GX.2.1",
        expect_fires: true,
    },
    Case {
        file: "gx_2_1_negative.txt",
        rule: "GX.2.1",
        expect_fires: false,
    },
    Case {
        file: "gx_2_2_positive.txt",
        rule: "GX.2.2",
        expect_fires: true,
    },
    Case {
        file: "gx_2_2_negative.txt",
        rule: "GX.2.2",
        expect_fires: false,
    },
    Case {
        file: "gx_2_3_positive.txt",
        rule: "GX.2.3",
        expect_fires: true,
    },
    Case {
        file: "gx_2_3_negative.txt",
        rule: "GX.2.3",
        expect_fires: false,
    },
    Case {
        file: "gx_2_4_positive.txt",
        rule: "GX.2.4",
        expect_fires: true,
    },
    Case {
        file: "gx_2_4_negative.txt",
        rule: "GX.2.4",
        expect_fires: false,
    },
    Case {
        file: "gx_2_5_positive.txt",
        rule: "GX.2.5",
        expect_fires: true,
    },
    Case {
        file: "gx_2_5_negative.txt",
        rule: "GX.2.5",
        expect_fires: false,
    },
    Case {
        file: "gx_2_6_positive.txt",
        rule: "GX.2.6",
        expect_fires: true,
    },
    Case {
        file: "gx_2_7_1_positive.txt",
        rule: "GX.2.7.1",
        expect_fires: true,
    },
    Case {
        file: "gx_2_7_1_negative.txt",
        rule: "GX.2.7.1",
        expect_fires: false,
    },
    Case {
        file: "gx_2_7_2_positive.txt",
        rule: "GX.2.7.2",
        expect_fires: true,
    },
    Case {
        file: "gx_2_7_2_negative.txt",
        rule: "GX.2.7.2",
        expect_fires: false,
    },
    Case {
        file: "gx_2_7_3_positive.txt",
        rule: "GX.2.7.3",
        expect_fires: true,
    },
    Case {
        file: "gx_2_7_3_negative.txt",
        rule: "GX.2.7.3",
        expect_fires: false,
    },
    Case {
        file: "gx_2_7_4_positive.txt",
        rule: "GX.2.7.4",
        expect_fires: true,
    },
    Case {
        file: "gx_2_7_4_negative.txt",
        rule: "GX.2.7.4",
        expect_fires: false,
    },
    // D02/D03: packs de objeto (opt-in) con fixtures positivos/negativos.
    Case {
        file: "gx_2_7_5_positive.txt",
        rule: "GX.2.7.5",
        expect_fires: true,
    },
    Case {
        file: "gx_2_7_5_negative.txt",
        rule: "GX.2.7.5",
        expect_fires: false,
    },
    Case {
        file: "gx_sec_1_positive.txt",
        rule: "GX.SEC.1",
        expect_fires: true,
    },
    Case {
        file: "gx_sec_1_negative.txt",
        rule: "GX.SEC.1",
        expect_fires: false,
    },
    Case {
        file: "gx_sec_2_positive.txt",
        rule: "GX.SEC.2",
        expect_fires: true,
    },
    Case {
        file: "gx_sec_2_negative.txt",
        rule: "GX.SEC.2",
        expect_fires: false,
    },
];

/// Cada regla concreta del registry está ejercitada por al menos un caso
/// verde (positivo o negativo) — criterio de aceptación de GX-002.
#[test]
fn all_concrete_rules_have_green_cases() {
    let covered: HashSet<&str> = GREEN_CASES.iter().map(|c| c.rule).collect();
    let concrete: Vec<&str> = gx_rules::all_rules()
        .iter()
        .filter(|r| !r.is_abstract())
        .map(|r| r.id())
        .collect();
    // D01: 24 reglas de línea + packs de objeto (D02/D03) = 27 concretas.
    assert_eq!(concrete.len(), 27);
    for id in concrete {
        assert!(
            covered.contains(id),
            "la regla {id} no tiene ningún fixture positivo/negativo"
        );
    }
}

#[test]
fn rule_fixtures_positive_and_negative() {
    let mut failures: Vec<String> = Vec::new();
    for case in GREEN_CASES {
        let path = case_fixture(case.file);
        let enabled: HashSet<String> = [case.rule.to_string()].into_iter().collect();
        let issues = scan(&path, &enabled);
        let fired = issues.iter().any(|i| i.rule_id == case.rule);
        let ok = if case.expect_fires {
            fired
        } else {
            issues.is_empty()
        };
        if !ok {
            failures.push(format!(
                "{} ({}) — esperado {} — issues: {:?}",
                case.file, case.rule, case.expect_fires, issues
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "fixtures fallidos:\n{}",
        failures.join("\n")
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Regresiones de GX-004/GX-008 — ya corregidas (M1). Cada test fue una
// demostración fallida en M0; ver tests/fixtures/BASELINE.md.
// ─────────────────────────────────────────────────────────────────────────

/// GX-004 (corregido): GX.1.3 recibe las líneas `endfor` y valida
/// tabla/comentario al cerrar el For Each.
#[test]
fn rule_1_3_endfor_without_table_flagged() {
    assert_rule_fires_with_anchor("gx_1_3_endfor_no_table_positive.txt", "GX.1.3");
}

/// GX-004 (corregido): GX.1.3 recibe la continuación `where` y exige
/// DEFINED BY.
#[test]
fn rule_1_3_missing_defined_by_flagged() {
    assert_rule_fires_with_anchor("gx_1_3_defined_by_missing_positive.txt", "GX.1.3");
}

/// GX-004 (corregido): las líneas `otherwise` llegan a GX.1.3.3; un CASE
/// completo con OTHERWISE ya no produce falso positivo.
#[test]
fn rule_1_3_3_case_with_otherwise_clean() {
    assert_rule_silent_with_anchor("gx_1_3_3_with_otherwise_negative.txt", "GX.1.3.3");
}

/// GX-004 (corregido): las líneas del cuerpo del sub llegan a GX.2.6 y la
/// inicialización con nullvalue() se detecta.
#[test]
fn rule_2_6_nullvalue_initialization_clean() {
    assert_rule_silent_with_anchor("gx_2_6_nullvalue_negative.txt", "GX.2.6");
}

/// GX-004 (corregido): el comentario descriptivo tras `sub` llega a
/// GX.1.6.2.
#[test]
fn rule_1_6_2_described_sub_clean() {
    assert_rule_silent_with_anchor("gx_1_6_2_comment_negative.txt", "GX.1.6.2");
}

/// GX-004 + GX-008 (corregidos): el comentario previo al `do` llega a
/// GX.1.6.1 y la regla consulta el flag antes de limpiarlo (paridad con
/// rule_gx_1_6_1.py:111).
#[test]
fn rule_1_6_1_comment_before_do_clean() {
    assert_rule_silent_with_anchor("gx_1_6_1_comment_before_negative.txt", "GX.1.6.1");
}
