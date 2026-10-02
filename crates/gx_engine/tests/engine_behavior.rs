//! Comportamiento del engine: determinismo, filtrado, rutas, archivo limpio.
//! Los tests marcados `#[ignore]` demuestran defectos conocidos (GX-003/GX-005)
//! y se des-ignoran en la historia que los corrige.

mod common;

use common::*;
use std::collections::HashSet;
use std::path::PathBuf;

/// Dos escaneos independientes del mismo archivo producen hallazgos
/// idénticos EN ORDEN (determinismo de emisión, GX-005).
#[test]
fn repeated_scans_are_deterministic() {
    let fixture = source_fixture("ejemplo_codigo.txt");
    let first = scan(&fixture, &default_enabled());
    let second = scan(&fixture, &default_enabled());
    assert_eq!(
        first, second,
        "la emisión debe ser estable orden a orden, no sólo en multiconjunto"
    );
}

/// Un archivo limpio con el set por defecto no produce hallazgos.
#[test]
fn clean_file_zero_findings() {
    let fixture = source_fixture("clean_object.txt");
    let issues = scan(&fixture, &default_enabled());
    assert!(
        issues.is_empty(),
        "archivo limpio no debería tener hallazgos; issues: {:?}",
        issues
    );
}

/// Archivos distintos no comparten estado cuando el engine se instanció
/// fresco por escaneo (scans independientes).
#[test]
fn scans_of_different_files_are_independent() {
    let golden_file = source_fixture("ejemplo_codigo.txt");
    let clean_file = source_fixture("clean_object.txt");

    let golden = scan(&golden_file, &default_enabled());
    assert_eq!(golden.len(), GOLDEN_TOTAL);

    let clean = scan(&clean_file, &default_enabled());
    assert!(clean.is_empty(), "issues: {clean:?}");

    let golden_again = canonical(&scan(&golden_file, &default_enabled()));
    assert_eq!(golden_again.len(), GOLDEN_TOTAL);
}

/// El filtrado por reglas habilitadas funciona: con una sola regla activa
/// sólo emite esa regla, y sin reglas no emite nada.
#[test]
fn enabled_rule_filtering_is_respected() {
    let fixture = source_fixture("ejemplo_codigo.txt");

    let only_2_3: HashSet<String> = ["GX.2.3".to_string()].into_iter().collect();
    let issues = scan(&fixture, &only_2_3);
    assert!(!issues.is_empty());
    assert!(
        issues.iter().all(|i| i.rule_id == "GX.2.3"),
        "sólo GX.2.3 debería emitir; issues: {issues:?}"
    );

    let none: HashSet<String> = HashSet::new();
    assert!(scan(&fixture, &none).is_empty());
}

/// La evaluación paralela y la secuencial concuerdan, y cada archivo
/// reporta su resultado o su error explícito (GX-005).
#[test]
fn parallel_and_sequential_agree() {
    let fixture = source_fixture("ejemplo_codigo.txt");
    let ctx = ctx_for(&fixture);
    let paths = vec![fixture.clone(), fixture.clone()];

    let parallel = gx_engine::runtime::evaluate_files_parallel(&paths, &default_enabled(), &ctx);
    assert_eq!(parallel.len(), 2);
    let seq = canonical(&scan(&fixture, &default_enabled()));
    for outcome in &parallel {
        assert_eq!(outcome.path, fixture);
        assert!(
            outcome.error.is_none(),
            "error inesperado: {:?}",
            outcome.error
        );
        assert_eq!(canonical(&outcome.issues), seq);
        assert_eq!(outcome.metrics.total_findings, GOLDEN_TOTAL);
        assert_eq!(outcome.metrics.errors, GOLDEN_ERRORS);
    }
}

/// Un archivo fallido en paralelo nunca se reporta como escaneo limpio.
#[test]
fn parallel_surfaces_per_file_errors() {
    let fixture = source_fixture("ejemplo_codigo.txt");
    let missing = fixtures_dir().join("sources/no_existe.txt");
    let paths = vec![fixture.clone(), missing.clone()];

    let outcomes =
        gx_engine::runtime::evaluate_files_parallel(&paths, &default_enabled(), &ctx_for(&fixture));
    let good = &outcomes[0];
    assert!(good.error.is_none());
    assert_eq!(good.issues.len(), GOLDEN_TOTAL);

    let bad = &outcomes[1];
    assert_eq!(bad.path, missing);
    assert!(
        bad.error.is_some(),
        "el archivo faltante debe reportar error"
    );
    assert!(bad.issues.is_empty());
}

/// Un archivo inexistente produce un error explícito, nunca éxito vacío.
#[test]
fn missing_file_fails_loudly() {
    let missing = fixtures_dir().join("sources/no_existe.txt");
    let (mut rules, dispatch) = gx_engine::runtime::build_rules(&default_enabled());
    let err = gx_engine::runtime::run_file(&mut rules, &dispatch, &missing, &ctx_for(&missing))
        .expect_err("un archivo inexistente debe fallar");
    assert!(
        err.to_string().contains("no existe"),
        "el error debe ser contextual: {err}"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Defectos conocidos — demostración (se corrigen en GX-003/GX-005).
// Ejecutar con: cargo test -p gx_engine --test engine_behavior -- --ignored
// ─────────────────────────────────────────────────────────────────────────

/// GX-003 (corregido): `run_file` llama `Rule::reset` con el path real antes
/// de evaluar; escanear A y luego B con la MISMA instancia de reglas produce
/// en B lo mismo que una instancia fresca.
#[test]
fn reset_state_leak_between_scans() {
    let golden_file = source_fixture("ejemplo_codigo.txt");
    let leaky_body = case_fixture("gx_2_7_3_negative.txt"); // "&ok = true"

    // Mismo array de reglas en dos escaneos consecutivos del mismo archivo.
    let (mut rules, dispatch) = gx_engine::runtime::build_rules(&default_enabled());
    let first =
        gx_engine::runtime::run_file(&mut rules, &dispatch, &golden_file, &ctx_for(&golden_file))
            .unwrap()
            .0;
    let second =
        gx_engine::runtime::run_file(&mut rules, &dispatch, &golden_file, &ctx_for(&golden_file))
            .unwrap()
            .0;
    assert_eq!(
        canonical(&second),
        canonical(&first),
        "re-escanear con el mismo estado produce hallazgos distintos"
    );

    // Escanear A y luego B con reglas compartidas == B con reglas frescas.
    let (mut rules, dispatch) = gx_engine::runtime::build_rules(&default_enabled());
    let _ =
        gx_engine::runtime::run_file(&mut rules, &dispatch, &golden_file, &ctx_for(&golden_file))
            .unwrap();
    let after_a =
        gx_engine::runtime::run_file(&mut rules, &dispatch, &leaky_body, &ctx_for(&leaky_body))
            .unwrap()
            .0;

    let fresh = scan(&leaky_body, &default_enabled());
    assert_eq!(
        canonical(&after_a),
        canonical(&fresh),
        "el estado de A contaminó el escaneo de B"
    );
}

/// GX-003 (corregido): los diagnósticos llevan el path real del archivo.
#[test]
fn issues_carry_real_file_path() {
    let fixture = source_fixture("ejemplo_codigo.txt");
    let issues = scan(&fixture, &default_enabled());
    assert!(!issues.is_empty());
    for issue in issues {
        assert_eq!(issue.file_path, fixture, "path placeholder en {issue:?}");
    }
}

/// GX-004: el dispatch optimizado NO pierde hallazgos respecto a la
/// implementación de referencia (todas las reglas habilitadas sobre todas
/// las líneas). Se verifica sobre todo el corpus de regresión.
#[test]
fn dispatch_matches_all_rules_per_line_reference() {
    let enabled = default_enabled();
    let mut corpus: Vec<PathBuf> = Vec::new();
    corpus.push(source_fixture("ejemplo_codigo.txt"));
    corpus.push(source_fixture("clean_object.txt"));
    let cases_dir = fixtures_dir().join("cases");
    let mut case_files: Vec<PathBuf> = std::fs::read_dir(&cases_dir)
        .expect("directorio de casos")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("txt"))
        .collect();
    case_files.sort();
    corpus.extend(case_files);

    assert!(corpus.len() >= 40, "corpus incompleto: {}", corpus.len());

    for path in corpus {
        let (mut rules, plan) = gx_engine::runtime::build_rules(&enabled);
        let dispatched =
            gx_engine::runtime::run_file(&mut rules, &plan, &path, &ctx_for(&path)).unwrap();
        let (mut rules_ref, _plan_ref) = gx_engine::runtime::build_rules(&enabled);
        let ref_len = rules_ref.len();
        let reference = gx_engine::runtime::run_file(
            &mut rules_ref,
            &gx_engine::dispatch::DispatchPlan::all_rules_every_line(ref_len),
            &path,
            &ctx_for(&path),
        )
        .unwrap();
        assert_eq!(
            canonical(&dispatched.0),
            canonical(&reference.0),
            "el dispatch pierde o agrega hallazgos vs la referencia en {:?}",
            path
        );
    }
}
