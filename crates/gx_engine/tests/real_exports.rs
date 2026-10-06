//! Exports GeneXus reales: snapshot adjudicado (GX-007/GX-008).
//!
//! Fija SHA-256, conteos por regla, identidad de objetos con código y
//! spot-checks verificados manualmente contra la fuente (ver
//! `tests/fixtures/real_exports/manifest.json`).

mod common;

use common::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

fn real_fixture(name: &str) -> PathBuf {
    fixtures_dir().join("sources").join("real").join(name)
}

fn manifest() -> Value {
    let path = fixtures_dir().join("real_exports").join("manifest.json");
    let text = std::fs::read_to_string(&path).expect("manifest legible");
    serde_json::from_str(&text).expect("manifest JSON válido")
}

fn sha256_file(path: &Path) -> String {
    let bytes = std::fs::read(path).expect("fixture legible");
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02X}")).collect()
}

/// Cada export real coincide con su snapshot: hash, métricas, conteos por
/// regla e identidad de los objetos con código.
#[test]
fn real_exports_match_snapshot() {
    let manifest = manifest();
    let enabled = default_enabled();

    for export in manifest["exports"].as_array().unwrap() {
        let file = export["file"].as_str().unwrap();
        let path = real_fixture(file);

        assert_eq!(
            sha256_file(&path),
            export["sha256"].as_str().unwrap(),
            "{file}: el fixture cambió; actualizar manifest.json como decisión de regresión"
        );

        let issues = scan(&path, &enabled);
        let metrics = gx_engine::runtime::build_metrics(&issues);

        assert_eq!(
            metrics.total_findings,
            export["metrics"]["total"].as_u64().unwrap() as usize,
            "{file}: total de hallazgos distinto al snapshot"
        );
        assert_eq!(
            metrics.errors,
            export["metrics"]["errors"].as_u64().unwrap() as usize,
            "{file}: errores distintos al snapshot"
        );
        assert_eq!(
            metrics.warnings,
            export["metrics"]["warnings"].as_u64().unwrap() as usize,
            "{file}: warnings distintos al snapshot"
        );

        // Conteos por regla.
        for (rule, expected) in export["perRule"].as_object().unwrap() {
            let got = issues.iter().filter(|i| i.rule_id == *rule).count();
            assert_eq!(
                got,
                expected.as_u64().unwrap() as usize,
                "{file}: conteo de {rule} distinto al snapshot"
            );
        }
        // No hay reglas extra fuera del snapshot.
        let mut extra_rules: Vec<&str> = issues
            .iter()
            .map(|i| i.rule_id.as_str())
            .filter(|r| export["perRule"].get(*r).is_none())
            .collect();
        extra_rules.sort_unstable();
        extra_rules.dedup();
        assert!(
            extra_rules.is_empty(),
            "{file}: reglas no documentadas en el snapshot: {extra_rules:?}"
        );

        // Identidad de los objetos con código.
        for obj in export["objectsWithCode"].as_array().unwrap() {
            let id = obj["id"].as_str().unwrap();
            let object_type = obj["objectType"].as_str().unwrap();
            let member = obj["member"].as_str().unwrap();
            let package = obj["package"].as_str().unwrap();
            assert!(
                issues.iter().any(|i| {
                    i.object.as_ref().is_some_and(|o| {
                        o.id == id
                            && o.object_type == object_type
                            && o.member == member
                            && o.package == package
                    })
                }),
                "{file}: no hay hallazgos del objeto {object_type}/{id} ({member}, pkg '{package}')"
            );
        }
    }
}

/// Los spot-checks adjudicados siguen presentes con identidad y línea
/// correctas (comparación de contenido recortado).
#[test]
fn real_exports_spot_checks() {
    let manifest = manifest();
    let enabled = default_enabled();
    let mut failures: Vec<String> = Vec::new();

    for spot in manifest["spotChecks"].as_array().unwrap() {
        let file = spot["file"].as_str().unwrap();
        let rule = spot["rule"].as_str().unwrap();
        let line = spot["line"].as_u64().unwrap() as u32;
        let severity = spot["severity"].as_str().unwrap();
        let object_id = spot["objectId"].as_str().unwrap();
        let object_type = spot["objectType"].as_str().unwrap();
        let content = spot["lineContent"].as_str().unwrap();

        let issues = scan(&real_fixture(file), &enabled);
        let found = issues.iter().any(|i| {
            i.rule_id == rule
                && i.line_number == line
                && i.severity.as_str() == severity
                && i.line_content.trim() == content
                && i.object
                    .as_ref()
                    .is_some_and(|o| o.id == object_id && o.object_type == object_type)
        });
        if !found {
            failures.push(format!(
                "{file}: spot-check {rule}@{line} ({object_type}/{object_id}) no encontrado"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "spot-checks fallidos:\n{}",
        failures.join("\n")
    );
}

/// Exports con objetos reconocidos pero sin secciones de código: escaneo
/// válido, cero hallazgos (el aviso va a stderr/log, no es un fallo).
#[test]
fn real_exports_without_code_scan_clean() {
    let manifest = manifest();
    for file in ["HJFCQ350.xpz", "jngz293.xpz"] {
        let export = manifest["exports"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["file"] == file)
            .expect("export en manifest");
        assert_eq!(export["objectsWithCode"].as_array().unwrap().len(), 0);

        let issues = scan(&real_fixture(file), &default_enabled());
        assert!(
            issues.is_empty(),
            "{file}: sin código debe dar 0 hallazgos; got {issues:?}"
        );
    }
}

/// La extensión `.zip` se acepta por contenido (mismo fixture copiado con
/// doble extensión, como llegan los exports descargados).
#[test]
fn zip_extension_is_accepted_by_content() {
    let src = real_fixture("JBMP018.xpz");
    let tmp = std::env::temp_dir().join("gx_real_zip_ext.xpz.zip");
    std::fs::copy(&src, &tmp).unwrap();
    let issues = scan(&tmp, &default_enabled());
    assert_eq!(issues.len(), 47, "JBMP018 vía .zip debe lintearse igual");
    let _ = std::fs::remove_file(&tmp);
}

/// El paquete RAR real se lista con `list_package_members`.
#[test]
fn rar_package_members_are_listed() {
    let members = gx_sources::xpz_extractor::list_package_members(&real_fixture("HJFCP716.xpz"))
        .expect("RAR listable");
    assert!(
        members.iter().any(|m| m == "HJFCP716/HJFCP716_1.xml"),
        "{members:?}"
    );
}
