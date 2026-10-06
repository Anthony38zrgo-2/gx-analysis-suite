//! Fidelidad de origen para XPZ/XML (GX-006 / GATE-ENGINE).

mod common;

use common::*;
use std::path::PathBuf;

/// Los hallazgos del segundo miembro del XPZ apuntan a la línea ORIGINAL
/// del miembro (3 y 7), nunca a coordenadas sintéticas de concatenación.
#[test]
fn xpz_second_member_lines_are_member_local() {
    let xpz = source_fixture("sample_package.xpz");
    let issues = scan(&xpz, &default_enabled());

    let member_malo = "PkgDemo/ProcMalo.xml";
    let malo: Vec<_> = issues
        .iter()
        .filter(|i| i.object.as_ref().map(|o| o.member.as_str()) == Some(member_malo))
        .collect();
    assert_eq!(
        malo.len(),
        2,
        "ProcMalo debería tener 2 hallazgos miembro-local; issues: {issues:?}"
    );

    let sub_issue = malo
        .iter()
        .find(|i| i.rule_id == "GX.2.6")
        .expect("GX.2.6 (sub sin nullvalue) debe disparar");
    assert_eq!(
        sub_issue.line_number, 3,
        "línea DENTRO del miembro, no coordenada sintética"
    );
    assert_eq!(sub_issue.line_content, "sub 'Inicializar'");

    let counter_issue = malo
        .iter()
        .find(|i| i.rule_id == "GX.2.7.2")
        .expect("GX.2.7.2 (contador &i) debe disparar");
    assert_eq!(
        counter_issue.line_number, 7,
        "línea DENTRO del miembro, no coordenada sintética"
    );

    // El miembro limpio no reporta nada.
    assert!(
        !issues
            .iter()
            .any(|i| i.object.as_ref().map(|o| o.member.as_str()) == Some("PkgDemo/ProcBueno.xml")),
        "ProcBueno debería estar limpio; issues: {issues:?}"
    );
}

/// Identidad de objeto completa en cada hallazgo: id, tipo, package,
/// member y contenedor.
#[test]
fn xpz_issues_carry_full_object_identity() {
    let xpz = source_fixture("sample_package.xpz");
    let issues = scan(&xpz, &default_enabled());
    assert!(!issues.is_empty());
    for issue in &issues {
        let obj = issue
            .object
            .as_ref()
            .expect("objeto stamp obligatorio (GX-006)");
        assert_eq!(obj.id, "ProcMalo");
        assert_eq!(obj.object_type, "Procedure");
        assert_eq!(obj.package, "PkgDemo");
        assert_eq!(obj.member, "PkgDemo/ProcMalo.xml");
        assert_eq!(obj.container_path, xpz.to_string_lossy());
    }
}

/// El mismo objeto exportado como XML y dentro del XPZ produce hallazgos
/// equivalentes (líneas miembro-local idénticas).
#[test]
fn xml_and_xpz_exports_yield_equivalent_findings() {
    let xml = source_fixture("proc_malo.xml");
    let xpz = source_fixture("sample_package.xpz");

    let xml_issues = scan(&xml, &default_enabled());
    let xpz_issues = scan(&xpz, &default_enabled());
    let member_malo = "PkgDemo/ProcMalo.xml";

    let xml_rows = canonical(&xml_issues);
    let xpz_rows: Vec<_> = xpz_issues
        .iter()
        .filter(|i| i.object.as_ref().map(|o| o.member.as_str()) == Some(member_malo))
        .cloned()
        .collect();
    let xpz_rows = canonical(&xpz_rows);

    assert_eq!(
        xml_rows.len(),
        2,
        "proc_malo.xml debería tener 2 hallazgos; issues: {xml_issues:?}"
    );
    assert_eq!(xml_rows, xpz_rows, "XML y XPZ deben ser equivalentes");

    // Identidad equivalente (id/tipo/package), aunque el member difiera.
    let xml_obj = xml_issues[0].object.as_ref().unwrap();
    assert_eq!(xml_obj.id, "ProcMalo");
    assert_eq!(xml_obj.object_type, "Procedure");
    assert_eq!(xml_obj.package, "PkgDemo");
}

/// Un XPZ sin bloques <Events> se rechaza como layout no soportado:
/// nunca se lintea como XML de marca (GX-007).
#[test]
fn unusable_xpz_is_reported_as_unsupported() {
    let xpz = source_fixture("unusable_package.xpz");
    let err = gx_engine::runtime::scan_file(&xpz, &default_enabled(), &ctx_for(&xpz))
        .expect_err("el XPZ sin fuente usable debe fallar");
    let msg = err.to_string();
    assert!(
        msg.contains("no soportado"),
        "el error debe ser explícito de layout: {msg}"
    );
}

/// Objetos fuente listados desde un XPZ real del fixture.
#[test]
fn xpz_members_are_listed() {
    let xpz = source_fixture("sample_package.xpz");
    let members = gx_sources::xpz_extractor::list_xpz_members(&xpz).unwrap();
    assert_eq!(members.len(), 2);
    assert!(members.iter().all(|m| m.ends_with(".xml")));
}

/// El stamping de objeto es estable entre escaneos (parte del contrato
/// determinista de GX-005).
#[test]
fn xpz_scan_is_fully_deterministic() {
    let xpz = source_fixture("sample_package.xpz");
    let a: Vec<_> = scan(&xpz, &default_enabled());
    let b: Vec<_> = scan(&xpz, &default_enabled());
    assert_eq!(a, b, "hallazgos e identidad de objeto deben ser idénticos");
}

/// Referencia de paths usados (evita warnings de imports sin uso).
#[allow(dead_code)]
fn _referenced(p: PathBuf) -> PathBuf {
    p
}
