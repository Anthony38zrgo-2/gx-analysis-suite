//! Matriz de aceptación del CLI compilado (GX-014 / GATE-CLI).
//!
//! Ejercita el binario real (`gx`) en subprocesos: text/JSON, XPZ,
//! directorio, archivo limpio, entradas corruptas y códigos de salida.

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

fn fixtures(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

struct Output {
    code: i32,
    stdout: String,
    stderr: String,
}

fn gx(args: &[&str]) -> Output {
    let out = Command::new(env!("CARGO_BIN_EXE_gx"))
        .args(args)
        .output()
        .expect("el binario gx debe poder ejecutarse");
    Output {
        code: out.status.code().expect("código de salida"),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    }
}

/// golden .txt vía --file (compat): JSON completo, 23 hallazgos, reject=1.
#[test]
fn scan_golden_file_json() {
    let fixture = fixtures("sources/ejemplo_codigo.txt");
    let out = gx(&[
        "scan",
        "--file",
        fixture.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(out.code, 1, "stderr: {}", out.stderr);
    let json: Value = serde_json::from_str(&out.stdout)
        .expect("JSON mode debe ser UN documento válido en reject");
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["verdict"], "reject");
    assert_eq!(json["metrics"]["total_findings"], 23);
    assert_eq!(json["metrics"]["errors"], 15);
    assert_eq!(json["metrics"]["warnings"], 8);
    assert!(
        json["request"]["inputs"][0]
            .as_str()
            .unwrap()
            .contains("ejemplo_codigo.txt"),
        "procedencia del input presente"
    );
    assert!(json["findings"].as_array().unwrap().len() == 23);
    // identidad de objeto presente en los hallazgos
    assert!(json["findings"][0]["object"]["id"].is_string());
}

/// Archivo limpio: JSON pass con cero hallazgos, exit 0.
#[test]
fn scan_clean_file_json_pass() {
    let fixture = fixtures("sources/clean_object.txt");
    let out = gx(&[
        "scan",
        "--file",
        fixture.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(out.code, 0);
    let json: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(json["verdict"], "pass");
    assert_eq!(json["findings"].as_array().unwrap().len(), 0);
}

/// Directorio: descubrimiento recursivo y PASS con cero hallazgos (clean).
#[test]
fn scan_clean_directory_pass() {
    let src = fixtures("dialects");
    let tmp = std::env::temp_dir().join("gx_cli_clean_dir");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    for name in [
        "dialect_nested_blocks_clean.txt",
        "dialect_parm_multiline_clean.txt",
        "dialect_block_comments_clean.txt",
        "dialect_web_panel_clean.txt",
        "dialect_trn_clean.txt",
        "dialect_report_clean.txt",
    ] {
        std::fs::copy(src.join(name), tmp.join(name)).unwrap();
    }

    let out = gx(&["scan", tmp.to_str().unwrap(), "--format", "json"]);
    assert_eq!(out.code, 0, "stdout: {}", out.stdout);
    let json: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(json["scanned_files"], 6);
    assert_eq!(json["verdict"], "pass");
    let _ = std::fs::remove_dir_all(&tmp);
}

/// XPZ multi-objeto: hallazgos con identidad de miembro original.
#[test]
fn scan_multi_object_xpz() {
    let fixture = fixtures("sources/sample_package.xpz");
    let out = gx(&[
        "scan",
        "--file",
        fixture.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(out.code, 1);
    let json: Value = serde_json::from_str(&out.stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 2);
    for f in findings {
        assert_eq!(f["object"]["member"], "PkgDemo/ProcMalo.xml");
        assert_eq!(f["object"]["id"], "ProcMalo");
    }
    let lines: Vec<u64> = findings
        .iter()
        .map(|f| f["line_number"].as_u64().unwrap())
        .collect();
    assert_eq!(lines, vec![3, 7], "líneas MIEMBRO-LOCAL, no sintéticas");
}

/// XPZ sin fuente usable → layout no soportado → exit 3 (nunca escaneo limpio).
#[test]
fn scan_unusable_xpz_fails_with_unsupported() {
    let fixture = fixtures("sources/unusable_package.xpz");
    let out = gx(&[
        "scan",
        "--file",
        fixture.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(out.code, 3, "stderr: {}", out.stderr);
    let _ = serde_json::from_str::<Value>(&out.stdout)
        .expect("JSON mode también emite un documento en fallo de scan");
    assert!(
        out.stderr.contains("no soportado"),
        "stderr: {}",
        out.stderr
    );
}

/// Entrada corrupta (ZIP roto) → exit 3 con error contextual.
#[test]
fn scan_corrupt_zip_fails() {
    let tmp = std::env::temp_dir().join("gx_cli_corrupt.xpz");
    std::fs::write(&tmp, b"PK\x03\x04 basura").unwrap();
    let out = gx(&["scan", "--file", tmp.to_str().unwrap(), "--format", "json"]);
    assert_eq!(out.code, 3);
    assert!(
        out.stderr.contains("ZIP inválido"),
        "stderr: {}",
        out.stderr
    );
    let _ = std::fs::remove_file(&tmp);
}

/// Path inexistente → exit 3 con stderr útil.
#[test]
fn scan_missing_path_exits_nonzero() {
    let out = gx(&["scan", "--file", "ruta_que_no_existe_gx.txt"]);
    assert_eq!(out.code, 3);
    assert!(
        out.stderr.contains("no existe") || out.stderr.contains("El path"),
        "stderr: {}",
        out.stderr
    );
}

/// Invocación sin ruta → exit 2.
#[test]
fn scan_without_path_exits_2() {
    let out = gx(&["scan"]);
    assert_eq!(out.code, 2);
}

/// A01/F01: una regla desconocida es invocación inválida (exit 2), nunca PASS.
#[test]
fn scan_unknown_rule_exits_2() {
    let clean = fixtures("sources/clean_object.txt");
    let out = gx(&[
        "scan",
        "--file",
        clean.to_str().unwrap(),
        "--enable",
        "GX.999",
    ]);
    assert_eq!(out.code, 2, "stderr: {}", out.stderr);
    assert!(out.stderr.contains("desconocida"), "stderr: {}", out.stderr);
}

/// A01/F01: `--disable` de una regla inexistente también es invocación inválida.
#[test]
fn scan_unknown_disable_exits_2() {
    let clean = fixtures("sources/clean_object.txt");
    let out = gx(&[
        "scan",
        "--file",
        clean.to_str().unwrap(),
        "--disable",
        "GX.999",
    ]);
    assert_eq!(out.code, 2, "stderr: {}", out.stderr);
}

/// A01/F01: porcentaje fuera de rango es invocación inválida (exit 2).
#[test]
fn scan_invalid_percentage_exits_2() {
    let clean = fixtures("sources/clean_object.txt");
    let out = gx(&[
        "scan",
        "--file",
        clean.to_str().unwrap(),
        "--error-pct",
        "101",
    ]);
    assert_eq!(out.code, 2, "stderr: {}", out.stderr);
    assert!(out.stderr.contains("Porcentaje"), "stderr: {}", out.stderr);
}

/// A01/F02: directorio sin archivos fuente → fallo explícito (exit 3), no PASS.
#[test]
fn scan_source_free_directory_exits_3() {
    let dir = std::env::temp_dir().join("gx_cli_source_free");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("datos.csv"), "a,b\n").unwrap();
    let out = gx(&["scan", dir.to_str().unwrap(), "--format", "json"]);
    assert_eq!(out.code, 3, "stderr: {}", out.stderr);
    assert!(
        out.stderr.contains("no contiene archivos fuente"),
        "stderr: {}",
        out.stderr
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// --help es preciso y sale con 0.
#[test]
fn help_is_accurate() {
    let out = gx(&["--help"]);
    assert_eq!(out.code, 0);
    assert!(out.stdout.contains("Usage"));
    assert!(out.stdout.contains("scan"));
    assert!(out.stdout.contains("rules"));
}

/// Modo text: resumen humano con veredicto y códigos correctos.
#[test]
fn scan_text_mode_summary() {
    let fixture = fixtures("sources/ejemplo_codigo.txt");
    let out = gx(&["scan", "--file", fixture.to_str().unwrap()]);
    assert_eq!(out.code, 1);
    assert!(out.stdout.contains("quality gate: REJECT"));
    assert!(out.stdout.contains("GX.1.4.3"));
    assert!(out.stdout.contains("línea 8"));
}

/// Determinismo CI: dos corridas JSON producen stdout byte a byte idéntico.
#[test]
fn json_output_is_deterministic() {
    let fixture = fixtures("sources/ejemplo_codigo.txt");
    let a = gx(&[
        "scan",
        "--file",
        fixture.to_str().unwrap(),
        "--format",
        "json",
    ]);
    let b = gx(&[
        "scan",
        "--file",
        fixture.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(
        a.stdout, b.stdout,
        "el JSON debe ser estable corrida a corrida"
    );
}

/// C01: `--format ndjson` emite un finding por línea + una línea final de
/// resumen, sin cambiar el framing de `--format json`.
#[test]
fn scan_ndjson_streams_findings_and_summary() {
    let fixture = fixtures("sources/ejemplo_codigo.txt");
    let out = gx(&[
        "scan",
        "--file",
        fixture.to_str().unwrap(),
        "--format",
        "ndjson",
    ]);
    assert_eq!(out.code, 1, "stderr: {}", out.stderr);
    let lines: Vec<&str> = out.stdout.lines().collect();
    assert_eq!(lines.len(), 23 + 1, "23 findings + línea de resumen");
    let first: Value = serde_json::from_str(lines[0]).unwrap();
    assert!(first["rule_id"].is_string(), "cada línea es un Issue");
    let summary: Value = serde_json::from_str(lines[lines.len() - 1]).unwrap();
    assert_eq!(summary["type"], "summary");
    assert_eq!(summary["metrics"]["total_findings"], 23);
    assert_eq!(summary["verdict"], "reject");
}

/// D03: el pack de seguridad reporta categoría/CWE con evidencia REDACTADA y
/// su veredicto no se diluye por la política de estilo.
#[test]
fn scan_security_pack_redacts_and_rejects() {
    let dir = std::env::temp_dir().join("gx_cli_security_pack");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("secrets.txt");
    std::fs::write(&file, "&password = 'S3cr3t-Value!'\n").unwrap();

    let out = gx(&[
        "scan",
        "--file",
        file.to_str().unwrap(),
        "--enable",
        "GX.SEC.1",
        "--error-pct",
        "100",
        "--format",
        "json",
    ]);
    assert_eq!(out.code, 1, "stderr: {}", out.stderr);
    assert!(
        !out.stdout.contains("S3cr3t-Value!"),
        "el secreto no puede aparecer en la salida"
    );
    let json: Value = serde_json::from_str(&out.stdout).unwrap();
    let issue = &json["findings"][0];
    assert_eq!(issue["rule_id"], "GX.SEC.1");
    assert_eq!(issue["category"], "security");
    assert_eq!(issue["cwe"], 798);
    assert!(issue["line_content"].as_str().unwrap().contains("***"));
    assert_eq!(json["security"]["errors"], 1);
    assert_eq!(json["verdict"], "reject", "100% de estilo no diluye");

    let _ = std::fs::remove_dir_all(&dir);
}

/// D03: la retención de evidencia sensible es opt-in explícito; por defecto
/// los secretos se redactan en la salida.
#[test]
fn scan_retain_sensitive_evidence_is_opt_in() {
    let dir = std::env::temp_dir().join("gx_cli_retain_evidence");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("secret.txt");
    std::fs::write(&file, "&password = 'S3cr3t-Value!'\n").unwrap();

    let redacted = gx(&[
        "scan",
        "--file",
        file.to_str().unwrap(),
        "--enable",
        "GX.SEC.1",
        "--format",
        "json",
    ]);
    assert!(!redacted.stdout.contains("S3cr3t-Value!"));

    let retained = gx(&[
        "scan",
        "--file",
        file.to_str().unwrap(),
        "--enable",
        "GX.SEC.1",
        "--retain-sensitive-evidence",
        "--format",
        "json",
    ]);
    assert!(
        retained.stdout.contains("S3cr3t-Value!"),
        "la retención opt-in conserva la evidencia: {}",
        retained.stderr
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Filtros de reglas: --enable domina al set por defecto.
#[test]
fn enable_filter_selects_rules() {
    let fixture = fixtures("sources/ejemplo_codigo.txt");
    let out = gx(&[
        "scan",
        "--file",
        fixture.to_str().unwrap(),
        "--format",
        "json",
        "--enable",
        "GX.2.3",
    ]);
    assert_eq!(out.code, 1);
    let json: Value = serde_json::from_str(&out.stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();
    assert!(!findings.is_empty());
    assert!(findings.iter().all(|f| f["rule_id"] == "GX.2.3"));
}

/// A01.6: `--rules-profile local` respeta los flags toggled en la base local;
/// el perfil default no los mira (semántica explícita, no implícita).
#[test]
fn rules_profile_local_reads_db_flags() {
    let dir = std::env::temp_dir().join("gx_cli_profile_local");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("gx.db");
    let fixture = fixtures("sources/ejemplo_codigo.txt");

    let out = gx(&["rules", "disable", "GX.2.5", "--db", db.to_str().unwrap()]);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);

    let default_out = gx(&[
        "scan",
        "--file",
        fixture.to_str().unwrap(),
        "--format",
        "json",
    ]);
    let local_out = gx(&[
        "scan",
        "--file",
        fixture.to_str().unwrap(),
        "--format",
        "json",
        "--rules-profile",
        "local",
        "--db",
        db.to_str().unwrap(),
    ]);
    assert_eq!(local_out.code, 1, "stderr: {}", local_out.stderr);
    let default_json: Value = serde_json::from_str(&default_out.stdout).unwrap();
    let local_json: Value = serde_json::from_str(&local_out.stdout).unwrap();
    assert_eq!(default_json["metrics"]["total_findings"], 23);
    assert_eq!(
        local_json["metrics"]["total_findings"], 20,
        "local deshabilitó los 3 GX.2.5"
    );
    assert!(local_json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .all(|f| f["rule_id"] != "GX.2.5"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Catálogo desde Reglas.csv en memoria (sin base local) y listado.
#[test]
fn rules_list_from_csv() {
    let csv = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../Reglas.csv");
    let out = gx(&["rules", "list", "--rules-csv", csv.to_str().unwrap()]);
    assert_eq!(out.code, 0);
    assert!(out.stdout.contains("GX.2.6"));
    assert!(out.stdout.contains("28 reglas operativas"));
}

/// XPZ real empaquetado como RAR: se lintea con identidad de objeto real.
#[test]
fn scan_real_rar_export() {
    let fixture = fixtures("sources/real/HJFCP716.xpz");
    let out = gx(&[
        "scan",
        "--file",
        fixture.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(out.code, 1, "stderr: {}", out.stderr);
    let json: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(json["metrics"]["total_findings"], 102);
    assert_eq!(json["metrics"]["errors"], 40);
    assert_eq!(json["findings"][0]["object"]["id"], "JFCP716");
    assert_eq!(json["findings"][0]["object"]["object_type"], "WebPanel");
    assert_eq!(
        json["findings"][0]["object"]["member"],
        "HJFCP716/HJFCP716_1.xml"
    );
}

/// Export real con WebPanel + Procedure (sección Rules): ambos objetos
/// aparecen con su identidad y el Procedure aporta hallazgos de Parm.
#[test]
fn scan_real_zip_export_with_procedure() {
    let fixture = fixtures("sources/real/JBMP018.xpz");
    let out = gx(&[
        "scan",
        "--file",
        fixture.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(out.code, 1);
    let json: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(json["metrics"]["total_findings"], 47);
    let findings = json["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| {
        f["object"]["object_type"] == "Procedure"
            && f["object"]["id"] == "JBMP018"
            && f["object"]["package"] == "NUCLEO_Tablas"
            && f["rule_id"] == "GX.1.4.3"
    }));
}

/// Export real sin secciones de código: PASS con 0 hallazgos y aviso en
/// stderr (nunca un fallo ni un silencio).
#[test]
fn scan_real_export_without_code_warns_and_passes() {
    let fixture = fixtures("sources/real/HJFCQ350.xpz");
    let out = gx(&[
        "scan",
        "--file",
        fixture.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let json: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(json["metrics"]["total_findings"], 0);
    assert_eq!(json["verdict"], "pass");
    assert!(
        out.stderr.contains("sin secciones de código"),
        "debe avisar en stderr: {}",
        out.stderr
    );
}

/// --record-history con --db temporal: la corrida queda registrada con
/// veredicto; scan sin la bandera NO escribe base alguna (CI limpio).
#[test]
fn record_history_writes_when_requested() {
    let dir = std::env::temp_dir().join("gx_cli_history");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("history.db");
    let fixture = fixtures("sources/sample_package.xpz");
    let out = gx(&[
        "scan",
        "--file",
        fixture.to_str().unwrap(),
        "--format",
        "json",
        "--record-history",
        "--db",
        db.to_str().unwrap(),
    ]);
    assert_eq!(out.code, 1);
    assert!(db.exists(), "la base debe existir tras --record-history");

    let conn = rusqlite::Connection::open(&db).unwrap();
    let runs: i64 = conn
        .query_row("SELECT COUNT(*) FROM audit_runs", [], |r| r.get(0))
        .unwrap();
    assert_eq!(runs, 1);
    let verdict: String = conn
        .query_row("SELECT verdict FROM audit_runs", [], |r| r.get(0))
        .unwrap();
    assert_eq!(verdict, "reject");
    let _ = std::fs::remove_dir_all(&dir);
}

/// GX-019: `--pdf` genera un PDF válido junto al resultado y un fallo del
/// PDF NUNCA altera el exit code del lint.
#[test]
fn scan_pdf_flag_generates_pdf_without_changing_exit_code() {
    let dir = std::env::temp_dir().join("gx_cli_pdf");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let fixture = fixtures("sources/ejemplo_codigo.txt");
    let pdf = dir.join("informe.pdf");

    let out = gx(&[
        "scan",
        "--file",
        fixture.to_str().unwrap(),
        "--pdf",
        pdf.to_str().unwrap(),
    ]);
    assert_eq!(out.code, 1, "reject se mantiene con PDF");
    let bytes = std::fs::read(&pdf).expect("el PDF debe existir");
    assert!(bytes.starts_with(b"%PDF"));

    // Fallo del PDF: un archivo normal usado como "directorio" padre.
    let blocker = dir.join("blocker.txt");
    std::fs::write(&blocker, "no soy un directorio").unwrap();
    let bad_pdf = blocker.join("sub").join("x.pdf");
    let clean = fixtures("sources/clean_object.txt");
    let out = gx(&[
        "scan",
        "--file",
        clean.to_str().unwrap(),
        "--pdf",
        bad_pdf.to_str().unwrap(),
    ]);
    assert_eq!(out.code, 0, "pass se mantiene aunque falle el PDF");
    assert!(
        out.stderr.contains("no se pudo generar el PDF"),
        "debe avisar en stderr: {}",
        out.stderr
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// GX-019: `gx export-pdf` genera el PDF desde el JSON sin re-ejecutar el
/// engine; el total de hallazgos coincide con el JSON.
#[test]
fn export_pdf_from_scan_json() {
    let dir = std::env::temp_dir().join("gx_cli_export_pdf");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let fixture = fixtures("sources/ejemplo_codigo.txt");
    let json_path = dir.join("result.json");
    let pdf_path = dir.join("export.pdf");

    let out = gx(&[
        "scan",
        "--file",
        fixture.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(out.code, 1);
    let json: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(json["metrics"]["total_findings"], 23);
    std::fs::write(&json_path, &out.stdout).unwrap();

    let out = gx(&[
        "export-pdf",
        "--result-file",
        json_path.to_str().unwrap(),
        "--out",
        pdf_path.to_str().unwrap(),
    ]);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    assert!(out.stdout.contains("23 hallazgos"));
    let bytes = std::fs::read(&pdf_path).expect("el PDF debe existir");
    assert!(bytes.starts_with(b"%PDF"));
    assert!(bytes.len() > 1_000);

    // JSON inválido: fallo explícito (exit 3), nunca un PDF vacío.
    let bad = dir.join("bad.json");
    std::fs::write(&bad, "{ no json }").unwrap();
    let out = gx(&[
        "export-pdf",
        "--result-file",
        bad.to_str().unwrap(),
        "--out",
        pdf_path.to_str().unwrap(),
    ]);
    assert_eq!(out.code, 3);
    let _ = std::fs::remove_dir_all(&dir);
}
