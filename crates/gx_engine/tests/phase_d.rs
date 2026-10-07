//! Fase D: gates de capacidades/hechos (D01/D02), seguridad (D03) y caché de
//! hechos (D04).
//!
//! Todo el trabajo con contadores globales vive en UN test secuencial: los
//! tests del binario corren en paralelo y los contadores de `gx_core::stats`
//! son globales.

use std::collections::HashSet;
use std::path::PathBuf;

use gx_core::models::{AnalysisRequest, QgPolicy, QgVerdict, ScanCompletion};
use gx_core::stats;
use gx_engine::runtime::{analyze, RulePlan};

fn tmp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn request(inputs: Vec<PathBuf>, rules: &[&str], pct: f32) -> AnalysisRequest {
    AnalysisRequest {
        schema_version: 1,
        inputs,
        enabled_rule_ids: rules.iter().map(|id| id.to_string()).collect(),
        policy: QgPolicy::Percentage { max_error_pct: pct },
        record_history: false,
        retain_sensitive_evidence: false,
        discovery: Default::default(),
    }
}

/// D01: el perfil de estilo común no construye hechos; habilitar un pack
/// cambia el plan pero no el trabajo de línea; D02/D03/D04: def-use, seguridad
/// redactada, veredicto separado y caché acotada con cold/warm hits.
#[test]
fn phase_d_capability_gates_facts_and_security() {
    // ── D01: hechos sólo cuando un pack seleccionado los requiere ─────────
    let line_ids: HashSet<String> = gx_storage::seed::default_enabled_ids()
        .into_iter()
        .collect();
    let line_plan = RulePlan::compile(&line_ids).unwrap();
    assert_eq!(line_plan.rules_len(), 15, "perfil por defecto sin packs");
    assert!(
        line_plan.facts_union().is_empty(),
        "el perfil de línea no pide hechos semánticos"
    );
    assert!(
        !line_ids.contains("GX.SEC.1") && !line_ids.contains("GX.2.7.5"),
        "los packs D01 están deshabilitados por defecto"
    );

    let mut with_pack = line_ids.clone();
    with_pack.insert("GX.SEC.1".to_string());
    let pack_plan = RulePlan::compile(&with_pack).unwrap();
    assert!(
        !pack_plan.facts_union().is_empty(),
        "un pack habilitado declara hechos"
    );

    // ── D01/D04: hechos una vez por objeto + caché cold/warm ──────────────
    let dir = tmp_dir("gx_phase_d_facts");
    let wide = dir.join("wide.xml");
    let mut xml = String::from("<ExportFile>\n");
    for index in 0..20 {
        xml.push_str(&format!(
            "<GXObject><Procedure><Info><Name>D{index:03}</Name></Info>\
             <Events><![CDATA[// nonce-gx-phase-d-4f21\n&Value = {index}\n\
             &password = 'secret-value-{index}'\n]]></Events></Procedure></GXObject>\n"
        ));
    }
    xml.push_str("</ExportFile>\n");
    std::fs::write(&wide, xml).unwrap();

    let sec_request = request(vec![wide.clone()], &["GX.SEC.1"], 100.0);
    stats::reset();
    let first = analyze(&sec_request);
    let first_stats = stats::snapshot();
    assert_eq!(
        first_stats.fact_model_requests, 20,
        "un modelo por objeto, no por pack"
    );
    assert_eq!(first_stats.fact_cache_misses, 20);
    assert_eq!(first_stats.fact_cache_hits, 0);
    assert_eq!(first.pack_coverage.len(), 1);
    assert_eq!(first.pack_coverage[0].id, "GX.SEC.1");
    assert_eq!(first.pack_coverage[0].objects_analyzed, 20);
    assert_eq!(first.pack_coverage[0].findings, 20);
    assert_eq!(first.scanned_files, 1);
    assert_eq!(first.completion, ScanCompletion::Complete);

    // D03: evidencia redactada y veredicto de seguridad separado.
    assert_eq!(first.security.as_ref().unwrap().errors, 20);
    assert_eq!(
        first.verdict,
        QgVerdict::Reject,
        "política al 100% no diluye"
    );
    for issue in &first.findings {
        assert_eq!(issue.category.as_deref(), Some("security"));
        assert_eq!(issue.confidence.as_deref(), Some("high"));
        assert_eq!(issue.cwe, Some(798));
        assert!(
            !issue.line_content.contains("secret-value"),
            "el secreto debe estar redactado: {}",
            issue.line_content
        );
        assert!(issue.line_content.contains("***"));
    }
    let serialized = serde_json::to_string(&first).unwrap();
    assert!(
        !serialized.contains("secret-value"),
        "el secreto no puede aparecer en el JSON"
    );

    // D04: la segunda corrida del mismo contenido es warm hit.
    stats::reset();
    let second = analyze(&sec_request);
    let second_stats = stats::snapshot();
    assert_eq!(second_stats.fact_model_requests, 20);
    assert_eq!(second_stats.fact_cache_hits, 20, "warm hits medidos");
    assert_eq!(second_stats.fact_cache_misses, 0);
    assert_eq!(second.pack_coverage, first.pack_coverage);
    assert_eq!(second.findings.len(), first.findings.len());

    // ── D02: def-use con direcciones y cobertura incompleta explícita ─────
    let out_param = dir.join("out_param.txt");
    std::fs::write(&out_param, "parm(out:&Resultado)\n&Resultado = 1\n").unwrap();
    let out_result = analyze(&request(vec![out_param], &["GX.2.7.5"], 100.0));
    assert!(
        out_result.findings.is_empty(),
        "un Out consumido externamente no es dead store"
    );

    let malformed = dir.join("malformed.txt");
    std::fs::write(&malformed, "for each Customer\n    &x = 1\n").unwrap();
    let malformed_result = analyze(&request(vec![malformed], &["GX.2.7.5"], 100.0));
    assert!(
        malformed_result.findings.is_empty(),
        "cobertura incompleta no declara dead store"
    );

    let dead_store = dir.join("dead_store.txt");
    std::fs::write(&dead_store, "&x = 1\n&x = 2\n&y = &x\n").unwrap();
    let dead_result = analyze(&request(vec![dead_store], &["GX.2.7.5"], 100.0));
    assert_eq!(dead_result.findings.len(), 1);
    assert_eq!(dead_result.findings[0].line_number, 1);
    assert_eq!(dead_result.pack_coverage[0].objects_analyzed, 1);

    // ── D03: dataflow local con traza source→sink (GX.SEC.2) ──────────────
    let sqli = dir.join("sqli.txt");
    std::fs::write(
        &sqli,
        "parm(in:&Filtro)\n\
         &sql = 'select * from Cliente where nombre = ' + &Filtro\n\
         &Result = &sql.Execute()\n",
    )
    .unwrap();
    let taint = analyze(&request(vec![sqli], &["GX.SEC.2"], 100.0));
    assert_eq!(taint.findings.len(), 1, "{}", taint.findings.len());
    let issue = &taint.findings[0];
    assert_eq!(issue.cwe, Some(89));
    assert_eq!(issue.category.as_deref(), Some("security"));
    assert_eq!(issue.confidence.as_deref(), Some("medium"));
    let trace = issue.trace.as_ref().expect("traza source→sink");
    assert_eq!(trace.first().unwrap().kind, "source");
    assert_eq!(trace.first().unwrap().line, 1);
    assert_eq!(trace.last().unwrap().kind, "sink");
    assert_eq!(trace.last().unwrap().line, 3);
    assert_eq!(taint.security.as_ref().unwrap().errors, 1);
    assert_eq!(taint.verdict, QgVerdict::Reject);

    // Sanitizador no modelado: conservador, visible y con confidence low.
    let unknown = dir.join("unknown_sanitizer.txt");
    std::fs::write(
        &unknown,
        "parm(in:&Filtro)\n\
         &safe = MiSanitizador(&Filtro)\n\
         &sql = &safe\n\
         &sql.Execute()\n",
    )
    .unwrap();
    let conservative = analyze(&request(vec![unknown], &["GX.SEC.2"], 100.0));
    assert_eq!(conservative.findings.len(), 1);
    assert_eq!(conservative.findings[0].confidence.as_deref(), Some("low"));
    assert_eq!(conservative.pack_coverage[0].unsupported_sanitizers, 1);
    assert!(conservative.findings[0]
        .trace
        .as_ref()
        .unwrap()
        .iter()
        .any(|step| step.kind == "unsupported_call"));

    // D03: la retención sin redactar es opt-in; por defecto se redacta.
    let secret = dir.join("secret.txt");
    std::fs::write(&secret, "&password = 'S3cr3t!'\n").unwrap();
    let redacted = analyze(&request(vec![secret.clone()], &["GX.SEC.1"], 100.0));
    assert!(!redacted.findings[0].line_content.contains("S3cr3t!"));
    let mut retain_request = request(vec![secret], &["GX.SEC.1"], 100.0);
    retain_request.retain_sensitive_evidence = true;
    let retained = analyze(&retain_request);
    assert!(
        retained.findings[0].line_content.contains("S3cr3t!"),
        "retención opt-in explícita"
    );

    // ── D03: sin pack de seguridad no hay resumen ni costo ────────────────
    stats::reset();
    let style = analyze(&request(vec![wide], &["GX.1.1"], 100.0));
    let style_stats = stats::snapshot();
    assert!(style.security.is_none());
    assert_eq!(
        style_stats.fact_model_requests, 0,
        "sin packs no hay hechos"
    );
    assert!(style.pack_coverage.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}
