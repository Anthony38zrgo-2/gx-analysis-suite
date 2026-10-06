#![allow(unused_imports)]
//! GX.SEC.2 (D03): dataflow local acotado (SQL/comando/archivo/salida).
//!
//! Fuentes, sinks y funciones neutras están DOCUMENTADOS en
//! `gx_core::security`; cada hallazgo incluye una traza acotada source→sink.
//! Un sanitizador no modelado NO se asume seguro: el taint se conserva, la
//! traza lo marca y la cobertura lo reporta (`unsupported_sanitizers`).
//!
//! Deshabilitada por defecto (perfil de seguridad opt-in).

use crate::base::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity};
use std::path::Path;

define_rule! {
    id = "GX.SEC.2",
    name = "Dataflow inseguro (SQL/comando/archivo/salida)",
    severity = Severity::Error,
    description = "Valor de entrada externa alcanza un sink peligroso sin sanitizador modelado.",
    triggers = [],
    abstract = false,
    route = object,
    version = "1.0",
    category = "security",
    scope = object,
    facts = [syntax, symbols, def_use],
    cost = deep,
    struct RuleGxSec2 { unsupported_sanitizers: usize },
    reset = |me: &mut RuleGxSec2, _file: &Path| { me.unsupported_sanitizers = 0; },
    evaluate = |_me: &mut RuleGxSec2, _line: &ParsedLine, _ctx: &AuditContext| vec![],
    analyze = |me: &mut RuleGxSec2, facts: &ObjectFacts, _ctx: &AuditContext| {
        let Some(model) = facts.model else {
            return vec![];
        };
        let report = gx_core::security::analyze_taint(model, facts.text);
        me.unsupported_sanitizers = report.unsupported_sanitizers;
        let lines: Vec<&str> = facts.text.split('\n').collect();
        report
            .findings
            .into_iter()
            .map(|finding| {
                let raw = lines
                    .get(finding.line.saturating_sub(1) as usize)
                    .copied()
                    .unwrap_or_default()
                    .trim_end_matches('\r');
                Issue {
                    rule_id: me.id().to_string(),
                    severity: me.severity(),
                    line_number: finding.line,
                    line_content: raw.to_string(),
                    description: finding.description.clone(),
                    file_path: me
                        .current_file
                        .clone()
                        .unwrap_or_else(|| std::path::PathBuf::from("Unknown")),
                    object: None,
                    category: Some("security".to_string()),
                    confidence: Some(finding.confidence.to_string()),
                    cwe: Some(finding.cwe),
                    trace: Some(finding.trace.clone()),
                }
            })
            .collect()
    },
    coverage = |me: &RuleGxSec2| CoverageHint {
        skipped_unsupported: 0,
        unsupported_sanitizers: me.unsupported_sanitizers,
    },
}
