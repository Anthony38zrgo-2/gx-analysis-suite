#![allow(unused_imports)]
//! GX.SEC.3 (D04): perfil profundo project-wide.
//!
//! Grafo de llamadas documentadas (`call('Objeto', …)`) + taint
//! interprocedural por sumarios con worklist/SCC acotados. Cada hallazgo
//! explica la ruta source→call→sink. Opt-in (`cost = deep`): el perfil
//! estándar no paga grafo ni caché de sumarios.

use crate::base::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity};
use std::path::Path;

define_rule! {
    id = "GX.SEC.3",
    name = "Taint interprocedural project-wide",
    severity = Severity::Error,
    description = "Valor externo atraviesa llamadas entre objetos y alcanza un sink sin sanitizador modelado.",
    triggers = [],
    abstract = false,
    route = project,
    version = "1.0",
    category = "security",
    scope = project,
    facts = [],
    cost = deep,
    struct RuleGxSec3 {},
    reset = |_me: &mut RuleGxSec3, _file: &Path| {},
    evaluate = |_me: &mut RuleGxSec3, _line: &ParsedLine, _ctx: &AuditContext| vec![],
    project = |me: &mut RuleGxSec3, project: &ProjectFacts, _ctx: &AuditContext| {
        let mut issues = Vec::new();
        for finding in &project.report.findings {
            let object = project.objects.get(&finding.object_name).cloned();
            let file_path = object
                .as_ref()
                .map(|object| std::path::PathBuf::from(&object.container_path))
                .unwrap_or_else(|| std::path::PathBuf::from("Unknown"));
            issues.push(Issue {
                rule_id: me.id().to_string(),
                severity: me.severity(),
                line_number: finding.line,
                line_content: finding.line_content.clone(),
                description: finding.description.clone(),
                file_path,
                object,
                category: Some("security".to_string()),
                confidence: Some(finding.confidence.to_string()),
                cwe: Some(finding.cwe),
                trace: Some(finding.trace.clone()),
            });
        }
        issues
    },
}
