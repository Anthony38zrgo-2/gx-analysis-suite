#![allow(unused_imports)]
//! GX.2.7.5 (D02): variable escrita y sobrescrita sin lectura intermedia.
//!
//! Pack de OBJETO: usa el modelo semántico (def-use local) en lugar de
//! heurísticas de línea. Deshabilitada por defecto (no está en
//! `DEFAULT_ENABLED`): un perfil de estilo común no paga el costo de los
//! hechos semánticos.

use crate::base::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity, SourceLine};
use std::path::Path;

define_rule! {
    id = "GX.2.7.5",
    name = "Variable escrita sin lectura",
    severity = Severity::Warning,
    description = "Se asigna una variable y se sobrescribe sin leerla: la primera asignación es innecesaria.",
    triggers = [],
    abstract = false,
    route = object,
    version = "1.0",
    category = "policy",
    scope = object,
    facts = [syntax, symbols, def_use],
    cost = moderate,
    struct RuleGx2_7_5 {},
    reset = |_me: &mut RuleGx2_7_5, _file: &Path| {},
    evaluate = |_me: &mut RuleGx2_7_5, _line: &ParsedLine, _ctx: &AuditContext| vec![],
    analyze = |me: &mut RuleGx2_7_5, facts: &ObjectFacts, _ctx: &AuditContext| {
        let Some(model) = facts.model else {
            return vec![];
        };
        // Cobertura incompleta (bloques sin cerrar): no se declara dead store.
        if !model.coverage.complete {
            return vec![];
        }
        let lines: Vec<&str> = facts.text.split('\n').collect();
        let mut issues = Vec::new();
        for access in model.dead_stores() {
            let content = lines
                .get(access.line.saturating_sub(1) as usize)
                .map(|line| line.trim_end_matches('\r').to_string())
                .unwrap_or_else(|| format!("{} (escritura)", access.name));
            let source = SourceLine {
                number: access.line,
                content,
            };
            issues.push(make_issue(
                me.id(),
                me.severity(),
                &source,
                me.current_file.as_deref(),
                Some(&format!(
                    "La variable '{}' se asigna y se sobrescribe sin ser leída entre ambas asignaciones.",
                    access.name
                )),
            ));
        }
        issues
    },
}
