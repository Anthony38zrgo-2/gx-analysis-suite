#![allow(unused_imports)]
use crate::base::*;
use crate::helpers::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity, SourceLine};
use gx_core::regex_cache::*;
use std::collections::HashSet;
use std::path::Path;

const REQUIRED_HEADERS: &[&str] = &["codigo iniciativa", "descripcion", "responsible", "version"];
const SECTION_END_PREFIXES: &[&str] = &["events", "source"];

define_rule! {
    id = "GX.1.7.1",
    name = "Historia de Cambios",
    severity = Severity::Warning,
    description = "En la sección Rules poner: CODIGO INICIATIVA, DESCRIPCION, RESPONSIBLE, VERSION.",
    triggers = ["*"],
    abstract = false,
    struct RuleGx1_7_1 {
        in_rules_section: bool,
        found_headers: HashSet<String>,
        first_line_obj: Option<SourceLine>,
        completed: bool,
    },
    reset = |me: &mut RuleGx1_7_1, _file: &Path| {
        me.in_rules_section = true;
        me.found_headers = HashSet::new();
        me.first_line_obj = None;
        me.completed = false;
     },
    evaluate = |me: &mut RuleGx1_7_1, line: &ParsedLine, ctx: &AuditContext| {
        if me.completed {
            return vec![];
        }
        if me.first_line_obj.is_none() {
            me.first_line_obj = Some(line.source.clone());
        }
        let stripped = &line.stripped;
        if stripped.is_empty() {
            return vec![];
        }
        let lower = &line.lower;
        if *lower == "rules:" || lower.starts_with("rules:") {
            me.in_rules_section = true;
            return vec![];
        }
        if lower.starts_with(SECTION_END_PREFIXES[0]) || lower.starts_with(SECTION_END_PREFIXES[1])
            || lower.starts_with("sub ")
        {
            me.in_rules_section = false;
            return vec![];
        }
        if !me.in_rules_section {
            return vec![];
        }
        let missing: HashSet<&&str> = REQUIRED_HEADERS.iter().filter(|h| !me.found_headers.contains(**h)).collect();
        if missing.is_empty() {
            me.completed = true;
            return vec![];
        }
        for header in missing {
            if lower.contains(*header) {
                me.found_headers.insert((*header).to_string());
            }
        }
        if me.found_headers.len() == REQUIRED_HEADERS.len() {
            me.completed = true;
        }
        vec![]
     },
    finalize = |me: &mut RuleGx1_7_1, _ctx: &AuditContext| {
        let missing: Vec<&str> = REQUIRED_HEADERS.iter().filter(|h| !me.found_headers.contains(**h)).cloned().collect();
        if missing.is_empty() || me.first_line_obj.is_none() {
            return vec![];
        }
        let mut sorted: Vec<String> = missing.iter().map(|h| h.to_uppercase()).collect();
        sorted_eq(missing, &mut sorted);
        let missing_str = sorted.join(", ");
        let first = me.first_line_obj.clone().unwrap();
        vec![make_issue(
            me.id(),
            me.severity(),
            &first,
            me.current_file.as_deref(),
            Some(&format!(
                "Bloque de Historia de Cambios incompleto o ausente en la cabecera/sección Rules del objeto. Falta incluir los tags obligatorios: {missing_str}."
            )),
        )]
     },
}

fn sorted_eq(_missing: Vec<&str>, sorted: &mut Vec<String>) {
    sorted.sort();
}
