#![allow(unused_imports)]
use crate::base::*;
use crate::helpers::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity, SourceLine};
use gx_core::regex_cache::*;
use std::collections::HashSet;
use std::path::Path;

const LOGICAL_OPERATORS: &[&str] = &["and", "or", "in"];

define_rule! {
    id = "GX.2.2",
    name = "Evitar palabras de condiciones In, Or o And dentro de cláusulas Where",
    severity = Severity::Error,
    description = "Evitar In, Or, And dentro del Where.",
    triggers = ["where", "for each"],
    abstract = false,
    struct RuleGx2_2 {
        in_for_each: bool,
        active_where_line: Option<SourceLine>,
    },
    reset = |me: &mut RuleGx2_2, _file: &Path| {
        me.in_for_each = false;
        me.active_where_line = None;
     },
    evaluate = |me: &mut RuleGx2_2, line: &ParsedLine, ctx: &AuditContext| {
        let lower = &line.clean_lower;
        if lower.is_empty() {
            return vec![];
        }
        if !me.in_for_each && !line.has_for_each {
            return vec![];
        }
        if starts_with_kw(lower, "for each") {
            me.in_for_each = true;
            me.active_where_line = None;
            return vec![];
        }
        if starts_with_kw(lower, "endfor") {
            me.in_for_each = false;
            me.active_where_line = None;
            return vec![];
        }
        if !me.in_for_each {
            return vec![];
        }
        if starts_with_kw(lower, "where") {
            me.active_where_line = Some(line.source.clone());
        } else if starts_with_kw(lower, "defined by") || starts_with_kw(lower, "order") {
            me.active_where_line = None;
        } else if me.active_where_line.is_some() && !is_where_continuation(lower) {
            me.active_where_line = None;
        }
        if me.active_where_line.is_none() {
            return vec![];
        }
        let clean_target = remove_between_and(lower);
        let mut detected: HashSet<String> = HashSet::new();
        for token in clean_target.split_whitespace() {
            if token.starts_with('&') {
                continue;
            }
            if LOGICAL_OPERATORS.contains(&token) {
                detected.insert(token.to_uppercase());
            }
        }
        if detected.is_empty() {
            return vec![];
        }
        let where_line_num = me.active_where_line.as_ref().unwrap().number;
        me.active_where_line = None;
        let mut sorted: Vec<&String> = detected.iter().collect();
        sorted.sort();
        vec![make_issue(
            me.id(),
            me.severity(),
            line,
            me.current_file.as_deref(),
            Some(&format!(
                "Mala práctica de optimización: Evitar el uso de operadores lógicos o subconsultas ({}) dentro de una misma cláusula WHERE (Bloque de la línea {where_line_num}). Se deben dividir en múltiples sentencias WHERE secuenciales independientes.",
                sorted.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            )),
        )]
     },
}
