#![allow(unused_imports)]
use crate::base::*;
use crate::helpers::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity, SourceLine};
use gx_core::regex_cache::*;
use std::path::Path;

const EXCLUDED_FUNCTION_TOKENS: &[&str] =
    &["and", "or", "not", "if", "case", "where", "in", "like"];

define_rule! {
    id = "GX.2.4",
    name = "No usar funciones en los comandos Where",
    severity = Severity::Error,
    description = "No usar funciones dentro de clausula Where.",
    triggers = ["where", "for each"],
    abstract = false,
    struct RuleGx2_4 {
        in_for_each: bool,
        active_where_line: Option<SourceLine>,
    },
    reset = |me: &mut RuleGx2_4, _file: &Path| {
        me.in_for_each = false;
        me.active_where_line = None;
     },
    evaluate = |me: &mut RuleGx2_4, line: &ParsedLine, ctx: &AuditContext| {
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
            me.active_where_line = Some(line.to_source_line());
        } else if starts_with_kw(lower, "defined by") || starts_with_kw(lower, "order") {
            me.active_where_line = None;
        } else if me.active_where_line.is_some() && !is_where_continuation(lower) {
            me.active_where_line = None;
        }
        if me.active_where_line.is_none() {
            return vec![];
        }
        let clean = &line.clean;
        let mut detected: std::collections::HashSet<String> = std::collections::HashSet::new();
        for m in FUNCTION_CALL_PATTERN.captures_iter(clean) {
            let func_name = m.get(1).unwrap().as_str();
            let start = m.get(1).unwrap().start();
            if start > 0 {
                let prev = clean.as_bytes()[start - 1] as char;
                if prev == '.' || prev == '&' {
                    continue;
                }
            }
            if EXCLUDED_FUNCTION_TOKENS.contains(&func_name.to_lowercase().as_str()) {
                continue;
            }
            detected.insert(func_name.to_uppercase());
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
                "Mala práctica de performance crítica: No se permite el uso de funciones ({}) dentro de las cláusulas WHERE (Bloque de la línea {where_line_num}). Invalida la optimización de índices en el DBMS. Se sugiere precalcular el valor en una variable antes del For Each.",
                sorted.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            )),
        )]
     },
}
