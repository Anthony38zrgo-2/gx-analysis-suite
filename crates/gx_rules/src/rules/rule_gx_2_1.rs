#![allow(unused_imports)]
use crate::base::*;
use crate::helpers::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity, SourceLine};
use gx_core::regex_cache::*;
use std::path::Path;

define_rule! {
    id = "GX.2.1",
    name = "Evitar uso de When dentro de cláusulas Where",
    severity = Severity::Error,
    description = "Se debe evitar usar clausula When dentro del condicional Where.",
    triggers = ["where", "for each"],
    abstract = false,
    struct RuleGx2_1 {
        in_for_each: bool,
        active_where_line: Option<SourceLine>,
    },
    reset = |me: &mut RuleGx2_1, _file: &Path| {
        me.in_for_each = false;
        me.active_where_line = None;
     },
    evaluate = |me: &mut RuleGx2_1, line: &ParsedLine, ctx: &AuditContext| {
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
        if let Some(where_line) = &me.active_where_line {
            if lower.contains("when") {
                let where_line_num = where_line.number;
                me.active_where_line = None;
                return vec![make_issue(
                    me.id(),
                    me.severity(),
                    line,
                    me.current_file.as_deref(),
                    Some(&format!(
                        "Mala práctica de rendimiento detectada: Se debe evitar el uso de la cláusula condicional WHEN dentro de las sentencias WHERE (Bloque de la línea {where_line_num}). Se sugiere resolver la lógica condicional mediante variables previas al For Each."
                    )),
                )];
            }
        }
        vec![]
     },
}
