#![allow(unused_imports)]
use crate::base::*;
use crate::helpers::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity, SourceLine};
use gx_core::regex_cache::*;
use std::path::Path;

type ForEachState = (SourceLine, bool, bool);

define_rule! {
    id = "GX.1.3",
    name = "Sintaxis de Sentencias particulares",
    severity = Severity::Warning,
    description = "Se debe indicar el índice que se está recorriendo en el For Each. También al finalizar el recorrido indicar el nombre de la tabla. Uso obligatorio la sentencia del DEFINED BY al final del Where.",
    triggers = ["for each"],
    abstract = false,
    struct RuleGx1_3 {
        for_each_stack: Vec<ForEachState>,
    },
    reset = |me: &mut RuleGx1_3, _file: &Path| {  me.for_each_stack = Vec::new();  },
    evaluate = |me: &mut RuleGx1_3, line: &ParsedLine, ctx: &AuditContext| {
        let lower = &line.clean_lower;
        if lower.is_empty() {
            return vec![];
        }
        if starts_with_kw(lower, "for each") {
            me.for_each_stack.push((line.source.clone(), false, false));
            let parts: Vec<&str> = line.clean.trim().split_whitespace().collect();
            if parts.len() < 3 {
                return vec![make_issue(
                    me.id(),
                    me.severity(),
                    line,
                    me.current_file.as_deref(),
                    Some("Se debe indicar el índice o tabla que se está recorriendo en la apertura del For Each."),
                )];
            }
            return vec![];
        }
        if !me.for_each_stack.is_empty() {
            let (cur_line, has_where, has_defined_by) = me.for_each_stack.last().unwrap().clone();
            let mut updated = false;
            let (mut h_where, mut h_defined) = (has_where, has_defined_by);
            if starts_with_kw(lower, "where") {
                h_where = true;
                updated = true;
            } else if lower.contains("defined by") {
                h_defined = true;
                updated = true;
            }
            if updated {
                let idx = me.for_each_stack.len() - 1;
                me.for_each_stack[idx] = (cur_line, h_where, h_defined);
            }
        }
        if starts_with_kw(lower, "endfor") {
            if me.for_each_stack.is_empty() {
                return vec![];
            }
            let (current_for, has_where, has_defined_by) = me.for_each_stack.pop().unwrap();
            let mut issues: Vec<Issue> = Vec::new();
            if !line.raw.contains("//") && line.clean.trim().split_whitespace().count() < 2 {
                issues.push(make_issue(
                    me.id(),
                    me.severity(),
                    line,
                    me.current_file.as_deref(),
                    Some("Al finalizar el For Each (endfor) se debe indicar el nombre de la tabla o un comentario aclaratorio (ej: endfor // Customer)."),
                ));
            }
            if has_where && !has_defined_by {
                issues.push(make_issue(
                    me.id(),
                    me.severity(),
                    &current_for,
                    me.current_file.as_deref(),
                    Some(&format!("Uso obligatorio de la sentencia DEFINED BY al final del Where para el For Each de la línea {}.", current_for.number)),
                ));
            }
            return issues;
        }
        vec![]
     },
}
