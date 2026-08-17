#![allow(unused_imports)]
use crate::base::*;
use crate::helpers::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity, SourceLine};
use gx_core::regex_cache::*;
use std::path::Path;

define_rule! {
    id = "GX.1.3.2",
    name = "If",
    severity = Severity::Warning,
    description = "Condiciones If debe estar completo con su Else.",
    triggers = [],
    abstract = false,
    struct RuleGx1_3_2 {
        if_stack: Vec<(SourceLine, bool)>,
    },
    reset = |me: &mut RuleGx1_3_2, _file: &Path| {  me.if_stack = Vec::new();  },
    evaluate = |me: &mut RuleGx1_3_2, line: &ParsedLine, ctx: &AuditContext| {
        let lower = &line.clean_lower;
        if lower.is_empty() {
            return vec![];
        }
        if starts_with_kw(lower, "if") && !starts_with_kw(lower, "elseif") {
            me.if_stack.push((line.source.clone(), false));
            return vec![];
        }
        else if starts_with_kw(lower, "else") && !starts_with_kw(lower, "elseif") {
            if let Some(last) = me.if_stack.last_mut() {
                last.1 = true;
            }
            return vec![];
        }
        else if starts_with_kw(lower, "endif") {
            if me.if_stack.is_empty() {
                return vec![];
            }
            let (last_if_line, has_else) = me.if_stack.pop().unwrap();
            if has_else {
                return vec![];
            }
            return vec![make_issue(
                me.id(),
                me.severity(),
                &last_if_line,
                me.current_file.as_deref(),
                Some(&format!("La condición IF en la línea {} debe estar completa con su ELSE.", last_if_line.number)),
            )];
        }
        vec![]
     },
}
