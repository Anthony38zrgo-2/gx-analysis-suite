#![allow(unused_imports)]
use crate::base::*;
use crate::helpers::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity, SourceLine};
use gx_core::regex_cache::*;
use std::path::Path;

define_rule! {
    id = "GX.1.3.3",
    name = "Case",
    severity = Severity::Warning,
    description = "Condiciones Case debe estar completo con su Otherwise.",
    triggers = ["case"],
    abstract = false,
    struct RuleGx1_3_3 {
        case_stack: Vec<(SourceLine, bool)>,
    },
    reset = |me: &mut RuleGx1_3_3, _file: &Path| {  me.case_stack = Vec::new();  },
    evaluate = |me: &mut RuleGx1_3_3, line: &ParsedLine, ctx: &AuditContext| {
        let lower = &line.clean_lower;
        if lower.is_empty() {
            return vec![];
        }
        if starts_with_kw(lower, "do case") {
            me.case_stack.push((line.source.clone(), false));
            return vec![];
        }
        if starts_with_kw(lower, "otherwise") {
            if let Some(last) = me.case_stack.last_mut() {
                last.1 = true;
            }
            return vec![];
        }
        if starts_with_kw(lower, "endcase") {
            if me.case_stack.is_empty() {
                return vec![];
            }
            let (last_case_line, has_otherwise) = me.case_stack.pop().unwrap();
            if has_otherwise {
                return vec![];
            }
            return vec![make_issue(
                me.id(),
                me.severity(),
                &last_case_line,
                me.current_file.as_deref(),
                Some(&format!("La estructura CASE en la línea {} debe estar completa con su OTHERWISE.", last_case_line.number)),
            )];
        }
        vec![]
     },
}
