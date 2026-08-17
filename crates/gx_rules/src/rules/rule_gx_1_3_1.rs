#![allow(unused_imports)]
use crate::base::*;
use crate::helpers::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity, SourceLine};
use gx_core::regex_cache::*;
use std::path::Path;

define_rule! {
    id = "GX.1.3.1",
    name = "For Each",
    severity = Severity::Warning,
    description = "Se debe indentar el For Each en cada Where y en el cuerpo de código.",
    triggers = ["*"],
    abstract = false,
    struct RuleGx1_3_1 {
        in_for_each: bool,
    },
    reset = |me: &mut RuleGx1_3_1, _file: &Path| {  me.in_for_each = false;  },
    evaluate = |me: &mut RuleGx1_3_1, line: &ParsedLine, ctx: &AuditContext| {
        let lower = &line.clean_lower;
        if lower.is_empty() {
            return vec![];
        }
        if starts_with_kw(lower, "for each") {
            me.in_for_each = true;
            return vec![];
        }
        if starts_with_kw(lower, "endfor") {
            me.in_for_each = false;
            return vec![];
        }
        if !me.in_for_each {
            return vec![];
        }
        let leading_spaces = line.raw.len() - line.raw.trim_start().len();
        if leading_spaces >= 4 {
            return vec![];
        }
        let description = if starts_with_kw(lower, "where") {
            "La cláusula Where de un For Each debe estar indentada (mínimo 4 espacios)."
        } else {
            "El cuerpo de código dentro de un For Each debe estar indentado (mínimo 4 espacios)."
        };
        vec![make_issue(me.id(), me.severity(), line, me.current_file.as_deref(), Some(description))]
     },
}
