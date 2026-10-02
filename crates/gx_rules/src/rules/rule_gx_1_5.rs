#![allow(unused_imports)]
use crate::base::*;
use crate::helpers::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity};
use gx_core::regex_cache::*;
use std::path::Path;

define_rule! {
    id = "GX.1.5",
    name = "Condiciones Booleanas",
    severity = Severity::Warning,
    description = "No es recomendable definir condiciones booleanas con más de tres operandos.",
    triggers = ["if", "case"],
    abstract = false, route = tokens,
    struct RuleGx1_5 {},
    reset = |me: &mut RuleGx1_5, _file: &Path| {  },
    evaluate = |me: &mut RuleGx1_5, line: &ParsedLine, ctx: &AuditContext| {
        if !line.has_if && !line.has_case {
            return vec![];
        }
        let lower = &line.clean_lower;
        if !(starts_with_kw(lower, "if") || starts_with_kw(lower, "case")) {
            return vec![];
        }
        if !lower.contains(" and ") && !lower.contains(" or ") {
            return vec![];
        }
        let operator_count = LOGICAL_OPERATOR_PATTERN.captures_iter(&line.clean).count();
        if operator_count >= 3 {
            return vec![make_issue(
                me.id(),
                me.severity(),
                line,
                me.current_file.as_deref(),
                Some(&format!(
                    "Condición booleana compleja detectada ({operator_count} operadores lógicos). Se recomienda no exceder los 3 operandos para mantener la legibilidad natural del código."
                )),
            )];
        }
        vec![]
     },
}
