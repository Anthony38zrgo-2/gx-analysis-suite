#![allow(unused_imports)]
use crate::base::*;
use crate::helpers::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity};
use gx_core::regex_cache::*;
use std::collections::HashSet;
use std::path::Path;

define_rule! {
    id = "GX.1.1",
    name = "Uso de Mayúsculas y Minúsculas",
    severity = Severity::Warning,
    description = "Usar Mayúsculas y Minúsculas en uso de variables, variable empieza con &.",
    triggers = ["&"],
    abstract = false,
    struct RuleGx1_1 {},
    reset = |me: &mut RuleGx1_1, _file: &Path| {  },
    evaluate = |me: &mut RuleGx1_1, line: &ParsedLine, ctx: &AuditContext| {
        if !line.has_ampersand {
            return vec![];
        }
        let matches: HashSet<String> = VARIABLE_LOWERCASE_PATTERN
            .captures_iter(&line.clean)
            .filter_map(|m| m.get(1))
            .map(|g| g.as_str().to_string())
            .collect();
        if matches.is_empty() {
            return vec![];
        }
        let vars: Vec<String> = matches.iter().map(|v| format!("&{v}")).collect();
        let vars_str = vars.join(", ");
        vec![make_issue(
            me.id(),
            me.severity(),
            line,
            me.current_file.as_deref(),
            Some(&format!(
                "Variable(s) {vars_str} debe(n) empezar con Mayúscula (PascalCase, ej: &MyVariable)."
            )),
        )]
     },
}
