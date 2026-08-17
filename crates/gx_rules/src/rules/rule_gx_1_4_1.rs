#![allow(unused_imports)]
use crate::base::*;
use crate::helpers::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity};
use gx_core::regex_cache::*;
use std::collections::HashMap;
use std::path::Path;

const EXCLUDED_VARS: &[&str] = &[
    "ok", "error", "flag", "status", "count", "exist", "sdt", "msg",
];

define_rule! {
    id = "GX.1.4.1",
    name = "Concepto de Variables",
    severity = Severity::Warning,
    description = "No se deben reutilizar variables en distintas partes del código.",
    triggers = ["=", "&"],
    abstract = false,
    struct RuleGx1_4_1 {
        assigned_vars: HashMap<String, u32>,
    },
    reset = |me: &mut RuleGx1_4_1, _file: &Path| {  me.assigned_vars = HashMap::new();  },
    evaluate = |me: &mut RuleGx1_4_1, line: &ParsedLine, ctx: &AuditContext| {
        if !line.has_ampersand || !line.has_equal {
            return vec![];
        }
        let clean = &line.clean;
        if clean.is_empty() {
            return vec![];
        }
        let m = match ASSIGN_PATTERN.captures(clean) {
            Some(m) => m,
            None => return vec![],
        };
        let var_name = match m.get(1) {
            Some(g) => g.as_str(),
            None => return vec![],
        };
        let var_name_lower = var_name.to_lowercase();
        if EXCLUDED_VARS.contains(&var_name_lower.as_str()) {
            return vec![];
        }
        let equal_pos = match clean.find('=') {
            Some(p) => p,
            None => return vec![],
        };
        let right_side = clean[equal_pos + 1..].to_lowercase();
        if right_side.contains(&format!("&{var_name_lower}")) {
            me.assigned_vars.insert(var_name_lower, line.number);
            return vec![];
        }
        match me.assigned_vars.get(&var_name_lower).copied() {
            Some(prev) if line.number - prev > 15 => {
                let issue = make_issue(
                    me.id(),
                    me.severity(),
                    line,
                    me.current_file.as_deref(),
                    Some(&format!(
                        "Posible reutilización incorrecta de contexto de la variable '&{var_name}' (previamente asignada en la línea {prev}). Se sugiere definir una nueva variable independiente."
                    )),
                );
                me.assigned_vars.insert(var_name_lower, line.number);
                vec![issue]
            }
            _ => {
                me.assigned_vars.insert(var_name_lower, line.number);
                vec![]
            }
        }
     },
}
