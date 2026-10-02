#![allow(unused_imports)]
use crate::base::*;
use crate::helpers::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity};
use gx_core::regex_cache::*;
use std::collections::HashSet;
use std::path::Path;

const CONDITION_VARS: &[&str] = &["&cond", "&ok", "&flag", "&status", "&condition"];
const ASSIGNMENT_OPERATORS: &[&str] = &[":=", "+=", "="];
const INVALID_EQUAL_OPERATORS: &[&str] = &["==", ">=", "<=", "!="];

define_rule! {
    id = "GX.2.7.3",
    name = "Condición",
    severity = Severity::Error,
    description = "Para el caso de la variable condición se recomienda evitar la reutilización.",
    triggers = ["=", "&"],
    abstract = false, route = tokens,
    struct RuleGx2_7_3 {
        assigned_condition_vars: HashSet<String>,
    },
    reset = |me: &mut RuleGx2_7_3, _file: &Path| {  me.assigned_condition_vars = HashSet::new();  },
    evaluate = |me: &mut RuleGx2_7_3, line: &ParsedLine, ctx: &AuditContext| {
        if !line.has_ampersand || !line.has_equal {
            return vec![];
        }
        let lower_line = &line.lower;
        for variable in CONDITION_VARS {
            let var_pos = match lower_line.find(variable) {
                Some(p) => p,
                None => continue,
            };
            let next_pos = var_pos + variable.len();
            if next_pos < lower_line.len() && lower_line.as_bytes()[next_pos].is_ascii_alphanumeric() {
                continue;
            }
            let remaining = lower_line[next_pos..].trim_start();
            let mut assignment_detected = false;
            for op in ASSIGNMENT_OPERATORS {
                if !remaining.starts_with(op) {
                    continue;
                }
                if *op == "=" && INVALID_EQUAL_OPERATORS.iter().any(|inv| remaining.starts_with(inv)) {
                    continue;
                }
                assignment_detected = true;
                break;
            }
            if !assignment_detected {
                continue;
            }
            let normalized_var = &variable[1..];
            if me.assigned_condition_vars.contains(normalized_var) {
                return vec![make_issue(
                    me.id(),
                    me.severity(),
                    line,
                    me.current_file.as_deref(),
                    Some(&format!(
                        "Mala práctica de control de flujos crítica: Se detectó la reutilización de la variable de condición/estado '{}' en una nueva asignación de contexto. Se exige definir variables con nombres descriptivos únicos por cada escenario de validación (ej: &IsCustomerValid, &ProcessSuccess) para evitar estados remanentes corruptos.",
                        variable
                    )),
                )];
            }
            me.assigned_condition_vars.insert(normalized_var.to_string());
        }
        vec![]
     },
}
