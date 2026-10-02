#![allow(unused_imports)]
use crate::base::*;
use crate::helpers::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity};
use gx_core::regex_cache::*;
use std::path::Path;

const COUNTER_VARS: &[&str] = &["&i", "&j", "&k"];
const ASSIGNMENT_OPERATORS: &[&str] = &["=", "+=", "-="];

define_rule! {
    id = "GX.2.7.2",
    name = "Contadores",
    severity = Severity::Error,
    description = "Evitar Variables sueltas i, j y k en los contadores.",
    triggers = ["=", "&"],
    abstract = false, route = tokens,
    struct RuleGx2_7_2 {},
    reset = |me: &mut RuleGx2_7_2, _file: &Path| {  },
    evaluate = |me: &mut RuleGx2_7_2, line: &ParsedLine, ctx: &AuditContext| {
        if !line.has_ampersand || !line.has_equal {
            return vec![];
        }
        let lower_line = &line.lower;
        let mut detected: Vec<String> = Vec::new();
        for var in COUNTER_VARS {
            let var_pos = match lower_line.find(var) {
                Some(p) => p,
                None => continue,
            };
            let next_pos = var_pos + var.len();
            if next_pos < lower_line.len() && lower_line.as_bytes()[next_pos].is_ascii_alphanumeric() {
                continue;
            }
            let remaining = lower_line[next_pos..].trim_start();
            for op in ASSIGNMENT_OPERATORS {
                if remaining.starts_with(op) {
                    detected.push(var.to_uppercase());
                    break;
                }
            }
        }
        if detected.is_empty() {
            return vec![];
        }
        let mut sorted = detected;
        sorted.sort();
        vec![make_issue(
            me.id(),
            me.severity(),
            line,
            me.current_file.as_deref(),
            Some(&format!(
                "Mala práctica de desarrollo: Se detectó el uso de variables sueltas genéricas ({}) actuando como contadores o acumuladores de datos. Modifique el identificador por un nombre descriptivo corporativo (ej: &ItemCount, &RowIndex).",
                sorted.join(", ")
            )),
        )]
     },
}
