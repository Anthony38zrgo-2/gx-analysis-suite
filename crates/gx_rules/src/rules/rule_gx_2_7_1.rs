#![allow(unused_imports)]
use crate::base::*;
use crate::helpers::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity};
use gx_core::regex_cache::*;
use std::path::Path;

const ITERATION_VARS: &[&str] = &["&i", "&j", "&k"];

define_rule! {
    id = "GX.2.7.1",
    name = "Iteraciones",
    severity = Severity::Error,
    description = "Evitar Variables sueltas i, j y k en las iteraciones.",
    triggers = ["for each", "do"],
    abstract = false,
    struct RuleGx2_7_1 {
        loop_depth: u32,
        loop_origin_line: u32,
    },
    reset = |me: &mut RuleGx2_7_1, _file: &Path| {
        me.loop_depth = 0;
        me.loop_origin_line = 0;
     },
    evaluate = |me: &mut RuleGx2_7_1, line: &ParsedLine, ctx: &AuditContext| {
        let lower = &line.lower;
        if lower.is_empty() {
            return vec![];
        }
        let has_for = lower.contains("for");
        let has_do = lower.contains("do");
        if has_for {
            let is_for_each = starts_with_kw(lower, "for each");
            // Nota: starts_with_kw ya añade el espacio; el Python original
            // usa lower == "for" || lower.startswith("for ").
            let is_for_loop = !is_for_each && (lower == "for" || starts_with_kw(lower, "for"));
            if is_for_loop {
                me.loop_depth += 1;
                if me.loop_depth == 1 {
                    me.loop_origin_line = line.number;
                }
            }
        } else if has_do && (lower == "do while" || starts_with_kw(lower, "do while")) {
            me.loop_depth += 1;
            if me.loop_depth == 1 {
                me.loop_origin_line = line.number;
            }
        }
        if me.loop_depth > 0 {
            let variables: std::collections::HashSet<String> =
                VARIABLE_ANY_PATTERN.captures_iter(lower).map(|m| m.get(0).unwrap().as_str().to_string()).collect();
            let detected: Vec<String> = variables
                .iter()
                .filter(|v| ITERATION_VARS.contains(&v.as_str()))
                .map(|v| v.to_uppercase())
                .collect();
            if !detected.is_empty() {
                let mut sorted = detected;
                sorted.sort();
                return vec![make_issue(
                    me.id(),
                    me.severity(),
                    line,
                    me.current_file.as_deref(),
                    Some(&format!(
                        "Mala práctica de legibilidad crítica: Se detectó el uso de variables sueltas genéricas ({}) dentro de un bloque de iteración (Origen en la línea {}). Modifique el identificador por un nombre descriptivo corporativo.",
                        sorted.join(", "),
                        me.loop_origin_line
                    )),
                )];
            }
        }
        if starts_with_kw(lower, "endfor") {
            if me.loop_depth > 0 {
                me.loop_depth -= 1;
            }
        } else if starts_with_kw(lower, "enddo") {
            if me.loop_depth > 0 {
                me.loop_depth -= 1;
            }
        }
        vec![]
     },
}
