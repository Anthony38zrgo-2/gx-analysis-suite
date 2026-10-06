#![allow(unused_imports)]
use crate::base::*;
use crate::helpers::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity, SourceLine};
use gx_core::regex_cache::*;
use std::collections::{HashMap, HashSet};
use std::path::Path;

const INVALID_ASSIGNMENTS: &[&str] = &["==", "!=", "<=", ">="];
const SYSTEM_EXCLUSIONS: &[&str] = &["pgmname", "time", "today", "mode", "gx_fail", "gx_empty"];

define_rule! {
    id = "GX.2.7.4",
    name = "Variables no usadas",
    severity = Severity::Error,
    description = "NO se deben definir variables ni vectores que no se utilicen dentro del programa.",
    triggers = ["&"],
    abstract = false, route = tokens,
    struct RuleGx2_7_4 {
        var_declaration_lines: HashMap<String, SourceLine>,
        read_vars: HashSet<String>,
        written_vars: HashSet<String>,
    },
    reset = |me: &mut RuleGx2_7_4, _file: &Path| {
        me.var_declaration_lines = HashMap::new();
        me.read_vars = HashSet::new();
        me.written_vars = HashSet::new();
     },
    evaluate = |me: &mut RuleGx2_7_4, line: &ParsedLine, ctx: &AuditContext| {
        if !line.has_ampersand {
            return vec![];
        }
        let lower_line = &line.lower;
        let is_assignment = line.has_equal
            && !INVALID_ASSIGNMENTS.iter().any(|op| lower_line.contains(*op));
        if is_assignment {
            let (left, right) = match lower_line.split_once('=') {
                Some((l, r)) => (l, r),
                None => (lower_line.as_ref(), ""),
            };
            for m in VARIABLE_ANY_PATTERN.captures_iter(left) {
                let var = m.get(1).unwrap().as_str().to_string();
                me.written_vars.insert(var.clone());
                me.register_variable(&var, &line.to_source_line());
            }
            for m in VARIABLE_ANY_PATTERN.captures_iter(right) {
                let var = m.get(1).unwrap().as_str().to_string();
                me.read_vars.insert(var.clone());
                me.register_variable(&var, &line.to_source_line());
            }
            return vec![];
        }
        for m in VARIABLE_ANY_PATTERN.captures_iter(lower_line) {
            let var = m.get(1).unwrap().as_str().to_string();
            me.read_vars.insert(var.clone());
            me.register_variable(&var, &line.to_source_line());
        }
        vec![]
     },
    finalize = |me: &mut RuleGx2_7_4, _ctx: &AuditContext| {
        let mut dead: Vec<String> = me.written_vars.difference(&me.read_vars).cloned().collect();
        // Orden determinista de emisión (GX-005).
        dead.sort();
        let mut issues: Vec<Issue> = Vec::new();
        for variable in dead {
            if SYSTEM_EXCLUSIONS.contains(&variable.as_str()) {
                continue;
            }
            if let Some(line_obj) = me.var_declaration_lines.get(&variable) {
                issues.push(make_issue(
                    me.id(),
                    me.severity(),
                    line_obj,
                    me.current_file.as_deref(),
                    Some(&format!(
                        "Mala práctica de optimización: Se detectó que la variable '&{variable}' es asignada o declarada, pero nunca es leída o consumida en el flujo del objeto. Elimínela para optimizar el consumo de memoria."
                    )),
                ));
            }
        }
        issues
     },
}

impl RuleGx2_7_4 {
    fn register_variable(&mut self, variable: &str, line: &SourceLine) {
        self.var_declaration_lines
            .entry(variable.to_string())
            .or_insert_with(|| line.clone());
    }
}
