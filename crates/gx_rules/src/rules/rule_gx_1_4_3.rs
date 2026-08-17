#![allow(unused_imports)]
use crate::base::*;
use crate::helpers::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity, SourceLine};
use gx_core::regex_cache::*;
use std::path::Path;

define_rule! {
    id = "GX.1.4.3",
    name = "Parámetros",
    severity = Severity::Warning,
    description = "Definir cada parámetro si es de entrada o de salida, en la sección rule.",
    triggers = ["*"],
    abstract = false,
    struct RuleGx1_4_3 {
        in_parm_block: bool,
        parm_buffer_parts: Vec<String>,
        start_line_obj: Option<SourceLine>,
    },
    reset = |me: &mut RuleGx1_4_3, _file: &Path| {
        me.in_parm_block = false;
        me.parm_buffer_parts = Vec::new();
        me.start_line_obj = None;
     },
    evaluate = |me: &mut RuleGx1_4_3, line: &ParsedLine, ctx: &AuditContext| {
        let lower = &line.clean_lower;
        if !me.in_parm_block && !lower.contains("parm") {
            return vec![];
        }
        if lower.is_empty() {
            return vec![];
        }
        if PARM_START_PATTERN.is_match(lower) {
            me.in_parm_block = true;
            me.parm_buffer_parts = vec![lower.clone()];
            me.start_line_obj = Some(line.source.clone());
            if lower.contains(')') {
                let issues = me.process_buffered_parm();
                me.clear_buffer();
                return issues;
            }
            return vec![];
        }
        if me.in_parm_block {
            me.parm_buffer_parts.push(lower.clone());
            if lower.contains(')') {
                let issues = me.process_buffered_parm();
                me.clear_buffer();
                return issues;
            }
        }
        vec![]
     },
}

impl RuleGx1_4_3 {
    fn process_buffered_parm(&mut self) -> Vec<Issue> {
        let start = match &self.start_line_obj {
            Some(s) => s.clone(),
            None => return vec![],
        };
        let buffer = self.parm_buffer_parts.join(" ");
        let m = match PARM_CONTENT_PATTERN.find(&buffer) {
            Some(m) => m,
            None => return vec![],
        };
        let inner = m.as_str().trim();
        if inner.is_empty() {
            return vec![];
        }
        let mut issues: Vec<Issue> = Vec::new();
        for param in inner.split(',') {
            let clean_param = param.trim();
            if clean_param.is_empty() {
                continue;
            }
            if has_direction(clean_param) {
                continue;
            }
            let display = match VARIABLE_ANY_PATTERN.find(clean_param) {
                Some(v) => v.as_str().to_string(),
                None => clean_param.to_string(),
            };
            issues.push(make_issue(
                self.id(),
                self.severity(),
                &start,
                self.current_file.as_deref(),
                Some(&format!(
                    "El parámetro '{display}' en la regla parm debe especificar explícitamente su dirección (In:, Out: o Inout:)."
                )),
            ));
        }
        issues
    }

    fn clear_buffer(&mut self) {
        self.in_parm_block = false;
        self.parm_buffer_parts.clear();
        self.start_line_obj = None;
    }
}
