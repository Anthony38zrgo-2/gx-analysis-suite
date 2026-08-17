#![allow(unused_imports)]
use crate::base::*;
use crate::helpers::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity};
use gx_core::regex_cache::*;
use std::collections::HashSet;
use std::path::Path;

define_rule! {
    id = "GX.2.3",
    name = "For Each anidados",
    severity = Severity::Error,
    description = "Evitar For Each / End For solo se permite dos anidaciones.",
    triggers = [],
    abstract = false,
    struct RuleGx2_3 {
        for_each_stack: Vec<u32>,
        reported_depths: HashSet<u32>,
    },
    reset = |me: &mut RuleGx2_3, _file: &Path| {
        me.for_each_stack = Vec::new();
        me.reported_depths = HashSet::new();
     },
    evaluate = |me: &mut RuleGx2_3, line: &ParsedLine, ctx: &AuditContext| {
        let normalized: Vec<&str> = line.clean_lower.split_whitespace().collect();
        let normalized = normalized.join(" ");
        if normalized.is_empty() {
            return vec![];
        }
        if starts_with_kw(&normalized, "for each") {
            return me.handle_for_each(line);
        }
        if starts_with_kw(&normalized, "endfor") || starts_with_kw(&normalized, "end for") {
            me.handle_end_for();
        }
        vec![]
     },
}

impl RuleGx2_3 {
    const MAX_DEPTH: u32 = 2;

    fn handle_for_each(&mut self, line: &ParsedLine) -> Vec<Issue> {
        self.for_each_stack.push(line.number);
        let depth = self.for_each_stack.len() as u32;
        if depth <= Self::MAX_DEPTH || self.reported_depths.contains(&depth) {
            return vec![];
        }
        self.reported_depths.insert(depth);
        vec![make_issue(
            self.id(),
            self.severity(),
            line,
            self.current_file.as_deref(),
            Some(&format!(
                "Mala práctica de rendimiento: Se ha excedido el límite máximo de {} niveles de For Each anidados de forma concurrente (Detectado nivel de anidación: {depth}). Optimice el diseño usando Data Providers, Subrutinas o unificando las consultas.",
                Self::MAX_DEPTH
            )),
        )]
    }

    fn handle_end_for(&mut self) {
        if self.for_each_stack.is_empty() {
            return;
        }
        self.for_each_stack.pop();
        let current_depth = self.for_each_stack.len() as u32;
        self.reported_depths.retain(|d| *d <= current_depth);
    }
}
