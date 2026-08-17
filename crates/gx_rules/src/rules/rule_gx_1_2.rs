#![allow(unused_imports)]
use crate::base::*;
use crate::helpers::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity};
use gx_core::regex_cache::*;
use std::path::Path;

const START_KEYWORDS: &[&str] = &["for each", "if", "case", "do while", "sub"];
const END_KEYWORDS: &[&str] = &["endfor", "endif", "endcase", "enddo", "endsub"];

define_rule! {
    id = "GX.1.2",
    name = "Indentar código",
    severity = Severity::Warning,
    description = "Indentar línea de código en uso de For each, If Then Else, Case.",
    triggers = ["*"],
    abstract = false,
    struct RuleGx1_2 {
        depth: i32,
    },
    reset = |me: &mut RuleGx1_2, _file: &Path| {  me.depth = 0;  },
    evaluate = |me: &mut RuleGx1_2, line: &ParsedLine, ctx: &AuditContext| {
        let clean = &line.clean;
        if clean.is_empty() {
            return vec![];
        }
        let lower = &line.clean_lower;
        if lower.is_empty() {
            return vec![];
        }
        let leading_spaces = line.raw.len() - line.raw.trim_start().len();
        let is_end = END_KEYWORDS.iter().any(|k| starts_with_kw(lower, k));
        let current_expected_depth = if is_end && me.depth > 0 {
            me.depth - 1
        } else {
            me.depth
        };
        let mut issues: Vec<Issue> = Vec::new();
        if current_expected_depth > 0 {
            let expected_spaces = current_expected_depth * 4;
            if (leading_spaces as i32) < expected_spaces {
                issues.push(make_issue(
                    me.id(),
                    me.severity(),
                    line,
                    me.current_file.as_deref(),
                    Some(&format!(
                        "Indentación incorrecta: se esperaban al menos {expected_spaces} espacios (nivel {current_expected_depth}), se encontraron {leading_spaces}."
                    )),
                ));
            }
        }
        if is_end {
            me.depth = me.depth.max(0) - 1;
            if me.depth < 0 {
                me.depth = 0;
            }
        } else if START_KEYWORDS.iter().any(|k| starts_with_kw(lower, k)) {
            me.depth += 1;
        }
        issues
     },
}
