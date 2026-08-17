#![allow(unused_imports)]
use crate::base::*;
use crate::helpers::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity};
use gx_core::regex_cache::*;
use std::path::Path;

define_rule! {
    id = "GX.1.6.1",
    name = "Comentario en el llamado a Sub Rutinas",
    severity = Severity::Warning,
    description = "Antes del llamado con DO poner un comentario.",
    triggers = ["do"],
    abstract = false,
    struct RuleGx1_6_1 {
        last_active_line_was_comment: bool,
    },
    reset = |me: &mut RuleGx1_6_1, _file: &Path| {  me.last_active_line_was_comment = false;  },
    evaluate = |me: &mut RuleGx1_6_1, line: &ParsedLine, ctx: &AuditContext| {
        let stripped = &line.stripped;
        if stripped.is_empty() {
            return vec![];
        }
        if stripped.starts_with("//") || stripped.starts_with("/*") {
            me.last_active_line_was_comment = true;
            return vec![];
        }
        let lower = &line.lower;
        if !lower.contains("do") {
            me.last_active_line_was_comment = false;
            return vec![];
        }
        let tokens: Vec<&str> = lower.split_whitespace().collect();
        if tokens.is_empty() {
            me.last_active_line_was_comment = false;
            return vec![];
        }
        let mut is_do_call = false;
        for (idx, token) in tokens.iter().enumerate() {
            if *token != "do" {
                continue;
            }
            if idx > 0 && tokens[idx - 1].ends_with('&') {
                continue;
            }
            let next = tokens.get(idx + 1).copied().unwrap_or("");
            if next == "while" || next == "case" {
                continue;
            }
            is_do_call = true;
            break;
        }
        if !is_do_call {
            me.last_active_line_was_comment = false;
            return vec![];
        }
        let called = get_called_subroutine(stripped);
        if called == "gu: op -> cancelar" {
            me.last_active_line_was_comment = false;
            return vec![];
        }
        me.last_active_line_was_comment = false;
        if !me.last_active_line_was_comment {
            return vec![make_issue(
                me.id(),
                me.severity(),
                line,
                me.current_file.as_deref(),
                Some("Falta un comentario explicativo en la línea superior inmediata antes del llamado a la Subrutina (DO)."),
            )];
        }
        vec![]
     },
}
