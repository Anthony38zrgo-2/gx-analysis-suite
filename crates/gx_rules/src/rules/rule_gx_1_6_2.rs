#![allow(unused_imports)]
use crate::base::*;
use crate::helpers::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity, SourceLine};
use gx_core::regex_cache::*;
use std::path::Path;

define_rule! {
    id = "GX.1.6.2",
    name = "Describir la Sub Rutina",
    severity = Severity::Warning,
    description = "En la subrutina Sub en la siguiente fila poner un Comentario de Descripción.",
    triggers = ["sub"],
    abstract = false,
    struct RuleGx1_6_2 {
        awaiting_description: bool,
        sub_declaration_line: Option<SourceLine>,
    },
    reset = |me: &mut RuleGx1_6_2, _file: &Path| {
        me.awaiting_description = false;
        me.sub_declaration_line = None;
     },
    evaluate = |me: &mut RuleGx1_6_2, line: &ParsedLine, ctx: &AuditContext| {
        let stripped = &line.stripped;
        if stripped.is_empty() {
            return vec![];
        }
        let is_comment = stripped.starts_with("//") || stripped.starts_with("/*");
        if me.awaiting_description {
            me.awaiting_description = false;
            if !is_comment {
                if let Some(decl) = &me.sub_declaration_line {
                    let issue = make_issue(
                        me.id(),
                        me.severity(),
                        decl,
                        me.current_file.as_deref(),
                        Some(&format!(
                            "La Subrutina declarada en la línea {} debe contener un comentario descriptivo en su primera línea interna ejecutable.",
                            decl.number
                        )),
                    );
                    me.sub_declaration_line = None;
                    return vec![issue];
                }
            }
            me.sub_declaration_line = None;
        }
        let lower = &line.lower;
        if !lower.starts_with("sub") {
            return vec![];
        }
        if lower != "sub" && !lower.starts_with("sub ") {
            return vec![];
        }
        let sub_name = if stripped.len() > 3 { stripped[3..].trim().to_string() } else { String::new() };
        let normalized = normalize_subroutine_name(&sub_name);
        if normalized == "gu: op -> cancelar" {
            me.awaiting_description = false;
            me.sub_declaration_line = None;
            return vec![];
        }
        me.awaiting_description = true;
        me.sub_declaration_line = Some(line.to_source_line());
        vec![]
     },
}
