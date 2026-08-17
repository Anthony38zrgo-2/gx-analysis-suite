#![allow(unused_imports)]
use crate::base::*;
use crate::helpers::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity};
use gx_core::regex_cache::*;
use std::path::Path;

const SEPARATOR_CHARS: &[char] = &['-', '_', '=', '*', '~', '.', '#', ' '];

define_rule! {
    id = "GX.1.7.2",
    name = "Comentario sobre cambios en filas",
    severity = Severity::Warning,
    description = "Cuando se comente una fila con // poner al final un comentario explicativo.",
    triggers = ["*"],
    abstract = false,
    struct RuleGx1_7_2 {},
    reset = |me: &mut RuleGx1_7_2, _file: &Path| {  },
    evaluate = |me: &mut RuleGx1_7_2, line: &ParsedLine, ctx: &AuditContext| {
        let stripped = &line.stripped;
        if stripped.is_empty() {
            return vec![];
        }
        if !stripped.starts_with("//") {
            return vec![];
        }
        let comment_content = stripped[2..].trim();
        if comment_content.is_empty() {
            return vec![make_issue(
                me.id(),
                me.severity(),
                line,
                me.current_file.as_deref(),
                Some("Línea de comentario vacía detectada. Si la fila está comentada, debe incluir una explicación justificativa real."),
            )];
        }
        let first_char = comment_content.chars().next().unwrap();
        if !SEPARATOR_CHARS.contains(&first_char) {
            return vec![];
        }
        for c in comment_content.chars() {
            if c != first_char && c != ' ' {
                return vec![];
            }
        }
        vec![make_issue(
            me.id(),
            me.severity(),
            line,
            me.current_file.as_deref(),
            Some("Uso incorrecto de comentarios como separadores estéticos puros. Las líneas comentadas deben aportar información explicativa sobre el cambio."),
        )]
     },
}
