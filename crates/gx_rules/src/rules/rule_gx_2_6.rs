#![allow(unused_imports)]
use crate::base::*;
use crate::helpers::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity, SourceLine};
use gx_core::regex_cache::*;
use std::path::Path;

const EXCLUDED_SUBROUTINES: &[&str] = &["gu: op -> cancelar"];

fn normalize_subroutine_name(name: &str) -> String {
    let normalized = name.trim().trim_end_matches(';').trim().to_string();
    if normalized.len() >= 2 {
        let first = normalized.chars().next().unwrap();
        let last = normalized.chars().last().unwrap();
        if first == last && (first == '\'' || first == '"') {
            return normalized[1..normalized.len() - 1]
                .trim()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
        }
    }
    normalized.split_whitespace().collect::<Vec<_>>().join(" ")
}

define_rule! {
    id = "GX.2.6",
    name = "Subrutinas",
    severity = Severity::Error,
    description = "Se debe iniciar siempre la variable de salida y una buena práctica es con la palabra clave 'nullvalue'.",
    triggers = ["sub"],
    abstract = false,
    struct RuleGx2_6 {
        in_sub: bool,
        skip_current_sub: bool,
        sub_declaration_line: Option<SourceLine>,
        sub_name: String,
        has_nullvalue_initialization: bool,
    },
    reset = |me: &mut RuleGx2_6, _file: &Path| {
        me.in_sub = false;
        me.skip_current_sub = false;
        me.sub_declaration_line = None;
        me.sub_name = String::new();
        me.has_nullvalue_initialization = false;
     },
    evaluate = |me: &mut RuleGx2_6, line: &ParsedLine, ctx: &AuditContext| {
        let stripped = &line.stripped;
        let lower_line = &line.lower;

        if stripped.is_empty() {
            return vec![];
        }

        if *lower_line == "sub" || lower_line.starts_with("sub ") {
            me.in_sub = true;
            me.sub_declaration_line = Some(line.source.clone());
            me.has_nullvalue_initialization = false;
            me.sub_name = if stripped.len() > 3 {
                stripped[3..].trim().to_string()
            } else {
                String::new()
            };
            let normalized_name = normalize_subroutine_name(&me.sub_name);
            me.skip_current_sub = EXCLUDED_SUBROUTINES.contains(&normalized_name.as_str());
            return vec![];
        }

        if !me.in_sub {
            return vec![];
        }

        if *lower_line == "endsub" || lower_line.starts_with("endsub ") {
            if me.skip_current_sub {
                me.sub_declaration_line = None;
                me.in_sub = false;
                me.skip_current_sub = false;
                me.sub_name = String::new();
                me.has_nullvalue_initialization = false;
                return vec![];
            }
            if !me.has_nullvalue_initialization && me.sub_declaration_line.is_some() {
                let decl_line = ParsedLine::from_source(
                    me.sub_declaration_line.clone().unwrap(),
                );
                let sub_name = me.sub_name.clone();
                me.sub_declaration_line = None;
                me.in_sub = false;
                me.skip_current_sub = false;
                me.sub_name = String::new();
                me.has_nullvalue_initialization = false;
                return vec![make_issue(
                    me.id(),
                    me.severity(),
                    &decl_line,
                    me.current_file.as_deref(),
                    Some(&format!(
                        "Mala práctica crítica en Subrutina {sub_name}: \
                         No se detectó ninguna inicialización de variable de \
                         salida/control. Se exige por política corporativa \
                         inicializar las variables de retorno usando la \
                         función 'nullvalue()' en las primeras líneas del bloque."
                    )),
                )];
            }
            me.sub_declaration_line = None;
            me.in_sub = false;
            me.skip_current_sub = false;
            me.sub_name = String::new();
            me.has_nullvalue_initialization = false;
            return vec![];
        }

        if me.skip_current_sub {
            return vec![];
        }

        let clean_lower = &line.clean_lower;
        if clean_lower.contains("nullvalue(")
            && clean_lower.contains('=')
            && clean_lower.contains('&')
        {
            let left_side = clean_lower.split_once('=').map(|(l, _)| l).unwrap_or(clean_lower);
            if left_side.contains('&') {
                me.has_nullvalue_initialization = true;
            }
        }
        vec![]
     },
}
