#![allow(unused_imports)]
use crate::base::*;
use crate::helpers::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity, SourceLine};
use gx_core::regex_cache::*;
use std::path::Path;

const SAFE_TRIVIAL_VALUES: &[&str] = &["0", "''", "\"\"", "true", "false", "null", "nullvalue"];

define_rule! {
    id = "GX.2.5",
    name = "Variables con código en duro",
    severity = Severity::Error,
    description = "No Asignar variables en código duro dentro del Where.",
    triggers = ["where", "for each"],
    abstract = false,
    struct RuleGx2_5 {
        in_for_each: bool,
        active_where_line: Option<SourceLine>,
    },
    reset = |me: &mut RuleGx2_5, _file: &Path| {
        me.in_for_each = false;
        me.active_where_line = None;
     },
    evaluate = |me: &mut RuleGx2_5, line: &ParsedLine, ctx: &AuditContext| {
        let lower = &line.clean_lower;
        if lower.is_empty() {
            return vec![];
        }
        if !me.in_for_each && !line.has_for_each {
            return vec![];
        }
        if starts_with_kw(lower, "for each") {
            me.in_for_each = true;
            me.active_where_line = None;
            return vec![];
        }
        if starts_with_kw(lower, "endfor") {
            me.in_for_each = false;
            me.active_where_line = None;
            return vec![];
        }
        if !me.in_for_each {
            return vec![];
        }
        if starts_with_kw(lower, "where") {
            me.active_where_line = Some(line.source.clone());
        } else if starts_with_kw(lower, "defined by") || starts_with_kw(lower, "order") {
            me.active_where_line = None;
        } else if me.active_where_line.is_some() && !is_where_continuation(lower) {
            me.active_where_line = None;
        }
        if me.active_where_line.is_none() {
            return vec![];
        }
        let mut scan_target = lower.clone();
        if let Some(rest) = scan_target.strip_prefix("where") {
            scan_target = rest.trim().to_string();
        }
        let mut issues: Vec<Issue> = Vec::new();
        if let Some(m) = HARDCODE_PATTERN.captures(&scan_target) {
            // El valor es el único grupo del patrón consolidado; el Python
            // original usaba group(2) de un regex local con el operador
            // capturado aparte (rule_gx_2_5.py:138).
            let literal = m.get(1).unwrap().as_str().trim().to_string();
            if !SAFE_TRIVIAL_VALUES.contains(&literal.as_str()) {
                let where_line_num = me.active_where_line.as_ref().unwrap().number;
                issues.push(make_issue(
                    me.id(),
                    me.severity(),
                    line,
                    me.current_file.as_deref(),
                    Some(&format!(
                        "Mala práctica de mantenibilidad: Se detectó un valor en código duro (Hardcoded) '{literal}' dentro de la cláusula WHERE (Bloque de la línea {where_line_num}). Se exige parametrizar este valor mediante una variable local antes del For Each."
                    )),
                ));
                me.active_where_line = None;
            }
        }
        issues
     },
}
