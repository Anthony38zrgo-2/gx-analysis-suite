#![allow(unused_imports)]
use crate::base::*;
use crate::helpers::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity};
use gx_core::regex_cache::*;
use std::collections::HashSet;
use std::path::Path;

const KEYWORDS: &[&str] = &[
    "if",
    "case",
    "and",
    "or",
    "not",
    "null",
    "nullvalue",
    "like",
    "in",
    "true",
    "false",
    "do",
    "otherwise",
    "empty",
    "isempty",
    "isvalid",
    "udp",
    "new",
    "rows",
    "count",
];

define_rule! {
    id = "GX.1.4.2",
    name = "Definición",
    severity = Severity::Warning,
    description = "En sentencias de decisión (If, Case) se debe usar variables, no debe usarse atributos.",
    triggers = ["if", "case"],
    abstract = false,
    struct RuleGx1_4_2 {},
    reset = |me: &mut RuleGx1_4_2, _file: &Path| {  },
    evaluate = |me: &mut RuleGx1_4_2, line: &ParsedLine, ctx: &AuditContext| {
        if !line.has_if && !line.has_case {
            return vec![];
        }
        let lower = &line.clean_lower;
        if !(starts_with_kw(lower, "if") || starts_with_kw(lower, "case")) {
            return vec![];
        }
        let clean = &line.clean;
        if starts_with_kw(lower, "if &") || starts_with_kw(lower, "if(&")
            || starts_with_kw(lower, "case &") || starts_with_kw(lower, "case(&")
        {
            return vec![];
        }
        let mut detected: HashSet<String> = HashSet::new();
        for m in WORD_PATTERN.captures_iter(clean) {
            let word = m.get(0).unwrap().as_str();
            let word_lower = word.to_lowercase();
            if KEYWORDS.contains(&word_lower.as_str()) {
                continue;
            }
            let start = m.get(0).unwrap().start();
            if start > 0 {
                let prev = clean.as_bytes()[start - 1] as char;
                if prev == '&' || prev == '.' {
                    continue;
                }
            }
            if word.chars().next().unwrap().is_uppercase() {
                detected.insert(word.to_string());
            }
        }
        if detected.is_empty() {
            return vec![];
        }
        let sorted: Vec<&String> = detected.iter().collect();
        vec![make_issue(
            me.id(),
            me.severity(),
            line,
            me.current_file.as_deref(),
            Some(&format!(
                "En sentencias de decisión se deben usar variables locales, no atributos directos de tablas como: {}.",
                sorted.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            )),
        )]
     },
}
