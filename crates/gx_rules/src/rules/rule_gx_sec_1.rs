#![allow(unused_imports)]
//! GX.SEC.1 (D03): credenciales en literales asignados a variables sensibles.
//!
//! Evidencia de patrón (lexical/sintáctica) de alta confianza: la categoría
//! "security" se evalúa aparte de la política de estilo y la evidencia se
//! REDACT (el valor secreto nunca sale en el hallazgo).
//!
//! Deshabilitada por defecto: requiere hechos semánticos y sólo corre cuando
//! el perfil de seguridad se habilita explícitamente.

use crate::base::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity};
use gx_core::semantics::{StatementKind, TokenKind};
use std::collections::HashMap;
use std::path::Path;

/// Nombres sensibles exactos (sin `&`).
const SENSITIVE_EXACT: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "clave",
    "secret",
    "token",
    "apikey",
    "api_key",
    "accesskey",
    "client_secret",
];

/// Sufijos sensibles: cubre `&dbPassword`, `&authToken`, etc.
const SENSITIVE_SUFFIXES: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "accesskey",
    "clave",
];

/// Valores que no son secretos reales (placeholders de ejemplo).
const PLACEHOLDERS: &[&str] = &[
    "***",
    "xxx",
    "xxxx",
    "changeme",
    "example",
    "placeholder",
    "todo",
    "secret",
    "password",
];

fn is_sensitive(name_with_ampersand: &str) -> bool {
    let name = name_with_ampersand.trim_start_matches('&').to_lowercase();
    if SENSITIVE_EXACT.contains(&name.as_str()) {
        return true;
    }
    SENSITIVE_SUFFIXES
        .iter()
        .any(|suffix| name.ends_with(suffix))
}

fn is_placeholder(value: &str) -> bool {
    let value = value.trim().to_lowercase();
    value.is_empty() || PLACEHOLDERS.contains(&value.as_str())
}

fn redact(line: &str, literal: &str) -> String {
    let quote = literal.chars().next().unwrap_or('\'');
    let redacted = format!("{quote}***{quote}");
    line.replace(literal, &redacted)
}

define_rule! {
    id = "GX.SEC.1",
    name = "Credenciales en código",
    severity = Severity::Error,
    description = "Credenciales o secretos embebidos en literales (CWE-798).",
    triggers = [],
    abstract = false,
    route = object,
    version = "1.0",
    category = "security",
    scope = object,
    facts = [syntax],
    cost = moderate,
    struct RuleGxSec1 {},
    reset = |_me: &mut RuleGxSec1, _file: &Path| {},
    evaluate = |_me: &mut RuleGxSec1, _line: &ParsedLine, _ctx: &AuditContext| vec![],
    analyze = |me: &mut RuleGxSec1, facts: &ObjectFacts, _ctx: &AuditContext| {
        let Some(model) = facts.model else {
            return vec![];
        };
        let line_kind: HashMap<u32, StatementKind> = model
            .statements
            .iter()
            .map(|statement| (statement.line, statement.kind))
            .collect();
        let mut by_line: HashMap<u32, Vec<&gx_core::semantics::Token>> = HashMap::new();
        for token in &model.tokens {
            by_line.entry(token.line).or_default().push(token);
        }

        let raw_lines: Vec<&str> = facts.text.split('\n').collect();
        let mut issues: Vec<Issue> = Vec::new();
        let mut lines: Vec<u32> = by_line.keys().copied().collect();
        lines.sort_unstable();
        for line in lines {
            if line_kind.get(&line) != Some(&StatementKind::Assignment) {
                continue;
            }
            let tokens = &by_line[&line];
            for (index, token) in tokens.iter().enumerate() {
                if token.kind != TokenKind::Variable || !is_sensitive(&token.text) {
                    continue;
                }
                // Debe haber un `=` de asignación después de la variable.
                let Some(equals) = tokens[index + 1..]
                    .iter()
                    .position(|t| t.kind == TokenKind::Operator && t.text == "=")
                else {
                    continue;
                };
                let after = &tokens[index + 1 + equals + 1..];
                let Some(literal) = after.iter().find(|t| t.kind == TokenKind::String) else {
                    continue;
                };
                let Some(value) = literal.string_value() else {
                    continue;
                };
                if is_placeholder(&value) {
                    continue;
                }
                let raw = raw_lines
                    .get(line.saturating_sub(1) as usize)
                    .copied()
                    .unwrap_or_default()
                    .trim_end_matches('\r');
                issues.push(Issue {
                    rule_id: me.id().to_string(),
                    severity: me.severity(),
                    line_number: line,
                    line_content: redact(raw, &literal.text),
                    description: format!(
                        "Se detectó un valor sensible embebido en '{}' (patrón de credencial, CWE-798). \
                         Parametrizar desde configuración segura y rotar el secreto.",
                        token.text
                    ),
                    file_path: me
                        .current_file
                        .clone()
                        .unwrap_or_else(|| std::path::PathBuf::from("Unknown")),
                    object: None,
                    category: Some("security".to_string()),
                    confidence: Some("high".to_string()),
                    cwe: Some(798),
                });
            }
        }
        issues
    },
}
