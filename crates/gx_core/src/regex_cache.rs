//! Patrones regex centralizados (compilados una sola vez con LazyLock).
//! Equivalente a `gx_linter/app/core/regex_cache.py`.
//!
//! Regla: NINGÚN otro módulo debe hacer `Regex::new`. Usar estos patrones
//! o los helpers de aquí.

use std::sync::LazyLock;

use regex::{Regex, RegexBuilder};

/// Borra strings y comentarios. Usado por `ParsedLine::from_source`.
pub static STRING_COMMENT_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    RegexBuilder::new(r#""[^"]*"|'[^']*'|//.*$|/\*.*?\*/"#)
        .multi_line(true)
        .build()
        .unwrap()
});

/// `&variableName` con primera letra minúscula (violación).
pub static VARIABLE_LOWERCASE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"&([a-z][a-zA-Z0-9_]*)\b").unwrap());

/// Cualquier referencia `&variable`.
pub static VARIABLE_ANY_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"&([a-zA-Z0-9_]+)").unwrap());

/// Operadores lógicos and/or (SIN lookbehind; ver `has_logical_operator`).
pub static LOGICAL_OPERATOR_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:and|or)\b").unwrap());

/// Token de llamada a función: `palabra(`.
pub static FUNCTION_CALL_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([a-zA-Z0-9_]+)\s*\(").unwrap());

/// `parm(` o `parm (`.
pub static PARM_START_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bparm\s*\(").unwrap());

/// Contenido de `parm(...)` (multilínea).
pub static PARM_CONTENT_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    RegexBuilder::new(r"(?i)parm\s*\((.*?)\)")
        .dot_matches_new_line(true)
        .build()
        .unwrap()
});

/// `&Var =` (asignación lado izquierdo).
pub static ASSIGN_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"&([a-zA-Z0-9_]+)\s*=").unwrap());

/// Identificadores simples.
pub static WORD_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[a-zA-Z][a-zA-Z0-9_]*\b").unwrap());

/// Dirección de parámetro `in:` / `out:` / `inout:`.
pub static DIRECTION_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^(in|out|inout)\s*:").unwrap());

/// Variable de iteración `&x`.
pub static LOOP_VARIABLE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)&[a-zA-Z_][a-zA-Z0-9_]*").unwrap());

/// Nombre de subrutina llamada con `do`.
pub static DO_NAME_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)(?:^|\s)do\s+(?P<name>'[^']+'|"[^"]+"|[^\s]+)"#).unwrap());

/// Valor en código duro dentro de una cláusula WHERE.
/// Grupo 2 = literal detectado.
pub static HARDCODE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)(?:=|!=|<|>|<=|>=|like)\s*(\d+|'[^']*'|"[^"]*")"#).unwrap());

/// Equivalente funcional a `(?<!&)\b(?:and|or)\b` (Rust no soporta lookbehind).
/// Devuelve true si hay un `and`/`or` no precedido por `&`.
pub fn has_logical_operator(clean_lower: &str) -> bool {
    for m in LOGICAL_OPERATOR_PATTERN.find_iter(clean_lower) {
        let start = m.start();
        if start == 0 || clean_lower.as_bytes()[start - 1] != b'&' {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_comment_pattern_strips() {
        let s = STRING_COMMENT_PATTERN.replace_all(r#"a = "x // y" // c"#, "");
        assert!(!s.contains("x // y"));
        assert!(!s.contains("// c"));
        assert!(s.contains('='));
    }

    #[test]
    fn has_logical_operator_lookbehind_emulation() {
        assert!(has_logical_operator("a and b"));
        assert!(!has_logical_operator("&and = 5"));
        assert!(has_logical_operator("or x"));
    }
}
