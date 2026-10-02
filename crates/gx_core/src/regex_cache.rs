//! Patrones regex centralizados (compilados una sola vez con LazyLock).
//! Equivalente a `gx_linter/app/core/regex_cache.py`.
//!
//! Regla: NINGÚN otro módulo debe hacer `Regex::new`. Usar estos patrones
//! o los helpers de aquí.

use std::sync::LazyLock;

use regex::{Regex, RegexBuilder};

/// Borra strings y comentarios de UNA línea (usado por `ParsedLine::from_source`).
///
/// GX-008 (adjudicado): `/\*[\s\S]*?\*/` permite bloques `/* */` de una
/// línea; los bloques multilínea se enmascaran aparte con
/// [`blank_multiline_block_comments`] (el Python original no los borra y
/// linteaba código deshabilitado). El orden de alternativas prioriza
/// strings antes que comentarios.
pub static STRING_COMMENT_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    RegexBuilder::new(r#""[^"]*"|'[^']*'|/\*[\s\S]*?\*/|//.*$"#)
        .multi_line(true)
        .build()
        .unwrap()
});

/// Enmascara bloques `/* ... */` MULTILÍNEA preservando los saltos de
/// línea, para que el linteo por línea no vea el código deshabilitado y
/// los números de línea no se desplacen (GX-008).
///
/// Un bloque sin `*/` de cierre queda intacto (exclusión documentada).
pub fn blank_multiline_block_comments(text: &str) -> String {
    BLOCK_COMMENT_PATTERN
        .replace_all(text, |caps: &regex::Captures| {
            let whole = caps.get(0).map(|m| m.as_str()).unwrap_or("");
            "\n".repeat(whole.matches('\n').count())
        })
        .to_string()
}

/// Bloques `/* ... */` que cruzan saltos de línea (solo multilínea).
static BLOCK_COMMENT_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| RegexBuilder::new(r"/\*[\s\S]*?\*/").build().unwrap());

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
    fn block_comments_multiline_are_masked_with_structure() {
        // GX-008: el helper enmascara bloques multilínea preservando la
        // estructura de líneas (por línea no se ve el bloque completo).
        let src = "linea\n/* bloque\nfor each Customer2\n&i = &i + 1\nendfor\n*/\n&Ok = 1";
        let masked = blank_multiline_block_comments(src);
        let lines: Vec<&str> = masked.split('\n').collect();
        assert_eq!(lines.len(), 7, "la estructura de líneas se preserva");
        for l in &lines[1..6] {
            assert!(
                l.trim().is_empty(),
                "línea del bloque debe quedar vacía: {l:?}"
            );
        }
        assert_eq!(lines[0], "linea");
        assert_eq!(lines[6], "&Ok = 1");
    }

    #[test]
    fn has_logical_operator_lookbehind_emulation() {
        assert!(has_logical_operator("a and b"));
        assert!(!has_logical_operator("&and = 5"));
        assert!(has_logical_operator("or x"));
    }
}
