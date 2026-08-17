//! Shared helpers consolidated from the Python rule files.

use regex::Regex;
use std::sync::LazyLock;

/// Keywords that signal the WHERE block has ended (shared by 2.1/2.2/2.4/2.5).
pub const BODY_KEYWORDS: &[&str] = &[
    "if",
    "do",
    "msg",
    "for",
    "while",
    "return",
    "new",
    "call",
    "sub",
    "endsub",
    "endfor",
    "endif",
    "else",
    "elseif",
    "do case",
    "case",
    "otherwise",
    "endcase",
];

const COMPARISON_OPS: &[&str] = &["==", "!=", "<=", ">="];

/// Return true if `lower` looks like a WHERE continuation line.
pub fn is_where_continuation(lower: &str) -> bool {
    if lower.is_empty() {
        return true;
    }
    if lower.starts_with("//") || lower.starts_with("/*") {
        return true;
    }
    for kw in BODY_KEYWORDS {
        if lower == *kw || lower.starts_with(&format!("{kw} ")) {
            return false;
        }
    }
    if lower.contains('=') && !COMPARISON_OPS.iter().any(|op| lower.contains(*op)) {
        if !lower.is_empty()
            && (lower.starts_with('_')
                || lower.starts_with('&')
                || lower.chars().next().unwrap().is_alphabetic())
        {
            return false;
        }
    }
    true
}

/// Remove the AND belonging to a BETWEEN clause (no regex).
pub fn remove_between_and(text: &str) -> String {
    if let Some(pos) = text.find("between") {
        if let Some(and_pos) = text[pos..].find(" and ") {
            return format!("{}{}", &text[..pos], &text[pos + and_pos + 5..]);
        }
    }
    text.to_string()
}

/// Normalize a subroutine name written with or without quotes.
pub fn normalize_subroutine_name(name: &str) -> String {
    let mut normalized = name.trim().trim_end_matches(';').trim().to_string();
    let chars: Vec<char> = normalized.chars().collect();
    if chars.len() >= 2
        && chars[0] == chars[chars.len() - 1]
        && (chars[0] == '\'' || chars[0] == '"')
    {
        normalized = normalized[1..normalized.len() - 1].trim().to_string();
    }
    let mut out = String::new();
    for word in normalized.to_lowercase().split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    out
}

static DO_CALL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)(?:^|\s)do\s+('[^']+'|"[^"]+"|[^\s]+)"#).unwrap());

/// Get the called subroutine name from a DO line, if identifiable.
pub fn get_called_subroutine(stripped: &str) -> String {
    match DO_CALL_RE.captures(stripped) {
        Some(c) => normalize_subroutine_name(c.get(1).unwrap().as_str()),
        None => String::new(),
    }
}

/// Match `in:`/`out:`/`inout:` at the start of a parameter.
pub fn has_direction(token: &str) -> bool {
    let t = token.trim();
    t.len() >= 2 && (t.starts_with("in:") || t.starts_with("out:") || t.starts_with("inout:"))
}

/// True when `lower` equals `kw` or starts with `kw ` (word-boundary prefix).
pub fn starts_with_kw(lower: &str, kw: &str) -> bool {
    lower == kw || lower.starts_with(&format!("{kw} "))
}
