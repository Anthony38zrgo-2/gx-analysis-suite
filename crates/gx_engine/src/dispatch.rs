//! Trigger tokens and their `ParsedLine` flag mappings.

use gx_core::models::ParsedLine;

/// Default trigger: rules with no triggers run on every non-empty line.
pub const DEFAULT_TRIGGER: &str = "*";

/// Map a trigger token to the `ParsedLine` boolean flag it requires.
pub type TriggerFn = fn(&ParsedLine) -> bool;

/// Whether a line carries the `&` (variable reference) token.
pub fn has_ampersand(l: &ParsedLine) -> bool {
    l.has_ampersand
}
/// Whether a line carries an `=` assignment.
pub fn has_equal(l: &ParsedLine) -> bool {
    l.has_equal
}
/// Whether a line carries a `where` clause.
pub fn has_where(l: &ParsedLine) -> bool {
    l.has_where
}
/// Whether a line carries a `for each`.
pub fn has_for_each(l: &ParsedLine) -> bool {
    l.has_for_each
}
/// Whether a line carries a `sub`.
pub fn has_sub(l: &ParsedLine) -> bool {
    l.has_sub
}
/// Whether a line carries an `if`.
pub fn has_if(l: &ParsedLine) -> bool {
    l.has_if
}
/// Whether a line carries a `case`.
pub fn has_case(l: &ParsedLine) -> bool {
    l.has_case
}
/// Whether a line carries a `do`.
pub fn has_do(l: &ParsedLine) -> bool {
    l.has_do
}

use std::collections::HashMap;
use std::sync::LazyLock;

/// Trigger token → flag predicate, mirroring `runtime.TRIGGER_MAP`.
pub static TRIGGER_MAP: LazyLock<HashMap<&'static str, TriggerFn>> = LazyLock::new(|| {
    let mut m: HashMap<&'static str, TriggerFn> = HashMap::new();
    m.insert("&", has_ampersand);
    m.insert("=", has_equal);
    m.insert("where", has_where);
    m.insert("for each", has_for_each);
    m.insert("sub", has_sub);
    m.insert("if", has_if);
    m.insert("case", has_case);
    m.insert("do", has_do);
    m
});
