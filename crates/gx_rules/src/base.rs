//! Rule trait, metadata macro and issue factory.
//!
//! Port of `gx_linter/app/rules/base.py`. Rules are stateful structs that
//! implement [`Rule`]; the engine drives them via
//! `reset` → `evaluate` (per candidate line) → `finalize`.
//!
//! The `define_rule!` macro emits the struct + the `Rule` impl. Rule bodies
//! are provided as closures so they can reference `me`/`line`/`ctx` freely
//! (a plain `expr`/`block` fragment would not resolve the method's own
//! `self`/`line`/`ctx` due to macro hygiene).

use std::path::{Path, PathBuf};

pub use gx_core::models::{AuditContext, Issue, ParsedLine, Severity, SourceLine};

/// Anything that exposes a line number + content (both `ParsedLine` and
/// `SourceLine` implement it), so `make_issue` can be called with either.
pub trait LineInfo {
    fn line_number(&self) -> u32;
    fn line_content(&self) -> &str;
}

impl LineInfo for ParsedLine {
    fn line_number(&self) -> u32 {
        self.number
    }
    fn line_content(&self) -> &str {
        &self.content
    }
}

impl LineInfo for SourceLine {
    fn line_number(&self) -> u32 {
        self.number
    }
    fn line_content(&self) -> &str {
        &self.content
    }
}

/// Build an `Issue` from the current rule and a `ParsedLine`/`SourceLine`.
pub fn make_issue(
    rule_id: &str,
    severity: Severity,
    line: &dyn LineInfo,
    file: Option<&Path>,
    override_desc: Option<&str>,
) -> Issue {
    Issue {
        rule_id: rule_id.to_string(),
        severity,
        line_number: line.line_number(),
        line_content: line.line_content().to_string(),
        description: override_desc.unwrap_or("").to_string(),
        file_path: file
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("Unknown")),
    }
}

/// The core rule contract.
pub trait Rule: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn severity(&self) -> Severity;
    fn description(&self) -> &'static str;
    /// Trigger tokens; empty ⇒ DEFAULT_TRIGGER (`*`).
    fn triggers(&self) -> &'static [&'static str] {
        &[]
    }
    fn is_abstract(&self) -> bool {
        false
    }
    fn reset(&mut self, file: &Path);
    fn evaluate(&mut self, line: &ParsedLine, ctx: &AuditContext) -> Vec<Issue>;
    fn finalize(&mut self, _ctx: &AuditContext) -> Vec<Issue> {
        vec![]
    }
}

/// Define a rule struct + `Rule` implementation with minimal boilerplate.
///
/// `reset` / `evaluate` / `finalize` are closures:
/// `|me: &mut Self, file: &Path| -> ()`, `|me, line, ctx| -> Vec<Issue>`, etc.
#[macro_export]
macro_rules! define_rule {
    (
        id = $rid:literal,
        name = $rname:literal,
        severity = $sev:expr,
        description = $desc:literal,
        triggers = [$($trig:literal),* $(,)?],
        abstract = $abs:expr,
        struct $name:ident { $($field:ident : $fty:ty),* $(,)? },
        reset = $reset:expr,
        evaluate = $eval:expr
        $(, finalize = $fin:expr)?
        $(,)?
    ) => {
        #[derive(Default)]
        pub struct $name {
            current_file: Option<::std::path::PathBuf>,
            $($field : $fty),*
        }

        impl $name {
            #[allow(dead_code)]
            pub fn new() -> Self {
                Self {
                    current_file: None,
                    $($field : Default::default()),*
                }
            }
        }

        impl $crate::base::Rule for $name {
            fn id(&self) -> &'static str { $rid }
            fn name(&self) -> &'static str { $rname }
            fn severity(&self) -> $crate::base::Severity { $sev }
            fn description(&self) -> &'static str { $desc }
            fn triggers(&self) -> &'static [&'static str] { &[$($trig),*] }
            fn is_abstract(&self) -> bool { $abs }

            fn reset(&mut self, file: &::std::path::Path) {
                self.current_file = Some(file.to_path_buf());
                ($reset)(self, file);
            }

            #[allow(unused_variables)]
            fn evaluate(&mut self, line: &$crate::base::ParsedLine, ctx: &$crate::base::AuditContext) -> ::std::vec::Vec<$crate::base::Issue> {
                ($eval)(self, line, ctx)
            }

            #[allow(unused_variables, unreachable_code)]
            fn finalize(&mut self, ctx: &$crate::base::AuditContext) -> ::std::vec::Vec<$crate::base::Issue> {
                $( return ($fin)(self, ctx); )?
                ::std::vec::Vec::new()
            }
        }
    };
}
