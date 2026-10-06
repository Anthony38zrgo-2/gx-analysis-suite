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

impl LineInfo for ParsedLine<'_> {
    fn line_number(&self) -> u32 {
        self.number
    }
    fn line_content(&self) -> &str {
        self.content
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
        object: None,
    }
}

/// How the engine selects the lines a rule must evaluate (GX-004).
///
/// `AllLines` is required by stateful rules whose logic needs to observe
/// continuation lines, bodies or comments (where/defined by/endfor,
/// otherwise, sub bodies, parm continuations, DO-comment tracking, …).
/// `Tokens` is valid ONLY for rules whose `evaluate` guards on exactly the
/// trigger flags — in that case the route is a pure optimization and its
/// results are identical to `AllLines` (covered by an equivalence test).
#[derive(Debug, Clone, Copy)]
pub enum DispatchRoute {
    AllLines,
    Tokens(&'static [&'static str]),
}

/// Descriptor inmutable de una regla (B02).
///
/// Reemplaza a `all_rules()` como fuente de metadatos: el catálogo es estático
/// y sólo se instancian (vía `factory`) las reglas seleccionadas.
pub struct RuleDescriptor {
    pub id: &'static str,
    pub name: &'static str,
    pub severity: Severity,
    pub description: &'static str,
    pub triggers: &'static [&'static str],
    pub is_abstract: bool,
    /// `Some(tokens)` ⇒ ruta `Tokens`; `None` ⇒ `AllLines`.
    pub tokens_route: Option<&'static [&'static str]>,
    pub factory: fn() -> Box<dyn Rule>,
}

impl RuleDescriptor {
    /// Ruta de despacho declarada por la regla.
    pub fn dispatch_route(&self) -> DispatchRoute {
        match self.tokens_route {
            Some(tokens) => DispatchRoute::Tokens(tokens),
            None => DispatchRoute::AllLines,
        }
    }
}

/// The core rule contract.
pub trait Rule: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn severity(&self) -> Severity;
    fn description(&self) -> &'static str;
    /// Trigger tokens; empty ⇒ DEFAULT_TRIGGER (`*`).
    ///
    /// This is METADATA (catalog/seed parity with the Python rule files);
    /// the actual line selection is [`Rule::dispatch_route`].
    fn triggers(&self) -> &'static [&'static str] {
        &[]
    }
    /// Line-selection route used by the engine's dispatch plan.
    fn dispatch_route(&self) -> DispatchRoute {
        DispatchRoute::AllLines
    }
    fn is_abstract(&self) -> bool {
        false
    }
    fn reset(&mut self, file: &Path);
    fn evaluate(&mut self, line: &ParsedLine<'_>, ctx: &AuditContext) -> Vec<Issue>;
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
    // Rutas internas del descriptor (B02).
    (@route [$($trig:literal),*]) => { ::core::option::Option::None };
    (@route [$($trig:literal),*] tokens) => {
        ::core::option::Option::Some(&[$($trig),*])
    };

    (
        id = $rid:literal,
        name = $rname:literal,
        severity = $sev:expr,
        description = $desc:literal,
        triggers = [$($trig:literal),* $(,)?],
        abstract = $abs:expr
        $(, route = $route:ident)?
        ,
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

            /// Descriptor estático para el catálogo (B02).
            pub const DESCRIPTOR: $crate::base::RuleDescriptor =
                $crate::base::RuleDescriptor {
                    id: $rid,
                    name: $rname,
                    severity: $sev,
                    description: $desc,
                    triggers: &[$($trig),*],
                    is_abstract: $abs,
                    tokens_route: $crate::define_rule!(@route [$($trig),*] $($route)?),
                    factory: || ::std::boxed::Box::new(<$name>::new()),
                };
        }

        impl $crate::base::Rule for $name {
            fn id(&self) -> &'static str { $rid }
            fn name(&self) -> &'static str { $rname }
            fn severity(&self) -> $crate::base::Severity { $sev }
            fn description(&self) -> &'static str { $desc }
            fn triggers(&self) -> &'static [&'static str] { &[$($trig),*] }

            fn dispatch_route(&self) -> $crate::base::DispatchRoute {
                $(
                    if stringify!($route) == "tokens" {
                        return $crate::base::DispatchRoute::Tokens(self.triggers());
                    }
                )?
                $crate::base::DispatchRoute::AllLines
            }

            fn is_abstract(&self) -> bool { $abs }

            fn reset(&mut self, file: &::std::path::Path) {
                self.current_file = Some(file.to_path_buf());
                ($reset)(self, file);
            }

            #[allow(unused_variables)]
            fn evaluate(&mut self, line: &$crate::base::ParsedLine<'_>, ctx: &$crate::base::AuditContext) -> ::std::vec::Vec<$crate::base::Issue> {
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
