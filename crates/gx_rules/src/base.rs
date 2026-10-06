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
pub use gx_core::semantics::{FactSet, SemanticModel, Token};

/// Alcance del análisis declarado por una regla/pack (D01).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Scope {
    /// Regla de línea (comportamiento histórico).
    #[default]
    Line,
    /// Análisis por objeto que requiere hechos compartidos.
    Object,
}

/// Clase de costo declarada (D01): permite perfiles opt-in profundos.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Cost {
    #[default]
    Cheap,
    Moderate,
    Deep,
}

/// Capacidad declarada: alcance + hechos requeridos + costo (D01).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Capability {
    pub scope: Scope,
    pub facts: FactSet,
    pub cost: Cost,
}

impl Capability {
    pub const fn line() -> Self {
        Capability {
            scope: Scope::Line,
            facts: FactSet::NONE,
            cost: Cost::Cheap,
        }
    }
}

/// Hechos compartidos calculados UNA vez por objeto y sólo si un pack
/// seleccionado los requiere (D01/D02).
pub struct ObjectFacts<'a> {
    /// Texto crudo del objeto (evidencia y patrones léxicos).
    pub text: &'a str,
    pub tokens: Option<&'a [Token]>,
    pub model: Option<&'a SemanticModel>,
}

impl ObjectFacts<'_> {
    /// `true` si los hechos requeridos están disponibles.
    pub fn has(&self, facts: FactSet) -> bool {
        if facts.needs_model() {
            self.model.is_some()
        } else if facts.needs_tokens() {
            self.tokens.is_some()
        } else {
            true
        }
    }
}

/// Cobertura declarada por un pack tras analizar un objeto (D03).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CoverageHint {
    /// Objetos que el pack decidió no analizar (p. ej. cobertura incompleta).
    pub skipped_unsupported: usize,
    /// Llamadas no modeladas sobre valores contaminados (semántica de
    /// sanitizador desconocida, taint conservador).
    pub unsupported_sanitizers: usize,
}

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
        category: None,
        confidence: None,
        cwe: None,
        trace: None,
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
    /// Pack de objeto (D01): nunca se despacha por línea.
    Object,
}

/// Descriptor inmutable de una regla (B02).
///
/// Reemplaza a `all_rules()` como fuente de metadatos: el catálogo es estático
/// y sólo se instancian (vía `factory`) las reglas seleccionadas.
pub struct RuleDescriptor {
    pub id: &'static str,
    /// Versión estable de la regla/pack (D01), parte de la clave de caché.
    pub version: &'static str,
    pub name: &'static str,
    pub severity: Severity,
    pub description: &'static str,
    /// Categoría declarada ("policy", "security", …) (D01/D03).
    pub category: &'static str,
    /// Tipos de objeto soportados; vacío = cualquiera (D01).
    pub object_types: &'static [&'static str],
    pub triggers: &'static [&'static str],
    pub is_abstract: bool,
    /// `Some(tokens)` ⇒ ruta `Tokens`; `None` ⇒ `AllLines`; `Object` ⇒ pack.
    pub tokens_route: Option<&'static [&'static str]>,
    pub is_object_route: bool,
    pub capability: Capability,
    pub factory: fn() -> Box<dyn Rule>,
}

impl RuleDescriptor {
    /// Ruta de despacho declarada por la regla.
    pub fn dispatch_route(&self) -> DispatchRoute {
        if self.is_object_route {
            return DispatchRoute::Object;
        }
        match self.tokens_route {
            Some(tokens) => DispatchRoute::Tokens(tokens),
            None => DispatchRoute::AllLines,
        }
    }
}

/// The core rule contract.
pub trait Rule: Send + Sync {
    fn id(&self) -> &'static str;
    /// Versión estable de la regla/pack (D01).
    fn version(&self) -> &'static str {
        "1.0"
    }
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
    /// Capacidad declarada (D01): hechos requeridos y costo.
    fn capability(&self) -> Capability {
        Capability::line()
    }
    fn reset(&mut self, file: &Path);
    fn evaluate(&mut self, line: &ParsedLine<'_>, ctx: &AuditContext) -> Vec<Issue>;
    /// Análisis por objeto (D01/D02): sólo lo implementan los packs.
    fn analyze_object(&mut self, _facts: &ObjectFacts<'_>, _ctx: &AuditContext) -> Vec<Issue> {
        vec![]
    }
    /// Cobertura declarada tras `analyze_object` (D03).
    fn coverage_hint(&self) -> CoverageHint {
        CoverageHint::default()
    }
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
    // Rutas internas del descriptor (B02/D01).
    (@route [$($trig:literal),*]) => { ::core::option::Option::None };
    (@route [$($trig:literal),*] tokens) => {
        ::core::option::Option::Some(&[$($trig),*])
    };
    (@route [$($trig:literal),*] object) => { ::core::option::Option::None };
    (@version $v:literal) => { $v };
    (@version) => { "1.0" };
    (@category $c:literal) => { $c };
    (@category) => { "policy" };
    (@scope line) => { $crate::base::Scope::Line };
    (@scope object) => { $crate::base::Scope::Object };
    (@scope) => { $crate::base::Scope::Line };
    (@cost cheap) => { $crate::base::Cost::Cheap };
    (@cost moderate) => { $crate::base::Cost::Moderate };
    (@cost deep) => { $crate::base::Cost::Deep };
    (@cost) => { $crate::base::Cost::Cheap };
    (@fact tokens) => { $crate::base::FactSet::TOKENS };
    (@fact syntax) => { $crate::base::FactSet::SYNTAX };
    (@fact symbols) => { $crate::base::FactSet::SYMBOLS };
    (@fact def_use) => { $crate::base::FactSet::DEF_USE };
    (@is_object object) => { true };
    (@is_object $other:ident) => { false };
    (@is_object) => { false };

    (
        id = $rid:literal,
        name = $rname:literal,
        severity = $sev:expr,
        description = $desc:literal,
        triggers = [$($trig:literal),* $(,)?],
        abstract = $abs:expr
        $(, route = $route:ident)?
        $(, version = $version:literal)?
        $(, category = $cat:literal)?
        $(, scope = $scope:ident)?
        $(, facts = [$($fact:ident),* $(,)?])?
        $(, cost = $cost:ident)?
        $(, object_types = [$($otype:literal),* $(,)?])?
        ,
        struct $name:ident { $($field:ident : $fty:ty),* $(,)? },
        reset = $reset:expr,
        evaluate = $eval:expr
        $(, analyze = $analyze:expr)?
        $(, coverage = $coverage:expr)?
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

            /// Descriptor estático para el catálogo (B02/D01).
            pub const DESCRIPTOR: $crate::base::RuleDescriptor =
                $crate::base::RuleDescriptor {
                    id: $rid,
                    version: $crate::define_rule!(@version $($version)?),
                    name: $rname,
                    severity: $sev,
                    description: $desc,
                    category: $crate::define_rule!(@category $($cat)?),
                    object_types: &[$($($otype),*)?],
                    triggers: &[$($trig),*],
                    is_abstract: $abs,
                    tokens_route: $crate::define_rule!(@route [$($trig),*] $($route)?),
                    is_object_route: $crate::define_rule!(@is_object $($route)?),
                    capability: $crate::base::Capability {
                        scope: $crate::define_rule!(@scope $($scope)?),
                        facts: $crate::base::FactSet::NONE
                            $($(.union($crate::define_rule!(@fact $fact)))*)?,
                        cost: $crate::define_rule!(@cost $($cost)?),
                    },
                    factory: || ::std::boxed::Box::new(<$name>::new()),
                };
        }

        impl $crate::base::Rule for $name {
            fn id(&self) -> &'static str { $rid }
            fn version(&self) -> &'static str {
                $crate::define_rule!(@version $($version)?)
            }
            fn name(&self) -> &'static str { $rname }
            fn severity(&self) -> $crate::base::Severity { $sev }
            fn description(&self) -> &'static str { $desc }
            fn triggers(&self) -> &'static [&'static str] { &[$($trig),*] }

            fn dispatch_route(&self) -> $crate::base::DispatchRoute {
                $(
                    if stringify!($route) == "tokens" {
                        return $crate::base::DispatchRoute::Tokens(self.triggers());
                    }
                    if stringify!($route) == "object" {
                        return $crate::base::DispatchRoute::Object;
                    }
                )?
                $crate::base::DispatchRoute::AllLines
            }

            fn is_abstract(&self) -> bool { $abs }

            fn capability(&self) -> $crate::base::Capability {
                <$name>::DESCRIPTOR.capability
            }

            fn reset(&mut self, file: &::std::path::Path) {
                self.current_file = Some(file.to_path_buf());
                ($reset)(self, file);
            }

            #[allow(unused_variables)]
            fn evaluate(&mut self, line: &$crate::base::ParsedLine<'_>, ctx: &$crate::base::AuditContext) -> ::std::vec::Vec<$crate::base::Issue> {
                ($eval)(self, line, ctx)
            }

            #[allow(unused_variables, unreachable_code)]
            fn analyze_object(
                &mut self,
                facts: &$crate::base::ObjectFacts<'_>,
                ctx: &$crate::base::AuditContext,
            ) -> ::std::vec::Vec<$crate::base::Issue> {
                $( return ($analyze)(self, facts, ctx); )?
                ::std::vec::Vec::new()
            }

            #[allow(unused_variables, unreachable_code)]
            fn coverage_hint(&self) -> $crate::base::CoverageHint {
                $( return ($coverage)(self); )?
                $crate::base::CoverageHint::default()
            }

            #[allow(unused_variables, unreachable_code)]
            fn finalize(&mut self, ctx: &$crate::base::AuditContext) -> ::std::vec::Vec<$crate::base::Issue> {
                $( return ($fin)(self, ctx); )?
                ::std::vec::Vec::new()
            }
        }
    };
}
