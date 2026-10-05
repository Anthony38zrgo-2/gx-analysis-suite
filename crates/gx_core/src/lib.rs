//! gx_core — dominio puro (models, ParsedLine, regex_cache, filesystem, xpz_extractor).
//! Port de `gx_linter/app/core/*` + `gx_linter/app/rules/base::ParsedLine`.

pub mod budget;
pub mod filesystem;
pub mod lexical;
pub mod models;
pub mod regex_cache;
pub mod stats;
pub mod summary;
pub mod validation;
pub mod xpz_extractor;

pub use models::{AuditContext, AuditMetrics, Issue, ParsedLine, Severity, SourceLine};
