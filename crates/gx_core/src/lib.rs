//! gx_core — dominio puro (models, ParsedLine, lexical, validation, budget,
//! stats, regex_cache, summary) (B04).
//! Port de `gx_linter/app/core/*` + `gx_linter/app/rules/base::ParsedLine`.
//!
//! Los adapters de entrada (filesystem/ZIP/RAR) viven en `gx_sources`, de modo
//! que el dominio no enlaza zip/unrar.

pub mod budget;
pub mod lexical;
pub mod models;
pub mod regex_cache;
pub mod semantics;
pub mod stats;
pub mod summary;
pub mod validation;

pub use models::{AuditContext, AuditMetrics, Issue, ParsedLine, Severity, SourceLine};
