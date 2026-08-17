#![allow(unused_imports)]
use crate::base::*;
use crate::helpers::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity};
use gx_core::regex_cache::*;
use std::path::Path;

define_rule! {
    id = "GX.2.0",
    name = "Mejores Prácticas - Errores",
    severity = Severity::Error,
    description = "Clase estructural para agrupar jerárquicamente las reglas críticas de la sección 2.",
    triggers = [],
    abstract = true,
    struct RuleGx2_0 {},
    reset = |me: &mut RuleGx2_0, _file: &Path| {  },
    evaluate = |me: &mut RuleGx2_0, line: &ParsedLine, ctx: &AuditContext| {  vec![]  },
}
