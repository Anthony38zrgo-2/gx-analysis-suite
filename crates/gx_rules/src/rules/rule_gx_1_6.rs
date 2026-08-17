#![allow(unused_imports)]
use crate::base::*;
use crate::helpers::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity};
use gx_core::regex_cache::*;
use std::path::Path;

define_rule! {
    id = "GX.1.6",
    name = "Comentarios",
    severity = Severity::Warning,
    description = "Clase estructural para agrupar las reglas de la sección 1.6.",
    triggers = [],
    abstract = true,
    struct RuleGx1_6 {},
    reset = |me: &mut RuleGx1_6, _file: &Path| {  },
    evaluate = |me: &mut RuleGx1_6, line: &ParsedLine, ctx: &AuditContext| {  vec![]  },
}
