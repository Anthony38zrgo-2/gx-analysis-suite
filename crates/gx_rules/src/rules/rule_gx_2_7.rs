#![allow(unused_imports)]
use crate::base::*;
use crate::helpers::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity};
use gx_core::regex_cache::*;
use std::path::Path;

define_rule! {
    id = "GX.2.7",
    name = "Iteración y contadores de Variables",
    severity = Severity::Error,
    description = "Clase estructural para agrupar las reglas de la sección 2.7.",
    triggers = [],
    abstract = true,
    struct RuleGx2_7 {},
    reset = |me: &mut RuleGx2_7, _file: &Path| {  },
    evaluate = |me: &mut RuleGx2_7, line: &ParsedLine, ctx: &AuditContext| {  vec![]  },
}
