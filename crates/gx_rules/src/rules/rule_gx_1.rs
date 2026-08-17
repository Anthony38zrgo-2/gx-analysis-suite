#![allow(unused_imports)]
use crate::base::*;
use crate::helpers::*;
use gx_core::models::{AuditContext, Issue, ParsedLine, Severity};
use gx_core::regex_cache::*;
use std::path::Path;

define_rule! {
    id = "GX.1",
    name = "Código de programas fuentes - Advertencias",
    severity = Severity::Warning,
    description = "Clase estructural para agrupar jerárquicamente las reglas GX.1.x.",
    triggers = [],
    abstract = true,
    struct RuleGx1 {},
    reset = |me: &mut RuleGx1, _file: &Path| {  },
    evaluate = |me: &mut RuleGx1, line: &ParsedLine, ctx: &AuditContext| {  vec![]  },
}
