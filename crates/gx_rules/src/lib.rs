//! gx_rules — catálogo de reglas (trait Rule + registro + 30 reglas).
//! Port de `gx_linter/app/rules/*`.
#![allow(unused_variables)]
// The `define_rule!` macro emits code that trips these clippy lints by design.
#![allow(clippy::derivable_impls)]
#![allow(clippy::ptr_arg)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::trim_split_whitespace)]

#[macro_use]
pub mod base;
pub mod helpers;
pub mod rules;

use base::Rule;

/// Instancia las 30 reglas (24 concretas + 6 abstractas) en un vector.
/// El engine filtra abstractas y deshabilitadas en `load_rules`.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(rules::rule_gx_1::RuleGx1::new()),
        Box::new(rules::rule_gx_1_1::RuleGx1_1::new()),
        Box::new(rules::rule_gx_1_2::RuleGx1_2::new()),
        Box::new(rules::rule_gx_1_3::RuleGx1_3::new()),
        Box::new(rules::rule_gx_1_3_1::RuleGx1_3_1::new()),
        Box::new(rules::rule_gx_1_3_2::RuleGx1_3_2::new()),
        Box::new(rules::rule_gx_1_3_3::RuleGx1_3_3::new()),
        Box::new(rules::rule_gx_1_4::RuleGx1_4::new()),
        Box::new(rules::rule_gx_1_4_1::RuleGx1_4_1::new()),
        Box::new(rules::rule_gx_1_4_2::RuleGx1_4_2::new()),
        Box::new(rules::rule_gx_1_4_3::RuleGx1_4_3::new()),
        Box::new(rules::rule_gx_1_5::RuleGx1_5::new()),
        Box::new(rules::rule_gx_1_6::RuleGx1_6::new()),
        Box::new(rules::rule_gx_1_6_1::RuleGx1_6_1::new()),
        Box::new(rules::rule_gx_1_6_2::RuleGx1_6_2::new()),
        Box::new(rules::rule_gx_1_7::RuleGx1_7::new()),
        Box::new(rules::rule_gx_1_7_1::RuleGx1_7_1::new()),
        Box::new(rules::rule_gx_1_7_2::RuleGx1_7_2::new()),
        Box::new(rules::rule_gx_2_0::RuleGx2_0::new()),
        Box::new(rules::rule_gx_2_1::RuleGx2_1::new()),
        Box::new(rules::rule_gx_2_2::RuleGx2_2::new()),
        Box::new(rules::rule_gx_2_3::RuleGx2_3::new()),
        Box::new(rules::rule_gx_2_4::RuleGx2_4::new()),
        Box::new(rules::rule_gx_2_5::RuleGx2_5::new()),
        Box::new(rules::rule_gx_2_6::RuleGx2_6::new()),
        Box::new(rules::rule_gx_2_7::RuleGx2_7::new()),
        Box::new(rules::rule_gx_2_7_1::RuleGx2_7_1::new()),
        Box::new(rules::rule_gx_2_7_2::RuleGx2_7_2::new()),
        Box::new(rules::rule_gx_2_7_3::RuleGx2_7_3::new()),
        Box::new(rules::rule_gx_2_7_4::RuleGx2_7_4::new()),
    ]
}
