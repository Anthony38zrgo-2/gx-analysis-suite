//! Dispatch plan (GX-004).
//!
//! Replaces the old token-only `HashMap` dispatch with an explicit plan:
//!
//! - `AllLines` rules run on every non-empty line. Required by stateful
//!   rules whose logic must observe continuation lines, bodies or comments
//!   (where/defined by/endfor for GX.1.3, otherwise for GX.1.3.3, sub
//!   bodies for GX.2.6, where continuations for GX.2.1/2.2/2.4/2.5, loop
//!   bodies for GX.2.7.1, comments for GX.1.6.x/1.7.x, parm continuations
//!   for GX.1.4.3, and the DEFAULT rules GX.1.2/1.3.1/1.3.2/2.3).
//! - `Tokens` rules run only when a line carries one of their trigger
//!   tokens. Only stateless rules use this route, and their `evaluate`
//!   guards on exactly those flags, so the route is a pure optimization.
//!
//! The old fallback ("no candidates ⇒ run every rule") is GONE: with
//! AllLines routes there are no holes to compensate for, and running a
//! token rule on a line it guards against produces identical results.
//!
//! Candidate order is deterministic: ascending rule-registry order.

use gx_core::models::ParsedLine;
use gx_rules::base::{DispatchRoute, Rule};

pub use gx_rules::base::DispatchRoute as Route;

/// Map a trigger token to the `ParsedLine` boolean flag it requires.
pub type TriggerFn = fn(&ParsedLine) -> bool;

/// Whether a line carries the `&` (variable reference) token.
pub fn has_ampersand(l: &ParsedLine) -> bool {
    l.has_ampersand
}
/// Whether a line carries an `=` assignment.
pub fn has_equal(l: &ParsedLine) -> bool {
    l.has_equal
}
/// Whether a line carries a `where` clause.
pub fn has_where(l: &ParsedLine) -> bool {
    l.has_where
}
/// Whether a line carries a `for each`.
pub fn has_for_each(l: &ParsedLine) -> bool {
    l.has_for_each
}
/// Whether a line carries a `sub`.
pub fn has_sub(l: &ParsedLine) -> bool {
    l.has_sub
}
/// Whether a line carries an `if`.
pub fn has_if(l: &ParsedLine) -> bool {
    l.has_if
}
/// Whether a line carries a `case`.
pub fn has_case(l: &ParsedLine) -> bool {
    l.has_case
}
/// Whether a line carries a `do`.
pub fn has_do(l: &ParsedLine) -> bool {
    l.has_do
}

use std::collections::HashMap;
use std::sync::LazyLock;

/// Trigger token → flag predicate, mirroring the Python `runtime.TRIGGER_MAP`.
pub static TRIGGER_MAP: LazyLock<HashMap<&'static str, TriggerFn>> = LazyLock::new(|| {
    let mut m: HashMap<&'static str, TriggerFn> = HashMap::new();
    m.insert("&", has_ampersand);
    m.insert("=", has_equal);
    m.insert("where", has_where);
    m.insert("for each", has_for_each);
    m.insert("sub", has_sub);
    m.insert("if", has_if);
    m.insert("case", has_case);
    m.insert("do", has_do);
    m
});

/// Precomputed per-scan line-selection plan.
#[derive(Clone)]
pub struct DispatchPlan {
    rule_count: usize,
    /// Ascending indices of rules that run on every line.
    all_lines: Vec<usize>,
    /// (ascending index, flag predicates) for token-routed rules.
    token_rules: Vec<(usize, Vec<TriggerFn>)>,
    /// Ascending indices de packs de objeto (D01): nunca corren por línea.
    object_rules: Vec<usize>,
    /// Ascending indices de packs project-wide (D04).
    project_rules: Vec<usize>,
}

impl DispatchPlan {
    /// Reference plan: every rule evaluates every line.
    pub fn all_rules_every_line(rule_count: usize) -> Self {
        DispatchPlan {
            rule_count,
            all_lines: (0..rule_count).collect(),
            token_rules: Vec::new(),
            object_rules: Vec::new(),
            project_rules: Vec::new(),
        }
    }

    /// Índices de los packs project-wide seleccionados (D04).
    pub fn project_rules(&self) -> &[usize] {
        &self.project_rules
    }

    /// Índices de los packs de objeto seleccionados, en orden de registry.
    pub fn object_rules(&self) -> &[usize] {
        &self.object_rules
    }
}

/// Build the plan from the rule set and their declared routes.
///
/// A token route whose trigger token has no flag mapping is an engine
/// configuration error: it is rejected instead of silently never firing.
pub fn plan_dispatch(rules: &[Box<dyn Rule>]) -> Result<DispatchPlan, String> {
    let routes: Vec<DispatchRoute> = rules.iter().map(|r| r.dispatch_route()).collect();
    plan_dispatch_routes(&routes)
}

/// Build the plan from static descriptors without instantiating rules (B02).
pub fn plan_dispatch_descriptors(
    descriptors: &[&gx_rules::base::RuleDescriptor],
) -> Result<DispatchPlan, String> {
    let routes: Vec<DispatchRoute> = descriptors
        .iter()
        .map(|descriptor| descriptor.dispatch_route())
        .collect();
    plan_dispatch_routes(&routes)
}

fn plan_dispatch_routes(routes: &[DispatchRoute]) -> Result<DispatchPlan, String> {
    let mut plan = DispatchPlan {
        rule_count: routes.len(),
        all_lines: Vec::new(),
        token_rules: Vec::new(),
        object_rules: Vec::new(),
        project_rules: Vec::new(),
    };
    for (idx, route) in routes.iter().enumerate() {
        match route {
            DispatchRoute::AllLines => plan.all_lines.push(idx),
            DispatchRoute::Tokens(tokens) => {
                let mut fns = Vec::with_capacity(tokens.len());
                for token in *tokens {
                    let flag = TRIGGER_MAP
                        .get(*token)
                        .ok_or_else(|| format!("trigger token sin mapeo de flag: {token}"))?;
                    fns.push(*flag);
                }
                plan.token_rules.push((idx, fns));
            }
            DispatchRoute::Object => plan.object_rules.push(idx),
            DispatchRoute::Project => plan.project_rules.push(idx),
        }
    }
    Ok(plan)
}

/// Rules that must evaluate `parsed`, in ascending registry order.
pub fn collect_candidate_rules(parsed: &ParsedLine<'_>, plan: &DispatchPlan) -> Vec<usize> {
    let mut candidates = Vec::with_capacity(plan.rule_count);
    collect_candidate_rules_into(parsed, plan, &mut candidates);
    candidates
}

/// [`collect_candidate_rules`] reutilizando un buffer (B02: sin asignar por
/// línea después del calentamiento).
pub fn collect_candidate_rules_into(
    parsed: &ParsedLine<'_>,
    plan: &DispatchPlan,
    out: &mut Vec<usize>,
) {
    out.clear();
    out.extend_from_slice(&plan.all_lines);
    for &(index, ref flags) in &plan.token_rules {
        if flags.iter().any(|flag| flag(parsed)) {
            out.push(index);
        }
    }
    out.sort_unstable();
}
