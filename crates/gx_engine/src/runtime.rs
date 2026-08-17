//! Analysis orchestrator. Port of `gx_linter/app/engine/runtime.py`.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Result;
use gx_core::models::{AuditContext, AuditMetrics, Issue, ParsedLine, SourceLine};
use gx_core::xpz_extractor::extract_genexus_source;
use gx_rules::base::Rule;
use gx_storage::dao::rules_dao;

use crate::dispatch::{DEFAULT_TRIGGER, TRIGGER_MAP};

/// Load enabled, non-abstract rules and build the trigger dispatch index.
///
/// Mirrors `runtime.load_rules`: filters abstract rules and disabled rules
/// (per `RulesDao::is_rule_enabled`), then indexes each rule by its trigger
/// tokens (or `DEFAULT_TRIGGER` when it has none).
pub fn load_rules(
    conn: &rusqlite::Connection,
) -> Result<(Vec<Box<dyn Rule>>, HashMap<String, Vec<usize>>)> {
    let all = gx_rules::all_rules();
    let mut rules: Vec<Box<dyn Rule>> = Vec::new();
    let mut dispatch: HashMap<String, Vec<usize>> = HashMap::new();

    for rule in all {
        if rule.is_abstract() {
            continue;
        }
        if !rules_dao::is_rule_enabled(conn, rule.id()) {
            continue;
        }
        let idx = rules.len();
        let triggers: Vec<&str> = if rule.triggers().is_empty() {
            vec![DEFAULT_TRIGGER]
        } else {
            rule.triggers().to_vec()
        };
        for t in triggers {
            dispatch.entry(t.to_string()).or_default().push(idx);
        }
        rules.push(rule);
    }
    Ok((rules, dispatch))
}

/// Build the set of rule indices that should evaluate `parsed`.
///
/// 1. Always include DEFAULT_TRIGGER rules.
/// 2. Include trigger-specific rules whose flag matches the line.
/// 3. Fallback to all rules if the set is still empty.
pub fn collect_candidate_rules(
    parsed: &ParsedLine,
    dispatch: &HashMap<String, Vec<usize>>,
    all_rules: &[Box<dyn Rule>],
) -> HashSet<usize> {
    let mut candidates: HashSet<usize> = HashSet::new();

    if let Some(v) = dispatch.get(DEFAULT_TRIGGER) {
        for &i in v {
            candidates.insert(i);
        }
    }
    for (trigger, flag_fn) in TRIGGER_MAP.iter() {
        if flag_fn(parsed) {
            if let Some(v) = dispatch.get(*trigger) {
                for &i in v {
                    candidates.insert(i);
                }
            }
        }
    }
    if candidates.is_empty() {
        for (i, _) in all_rules.iter().enumerate() {
            candidates.insert(i);
        }
    }
    candidates
}

/// Evaluate a single file: reset → per-line dispatch → finalize.
pub fn run_file(
    rules: &mut [Box<dyn Rule>],
    dispatch: &HashMap<String, Vec<usize>>,
    path: &Path,
    ctx: &AuditContext,
) -> Result<(Vec<Issue>, u128)> {
    let contents = extract_genexus_source(path)?;
    let mut issues: Vec<Issue> = Vec::new();
    let lines: Vec<&str> = contents.split('\n').collect();

    let t_start = Instant::now();
    let mut rules_fired_total: usize = 0;

    for (idx, raw_line) in lines.iter().enumerate() {
        let content = raw_line.trim_end_matches('\r');
        if content
            .to_lowercase()
            .contains("generated subroutines (public)")
        {
            break;
        }
        let source = SourceLine {
            number: idx as u32 + 1,
            content: content.to_string(),
        };
        let parsed = ParsedLine::from_source(source);
        if parsed.stripped.is_empty() {
            continue;
        }
        let candidates = collect_candidate_rules(&parsed, dispatch, rules);
        rules_fired_total += candidates.len();
        for idx in candidates {
            let result = rules[idx].evaluate(&parsed, ctx);
            issues.extend(result);
        }
    }

    for r in rules.iter_mut() {
        issues.extend(r.finalize(ctx));
    }

    let elapsed_ms = t_start.elapsed().as_millis();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    tracing::info!(
        "[ENGINE] {name} — {} lines | {rules_fired_total} rule-evaluations | {} findings | {elapsed_ms} ms",
        lines.len(),
        issues.len()
    );
    Ok((issues, elapsed_ms))
}

/// Convenience wrapper: load rules from `conn` then evaluate `path`.
pub fn evaluate_file(
    path: &Path,
    conn: &rusqlite::Connection,
    ctx: &AuditContext,
) -> Result<(Vec<Issue>, u128)> {
    let (mut rules, dispatch) = load_rules(conn)?;
    run_file(&mut rules, &dispatch, path, ctx)
}

/// Summarize issues into metrics (mirrors `runtime.build_metrics`).
pub fn build_metrics(issues: &[Issue]) -> AuditMetrics {
    AuditMetrics::from_issues(issues)
}

/// Build rules + dispatch from an explicit enabled set (used for parallelism).
fn build_rules_dispatch(
    enabled_ids: &HashSet<String>,
) -> (Vec<Box<dyn Rule>>, HashMap<String, Vec<usize>>) {
    let all = gx_rules::all_rules();
    let mut rules: Vec<Box<dyn Rule>> = Vec::new();
    let mut dispatch: HashMap<String, Vec<usize>> = HashMap::new();
    for rule in all {
        if rule.is_abstract() {
            continue;
        }
        if !enabled_ids.contains(rule.id()) {
            continue;
        }
        let idx = rules.len();
        let triggers: Vec<&str> = if rule.triggers().is_empty() {
            vec![DEFAULT_TRIGGER]
        } else {
            rule.triggers().to_vec()
        };
        for t in triggers {
            dispatch.entry(t.to_string()).or_default().push(idx);
        }
        rules.push(rule);
    }
    (rules, dispatch)
}

/// Evaluate multiple files in parallel (one rule set per thread).
pub fn evaluate_files_parallel(
    paths: &[PathBuf],
    enabled_ids: &HashSet<String>,
    ctx: &AuditContext,
) -> Vec<(PathBuf, Vec<Issue>, AuditMetrics)> {
    use rayon::prelude::*;
    paths
        .par_iter()
        .map(|p| {
            let (mut rules, dispatch) = build_rules_dispatch(enabled_ids);
            match run_file(&mut rules, &dispatch, p, ctx) {
                Ok((issues, _)) => {
                    let metrics = AuditMetrics::from_issues(&issues);
                    (p.clone(), issues, metrics)
                }
                Err(_) => (p.clone(), vec![], AuditMetrics::default()),
            }
        })
        .collect()
}
