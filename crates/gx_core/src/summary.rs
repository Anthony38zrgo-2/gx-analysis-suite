//! Resumen textual de un [`AnalysisResult`], compartido por el CLI (`gx scan`)
//! y el desktop (GX-016/GX-017) para que AMBOS muestren exactamente lo mismo.

use std::fmt::Write as _;

use crate::models::{AnalysisResult, QgPolicy, QgVerdict};

/// Texto del resumen (misma salida que `gx scan --format text`, con salto de
/// línea final).
pub fn text_summary(result: &AnalysisResult) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "[gx] política: {}", policy_label(&result.policy));
    let _ = writeln!(
        out,
        "[gx] archivos escaneados: {} | hallazgos: {} ({} ERROR / {} WARNING / {} INFO)",
        result.scanned_files,
        result.metrics.total_findings,
        result.metrics.errors,
        result.metrics.warnings,
        result.metrics.info
    );
    for issue in &result.findings {
        let object = match &issue.object {
            Some(o) => format!(" [{} ({}) {}]", o.id, o.object_type, o.member),
            None => String::new(),
        };
        let _ = writeln!(
            out,
            "{:<7} {:<10} línea {:<4}{} {}",
            issue.severity.as_str(),
            issue.rule_id,
            issue.line_number,
            object,
            issue.description
        );
    }
    if let Some(security) = &result.security {
        let _ = writeln!(
            out,
            "[gx] seguridad: {} hallazgo(s), {} error(es) — veredicto {} (CWE/patrones)",
            security.findings,
            security.errors,
            verdict_label(security.verdict)
        );
    }
    let _ = writeln!(
        out,
        "[gx] quality gate: {} ({})",
        verdict_label(result.verdict),
        result.policy.name()
    );
    out
}

fn policy_label(policy: &QgPolicy) -> String {
    match policy {
        QgPolicy::Absolute {
            max_errors,
            max_warnings,
        } => format!("absolute (max_errors={max_errors}, max_warnings={max_warnings})"),
        QgPolicy::Percentage { max_error_pct } => {
            format!("percentage (max_error_pct={max_error_pct})")
        }
    }
}

fn verdict_label(verdict: QgVerdict) -> &'static str {
    match verdict {
        QgVerdict::Pass => "PASS",
        QgVerdict::Reject => "REJECT",
        QgVerdict::Error => "ERROR (fallos de scan)",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        AnalysisRequest, AuditMetrics, DiscoveryPolicy, Issue, QgVerdict, Severity,
    };
    use std::path::PathBuf;

    fn sample_result() -> AnalysisResult {
        let request = AnalysisRequest {
            schema_version: 1,
            inputs: vec![PathBuf::from("x.txt")],
            enabled_rule_ids: vec!["GX.2.6".to_string()],
            policy: QgPolicy::Absolute {
                max_errors: 0,
                max_warnings: 999_999,
            },
            record_history: false,
            retain_sensitive_evidence: false,
            discovery: DiscoveryPolicy::default(),
        };
        AnalysisResult {
            schema_version: 1,
            request,
            scanned_files: 1,
            findings: vec![Issue {
                rule_id: "GX.2.6".to_string(),
                severity: Severity::Error,
                line_number: 3,
                line_content: "sub 'X'".to_string(),
                description: "desc".to_string(),
                file_path: PathBuf::from("x.txt"),
                object: None,
                category: None,
                confidence: None,
                cwe: None,
                trace: None,
            }],
            metrics: AuditMetrics {
                total_findings: 1,
                errors: 1,
                warnings: 0,
                info: 0,
            },
            failures: vec![],
            policy: QgPolicy::Absolute {
                max_errors: 0,
                max_warnings: 999_999,
            },
            verdict: QgVerdict::Reject,
            coverage: Default::default(),
            completion: Default::default(),
            pack_coverage: Vec::new(),
            security: None,
        }
    }

    #[test]
    fn text_summary_matches_cli_shape() {
        let text = text_summary(&sample_result());
        assert!(text.contains("[gx] política: absolute (max_errors=0, max_warnings=999999)"));
        assert!(text.contains("hallazgos: 1 (1 ERROR / 0 WARNING / 0 INFO)"));
        assert!(text.contains("ERROR   GX.2.6"));
        assert!(text.contains("[gx] quality gate: REJECT (absolute)"));
        assert!(text.ends_with('\n'));
    }
}
