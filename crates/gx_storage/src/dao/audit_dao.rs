//! Audit run / issue history DAO.

use rusqlite::Connection;

use gx_core::models::Issue;

use crate::Result;

/// A row from `audit_runs`.
#[derive(Debug, Clone)]
pub struct AuditRun {
    pub file_path: String,
    pub file_name: String,
    pub file_hash: Option<String>,
    pub file_size_bytes: Option<i64>,
    pub triggered_by: String,
    pub total_findings: i64,
    pub errors: i64,
    pub warnings: i64,
    pub info: i64,
    pub qg_passed: bool,
    pub qg_threshold_pct: f32,
    pub duration_ms: Option<i64>,
    pub pdf_path: Option<String>,
    pub engine_version: String,
}

/// Insert a run row and return its autoincrement id.
pub fn insert_run(conn: &Connection, run: &AuditRun) -> Result<i64> {
    conn.execute(
        "INSERT INTO audit_runs \
         (file_path, file_name, file_hash, file_size_bytes, triggered_by, \
          total_findings, errors, warnings, info, qg_passed, qg_threshold_pct, \
          duration_ms, pdf_path, engine_version, finished_at) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14, \
                 strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
        (
            &run.file_path,
            &run.file_name,
            &run.file_hash,
            &run.file_size_bytes,
            &run.triggered_by,
            &run.total_findings,
            &run.errors,
            &run.warnings,
            &run.info,
            &run.qg_passed,
            &run.qg_threshold_pct,
            &run.duration_ms,
            &run.pdf_path,
            &run.engine_version,
        ),
    )?;
    Ok(conn.last_insert_rowid())
}

/// Insert all issues for a run.
pub fn insert_issues(conn: &mut Connection, run_id: i64, issues: &[Issue]) -> Result<()> {
    let tx = conn.transaction()?;
    for issue in issues {
        tx.execute(
            "INSERT INTO audit_issues \
             (audit_run_id, rule_id, severity, line_number, line_content, description, file_path) \
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            (
                &run_id,
                &issue.rule_id,
                &issue.severity.as_str(),
                &(issue.line_number as i64),
                &issue.line_content,
                &issue.description,
                &issue.file_path.to_string_lossy().to_string(),
            ),
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// Most recent runs, newest first.
pub fn list_runs(conn: &Connection, limit: i64) -> Result<Vec<(i64, String, i64)>> {
    let mut stmt = conn.prepare(
        "SELECT id, file_name, total_findings FROM audit_runs \
         ORDER BY started_at DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map([limit], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Issues for a given run, ordered by severity.
pub fn get_issues_for_run(conn: &Connection, run_id: i64) -> Result<Vec<Issue>> {
    let mut stmt = conn.prepare(
        "SELECT ai.rule_id, ai.line_number, ai.line_content, ai.description, ai.file_path, ai.severity \
         FROM audit_issues ai WHERE ai.audit_run_id = ?1 \
         ORDER BY CASE ai.severity WHEN 'ERROR' THEN 0 WHEN 'WARNING' THEN 1 ELSE 2 END",
    )?;
    let rows = stmt.query_map([run_id], |r| {
        Ok(Issue {
            rule_id: r.get(0)?,
            line_number: r.get::<_, i64>(1)? as u32,
            line_content: r.get(2)?,
            description: r.get(3)?,
            file_path: std::path::PathBuf::from(r.get::<_, String>(4)?),
            severity: match r.get::<_, String>(5)?.as_str() {
                "ERROR" => gx_core::models::Severity::Error,
                "WARNING" => gx_core::models::Severity::Warning,
                _ => gx_core::models::Severity::Info,
            },
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}
