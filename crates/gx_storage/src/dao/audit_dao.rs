//! Audit run / issue history DAO.

use rusqlite::Connection;

use gx_core::models::Issue;

use crate::Result;

/// A row from `audit_runs`.
#[derive(Debug, Clone, Default)]
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
    /// GX-011: política que produjo el veredicto ("absolute"/"percentage").
    pub policy: Option<String>,
    /// GX-011: veredicto ("pass"/"reject"/"error").
    pub verdict: Option<String>,
    /// GX-011: fallos de scan serializados (JSON).
    pub failures_json: Option<String>,
}

/// Insert a run row and return its autoincrement id.
pub fn insert_run(conn: &Connection, run: &AuditRun) -> Result<i64> {
    conn.execute(
        "INSERT INTO audit_runs \
         (file_path, file_name, file_hash, file_size_bytes, triggered_by, \
          total_findings, errors, warnings, info, qg_passed, qg_threshold_pct, \
          duration_ms, pdf_path, engine_version, policy, verdict, failures_json, \
          finished_at) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17, \
                 strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
        rusqlite::params![
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
            &run.policy,
            &run.verdict,
            &run.failures_json,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Insert all issues for a run (GX-011: incluye identidad de objeto).
pub fn insert_issues(conn: &mut Connection, run_id: i64, issues: &[Issue]) -> Result<()> {
    let tx = conn.transaction()?;
    insert_issues_in_tx(&tx, run_id, issues)?;
    tx.commit()?;
    Ok(())
}

fn insert_issues_in_tx(conn: &Connection, run_id: i64, issues: &[Issue]) -> Result<()> {
    for issue in issues {
        let (object_id, object_type, object_package, object_member, object_container) =
            match &issue.object {
                Some(o) => (
                    Some(o.id.clone()),
                    Some(o.object_type.clone()),
                    Some(o.package.clone()),
                    Some(o.member.clone()),
                    Some(o.container_path.clone()),
                ),
                None => (None, None, None, None, None),
            };
        conn.execute(
            "INSERT INTO audit_issues \
             (audit_run_id, rule_id, severity, line_number, line_content, description, file_path, \
              object_id, object_type, object_package, object_member, object_container) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            rusqlite::params![
                run_id,
                issue.rule_id,
                issue.severity.as_str(),
                issue.line_number as i64,
                issue.line_content,
                issue.description,
                issue.file_path.to_string_lossy().to_string(),
                object_id,
                object_type,
                object_package,
                object_member,
                object_container,
            ],
        )?;
    }
    Ok(())
}

/// GX-011: persiste la corrida completa (metadata + issues) en UNA
/// transacción. Cualquier fallo de inserción revierte la corrida entera.
pub fn persist_run(conn: &mut Connection, run: &AuditRun, issues: &[Issue]) -> Result<i64> {
    let tx = conn.transaction()?;
    let run_id = insert_run(&tx, run)?;
    insert_issues_in_tx(&tx, run_id, issues)?;
    tx.commit()?;
    Ok(run_id)
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
///
/// GX-011: reconstruye la identidad de objeto cuando existe (suficiente
/// para reabrir el miembro correcto del XPZ en el visor).
pub fn get_issues_for_run(conn: &Connection, run_id: i64) -> Result<Vec<Issue>> {
    let mut stmt = conn.prepare(
        "SELECT ai.rule_id, ai.line_number, ai.line_content, ai.description, ai.file_path, ai.severity, \
                ai.object_id, ai.object_type, ai.object_package, ai.object_member, ai.object_container \
         FROM audit_issues ai WHERE ai.audit_run_id = ?1 \
         ORDER BY CASE ai.severity WHEN 'ERROR' THEN 0 WHEN 'WARNING' THEN 1 ELSE 2 END, ai.id",
    )?;
    let rows = stmt.query_map([run_id], |r| {
        let rule_id: String = r.get(0)?;
        let line_number: i64 = r.get(1)?;
        let line_content: String = r.get(2)?;
        let description: String = r.get(3)?;
        let file_path: String = r.get(4)?;
        let severity: String = r.get(5)?;
        let object_id: Option<String> = r.get(6)?;
        let object_type: Option<String> = r.get(7)?;
        let object_package: Option<String> = r.get(8)?;
        let object_member: Option<String> = r.get(9)?;
        let object_container: Option<String> = r.get(10)?;

        let object = object_id.map(|id| gx_core::models::ObjectRef {
            id,
            object_type: object_type.unwrap_or_default(),
            package: object_package.unwrap_or_default(),
            member: object_member.unwrap_or_default(),
            container_path: object_container.unwrap_or_default(),
        });
        Ok(Issue {
            rule_id,
            line_number: line_number as u32,
            line_content,
            description,
            file_path: std::path::PathBuf::from(file_path),
            severity: match severity.as_str() {
                "ERROR" => gx_core::models::Severity::Error,
                "WARNING" => gx_core::models::Severity::Warning,
                _ => gx_core::models::Severity::Info,
            },
            object,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gx_core::models::{Issue, ObjectRef, Severity};

    fn golden_run() -> AuditRun {
        AuditRun {
            file_path: "sample.xpz".to_string(),
            file_name: "sample.xpz".to_string(),
            triggered_by: "cli".to_string(),
            total_findings: 2,
            errors: 2,
            qg_passed: false,
            qg_threshold_pct: 10.0,
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            policy: Some("absolute".to_string()),
            verdict: Some("reject".to_string()),
            failures_json: None,
            ..Default::default()
        }
    }

    fn issue_with_object(line: u32) -> Issue {
        Issue {
            rule_id: "GX.2.6".to_string(),
            severity: Severity::Error,
            line_number: line,
            line_content: "sub 'Inicializar'".to_string(),
            description: "Mala práctica crítica en Subrutina 'Inicializar'".to_string(),
            file_path: std::path::PathBuf::from("sample.xpz"),
            object: Some(ObjectRef {
                id: "ProcMalo".to_string(),
                object_type: "Procedure".to_string(),
                container_path: "sample.xpz".to_string(),
                member: "PkgDemo/ProcMalo.xml".to_string(),
                package: "PkgDemo".to_string(),
            }),
        }
    }

    /// GX-011: persist_run guarda metadata + issues en una transacción y el
    /// historial conserva la identidad de objeto (member del XPZ).
    #[test]
    fn persist_run_stores_issues_and_object_identity() {
        let mut conn = crate::db::init_memory_db().unwrap();
        let run_id = persist_run(
            &mut conn,
            &golden_run(),
            &[issue_with_object(3), issue_with_object(7)],
        )
        .unwrap();
        let issues = get_issues_for_run(&conn, run_id).unwrap();
        assert_eq!(issues.len(), 2);
        let obj = issues[0].object.as_ref().unwrap();
        assert_eq!(obj.id, "ProcMalo");
        assert_eq!(obj.object_type, "Procedure");
        assert_eq!(obj.package, "PkgDemo");
        assert_eq!(obj.member, "PkgDemo/ProcMalo.xml");
        assert_eq!(issues[0].line_number, 3);
        assert_eq!(issues[1].line_number, 7);
    }

    /// GX-011: si falla la inserción de issues, la corrida COMPLETA se
    /// revierte (cero corridas en la base).
    #[test]
    fn failed_issue_insert_rolls_back_the_run() {
        let conn = crate::db::init_memory_db().unwrap();
        // Trigger que aborta cualquier inserción en audit_issues.
        conn.execute(
            "CREATE TRIGGER force_fail BEFORE INSERT ON audit_issues \
             BEGIN SELECT RAISE(ABORT, 'forced'); END;",
            [],
        )
        .unwrap();

        let mut conn = conn;
        let err = persist_run(&mut conn, &golden_run(), &[issue_with_object(3)])
            .expect_err("el trigger fuerza el fallo");
        assert!(err.to_string().contains("forced"));

        let runs: i64 = conn
            .query_row("SELECT COUNT(*) FROM audit_runs", [], |r| r.get(0))
            .unwrap();
        assert_eq!(runs, 0, "la corrida fallida no debe quedar persistida");
    }
}
