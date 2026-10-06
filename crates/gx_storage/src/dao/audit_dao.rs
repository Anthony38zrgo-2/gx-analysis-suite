//! Audit run / issue history DAO.

use rusqlite::Connection;
use serde::Serialize;

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

impl AuditRun {
    /// Construye la fila de historial desde el contrato compartido
    /// CLI/desktop (GX-016): una sola procedencia para ambos entrypoints.
    pub fn from_analysis(
        request: &gx_core::models::AnalysisRequest,
        result: &gx_core::models::AnalysisResult,
        triggered_by: &str,
    ) -> Self {
        use gx_core::models::{QgPolicy, QgVerdict};

        let file_path = request
            .inputs
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join("; ");
        let file_name = match request.inputs.as_slice() {
            [single] => single
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default(),
            inputs => format!("{} entrada(s)", inputs.len()),
        };
        let file_size_bytes = match request.inputs.as_slice() {
            [single] => std::fs::metadata(single).ok().map(|m| m.len() as i64),
            _ => None,
        };

        AuditRun {
            file_path,
            file_name,
            file_hash: None,
            file_size_bytes,
            triggered_by: triggered_by.to_string(),
            total_findings: result.metrics.total_findings as i64,
            errors: result.metrics.errors as i64,
            warnings: result.metrics.warnings as i64,
            info: result.metrics.info as i64,
            qg_passed: result.verdict == QgVerdict::Pass,
            qg_threshold_pct: match &request.policy {
                QgPolicy::Percentage { max_error_pct } => *max_error_pct,
                _ => 0.0,
            },
            duration_ms: None,
            pdf_path: None,
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            policy: Some(request.policy.name().to_string()),
            verdict: Some(match result.verdict {
                QgVerdict::Pass => "pass".to_string(),
                QgVerdict::Reject => "reject".to_string(),
                QgVerdict::Error => "error".to_string(),
            }),
            failures_json: if result.failures.is_empty() {
                None
            } else {
                serde_json::to_string(&result.failures).ok()
            },
        }
    }
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
    // C01: UN statement preparado (cacheado por conexión) para todos los
    // issues de la corrida; la inserción no re-prepara por fila.
    let mut stmt = conn.prepare_cached(
        "INSERT INTO audit_issues \
         (audit_run_id, rule_id, severity, line_number, line_content, description, file_path, \
          object_id, object_type, object_package, object_member, object_container, \
          category, confidence, cwe) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
    )?;
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
        stmt.execute(rusqlite::params![
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
            issue.category,
            issue.confidence,
            issue.cwe.map(|cwe| cwe as i64),
        ])?;
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

/// Summary row for the audit history UI (GX-016/GX-017).
#[derive(Debug, Clone, Serialize)]
pub struct AuditRunSummary {
    pub id: i64,
    pub file_path: String,
    pub file_name: String,
    pub started_at: String,
    pub total_findings: i64,
    pub errors: i64,
    pub warnings: i64,
    pub info: i64,
    pub verdict: Option<String>,
    pub policy: Option<String>,
    pub qg_passed: bool,
}

/// Most recent runs, newest first.
pub fn list_runs(conn: &Connection, limit: i64) -> Result<Vec<AuditRunSummary>> {
    list_runs_page(conn, None, limit)
}

/// Cursor keyset de issues: (rank de severidad, id) (C01).
///
/// `rank` ordena ERROR < WARNING < INFO y `id` desempata de forma estable;
/// la página siguiente se pide con el último cursor visto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssueCursor {
    pub rank: u8,
    pub id: i64,
}

/// Página de issues históricos con cursor opcional.
#[derive(Debug, Clone)]
pub struct IssuesPage {
    pub items: Vec<Issue>,
    pub next_cursor: Option<IssueCursor>,
}

const ISSUE_RANK_SQL: &str =
    "CASE ai.severity WHEN 'ERROR' THEN 0 WHEN 'WARNING' THEN 1 ELSE 2 END";

fn row_to_issue(r: &rusqlite::Row<'_>) -> rusqlite::Result<Issue> {
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
    let category: Option<String> = r.get(11)?;
    let confidence: Option<String> = r.get(12)?;
    let cwe: Option<i64> = r.get(13)?;

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
        category,
        confidence,
        cwe: cwe.map(|value| value as u32),
    })
}

const ISSUE_COLUMNS: &str = "ai.rule_id, ai.line_number, ai.line_content, ai.description, \
     ai.file_path, ai.severity, ai.object_id, ai.object_type, ai.object_package, \
     ai.object_member, ai.object_container, ai.category, ai.confidence, ai.cwe, ai.id";

/// Issues for a given run, ordered by severity.
///
/// GX-011: reconstruye la identidad de objeto cuando existe (suficiente
/// para reabrir el miembro correcto del XPZ en el visor).
pub fn get_issues_for_run(conn: &Connection, run_id: i64) -> Result<Vec<Issue>> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {ISSUE_COLUMNS} FROM audit_issues ai WHERE ai.audit_run_id = ?1 \
         ORDER BY {ISSUE_RANK_SQL}, ai.id"
    ))?;
    let rows = stmt.query_map([run_id], row_to_issue)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Página keyset de issues de una corrida (C01): `after = None` comienza por
/// el primero; el cursor se toma de [`IssuesPage::next_cursor`].
pub fn get_issues_page(
    conn: &Connection,
    run_id: i64,
    after: Option<IssueCursor>,
    limit: i64,
) -> Result<IssuesPage> {
    let limit = limit.clamp(1, 500);
    let fetch = limit + 1;

    let mut out: Vec<(Issue, u8, i64)> = Vec::with_capacity(fetch as usize);
    match after {
        Some(cursor) => {
            let mut stmt = conn.prepare_cached(&format!(
                "SELECT {ISSUE_COLUMNS}, {ISSUE_RANK_SQL} AS rank \
                 FROM audit_issues ai WHERE ai.audit_run_id = ?1 \
                   AND ({ISSUE_RANK_SQL} > ?2 OR ({ISSUE_RANK_SQL} = ?2 AND ai.id > ?3)) \
                 ORDER BY {ISSUE_RANK_SQL}, ai.id LIMIT ?4"
            ))?;
            let rows = stmt.query_map(
                rusqlite::params![run_id, cursor.rank as i64, cursor.id, fetch],
                |r| {
                    let id: i64 = r.get(14)?;
                    let rank: i64 = r.get(15)?;
                    Ok((row_to_issue(r)?, rank as u8, id))
                },
            )?;
            for row in rows {
                out.push(row?);
            }
        }
        None => {
            let mut stmt = conn.prepare_cached(&format!(
                "SELECT {ISSUE_COLUMNS}, {ISSUE_RANK_SQL} AS rank \
                 FROM audit_issues ai WHERE ai.audit_run_id = ?1 \
                 ORDER BY {ISSUE_RANK_SQL}, ai.id LIMIT ?2"
            ))?;
            let rows = stmt.query_map(rusqlite::params![run_id, fetch], |r| {
                let id: i64 = r.get(14)?;
                let rank: i64 = r.get(15)?;
                Ok((row_to_issue(r)?, rank as u8, id))
            })?;
            for row in rows {
                out.push(row?);
            }
        }
    }

    let has_more = out.len() as i64 > limit;
    if has_more {
        out.truncate(limit as usize);
    }
    let next_cursor = if has_more {
        out.last().map(|(_, rank, id)| IssueCursor {
            rank: *rank,
            id: *id,
        })
    } else {
        None
    };
    Ok(IssuesPage {
        items: out.into_iter().map(|(issue, _, _)| issue).collect(),
        next_cursor,
    })
}

/// Keyset pagination for history: runs older than `before_id` (exclusive),
/// newest first (C01). `None` starts from the newest run.
pub fn list_runs_page(
    conn: &Connection,
    before_id: Option<i64>,
    limit: i64,
) -> Result<Vec<AuditRunSummary>> {
    let limit = limit.clamp(1, 500);
    let sql = match before_id {
        Some(_) => {
            "SELECT id, file_path, file_name, started_at, total_findings, errors, warnings, info, \
                    verdict, policy, qg_passed \
             FROM audit_runs WHERE id < ?1 ORDER BY id DESC LIMIT ?2"
        }
        None => {
            "SELECT id, file_path, file_name, started_at, total_findings, errors, warnings, info, \
                    verdict, policy, qg_passed \
             FROM audit_runs ORDER BY id DESC LIMIT ?1"
        }
    };
    let mut stmt = conn.prepare_cached(sql)?;
    let map_row = |r: &rusqlite::Row<'_>| {
        Ok(AuditRunSummary {
            id: r.get(0)?,
            file_path: r.get(1)?,
            file_name: r.get(2)?,
            started_at: r.get(3)?,
            total_findings: r.get(4)?,
            errors: r.get(5)?,
            warnings: r.get(6)?,
            info: r.get(7)?,
            verdict: r.get(8)?,
            policy: r.get(9)?,
            qg_passed: r.get::<_, Option<bool>>(10)?.unwrap_or(false),
        })
    };
    let mut out = Vec::new();
    match before_id {
        Some(before) => {
            let rows = stmt.query_map(rusqlite::params![before, limit], map_row)?;
            for row in rows {
                out.push(row?);
            }
        }
        None => {
            let rows = stmt.query_map(rusqlite::params![limit], map_row)?;
            for row in rows {
                out.push(row?);
            }
        }
    }
    Ok(out)
}

/// Contenedores registrados por los hallazgos de una corrida (C04): scope
/// válido para el visor histórico.
pub fn containers_for_run(conn: &Connection, run_id: i64) -> Result<Vec<String>> {
    let mut stmt = conn.prepare_cached(
        "SELECT DISTINCT object_container FROM audit_issues \
         WHERE audit_run_id = ?1 AND object_container IS NOT NULL",
    )?;
    let rows = stmt.query_map([run_id], |r| r.get::<_, String>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Retention (C01): conserva las `keep` corridas más nuevas y borra el resto
/// (los issues caen por `ON DELETE CASCADE`). Devuelve las corridas borradas.
pub fn prune_runs(conn: &Connection, keep: i64) -> Result<usize> {
    let keep = keep.max(1);
    let deleted = conn.execute(
        "DELETE FROM audit_runs WHERE id NOT IN \
         (SELECT id FROM audit_runs ORDER BY id DESC LIMIT ?1)",
        rusqlite::params![keep],
    )?;
    Ok(deleted)
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
            category: None,
            confidence: None,
            cwe: None,
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

    fn issue_with_severity(rule_id: &str, severity: Severity, line: u32) -> Issue {
        Issue {
            rule_id: rule_id.to_string(),
            severity,
            line_number: line,
            line_content: format!("linea {line}"),
            description: format!("desc {rule_id}"),
            file_path: std::path::PathBuf::from("sample.xpz"),
            object: None,
            category: None,
            confidence: None,
            cwe: None,
        }
    }

    /// C01: la paginación keyset recorre TODOS los issues una sola vez, en
    /// orden severidad→id, sin duplicados ni saltos.
    #[test]
    fn issues_keyset_pagination_walks_every_issue_once() {
        let mut conn = crate::db::init_memory_db().unwrap();
        let issues: Vec<Issue> = (0..7)
            .map(|i| match i % 3 {
                0 => issue_with_severity("GX.1.1", Severity::Warning, i),
                1 => issue_with_severity("GX.2.6", Severity::Error, i),
                _ => issue_with_severity("GX.1.2", Severity::Info, i),
            })
            .collect();
        let run_id = persist_run(&mut conn, &golden_run(), &issues).unwrap();

        let mut collected: Vec<(String, u32)> = Vec::new();
        let mut cursor = None;
        loop {
            let page = get_issues_page(&conn, run_id, cursor, 2).unwrap();
            assert!(page.items.len() <= 2);
            for issue in &page.items {
                collected.push((issue.rule_id.clone(), issue.line_number));
            }
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        assert_eq!(collected.len(), 7, "sin duplicados ni saltos");
        let severities: Vec<&str> = collected
            .iter()
            .map(|(rule, _)| match rule.as_str() {
                "GX.2.6" => "ERROR",
                "GX.1.1" => "WARNING",
                _ => "INFO",
            })
            .collect();
        let mut sorted = severities.clone();
        sorted.sort_by_key(|s| match *s {
            "ERROR" => 0,
            "WARNING" => 1,
            _ => 2,
        });
        assert_eq!(severities, sorted, "orden severidad→id");
    }

    /// C01: la retención conserva las corridas más nuevas y el CASCADE borra
    /// los issues de las corridas podadas.
    #[test]
    fn prune_runs_keeps_newest_and_cascades_issues() {
        let mut conn = crate::db::init_memory_db().unwrap();
        let mut run_ids = Vec::new();
        for _ in 0..5 {
            let run_id = persist_run(
                &mut conn,
                &golden_run(),
                &[issue_with_severity("GX.2.6", Severity::Error, 1)],
            )
            .unwrap();
            run_ids.push(run_id);
        }

        let deleted = prune_runs(&conn, 2).unwrap();
        assert_eq!(deleted, 3);
        let remaining = list_runs_page(&conn, None, 10).unwrap();
        assert_eq!(remaining.len(), 2);
        assert_eq!(remaining[0].id, run_ids[4], "la más nueva se conserva");
        assert_eq!(remaining[1].id, run_ids[3]);

        let orphan_issues: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM audit_issues WHERE audit_run_id NOT IN \
                 (SELECT id FROM audit_runs)",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(orphan_issues, 0, "CASCADE limpia los issues podados");
    }

    /// C01: el historial pagina por keyset (before_id) sin repetir corridas.
    #[test]
    fn runs_keyset_pagination_is_stable() {
        let mut conn = crate::db::init_memory_db().unwrap();
        let mut ids = Vec::new();
        for _ in 0..5 {
            ids.push(persist_run(&mut conn, &golden_run(), &[]).unwrap());
        }
        let first = list_runs_page(&conn, None, 2).unwrap();
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].id, ids[4]);
        let second = list_runs_page(&conn, Some(first[1].id), 2).unwrap();
        assert_eq!(second.len(), 2);
        assert_eq!(second[0].id, ids[2]);
        assert!(second.iter().all(|r| r.id < first[1].id));
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
