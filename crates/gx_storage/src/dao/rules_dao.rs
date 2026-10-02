//! Rule configuration and activation DAO.

use std::collections::HashMap;

use rusqlite::Connection;
use serde::Serialize;

use crate::Result;

/// A row from the `rules` table.
#[derive(Debug, Clone, Serialize)]
pub struct RuleRecord {
    pub id: String,
    pub raw_id: String,
    pub name: String,
    pub description: String,
    pub severity: String,
    pub category_id: Option<String>,
    pub enabled: bool,
    pub is_abstract: bool,
    pub triggers: String,
}

/// Load the full `rule_id -> enabled` configuration.
pub fn load_rule_config(conn: &Connection) -> Result<HashMap<String, bool>> {
    let mut stmt = conn.prepare("SELECT id, enabled FROM rules WHERE is_abstract = 0")?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?)))?;
    let mut map = HashMap::new();
    for row in rows {
        let (id, enabled) = row?;
        map.insert(id, enabled);
    }
    Ok(map)
}

/// Whether a rule is enabled (GX-009, fail-closed).
///
/// Una fila faltante = DESHABILITADA (nunca se escanea una regla sin
/// registro en el catálogo); los errores de SQL se PROPAGAN en lugar de
/// interpretarse como "todas habilitadas".
pub fn is_rule_enabled(conn: &Connection, rule_id: &str) -> Result<bool> {
    let mut stmt = conn.prepare("SELECT enabled FROM rules WHERE id = ?1")?;
    let mut rows = stmt.query_map([rule_id], |r| r.get::<_, bool>(0))?;
    match rows.next() {
        Some(Ok(v)) => Ok(v),
        Some(Err(e)) => Err(e.into()),
        None => Ok(false),
    }
}

/// Whether a rule id exists in the catalog.
pub fn exists(conn: &Connection, rule_id: &str) -> Result<bool> {
    let count: i64 =
        conn.query_row("SELECT COUNT(*) FROM rules WHERE id = ?1", [rule_id], |r| {
            r.get(0)
        })?;
    Ok(count > 0)
}

/// Persist an enabled flag for a rule.
pub fn set_enabled(conn: &Connection, rule_id: &str, enabled: bool) -> Result<()> {
    conn.execute(
        "UPDATE rules SET enabled = ?1 WHERE id = ?2",
        rusqlite::params![enabled, rule_id],
    )?;
    Ok(())
}

/// All rule records.
pub fn get_all(conn: &Connection) -> Result<Vec<RuleRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id, raw_id, name, description, severity, category_id, enabled, is_abstract, triggers \
         FROM rules ORDER BY raw_id",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(RuleRecord {
            id: r.get(0)?,
            raw_id: r.get(1)?,
            name: r.get(2)?,
            description: r.get(3)?,
            severity: r.get(4)?,
            category_id: r.get(5)?,
            enabled: r.get(6)?,
            is_abstract: r.get(7)?,
            triggers: r.get(8)?,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Ids of all enabled, non-abstract rules.
pub fn get_enabled_ids(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt =
        conn.prepare("SELECT id FROM rules WHERE is_abstract = 0 AND enabled = 1 ORDER BY raw_id")?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Number of enabled, non-abstract rules.
pub fn enabled_count(conn: &Connection) -> Result<usize> {
    let count: usize = conn.query_row(
        "SELECT COUNT(*) FROM rules WHERE is_abstract = 0 AND enabled = 1",
        [],
        |r| r.get(0),
    )?;
    Ok(count)
}
