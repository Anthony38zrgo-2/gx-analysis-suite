//! Application settings DAO (thresholds, UI prefs).

use rusqlite::Connection;

use crate::{Result, StorageError};

fn value_type_of(value: &str) -> &'static str {
    if value.parse::<bool>().is_ok() {
        "boolean"
    } else if value.parse::<i64>().is_ok() {
        "integer"
    } else if value.parse::<f64>().is_ok() {
        "float"
    } else {
        "string"
    }
}

/// Read a raw setting value.
pub fn get(conn: &Connection, key: &str) -> Result<Option<String>> {
    let mut stmt = conn.prepare("SELECT value FROM app_settings WHERE key = ?1")?;
    let mut rows = stmt.query_map([key], |r| r.get::<_, String>(0))?;
    match rows.next() {
        Some(Ok(v)) => Ok(Some(v)),
        Some(Err(e)) => Err(e.into()),
        None => Ok(None),
    }
}

/// Set a setting value, inferring its `value_type`.
pub fn set(conn: &Connection, key: &str, value: &str) -> Result<()> {
    let value_type = value_type_of(value);
    conn.execute(
        "INSERT INTO app_settings(key, value, value_type) VALUES (?1, ?2, ?3) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, value_type = excluded.value_type",
        [key, value, value_type],
    )?;
    Ok(())
}

pub fn get_int(conn: &Connection, key: &str) -> Result<Option<i64>> {
    match get(conn, key)? {
        Some(v) => v
            .parse::<i64>()
            .map(Some)
            .map_err(|e| StorageError::Seed(e.to_string())),
        None => Ok(None),
    }
}

pub fn get_float(conn: &Connection, key: &str) -> Result<Option<f64>> {
    match get(conn, key)? {
        Some(v) => v
            .parse::<f64>()
            .map(Some)
            .map_err(|e| StorageError::Seed(e.to_string())),
        None => Ok(None),
    }
}

/// Quality Gate threshold percentage (GUI algorithm). Default 10.0.
pub fn get_qg_threshold(conn: &Connection) -> f32 {
    get_float(conn, "qg_threshold_pct")
        .ok()
        .flatten()
        .unwrap_or(10.0) as f32
}

/// CLI absolute threshold: max errors. Default 0.
pub fn get_max_errors(conn: &Connection) -> u32 {
    get_int(conn, "max_errors").ok().flatten().unwrap_or(0) as u32
}

/// CLI absolute threshold: max warnings. Default 999999.
pub fn get_max_warnings(conn: &Connection) -> u32 {
    get_int(conn, "max_warnings")
        .ok()
        .flatten()
        .unwrap_or(999_999) as u32
}
