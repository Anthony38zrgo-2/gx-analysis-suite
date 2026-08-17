//! Seed rules and settings from `Reglas.csv`.
//!
//! Mirrors `sync_rules.py` import logic. Triggers are taken from the
//! hard-coded table in the migration plan (based on the real Python
//! rule files), and the `enabled` flag reproduces the project's
//! `config/rules.json` so parity with the Python engine is exact.

use std::collections::HashMap;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use rusqlite::Connection;

use crate::{Result, StorageError};

/// Trigger tokens per `raw_id` (from migration plan, ST-03.3).
static TRIGGERS: LazyLock<HashMap<&'static str, &'static [&'static str]>> = LazyLock::new(|| {
    use std::collections::HashMap;
    let mut m: HashMap<&'static str, &'static [&'static str]> = HashMap::new();
    m.insert("1.1", &["&"]);
    m.insert("1.2", &["*"]);
    m.insert("1.3", &["for each"]);
    m.insert("1.3.1", &["*"]);
    m.insert("1.3.2", &[]);
    m.insert("1.3.3", &["case"]);
    m.insert("1.4.1", &["=", "&"]);
    m.insert("1.4.2", &["if", "case"]);
    m.insert("1.4.3", &["*"]);
    m.insert("1.5", &["if", "case"]);
    m.insert("1.6.1", &["do"]);
    m.insert("1.6.2", &["sub"]);
    m.insert("1.7.1", &["*"]);
    m.insert("1.7.2", &["*"]);
    m.insert("2.1", &["where", "for each"]);
    m.insert("2.2", &["where", "for each"]);
    m.insert("2.3", &[]);
    m.insert("2.4", &["where", "for each"]);
    m.insert("2.5", &["where", "for each"]);
    m.insert("2.6", &["sub"]);
    m.insert("2.7.1", &["for each", "do"]);
    m.insert("2.7.2", &["=", "&"]);
    m.insert("2.7.3", &["=", "&"]);
    m.insert("2.7.4", &["&"]);
    m
});

/// Abstract grouping nodes — present in CSV as category headers, not rules.
static ABSTRACT_RAW_IDS: &[&str] = &["1", "1.4", "1.6", "1.7", "2.0", "2.7"];

/// Enabled flags reproducing `config/rules.json` (15 enabled).
static DEFAULT_ENABLED: LazyLock<HashMap<&'static str, bool>> = LazyLock::new(|| {
    use std::collections::HashMap;
    let mut m: HashMap<&'static str, bool> = HashMap::new();
    for id in [
        "GX.1.1", "GX.1.2", "GX.1.3.1", "GX.1.4.1", "GX.1.4.2", "GX.1.6.1", "GX.1.6.2", "GX.1.7.1",
    ] {
        m.insert(id, false);
    }
    for id in [
        "GX.1.3", "GX.1.3.2", "GX.1.3.3", "GX.1.4.3", "GX.1.5", "GX.1.7.2", "GX.2.1", "GX.2.2",
        "GX.2.3", "GX.2.4", "GX.2.5", "GX.2.6", "GX.2.7.1", "GX.2.7.2", "GX.2.7.3",
    ] {
        m.insert(id, true);
    }
    m
});

static RULE_NUMBER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*(\d+(?:\.\d+)*)\s").unwrap());

fn category_for(raw_id: &str) -> &'static str {
    if raw_id.starts_with("2.") {
        "2.0"
    } else if raw_id.starts_with("1.4") {
        "1.4"
    } else if raw_id.starts_with("1.6") {
        "1.6"
    } else if raw_id.starts_with("1.7") {
        "1.7"
    } else {
        "1"
    }
}

/// Import `Reglas.csv` into the `rules` table (idempotent upsert).
pub fn import_reglas_csv(conn: &Connection, csv_path: &Path) -> Result<usize> {
    let bytes = std::fs::read(csv_path)?;
    let hash = fnv1a_64(&bytes);
    let text = String::from_utf8_lossy(&bytes).to_string();

    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(text.as_bytes());

    let mut inserted = 0usize;
    let mut qg_pct: Option<f32> = None;

    for record in reader.records() {
        let record = record.map_err(|e| StorageError::Csv(e.to_string()))?;
        let fields: Vec<String> = record.iter().map(|s| s.to_string()).collect();
        if fields.iter().all(|f| f.trim().is_empty()) {
            continue;
        }

        // Percentage-of-error setting row.
        let joined = fields.join(" ");
        if joined.to_lowercase().contains("porcentaje de error") {
            for f in &fields {
                if let Ok(v) = f.trim().parse::<f32>() {
                    qg_pct = Some(v);
                    break;
                }
            }
            continue;
        }

        // Locate the rule-number field.
        let mut matched: Option<(String, String)> = None;
        for f in &fields {
            if let Some(c) = RULE_NUMBER_RE.captures(f) {
                matched = Some((c.get(1).unwrap().as_str().to_string(), f.trim().to_string()));
                break;
            }
        }
        let (raw_id, name_field) = match matched {
            Some(m) => m,
            None => continue,
        };
        if ABSTRACT_RAW_IDS.contains(&raw_id.as_str()) {
            continue;
        }
        let triggers = match TRIGGERS.get(raw_id.as_str()) {
            Some(t) => t,
            None => continue,
        };

        // Severity: a field containing "error" (case-insensitive) → ERROR.
        let severity = fields
            .iter()
            .find(|f| {
                let l = f.to_lowercase();
                l == "error" || l == "advertencia"
            })
            .map(|f| {
                if f.to_lowercase().contains("error") {
                    "ERROR"
                } else {
                    "WARNING"
                }
            })
            .unwrap_or("WARNING");

        let description = fields
            .iter()
            .find(|f| {
                let t = f.trim();
                !t.is_empty()
                    && !RULE_NUMBER_RE.is_match(t)
                    && t.to_lowercase() != "error"
                    && t.to_lowercase() != "advertencia"
            })
            .cloned()
            .unwrap_or_default();

        let id = format!("GX.{raw_id}");
        let enabled = DEFAULT_ENABLED.get(id.as_str()).copied().unwrap_or(true);
        let triggers_json =
            serde_json::to_string(triggers).map_err(|e| StorageError::Seed(e.to_string()))?;

        conn.execute(
            "INSERT INTO rules(id, raw_id, name, description, severity, category_id, \
             enabled, is_abstract, triggers) \
             VALUES (?1,?2,?3,?4,?5,?6, COALESCE((SELECT enabled FROM rules WHERE id=?1), ?7), 0, ?8) \
             ON CONFLICT(id) DO UPDATE SET \
               name=excluded.name, description=excluded.description, severity=excluded.severity, \
               category_id=excluded.category_id, triggers=excluded.triggers, \
               updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')",
            (
                &id,
                &raw_id,
                &name_field,
                &description,
                severity,
                category_for(&raw_id),
                &enabled,
                &triggers_json,
            ),
        )?;
        inserted += 1;
    }

    if let Some(pct) = qg_pct {
        crate::dao::settings_dao::set(conn, "qg_threshold_pct", &pct.to_string())?;
    }
    crate::dao::settings_dao::set(conn, "seed_csv_hash", &format!("{hash:016x}"))?;

    Ok(inserted)
}

/// Cheap FNV-1a 64-bit hash (avoids an extra crypto dependency).
fn fnv1a_64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in data {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Seed only if the `rules` table is empty; returns inserted count.
pub fn seed_if_empty(conn: &Connection, csv_path: &Path) -> Result<usize> {
    let count: usize = conn.query_row("SELECT COUNT(*) FROM rules", [], |r| r.get(0))?;
    if count > 0 {
        return Ok(0);
    }
    import_reglas_csv(conn, csv_path)
}
