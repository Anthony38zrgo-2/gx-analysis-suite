//! Database connection, path resolution and migration runner.

use std::path::PathBuf;

use rusqlite::Connection;
use rusqlite_migration::{Migrations, M};

use crate::{Result, StorageError};

const MIGRATION_V1: &str = include_str!("../../../migrations/V001__initial_schema.sql");
const MIGRATION_V2: &str = include_str!("../../../migrations/V002__seed_rules_and_settings.sql");

/// Resolve the SQLite database path.
///
/// Uses `%APPDATA%/GX/Linter/gx_linter.db` on Windows (via `directories`),
/// falling back to `./data/gx_linter.db`.
pub fn get_db_path() -> PathBuf {
    if let Some(proj) = directories::ProjectDirs::from("com", "GX", "Linter") {
        let dir = proj.data_dir().to_path_buf();
        let _ = std::fs::create_dir_all(&dir);
        return dir.join("gx_linter.db");
    }
    let fallback = PathBuf::from("./data");
    let _ = std::fs::create_dir_all(&fallback);
    fallback.join("gx_linter.db")
}

/// Run all pending migrations against an open connection.
pub fn run_migrations(conn: &mut Connection) -> Result<()> {
    let migrations = Migrations::new(vec![M::up(MIGRATION_V1), M::up(MIGRATION_V2)]);
    migrations
        .to_latest(conn)
        .map_err(|e| StorageError::Migration(e.to_string()))
}

/// Open (creating if necessary) the database at [`get_db_path`] and run
/// migrations.
pub fn init_db() -> Result<Connection> {
    let path = get_db_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut conn = Connection::open(&path)?;
    conn.pragma_update(None, "journal_mode", "WAL").ok();
    conn.pragma_update(None, "foreign_keys", "ON").ok();
    run_migrations(&mut conn)?;
    Ok(conn)
}

/// Open an in-memory database and run migrations (useful for tests).
pub fn init_memory_db() -> Result<Connection> {
    let mut conn = Connection::open_in_memory()?;
    conn.pragma_update(None, "foreign_keys", "ON").ok();
    run_migrations(&mut conn)?;
    Ok(conn)
}

/// Return a thread-safe connection pool for GUI/CLI concurrency.
pub fn get_pool() -> Result<r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>> {
    let manager = r2d2_sqlite::SqliteConnectionManager::file(get_db_path()).with_init(|c| {
        c.pragma_update(None, "journal_mode", "WAL").ok();
        c.pragma_update(None, "foreign_keys", "ON").ok();
        Ok(())
    });
    let pool = r2d2::Pool::builder().build(manager)?;
    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_create_schema() {
        let conn = init_memory_db().unwrap();
        let count: usize = conn
            .query_row("SELECT COUNT(*) FROM rules", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
        let settings: usize = conn
            .query_row("SELECT COUNT(*) FROM app_settings", [], |r| r.get(0))
            .unwrap();
        assert!(settings >= 7);
    }
}
