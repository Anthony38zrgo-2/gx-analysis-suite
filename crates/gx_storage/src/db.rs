//! Database connection, path resolution and migration runner.

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use rusqlite_migration::{Migrations, M};

use crate::{Result, StorageError};

const MIGRATION_V1: &str = include_str!("../../../migrations/V001__initial_schema.sql");
const MIGRATION_V2: &str = include_str!("../../../migrations/V002__seed_rules_and_settings.sql");
const MIGRATION_V3: &str = include_str!("../../../migrations/V003__audit_object_identity.sql");

/// Todas las migraciones, en orden (V001→V003).
pub fn all_migrations() -> Migrations<'static> {
    Migrations::new(vec![
        M::up(MIGRATION_V1),
        M::up(MIGRATION_V2),
        M::up(MIGRATION_V3),
    ])
}

/// Run all pending migrations against an open connection.
pub fn run_migrations(conn: &mut Connection) -> Result<()> {
    all_migrations()
        .to_latest(conn)
        .map_err(|e| StorageError::Migration(e.to_string()))
}

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

/// Open (creating if necessary) the database at `path`, run migrations and
/// seed + validate the rule catalog (GX-009).
pub fn init_db_at(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    let mut conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL").ok();
    conn.pragma_update(None, "foreign_keys", "ON").ok();
    run_migrations(&mut conn)?;
    crate::seed::seed_and_validate(&conn)?;
    Ok(conn)
}

/// Open (creating if necessary) the database at [`get_db_path`] and run
/// migrations.
pub fn init_db() -> Result<Connection> {
    init_db_at(&get_db_path())
}

/// Open an in-memory database, run migrations and seed (useful for tests).
pub fn init_memory_db() -> Result<Connection> {
    init_db_at(Path::new(":memory:"))
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

    /// GX-009: una base fresca tiene 30 filas de catálogo (24 concretas) y
    /// exactamente 15 reglas concretas habilitadas.
    #[test]
    fn fresh_db_has_full_catalog() {
        let conn = init_memory_db().unwrap();
        let concrete: usize = conn
            .query_row(
                "SELECT COUNT(*) FROM rules WHERE is_abstract = 0",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(concrete, 24);
        let enabled: usize = conn
            .query_row(
                "SELECT COUNT(*) FROM rules WHERE is_abstract = 0 AND enabled = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(enabled, 15);
    }

    /// GX-009: la re-inicialización es idempotente y PRESERVA los flags de
    /// usuario (segunda corrida no cambia nada).
    #[test]
    fn reseed_is_idempotent_and_preserves_user_flags() {
        let dir = std::env::temp_dir().join("gx_storage_reseed_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("gx_linter.db");

        let conn = init_db_at(&db).unwrap();
        crate::dao::rules_dao::set_enabled(&conn, "GX.2.3", false).unwrap();
        drop(conn);

        // Segunda apertura: migraciones + seed no rompen el flag del usuario.
        let conn = init_db_at(&db).unwrap();
        let enabled = crate::dao::rules_dao::is_rule_enabled(&conn, "GX.2.3").unwrap();
        assert!(!enabled, "el flag del usuario debe preservarse");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// GX-011: migrar una base existente (V1→V3) preserva los datos del
    /// usuario.
    #[test]
    fn migration_preserves_existing_data() {
        let dir = std::env::temp_dir().join("gx_storage_migrate_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("gx_linter.db");

        // Base "antigua": sólo V1+V2, sin seed (con los pragmas previos de
        // init_db_at, replicando la apertura del usuario real).
        let mut conn = Connection::open(&db).unwrap();
        conn.pragma_update(None, "journal_mode", "WAL").ok();
        Migrations::new(vec![M::up(MIGRATION_V1), M::up(MIGRATION_V2)])
            .to_latest(&mut conn)
            .unwrap();
        conn.execute(
            "INSERT INTO rules(id, raw_id, name, description, severity, enabled, \
             is_abstract, triggers) VALUES ('GX.2.3','2.3','For Each anidados','desc',\
             'ERROR',1,0,'[]')",
            [],
        )
        .unwrap();
        drop(conn);

        // Apertura actual: agrega V3 sin borrar datos.
        let conn = init_db_at(&db).unwrap();
        let raw_id: String = conn
            .query_row("SELECT raw_id FROM rules WHERE id='GX.2.3'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(
            raw_id, "2.3",
            "los datos del usuario deben sobrevivir la migración"
        );
        let has_verdict: bool = conn
            .prepare("SELECT verdict FROM audit_runs LIMIT 0")
            .is_ok();
        assert!(has_verdict, "las columnas V003 deben existir");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
