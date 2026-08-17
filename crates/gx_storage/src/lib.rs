//! gx_storage — persistencia SQLite (parámetros, reglas, historial).

pub mod dao;
pub mod db;
pub mod seed;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("migration error: {0}")]
    Migration(String),
    #[error("csv error: {0}")]
    Csv(String),
    #[error("seed error: {0}")]
    Seed(String),
    #[error(transparent)]
    Rusqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Pool(#[from] r2d2::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, StorageError>;
