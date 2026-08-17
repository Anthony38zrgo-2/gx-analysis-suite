//! Filesystem helpers for locating and validating GeneXus source files.
//!
//! Port of `gx_linter/app/core/filesystem.py`.

use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

/// Accepted plain-text GeneXus export extensions.
const SOURCE_EXTENSIONS: &[&str] = &[".txt", ".prg", ".gxd", ".src", ".xpz"];

/// Extensions excluded when falling back to "any file".
const EXCLUDED_EXTENSIONS: &[&str] = &[
    ".py",
    ".pyc",
    ".csv",
    ".pdf",
    ".gitkeep",
    ".md",
    ".txt_backup",
];

/// Static helper for filesystem validation and source discovery.
pub struct Filesystem;

impl Filesystem {
    /// Validate a directory path; returns the resolved `PathBuf` or an error.
    pub fn validate_directory(path_str: &str) -> Result<PathBuf> {
        if path_str.trim().is_empty() {
            bail!("El path proporcionado está vacío.");
        }
        let path = Path::new(path_str.trim()).to_path_buf();
        if !path.exists() {
            bail!("El path '{}' no existe.", path_str);
        }
        if !path.is_dir() {
            bail!("El path '{}' no es un directorio válido.", path_str);
        }
        Ok(path.canonicalize().unwrap_or(path))
    }

    /// Validate a file path; returns the resolved `PathBuf` or an error.
    pub fn validate_file(path_str: &str) -> Result<PathBuf> {
        if path_str.trim().is_empty() {
            bail!("El path de archivo proporcionado está vacío.");
        }
        let path = Path::new(path_str.trim()).to_path_buf();
        if !path.exists() {
            bail!("El archivo '{}' no existe.", path_str);
        }
        if !path.is_file() {
            bail!("El path '{}' no es un archivo válido.", path_str);
        }
        Ok(path.canonicalize().unwrap_or(path))
    }

    /// Recursively find GeneXus source files under `path`.
    ///
    /// If `path` is a file, returns a single-element list. Otherwise it
    /// walks the tree, preferring known extensions; if none are found it
    /// falls back to any non-hidden file that is not in the excluded set.
    pub fn find_source_files(path: &Path) -> Vec<PathBuf> {
        if path.is_file() {
            return vec![path.to_path_buf()];
        }

        let mut found: Vec<PathBuf> = Vec::new();
        for entry in walkdir::WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            let name = match p.file_name().and_then(|n| n.to_str()) {
                Some(n) => n,
                None => continue,
            };
            if name.starts_with('.') {
                continue;
            }
            let ext = p
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| format!(".{e}"))
                .unwrap_or_default()
                .to_lowercase();
            if SOURCE_EXTENSIONS.contains(&ext.as_str()) {
                found.push(p.to_path_buf());
            }
        }

        if !found.is_empty() {
            found.sort();
            return found;
        }

        for entry in walkdir::WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            let name = match p.file_name().and_then(|n| n.to_str()) {
                Some(n) => n,
                None => continue,
            };
            if name.starts_with('.') {
                continue;
            }
            let ext = p
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| format!(".{e}"))
                .unwrap_or_default()
                .to_lowercase();
            if !EXCLUDED_EXTENSIONS.contains(&ext.as_str()) {
                found.push(p.to_path_buf());
            }
        }

        found.sort();
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_directory_rejects_empty() {
        let err = Filesystem::validate_directory("   ").unwrap_err();
        assert_eq!(err.to_string(), "El path proporcionado está vacío.");
    }

    #[test]
    fn find_source_files_returns_single_for_file() {
        let tmp = std::env::temp_dir().join("gx_fs_test.txt");
        std::fs::write(&tmp, "for each Customer\n").unwrap();
        let res = Filesystem::find_source_files(&tmp);
        assert_eq!(res.len(), 1);
        let _ = std::fs::remove_file(&tmp);
    }
}
