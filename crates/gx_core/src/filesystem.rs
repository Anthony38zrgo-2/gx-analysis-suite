//! Filesystem helpers for locating and validating GeneXus source files.
//!
//! Port of `gx_linter/app/core/filesystem.py`.

use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

/// Accepted GeneXus source extensions (GX-007: incluye .xml).
const SOURCE_EXTENSIONS: &[&str] = &[".txt", ".xml", ".xpz", ".prg", ".gxd", ".src"];

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
    /// walks the tree returning only files with known source extensions.
    /// GX-007: NO hay fallback "cualquier archivo" — los archivos sin
    /// extensión fuente NO se lintean; el caller decide el error.
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

    #[test]
    fn find_source_files_includes_xml() {
        let dir = std::env::temp_dir().join("gx_fs_dir_xml");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("obj.txt"), "code\n").unwrap();
        std::fs::write(
            dir.join("obj.xml"),
            "<Root><Events><![CDATA[=]]></Events></Root>",
        )
        .unwrap();
        std::fs::write(dir.join("data.csv"), "a,b\n").unwrap();
        std::fs::write(dir.join("doc.pdf"), "pdf").unwrap();

        let res = Filesystem::find_source_files(&dir);
        let names: Vec<String> = res
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, vec!["obj.txt".to_string(), "obj.xml".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// GX-007: sin fallback "cualquier archivo" — extensiones ajenas no se
    /// lintean; el resultado es una lista vacía (el caller reporta el error).
    #[test]
    fn find_source_files_rejects_unrelated_extensions() {
        let dir = std::env::temp_dir().join("gx_fs_dir_other");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("data.csv"), "a,b\n").unwrap();
        std::fs::write(dir.join("doc.md"), "doc").unwrap();

        let res = Filesystem::find_source_files(&dir);
        assert!(res.is_empty(), "no debe lintear fallback: {res:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
