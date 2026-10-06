//! Filesystem helpers for locating and validating GeneXus source files.
//!
//! Port of `gx_linter/app/core/filesystem.py`.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{bail, Result};

/// Accepted GeneXus source extensions (GX-007: incluye .xml).
///
/// A01/F02: incluye `.zip`/`.rar` porque la extracción los soporta por magic
/// bytes y el diálogo nativo los ofrece; discovery y extracción comparten la
/// misma política.
pub const SOURCE_EXTENSIONS: &[&str] = &[
    ".txt", ".xml", ".xpz", ".zip", ".rar", ".prg", ".gxd", ".src",
];

/// Whether `path` has a supported GeneXus source extension (case-insensitive).
///
/// Usado por el desktop para validar la selección del diálogo nativo (GX-016)
/// con la MISMA lista que el discovery del engine.
pub fn is_source_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| format!(".{}", e.to_lowercase()))
        .map(|ext| SOURCE_EXTENSIONS.contains(&ext.as_str()))
        .unwrap_or(false)
}

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
        discover_source_files(path).files
    }
}

/// Archivo descartado durante el discovery con su motivo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryError {
    pub path: PathBuf,
    pub message: String,
}

/// Reporte de discovery con cobertura estructurada (A01/F02).
///
/// `errors` NUNCA se descarta en silencio: un subtree inaccesible se reporta
/// y el runtime lo convierte en fallo de scan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiscoveryReport {
    pub files: Vec<PathBuf>,
    /// Archivos con extensión no soportada u ocultos.
    pub excluded_files: usize,
    pub errors: Vec<DiscoveryError>,
    /// La caminata se detuvo por cancelación (A04).
    pub cancelled: bool,
}

/// Descubre archivos fuente bajo `path` reportando exclusiones y errores.
pub fn discover_source_files(path: &Path) -> DiscoveryReport {
    discover_source_files_with_cancel(path, None)
}

/// [`discover_source_files`] con checkpoint de cancelación (A04/F08).
pub fn discover_source_files_with_cancel(
    path: &Path,
    cancel: Option<&AtomicBool>,
) -> DiscoveryReport {
    if path.is_file() {
        return DiscoveryReport {
            files: vec![path.to_path_buf()],
            ..Default::default()
        };
    }

    let mut report = DiscoveryReport::default();
    for entry in walkdir::WalkDir::new(path) {
        if cancel.map(|c| c.load(Ordering::Relaxed)).unwrap_or(false) {
            report.cancelled = true;
            break;
        }
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                report.errors.push(DiscoveryError {
                    path: e
                        .path()
                        .map(|p| p.to_path_buf())
                        .unwrap_or_else(|| path.to_path_buf()),
                    message: format!("No se pudo recorrer el directorio: {e}"),
                });
                continue;
            }
        };
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        let name = match p.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => {
                report.excluded_files += 1;
                continue;
            }
        };
        if name.starts_with('.') {
            report.excluded_files += 1;
            continue;
        }
        let ext = p
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| format!(".{e}"))
            .unwrap_or_default()
            .to_lowercase();
        if SOURCE_EXTENSIONS.contains(&ext.as_str()) {
            report.files.push(p.to_path_buf());
        } else {
            report.excluded_files += 1;
        }
    }

    report.files.sort();
    report
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
