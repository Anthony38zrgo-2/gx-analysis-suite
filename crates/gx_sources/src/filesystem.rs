//! Filesystem helpers for locating and validating GeneXus source files.
//!
//! Port of `gx_linter/app/core/filesystem.py`.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{bail, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use gx_core::models::DiscoveryPolicy;

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
    /// Archivos descartados por extensión, ocultos o excluidos por la
    /// política (globs de `exclude` / archivo de ignorado).
    pub excluded_files: usize,
    pub errors: Vec<DiscoveryError>,
    /// La caminata se detuvo por cancelación (A04).
    pub cancelled: bool,
}

/// Opciones de discovery compiladas (A01.5).
///
/// Los globs se compilan UNA vez desde la [`DiscoveryPolicy`] del request;
/// un patrón inválido o un `ignore_file` ilegible se rechazan antes de
/// escanear. Semántica de matching: la ruta del archivo RELATIVA al root
/// escaneado, con separador `/`; `*` puede cruzar separadores, por lo que
/// `*.xpz` (sin carpeta) matchea también archivos anidados.
#[derive(Debug, Clone, Default)]
pub struct DiscoveryOptions {
    include: GlobSet,
    exclude: GlobSet,
    follow_symlinks: bool,
    include_hidden: bool,
}

impl DiscoveryOptions {
    /// Compila la política del request (globs + archivo de ignorado).
    pub fn compile(policy: &DiscoveryPolicy) -> Result<Self, String> {
        let mut include_builder = GlobSetBuilder::new();
        for pattern in &policy.include {
            add_glob(&mut include_builder, pattern, "include")?;
        }
        let include = include_builder
            .build()
            .map_err(|e| format!("globs inválidos en include: {e}"))?;

        let mut exclude_builder = GlobSetBuilder::new();
        for pattern in &policy.exclude {
            add_glob(&mut exclude_builder, pattern, "exclude")?;
        }
        if let Some(ignore_file) = &policy.ignore_file {
            let raw = std::fs::read_to_string(ignore_file).map_err(|e| {
                format!(
                    "no se pudo leer el archivo de ignorado '{}': {e}",
                    ignore_file.display()
                )
            })?;
            let context = format!("ignore_file '{}'", ignore_file.display());
            for (index, line) in raw.lines().enumerate() {
                let pattern = line.trim();
                if pattern.is_empty() || pattern.starts_with('#') {
                    continue;
                }
                add_glob(
                    &mut exclude_builder,
                    pattern,
                    &format!("{context} línea {}", index + 1),
                )?;
            }
        }
        let exclude = exclude_builder
            .build()
            .map_err(|e| format!("globs inválidos en exclude/ignore: {e}"))?;

        Ok(Self {
            include,
            exclude,
            follow_symlinks: policy.follow_symlinks,
            include_hidden: policy.include_hidden,
        })
    }

    /// `true` si el archivo pasa include/exclude respecto del root.
    fn allows(&self, path: &Path, root: &Path) -> bool {
        let relative = path.strip_prefix(root).unwrap_or(path);
        if !self.include.is_empty() && !self.include.is_match(relative) {
            return false;
        }
        !self.exclude.is_match(relative)
    }
}

/// Valida la política de discovery SIN escanear archivos fuente (A01/F01):
/// la validación compartida del request la usa para fallar antes del scan.
pub fn validate_discovery(policy: &DiscoveryPolicy) -> Result<(), String> {
    DiscoveryOptions::compile(policy).map(|_| ())
}

fn add_glob(builder: &mut GlobSetBuilder, pattern: &str, context: &str) -> Result<(), String> {
    let glob =
        Glob::new(pattern).map_err(|e| format!("glob inválido en {context} ('{pattern}'): {e}"))?;
    builder.add(glob);
    Ok(())
}

fn is_hidden(name: &OsStr) -> bool {
    name.to_str().map(|n| n.starts_with('.')).unwrap_or(false)
}

fn is_dir_like(entry: &walkdir::DirEntry) -> bool {
    entry.file_type().is_dir() || (entry.file_type().is_symlink() && entry.path().is_dir())
}

/// Descubre archivos fuente bajo `path` (política por defecto).
pub fn discover_source_files(path: &Path) -> DiscoveryReport {
    discover_source_files_with_policy(path, &DiscoveryOptions::default(), None)
}

/// [`discover_source_files`] con checkpoint de cancelación (A04/F08).
pub fn discover_source_files_with_cancel(
    path: &Path,
    cancel: Option<&AtomicBool>,
) -> DiscoveryReport {
    discover_source_files_with_policy(path, &DiscoveryOptions::default(), cancel)
}

/// Descubre archivos fuente aplicando una política compilada (A01.5).
///
/// Reglas de exclusión (todas acumulan en `excluded_files`):
/// - extensión no soportada;
/// - oculto (`.nombre`) salvo `include_hidden`;
/// - glob de `exclude`/`ignore_file` (relativo al root).
///
/// Los directorios ocultos no se recorren salvo `include_hidden`.
/// Symlinks: ver [`DiscoveryPolicy::follow_symlinks`].
pub fn discover_source_files_with_policy(
    path: &Path,
    options: &DiscoveryOptions,
    cancel: Option<&AtomicBool>,
) -> DiscoveryReport {
    if path.is_file() {
        let root = path.parent().unwrap_or_else(|| Path::new(""));
        let mut report = DiscoveryReport::default();
        if options.allows(path, root) {
            report.files.push(path.to_path_buf());
        } else {
            report.excluded_files += 1;
        }
        return report;
    }

    let mut report = DiscoveryReport::default();
    let walker = walkdir::WalkDir::new(path).follow_links(options.follow_symlinks);
    for entry in walker.into_iter().filter_entry(|entry| {
        if is_dir_like(entry) {
            options.include_hidden || !is_hidden(entry.file_name())
        } else {
            true
        }
    }) {
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
        if !options.include_hidden && name.starts_with('.') {
            report.excluded_files += 1;
            continue;
        }
        let ext = p
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| format!(".{e}"))
            .unwrap_or_default()
            .to_lowercase();
        if !SOURCE_EXTENSIONS.contains(&ext.as_str()) {
            report.excluded_files += 1;
            continue;
        }
        if !options.allows(p, path) {
            report.excluded_files += 1;
            continue;
        }
        report.files.push(p.to_path_buf());
    }

    report.files.sort();
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

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
        let dir = temp_dir("gx_fs_dir_xml");
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
        let dir = temp_dir("gx_fs_dir_other");
        std::fs::write(dir.join("data.csv"), "a,b\n").unwrap();
        std::fs::write(dir.join("doc.md"), "doc").unwrap();

        let res = Filesystem::find_source_files(&dir);
        assert!(res.is_empty(), "no debe lintear fallback: {res:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn policy_with(include: &[&str], exclude: &[&str]) -> DiscoveryPolicy {
        DiscoveryPolicy {
            include: include.iter().map(|s| s.to_string()).collect(),
            exclude: exclude.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn include_and_exclude_globs_filter_files() {
        let dir = temp_dir("gx_fs_dir_globs");
        std::fs::write(dir.join("keep.txt"), "code\n").unwrap();
        std::fs::write(dir.join("skip.txt"), "code\n").unwrap();
        std::fs::write(dir.join("other.xpz"), "not a real zip").unwrap();

        let options = DiscoveryOptions::compile(&policy_with(&["*.txt"], &["skip.txt"])).unwrap();
        let report = discover_source_files_with_policy(&dir, &options, None);
        let names: Vec<String> = report
            .files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, vec!["keep.txt".to_string()]);
        assert!(report.excluded_files >= 2, "{report:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn include_glob_does_not_override_extension_policy() {
        let dir = temp_dir("gx_fs_dir_ext_policy");
        std::fs::write(dir.join("data.csv"), "a,b\n").unwrap();

        let options = DiscoveryOptions::compile(&policy_with(&["*.csv"], &[])).unwrap();
        let report = discover_source_files_with_policy(&dir, &options, None);
        assert!(report.files.is_empty(), "{report:?}");
        assert_eq!(report.excluded_files, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ignore_file_patterns_apply_and_comments_are_skipped() {
        let dir = temp_dir("gx_fs_dir_ignore");
        std::fs::write(dir.join("keep.txt"), "code\n").unwrap();
        std::fs::write(dir.join("drop.txt"), "code\n").unwrap();
        let ignore = dir.join("gx.ignore");
        std::fs::write(&ignore, "# comentario\ndrop.txt\n\n").unwrap();

        let policy = DiscoveryPolicy {
            ignore_file: Some(ignore),
            ..Default::default()
        };
        let options = DiscoveryOptions::compile(&policy).unwrap();
        let report = discover_source_files_with_policy(&dir, &options, None);
        let names: Vec<String> = report
            .files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, vec!["keep.txt".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalid_glob_and_missing_ignore_file_are_rejected() {
        let err = DiscoveryOptions::compile(&policy_with(&["[bad"], &[])).unwrap_err();
        assert!(err.contains("glob inválido en include"), "{err}");

        let policy = DiscoveryPolicy {
            ignore_file: Some(PathBuf::from("no-existe-ignore.txt")),
            ..Default::default()
        };
        let err = DiscoveryOptions::compile(&policy).unwrap_err();
        assert!(err.contains("no se pudo leer"), "{err}");
    }

    #[test]
    fn hidden_files_and_dirs_are_excluded_unless_requested() {
        let dir = temp_dir("gx_fs_dir_hidden");
        std::fs::create_dir_all(dir.join(".oculto")).unwrap();
        std::fs::write(dir.join(".oculto/inner.txt"), "code\n").unwrap();
        std::fs::write(dir.join(".hidden.txt"), "code\n").unwrap();
        std::fs::write(dir.join("visible.txt"), "code\n").unwrap();

        let visible = discover_source_files(&dir);
        let names: Vec<String> = visible
            .files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, vec!["visible.txt".to_string()], "{visible:?}");

        let policy = DiscoveryPolicy {
            include_hidden: true,
            ..Default::default()
        };
        let options = DiscoveryOptions::compile(&policy).unwrap();
        let all = discover_source_files_with_policy(&dir, &options, None);
        assert_eq!(all.files.len(), 3, "{all:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn symlinked_file_is_read_but_symlinked_dir_is_not_followed_by_default() {
        let dir = temp_dir("gx_fs_dir_symlink");
        let real = dir.join("real");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(real.join("linked.txt"), "code\n").unwrap();
        let link = dir.join("link");

        // En Windows requiere privilegios (developer mode); si no se puede
        // crear, el test no aplica.
        #[cfg(windows)]
        let created = std::os::windows::fs::symlink_dir(&real, &link).is_ok();
        #[cfg(not(windows))]
        let created = std::os::unix::fs::symlink(&real, &link).is_ok();
        if !created {
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }

        let default = discover_source_files(&dir);
        assert!(
            default.files.is_empty(),
            "un symlink a directorio no se recorre por defecto: {default:?}"
        );

        let policy = DiscoveryPolicy {
            follow_symlinks: true,
            ..Default::default()
        };
        let options = DiscoveryOptions::compile(&policy).unwrap();
        let followed = discover_source_files_with_policy(&dir, &options, None);
        assert_eq!(followed.files.len(), 1, "{followed:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
