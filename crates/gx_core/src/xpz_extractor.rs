//! Unified GeneXus source extraction for `.txt`, `.xml`, `.xpz`, `.zip`
//! and RAR-based packages.
//!
//! Formatos soportados (GX-007):
//! - `.txt`/`.prg`/`.gxd`/`.src`: un objeto `Source`.
//! - `.xml`: export GeneXus (`ExportFile`/`GXObject`) o layout legacy con
//!   `<Events>` directos.
//! - `.xpz`/`.zip`/`.rar`: paquete ZIP o RAR (GeneXus empaqueta con WinRAR
//!   cuando está instalado; se detecta por magic bytes, no por extensión).
//!
//! Formato real de export (`ExportFile`): cada `<GXObject>` aporta identidad
//! (`<Info><Name>`, `<Info><Folder>`, tipo = primer elemento hijo) y sus
//! secciones de CÓDIGO en orden documental: `<Events>`, `<Rules>` y
//! `<Subroutines>` (CDATA). Las secciones que NO son código
//! (`Documentation/Source`, `Layout/Source`, `Help`, `Structure`, …) se
//! excluyen explícitamente.
//!
//! Contrato de "sin código" (GX-007 revisado): un paquete con objetos
//! GeneXus reconocidos pero sin secciones de código es un escaneo VÁLIDO con
//! cero objetos/hallazgos (se emite un warning). Un layout sin objetos
//! GeneXus ni `<Events>` (markup arbitrario) se rechaza como "no soportado"
//! y nunca se lintea como XML de marca.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{bail, Result};
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

use crate::budget::ExecutionBudget;
use crate::models::{ObjectRef, SourceObject, SourceSegment};

/// Máximo de miembros por paquete (protección contra paquetes anómalos).
pub const MAX_XPZ_MEMBERS: usize = 4096;
/// Máximo de bytes descomprimidos por miembro.
pub const MAX_MEMBER_BYTES: usize = 32 * 1024 * 1024;
/// Máximo de bytes descomprimidos totales por artefacto.
pub const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;

/// Contenedores XML que NUNCA aportan código (A03): un `<Events>` dentro de
/// documentación/layout no puede convertirse en fuente ejecutable.
const NON_CODE_CONTAINERS: &[&str] = &["documentation", "layout", "help", "structure"];

/// Secciones de CÓDIGO reconocidas dentro de un objeto.
const CODE_SECTIONS: &[&str] = &["events", "rules", "subroutines"];

/// Resultado de una extracción con presupuesto (A04/F07).
#[derive(Debug, Clone)]
pub struct ExtractionOutcome {
    /// Objetos completos extraídos (los parciales se conservan).
    pub objects: Vec<SourceObject>,
    /// Motivo del corte por presupuesto; la corrida es `partial`.
    pub limit: Option<String>,
    /// Cancelación solicitada: los objetos ya extraídos se conservan.
    pub cancelled: bool,
}

impl ExtractionOutcome {
    fn complete(objects: Vec<SourceObject>) -> Self {
        Self {
            objects,
            limit: None,
            cancelled: false,
        }
    }
}

fn is_cancelled(cancel: Option<&AtomicBool>) -> bool {
    cancel.map(|c| c.load(Ordering::Relaxed)).unwrap_or(false)
}

/// Extrae los objetos fuente de un artefacto GeneXus (GX-006) con el
/// presupuesto por defecto.
pub fn extract_source_objects(file_path: &Path) -> Result<Vec<SourceObject>> {
    let budget = ExecutionBudget::default();
    Ok(extract_source_objects_with_budget(file_path, &budget, None)?.objects)
}

/// Extrae con presupuesto explícito y token de cancelación (A04).
///
/// Un límite alcanzado NO es un error de formato: devuelve los objetos ya
/// extraídos con `limit`/`cancelled`, y el runtime lo convierte en un
/// resultado `partial`/`cancelled` (nunca PASS).
pub fn extract_source_objects_with_budget(
    file_path: &Path,
    budget: &ExecutionBudget,
    cancel: Option<&AtomicBool>,
) -> Result<ExtractionOutcome> {
    if !file_path.is_file() {
        bail!("El archivo no existe: {}", file_path.display());
    }
    // F07: la lectura también se acota para texto/XML/paquetes, no sólo por
    // headers de archivo.
    let input_len = std::fs::metadata(file_path)
        .map(|m| m.len())
        .unwrap_or(u64::MAX);
    if input_len > budget.max_input_bytes {
        return Ok(ExtractionOutcome {
            objects: Vec::new(),
            limit: Some(format!(
                "el archivo '{}' supera el máximo de entrada ({} > {} bytes)",
                file_path.display(),
                input_len,
                budget.max_input_bytes
            )),
            cancelled: false,
        });
    }
    if is_cancelled(cancel) {
        return Ok(ExtractionOutcome {
            objects: Vec::new(),
            limit: None,
            cancelled: true,
        });
    }
    let ext = file_path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_default();

    match ext.as_str() {
        // El contenido manda sobre la extensión: ZIP o RAR.
        "xpz" | "zip" | "rar" => {
            let head = archive_magic(file_path)?;
            if is_rar_magic(&head) {
                objects_from_rar(file_path, budget, cancel)
            } else {
                objects_from_zip(file_path, budget, cancel)
            }
        }
        "xml" => objects_from_xml(file_path, budget, cancel),
        "txt" | "prg" | "gxd" | "src" => objects_from_text(file_path, budget, cancel),
        _ => bail!(
            "Formato no soportado '{}': se esperaban fuentes .xpz, .zip, .rar, .xml, \
             .txt, .prg, .gxd o .src",
            file_path.display()
        ),
    }
}

/// Lee los primeros bytes para identificar el formato del paquete.
fn archive_magic(file_path: &Path) -> Result<[u8; 8]> {
    use std::io::Read;
    let mut file = std::fs::File::open(file_path)?;
    let mut head = [0u8; 8];
    file.read_exact(&mut head)
        .map_err(|e| anyhow::anyhow!("No se pudo leer '{}': {e}", file_path.display()))?;
    Ok(head)
}

/// Magic de RAR4 (`Rar!\x1A\x07\x00`) y RAR5 (`Rar!\x1A\x07\x01\x00`).
fn is_rar_magic(head: &[u8; 8]) -> bool {
    head[0] == b'R' && head[1] == b'a' && head[2] == b'r' && head[3] == b'!'
}

/// Compatibilidad: contenido concatenado (solo para consumo simple).
#[deprecated(since = "0.2.0", note = "usar extract_source_objects (GX-006)")]
pub fn extract_genexus_source(file_path: &Path) -> Result<String> {
    let objects = extract_source_objects(file_path)?;
    Ok(objects
        .iter()
        .map(|o| o.text.clone())
        .collect::<Vec<_>>()
        .join("\n\n"))
}

// ─────────────────────────────────────────────────────────────────────────
// Miembros de paquete (ZIP/RAR)
// ─────────────────────────────────────────────────────────────────────────

/// List member names inside an `.xpz` (ZIP) file.
pub fn list_xpz_members(xpz_path: &Path) -> Result<Vec<String>> {
    let file = std::fs::File::open(xpz_path)?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| anyhow::anyhow!("ZIP inválido '{}': {e}", xpz_path.display()))?;
    let mut names = Vec::new();
    for i in 0..archive.len() {
        if let Ok(member) = archive.by_index(i) {
            names.push(member.name().replace('\\', "/"));
        }
    }
    Ok(names)
}

/// List member names inside a RAR file.
pub fn list_rar_members(rar_path: &Path) -> Result<Vec<String>> {
    let listing = unrar::Archive::new(rar_path)
        .open_for_listing()
        .map_err(|e| anyhow::anyhow!("RAR inválido '{}': {e}", rar_path.display()))?;
    let mut names = Vec::new();
    for item in listing {
        let header = item.map_err(|e| {
            anyhow::anyhow!("Miembro RAR ilegible de '{}': {e}", rar_path.display())
        })?;
        names.push(header.filename.to_string_lossy().replace('\\', "/"));
    }
    Ok(names)
}

/// List member names of a package (ZIP or RAR, detectado por magic).
pub fn list_package_members(package_path: &Path) -> Result<Vec<String>> {
    let head = archive_magic(package_path)?;
    if is_rar_magic(&head) {
        list_rar_members(package_path)
    } else {
        list_xpz_members(package_path)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Texto plano
// ─────────────────────────────────────────────────────────────────────────

fn objects_from_text(
    file_path: &Path,
    budget: &ExecutionBudget,
    cancel: Option<&AtomicBool>,
) -> Result<ExtractionOutcome> {
    if is_cancelled(cancel) {
        return Ok(ExtractionOutcome {
            objects: Vec::new(),
            limit: None,
            cancelled: true,
        });
    }
    let bytes = std::fs::read(file_path)?;
    let text = decode_bytes(&bytes).ok_or_else(|| {
        anyhow::anyhow!(
            "No se pudo decodificar el archivo '{}' (encoding no reconocido).",
            file_path.display()
        )
    })?;
    if text.trim().is_empty() {
        bail!("El archivo fuente '{}' está vacío.", file_path.display());
    }
    if budget.max_objects == 0 {
        return Ok(ExtractionOutcome {
            objects: Vec::new(),
            limit: Some("presupuesto de objetos agotado (max_objects=0)".to_string()),
            cancelled: false,
        });
    }
    let name = file_name_lossy(file_path);
    let id = file_stem_lossy(file_path).unwrap_or_else(|| name.clone());
    Ok(ExtractionOutcome::complete(vec![SourceObject {
        object: ObjectRef {
            id,
            object_type: "Source".to_string(),
            container_path: file_path.to_string_lossy().to_string(),
            member: name,
            package: String::new(),
        },
        text,
        code_start_line: 1,
        segments: Vec::new(),
    }]))
}

// ─────────────────────────────────────────────────────────────────────────
// XML
// ─────────────────────────────────────────────────────────────────────────

fn objects_from_xml(
    xml_path: &Path,
    budget: &ExecutionBudget,
    cancel: Option<&AtomicBool>,
) -> Result<ExtractionOutcome> {
    if is_cancelled(cancel) {
        return Ok(ExtractionOutcome {
            objects: Vec::new(),
            limit: None,
            cancelled: true,
        });
    }
    let bytes = std::fs::read(xml_path)?;
    let xml_text = decode_bytes(&bytes).ok_or_else(|| {
        anyhow::anyhow!(
            "No se pudo decodificar el archivo '{}'. Pruebe con otra codificación.",
            xml_path.display()
        )
    })?;
    if xml_text.trim().is_empty() {
        bail!("El archivo XML '{}' está vacío.", xml_path.display());
    }

    let name = file_name_lossy(xml_path);
    let container = xml_path.to_string_lossy().to_string();
    let extracted = extract_from_xml_text(&xml_text, &container, &name, cancel)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    if let Some(limit) = object_limit(budget, extracted.objects.len(), &container) {
        return Ok(ExtractionOutcome {
            objects: extracted.objects,
            limit: Some(limit),
            cancelled: extracted.cancelled,
        });
    }
    if extracted.cancelled {
        return Ok(ExtractionOutcome {
            objects: extracted.objects,
            limit: None,
            cancelled: true,
        });
    }
    if extracted.objects.is_empty() {
        if extracted.gx_objects == 0 {
            bail!(
                "Layout XML no soportado en '{}': no se encontraron objetos GeneXus \
                 (<GXObject>) ni bloques <Events><![CDATA[...]]></Events con código.",
                xml_path.display()
            );
        }
        warn_no_code(&xml_path.display().to_string(), extracted.gx_objects);
    }
    Ok(ExtractionOutcome::complete(extracted.objects))
}

/// Motivo de corte si `count` excede `max_objects` (A04).
fn object_limit(budget: &ExecutionBudget, count: usize, container: &str) -> Option<String> {
    if count > budget.max_objects {
        Some(format!(
            "'{container}' supera el máximo de objetos extraídos ({count} > {})",
            budget.max_objects
        ))
    } else {
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Paquete ZIP
// ─────────────────────────────────────────────────────────────────────────

fn objects_from_zip(
    xpz_path: &Path,
    budget: &ExecutionBudget,
    cancel: Option<&AtomicBool>,
) -> Result<ExtractionOutcome> {
    let file = std::fs::File::open(xpz_path)?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| anyhow::anyhow!("ZIP inválido '{}': {e}", xpz_path.display()))?;
    if archive.is_empty() {
        bail!("El archivo '{}' está vacío.", xpz_path.display());
    }

    let container = xpz_path.to_string_lossy().to_string();
    let mut objects: Vec<SourceObject> = Vec::new();
    let mut gx_objects: usize = 0;
    let mut total_bytes: u64 = 0;
    let stop = |objects: Vec<SourceObject>, reason: String| ExtractionOutcome {
        objects,
        limit: Some(reason),
        cancelled: false,
    };

    if archive.len() > budget.max_members {
        return Ok(stop(
            objects,
            format!(
                "el archivo '{}' supera el máximo de miembros ({} > {})",
                xpz_path.display(),
                archive.len(),
                budget.max_members
            ),
        ));
    }

    for i in 0..archive.len() {
        if is_cancelled(cancel) {
            return Ok(ExtractionOutcome {
                objects,
                limit: None,
                cancelled: true,
            });
        }
        let mut member = archive.by_index(i)?;
        let member_name = member.name().replace('\\', "/");
        if member_name.ends_with('/') {
            continue;
        }
        let member_size = member.size();
        if member_size > budget.max_member_bytes {
            return Ok(stop(
                objects,
                format!(
                    "el miembro '{member_name}' de '{}' supera el máximo por miembro ({} > {} bytes)",
                    xpz_path.display(),
                    member_size,
                    budget.max_member_bytes
                ),
            ));
        }
        total_bytes += member_size;
        if total_bytes > budget.max_expanded_bytes {
            return Ok(stop(
                objects,
                format!(
                    "el archivo '{}' supera el máximo descomprimido ({} > {} bytes)",
                    xpz_path.display(),
                    total_bytes,
                    budget.max_expanded_bytes
                ),
            ));
        }
        let mut raw = Vec::with_capacity((member_size as usize).min(8 * 1024 * 1024));
        use std::io::Read;
        member
            .read_to_end(&mut raw)
            .map_err(|e| anyhow::anyhow!("Miembro ZIP ilegible '{member_name}': {e}"))?;
        let xml_text = match decode_bytes(&raw) {
            Some(t) => t,
            None => {
                bail!(
                    "No se pudo decodificar el miembro '{member_name}' de '{}'.",
                    xpz_path.display()
                )
            }
        };
        if xml_text.trim().is_empty() {
            continue;
        }

        let extracted = extract_from_xml_text(&xml_text, &container, &member_name, cancel)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        gx_objects += extracted.gx_objects;
        objects.extend(extracted.objects);
        if extracted.cancelled {
            return Ok(ExtractionOutcome {
                objects,
                limit: None,
                cancelled: true,
            });
        }
        if let Some(limit) = object_limit(budget, objects.len(), &container) {
            return Ok(stop(objects, limit));
        }
    }

    if objects.is_empty() {
        if gx_objects == 0 {
            bail!(
                "Layout no soportado en '{}': ningún miembro contiene objetos GeneXus \
                 (<GXObject>) ni bloques <Events><![CDATA[...]]></Events con código. \
                 El paquete no se lintea como XML de marca.",
                xpz_path.display()
            );
        }
        warn_no_code(&xpz_path.display().to_string(), gx_objects);
    }
    Ok(ExtractionOutcome::complete(objects))
}

// ─────────────────────────────────────────────────────────────────────────
// Paquete RAR (GeneXus con WinRAR)
// ─────────────────────────────────────────────────────────────────────────

fn objects_from_rar(
    xpz_path: &Path,
    budget: &ExecutionBudget,
    cancel: Option<&AtomicBool>,
) -> Result<ExtractionOutcome> {
    let container = xpz_path.to_string_lossy().to_string();
    let mut objects: Vec<SourceObject> = Vec::new();
    let mut gx_objects: usize = 0;

    let mut archive = unrar::Archive::new(xpz_path)
        .open_for_processing()
        .map_err(|e| anyhow::anyhow!("RAR inválido '{}': {e}", xpz_path.display()))?;

    let mut member_seen = 0usize;
    let mut total_bytes: u64 = 0;
    while let Some(state) = archive
        .read_header()
        .map_err(|e| anyhow::anyhow!("Miembro RAR ilegible de '{}': {e}", xpz_path.display()))?
    {
        // Nota A04: unrar es una operación nativa no interrumpible; el
        // checkpoint se evalúa entre miembros, no dentro de `read()`.
        if is_cancelled(cancel) {
            return Ok(ExtractionOutcome {
                objects,
                limit: None,
                cancelled: true,
            });
        }
        let member_name = state.entry().filename.to_string_lossy().replace('\\', "/");
        if member_name.ends_with('/') {
            archive = state.skip().map_err(|e| {
                anyhow::anyhow!("Miembro RAR ilegible de '{}': {e}", xpz_path.display())
            })?;
            continue;
        }
        member_seen += 1;
        if member_seen > budget.max_members {
            return Ok(ExtractionOutcome {
                objects,
                limit: Some(format!(
                    "el archivo '{}' supera el máximo de miembros ({} > {})",
                    xpz_path.display(),
                    member_seen,
                    budget.max_members
                )),
                cancelled: false,
            });
        }
        let size = state.entry().unpacked_size;
        if size > budget.max_member_bytes {
            return Ok(ExtractionOutcome {
                objects,
                limit: Some(format!(
                    "el miembro '{member_name}' de '{}' supera el máximo por miembro ({} > {} bytes)",
                    xpz_path.display(),
                    size,
                    budget.max_member_bytes
                )),
                cancelled: false,
            });
        }
        total_bytes += size;
        if total_bytes > budget.max_expanded_bytes {
            return Ok(ExtractionOutcome {
                objects,
                limit: Some(format!(
                    "el archivo '{}' supera el máximo descomprimido ({} > {} bytes)",
                    xpz_path.display(),
                    total_bytes,
                    budget.max_expanded_bytes
                )),
                cancelled: false,
            });
        }

        let (raw, rest) = state
            .read()
            .map_err(|e| anyhow::anyhow!("Miembro RAR ilegible '{member_name}': {e}"))?;
        archive = rest;

        let xml_text = match decode_bytes(&raw) {
            Some(t) => t,
            None => {
                bail!(
                    "No se pudo decodificar el miembro '{member_name}' de '{}'.",
                    xpz_path.display()
                )
            }
        };
        if xml_text.trim().is_empty() {
            continue;
        }

        let extracted = extract_from_xml_text(&xml_text, &container, &member_name, cancel)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        gx_objects += extracted.gx_objects;
        objects.extend(extracted.objects);
        if extracted.cancelled {
            return Ok(ExtractionOutcome {
                objects,
                limit: None,
                cancelled: true,
            });
        }
        if let Some(limit) = object_limit(budget, objects.len(), &container) {
            return Ok(ExtractionOutcome {
                objects,
                limit: Some(limit),
                cancelled: false,
            });
        }
    }

    if objects.is_empty() {
        if gx_objects == 0 {
            bail!(
                "Layout no soportado en '{}': ningún miembro contiene objetos GeneXus \
                 (<GXObject>) ni bloques <Events><![CDATA[...]]></Events con código. \
                 El paquete no se lintea como XML de marca.",
                xpz_path.display()
            );
        }
        warn_no_code(&xpz_path.display().to_string(), gx_objects);
    }
    Ok(ExtractionOutcome::complete(objects))
}

fn warn_no_code(container: &str, gx_objects: usize) {
    tracing::warn!(
        "[GX] '{container}' contiene {gx_objects} objeto(s) GeneXus sin secciones de \
         código (Events/Rules/Subroutines): 0 hallazgos."
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Parser del formato real (ExportFile/GXObject) + fallback legacy
// ─────────────────────────────────────────────────────────────────────────

struct Extracted {
    objects: Vec<SourceObject>,
    /// Cantidad de bloques `<GXObject>` reconocidos en el texto.
    gx_objects: usize,
    /// El parseo se detuvo porque se solicitó cancelación (A04).
    cancelled: bool,
}

/// Sección de código cruda con su línea física en el miembro.
#[derive(Debug, Clone)]
struct Section {
    kind: String,
    text: String,
    /// Línea (1-based) del miembro donde comienza el contenido del CDATA.
    member_start_line: u32,
}

/// Estado de un `<GXObject>` en construcción.
#[derive(Default)]
struct ObjectBuilder {
    object_type: Option<String>,
    info_depth: usize,
    name: String,
    package: String,
    sections: Vec<Section>,
}

/// Sección de código en construcción.
struct SectionBuilder {
    kind: String,
    cdata: String,
    member_start_line: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Capture {
    Name,
    Folder,
}

/// Índice de inicios de línea: offset de byte → línea 1-based en O(log n).
struct LineIndex {
    starts: Vec<usize>,
}

impl LineIndex {
    fn new(text: &str) -> Self {
        let mut starts = vec![0usize];
        for (i, b) in text.bytes().enumerate() {
            if b == b'\n' {
                starts.push(i + 1);
            }
        }
        LineIndex { starts }
    }

    fn line_of(&self, offset: usize) -> u32 {
        self.starts.partition_point(|&s| s <= offset).max(1) as u32
    }
}

/// Extrae objetos de un texto XML con un parser de eventos (A03/F04).
///
/// - Formato real: cada `<GXObject>` aporta identidad y secciones de código
///   (`Events`/`Rules`/`Subroutines`) con contexto de anidamiento explícito.
/// - Layout legacy: si no hay ningún `<GXObject>`, las secciones de código
///   se agrupan en un objeto con identidad del elemento raíz.
/// - XML de documentación con apariencia de código no es ejecutable: sólo
///   se capturan CDATA de secciones de código fuera de contenedores no-código.
/// - XML malformado se rechaza explícitamente (nunca se lintea a medias).
fn extract_from_xml_text(
    xml_text: &str,
    container: &str,
    member: &str,
    cancel: Option<&AtomicBool>,
) -> Result<Extracted, String> {
    crate::stats::count_parser_invocation();
    let lines = LineIndex::new(xml_text);
    let mut reader = Reader::from_str(xml_text);
    let mut events: usize = 0;

    let mut stack: Vec<String> = Vec::new();
    let mut objects: Vec<SourceObject> = Vec::new();
    let mut current: Option<ObjectBuilder> = None;
    let mut gx_objects: usize = 0;
    let mut legacy_sections: Vec<Section> = Vec::new();
    let mut legacy_root: Option<(String, String, String)> = None;
    let mut noncode_depth: Option<usize> = None;
    let mut section: Option<SectionBuilder> = None;
    let mut capture: Option<Capture> = None;
    let mut capture_buf = String::new();

    loop {
        // Checkpoint de cancelación cada 1024 eventos (A04).
        if events.is_multiple_of(1024) && is_cancelled(cancel) {
            return Ok(Extracted {
                objects,
                gx_objects,
                cancelled: true,
            });
        }
        events += 1;
        let event = match reader.read_event() {
            Ok(Event::Eof) => break,
            Ok(ev) => ev,
            Err(e) => {
                return Err(format!(
                    "XML inválido en '{}' (miembro '{member}'): {e}",
                    container
                ))
            }
        };

        match event {
            Event::Start(e) => {
                let name = decode_name_bytes(e.name().as_ref());
                let lname = name.to_ascii_lowercase();

                if lname == "gxobject" {
                    gx_objects += 1;
                    current = Some(ObjectBuilder::default());
                    noncode_depth = None;
                    section = None;
                    stack.push(lname);
                    continue;
                }

                let parent_is_root = stack.is_empty();
                let parent_is_gxobject = stack.last().map(|s| s == "gxobject").unwrap_or(false);
                let inside_object = current.is_some();

                if parent_is_root && legacy_root.is_none() {
                    let (n, p) = element_name_package(&e);
                    legacy_root = Some((name.clone(), n, p));
                }

                if noncode_depth.is_none() && NON_CODE_CONTAINERS.contains(&lname.as_str()) {
                    stack.push(lname);
                    noncode_depth = Some(stack.len());
                    continue;
                }
                let in_noncode = noncode_depth.is_some();

                if inside_object && parent_is_gxobject {
                    let builder = current.as_mut().expect("current verificado");
                    if builder.object_type.is_none() {
                        builder.object_type = Some(name.clone());
                    }
                }

                if inside_object && !in_noncode && lname == "info" {
                    current.as_mut().expect("current verificado").info_depth += 1;
                } else if inside_object
                    && !in_noncode
                    && capture.is_none()
                    && current.as_ref().map(|b| b.info_depth > 0).unwrap_or(false)
                {
                    if lname == "name" {
                        capture = Some(Capture::Name);
                        capture_buf.clear();
                    } else if lname == "folder" {
                        capture = Some(Capture::Folder);
                        capture_buf.clear();
                    }
                }

                if !in_noncode
                    && section.is_none()
                    && CODE_SECTIONS.contains(&lname.as_str())
                    && (inside_object || current.is_none())
                {
                    section = Some(SectionBuilder {
                        kind: name.clone(),
                        cdata: String::new(),
                        member_start_line: 0,
                    });
                }

                stack.push(lname);
            }
            Event::Empty(e) => {
                let empty_name = decode_name_bytes(e.name().as_ref());
                if let Some(builder) = current.as_mut() {
                    if builder.object_type.is_none()
                        && stack.last().map(|s| s == "gxobject").unwrap_or(false)
                    {
                        builder.object_type = Some(empty_name);
                    }
                }
            }
            Event::End(e) => {
                let name = decode_name_bytes(e.name().as_ref());
                let lname = name.to_ascii_lowercase();

                if let Some(sec) = section.as_ref() {
                    if sec.kind.to_ascii_lowercase() == lname {
                        let sec = section.take().expect("section verificada");
                        if !sec.cdata.trim().is_empty() {
                            let target = Section {
                                kind: sec.kind,
                                text: sec.cdata,
                                member_start_line: sec.member_start_line.max(1),
                            };
                            match current.as_mut() {
                                Some(builder) => builder.sections.push(target),
                                None => legacy_sections.push(target),
                            }
                        }
                    }
                }

                if capture.is_some() {
                    let is_match = match capture {
                        Some(Capture::Name) => lname == "name",
                        Some(Capture::Folder) => lname == "folder",
                        None => false,
                    };
                    if is_match {
                        let cap = capture.take().expect("capture verificada");
                        let value = capture_buf.trim().to_string();
                        if let Some(builder) = current.as_mut() {
                            match cap {
                                Capture::Name => builder.name = value,
                                Capture::Folder => builder.package = value,
                            }
                        }
                        capture_buf.clear();
                    }
                }

                if lname == "info" {
                    if let Some(builder) = current.as_mut() {
                        builder.info_depth = builder.info_depth.saturating_sub(1);
                    }
                }

                if lname == "gxobject" {
                    if let Some(builder) = current.take() {
                        if let Some(object) = build_source_object(builder, container, member) {
                            objects.push(object);
                        }
                    }
                    noncode_depth = None;
                    section = None;
                }

                if stack.last().map(|s| s.as_str()) == Some(lname.as_str()) {
                    stack.pop();
                }
                if let Some(depth) = noncode_depth {
                    if stack.len() < depth {
                        noncode_depth = None;
                    }
                }
            }
            Event::Text(e) if capture.is_some() => {
                let text = e
                    .unescape()
                    .map(|c| c.into_owned())
                    .unwrap_or_else(|_| String::from_utf8_lossy(e.as_ref()).into_owned());
                capture_buf.push_str(&text);
            }
            Event::CData(e) => {
                if let Some(sec) = section.as_mut() {
                    let content = String::from_utf8_lossy(e.as_ref()).into_owned();
                    if sec.cdata.is_empty() {
                        let end = reader.buffer_position();
                        let start = end.saturating_sub(3 + content.len());
                        sec.member_start_line = lines.line_of(start);
                    }
                    sec.cdata.push_str(&content);
                }
            }
            _ => {}
        }
    }

    if gx_objects == 0 && !legacy_sections.is_empty() {
        let (kind, name, package) = legacy_root.unwrap_or_default();
        let builder = ObjectBuilder {
            object_type: Some(kind),
            info_depth: 0,
            name,
            package,
            sections: legacy_sections,
        };
        if let Some(object) = build_source_object(builder, container, member) {
            objects.push(object);
        }
    }

    Ok(Extracted {
        objects,
        gx_objects,
        cancelled: false,
    })
}

/// Construye el `SourceObject` concatenando secciones con `\n\n` y
/// registrando el mapa de segmentos (A03/F04).
fn build_source_object(
    builder: ObjectBuilder,
    container: &str,
    member: &str,
) -> Option<SourceObject> {
    if builder.sections.is_empty() {
        return None;
    }
    let mut text = String::new();
    let mut segments: Vec<SourceSegment> = Vec::with_capacity(builder.sections.len());
    let mut line: u32 = 1;
    for (i, sec) in builder.sections.iter().enumerate() {
        if i > 0 {
            text.push_str("\n\n");
            line += 2;
        }
        segments.push(SourceSegment {
            kind: sec.kind.clone(),
            text_start_line: line,
            member_start_line: sec.member_start_line,
        });
        text.push_str(&sec.text);
        line += sec.text.matches('\n').count() as u32;
    }
    let code_start_line = segments.first().map(|s| s.member_start_line).unwrap_or(1);
    let object_type = builder.object_type.unwrap_or_else(|| "Source".to_string());
    Some(SourceObject {
        object: ObjectRef {
            id: if builder.name.is_empty() {
                member_stem(member)
            } else {
                builder.name
            },
            object_type,
            container_path: container.to_string(),
            member: member.to_string(),
            package: builder.package,
        },
        text,
        code_start_line,
        segments,
    })
}

/// Nombre de un elemento XML (case original).
fn decode_name_bytes(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw).to_string()
}

/// Atributos `name`/`package` del elemento (layout legacy).
fn element_name_package(e: &BytesStart) -> (String, String) {
    let mut name = String::new();
    let mut package = String::new();
    for attr in e.attributes().flatten() {
        let key = String::from_utf8_lossy(attr.key.as_ref()).to_ascii_lowercase();
        let value = attr
            .unescape_value()
            .map(|v| v.into_owned())
            .unwrap_or_else(|_| String::from_utf8_lossy(&attr.value).into_owned());
        match key.as_str() {
            "name" => name = value.trim().to_string(),
            "package" => package = value.trim().to_string(),
            _ => {}
        }
    }
    (name, package)
}

fn file_name_lossy(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default()
}

fn file_stem_lossy(path: &Path) -> Option<String> {
    path.file_stem()
        .and_then(|s| s.to_str())
        .map(|s| s.to_string())
}

/// Stem del miembro como identidad de respaldo (nunca la primera línea de
/// código, que producía ids basura).
fn member_stem(member: &str) -> String {
    Path::new(member)
        .file_stem()
        .and_then(|s| s.to_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| member.to_string())
}

// ─────────────────────────────────────────────────────────────────────────
// Decodificación (GX-007): UTF-8 (con/sin BOM) → CP1252 → Latin-1
// ─────────────────────────────────────────────────────────────────────────

/// Orden documentado del fallback de encodings de exports GeneXus.
///
/// CP1252 precede a Latin-1 porque los exports reales usan la página
/// 1252 (aunque comparten 0xA0-0xFF, CP1252 resuelve 0x80-0x9F correctos);
/// Latin-1 queda como último recurso (acepta cualquier byte).
pub const ENCODING_FALLBACK: &[&str] = &["utf-8", "utf-8-sig", "cp1252", "latin-1"];

fn decode_bytes(data: &[u8]) -> Option<String> {
    for enc in ENCODING_FALLBACK {
        if let Some(decoded) = decode_with(enc, data) {
            return Some(decoded);
        }
    }
    None
}

fn decode_with(enc_label: &str, data: &[u8]) -> Option<String> {
    match enc_label {
        "utf-8" => {
            let s = std::str::from_utf8(data).ok()?;
            Some(s.strip_prefix('\u{feff}').unwrap_or(s).to_string())
        }
        "utf-8-sig" => {
            let s = std::str::from_utf8(data).ok()?;
            Some(s.strip_prefix('\u{feff}').unwrap_or(s).to_string())
        }
        other => {
            let encoding = encoding_rs::Encoding::for_label(other.as_bytes())?;
            let (cow, _, had_errors) = encoding.decode(data);
            if had_errors {
                None
            } else {
                Some(cow.into_owned())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(name)
    }

    #[test]
    fn txt_extract_is_identity() {
        let p = tmp("gx_xpz_test.txt");
        std::fs::write(&p, "for each Customer\n  &x = 1\n").unwrap();
        let objects = extract_source_objects(&p).unwrap();
        assert_eq!(objects.len(), 1);
        assert!(objects[0].text.contains("for each Customer"));
        assert_eq!(objects[0].object.object_type, "Source");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn txt_with_bom_is_stripped() {
        let p = tmp("gx_bom_test.txt");
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice("for each Customer\n".as_bytes());
        std::fs::write(&p, &bytes).unwrap();
        let objects = extract_source_objects(&p).unwrap();
        assert!(objects[0].text.starts_with("for each Customer"));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn txt_cp1252_decodes() {
        let p = tmp("gx_cp1252_test.txt");
        // "Café" en CP1252: 43 61 66 E9
        let bytes = b"&Nombre = 'Caf\xE9'\n".to_vec();
        std::fs::write(&p, &bytes).unwrap();
        let objects = extract_source_objects(&p).unwrap();
        assert!(
            objects[0].text.contains("Caf\u{e9}"),
            "texto: {:?}",
            objects[0].text
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn txt_empty_is_rejected() {
        let p = tmp("gx_empty_test.txt");
        std::fs::write(&p, "   \n \n").unwrap();
        let err = extract_source_objects(&p).unwrap_err();
        assert!(err.to_string().contains("vacío"));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn unsupported_extension_is_rejected() {
        let p = tmp("gx_bad_test.csv");
        std::fs::write(&p, "a,b,c\n").unwrap();
        let err = extract_source_objects(&p).unwrap_err();
        assert!(err.to_string().contains("no soportado"));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn xml_extract_cdata_legacy() {
        let xml = "<Root name=\"MiObj\"><Events><![CDATA[\nfor each Customer\n]]></Events></Root>";
        let p = tmp("gx_xpz_test.xml");
        std::fs::write(&p, xml).unwrap();
        let objects = extract_source_objects(&p).unwrap();
        assert_eq!(objects.len(), 1);
        assert!(objects[0].text.contains("for each Customer"));
        assert_eq!(objects[0].object.object_type, "Root");
        assert_eq!(objects[0].object.id, "MiObj");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn xml_without_events_is_unsupported() {
        let xml = "<Root><Name>doc</Name></Root>";
        let p = tmp("gx_unsupported.xml");
        std::fs::write(&p, xml).unwrap();
        let err = extract_source_objects(&p).unwrap_err();
        assert!(err.to_string().contains("no soportado"), "err: {err}");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn corrupt_zip_is_rejected() {
        let p = tmp("gx_corrupt.xpz");
        std::fs::write(&p, b"PK\x03\x04 datos corruptos").unwrap();
        let err = extract_source_objects(&p).unwrap_err();
        assert!(err.to_string().contains("ZIP inválido"), "err: {err}");
        let _ = std::fs::remove_file(&p);
    }

    // ── Formato real ExportFile/GXObject ─────────────────────────────────

    fn real_export_xml() -> String {
        r#"<?xml version='1.0' encoding='iso-8859-1'?>
<ExportFile>
  <Model><Name>Java-Oracle</Name></Model>
  <GXObject>
    <WebPanel>
      <Info>
        <Name>JFCQ350</Name>
        <Description>Panel demo</Description>
        <Folder>CE</Folder>
      </Info>
      <Documentation>
        <Source><![CDATA[<P>documentacion html</P>]]></Source>
      </Documentation>
      <Events><![CDATA[
Sub 'Obtener'
    &Ctnom = Ctnom
EndSub
]]></Events>
    </WebPanel>
  </GXObject>
  <GXObject>
    <Procedure>
      <Info>
        <Name>JBMP018</Name>
        <Folder>NUCLEO_Tablas</Folder>
      </Info>
      <Layout>
        <Source><![CDATA[//@ LAYOUT no lintable]]></Source>
      </Layout>
      <Rules><![CDATA[Parm(&PPgcod, &PModulo)
]]></Rules>
    </Procedure>
  </GXObject>
  <GXObject>
    <Theme>
      <Info><Name>DlyaTheme</Name></Info>
    </Theme>
  </GXObject>
</ExportFile>
"#
        .to_string()
    }

    #[test]
    fn real_export_objects_identity_and_sections() {
        let p = tmp("gx_real_export.xml");
        std::fs::write(&p, real_export_xml()).unwrap();
        let objects = extract_source_objects(&p).unwrap();

        // WebPanel (Events) + Procedure (Rules); Theme sin código se omite.
        assert_eq!(objects.len(), 2);

        let panel = &objects[0];
        assert_eq!(panel.object.id, "JFCQ350");
        assert_eq!(panel.object.object_type, "WebPanel");
        assert_eq!(panel.object.package, "CE");
        assert!(panel.text.contains("Sub 'Obtener'"));
        assert!(
            !panel.text.contains("documentacion html"),
            "Documentation/Source NO debe lintarse"
        );

        let proc = &objects[1];
        assert_eq!(proc.object.id, "JBMP018");
        assert_eq!(proc.object.object_type, "Procedure");
        assert_eq!(proc.object.package, "NUCLEO_Tablas");
        assert!(proc.text.contains("Parm(&PPgcod"), "Rules es código");
        assert!(
            !proc.text.contains("LAYOUT no lintable"),
            "Layout/Source NO debe lintarse"
        );

        let _ = std::fs::remove_file(&p);
    }

    /// Objetos GeneXus reconocidos sin secciones de código: válido, 0 objetos.
    #[test]
    fn recognized_objects_without_code_are_valid() {
        let xml = r#"<ExportFile>
  <GXObject><Transaction><Info><Name>JNGZ293</Name></Info></Transaction></GXObject>
  <GXObject><Table><Info><Name>JNGZ293</Name></Info></Table></GXObject>
</ExportFile>"#;
        let p = tmp("gx_no_code.xml");
        std::fs::write(&p, xml).unwrap();
        let objects = extract_source_objects(&p).unwrap();
        assert!(objects.is_empty(), "sin secciones de código: 0 objetos");
        let _ = std::fs::remove_file(&p);
    }

    /// Paquete ZIP construido en el test (incluye un miembro no-XML).
    #[test]
    fn zip_package_extracts_gxobjects() {
        let p = tmp("gx_zip_test.zip");
        {
            let file = std::fs::File::create(&p).unwrap();
            let mut zw = zip::ZipWriter::new(file);
            let opts = zip::write::SimpleFileOptions::default();
            use std::io::Write;
            zw.start_file("KB/KB_1.xml", opts).unwrap();
            zw.write_all(real_export_xml().as_bytes()).unwrap();
            zw.start_file("leeme.txt", opts).unwrap();
            zw.write_all(b"no es xml").unwrap();
            zw.finish().unwrap();
        }
        let objects = extract_source_objects(&p).unwrap();
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].object.member, "KB/KB_1.xml");
        assert_eq!(objects[0].object.id, "JFCQ350");
        let _ = std::fs::remove_file(&p);
    }

    /// GX-006/GX-017: `code_start_line` apunta a la línea del `<!\[CDATA\[`
    /// y `member_line` mapea 1:1 el texto extraído al miembro.
    #[test]
    fn cdata_start_line_maps_to_member_lines() {
        let xml = "<?xml version=\"1.0\"?>\n\
                   <Procedure name=\"ProcMalo\" package=\"Pkg\">\n\
                   <Events>\n\
                   <![CDATA[\n\
                   &MiVar = 1\n\
                   sub 'Inicializar'\n\
                   ]]>\n\
                   </Events>\n\
                   </Procedure>\n";
        let p = tmp("gx_member_line.xml");
        std::fs::write(&p, xml).unwrap();
        let objects = extract_source_objects(&p).unwrap();
        assert_eq!(objects.len(), 1);
        let obj = &objects[0];
        assert_eq!(obj.code_start_line, 4, "el CDATA comienza en la línea 4");
        assert_eq!(
            obj.member_line(2),
            5,
            "&MiVar = 1 está en la línea 5 del miembro"
        );
        assert_eq!(
            obj.member_line(3),
            6,
            "sub 'Inicializar' está en la línea 6 del miembro"
        );
        let _ = std::fs::remove_file(&p);
    }

    /// A03/F04: un objeto con dos secciones separadas mapea cada línea del
    /// texto concatenado a la línea FÍSICA real del miembro.
    #[test]
    fn sections_segments_map_to_member_lines() {
        let xml = "<ExportFile>\n\
                   <GXObject>\n\
                   <Procedure>\n\
                   <Info><Name>P1</Name></Info>\n\
                   <Events><![CDATA[\n\
                   &a = 1\n\
                   ]]></Events>\n\
                   <Rules><![CDATA[Parm(&x)\n\
                   ]]></Rules>\n\
                   </Procedure>\n\
                   </GXObject>\n\
                   </ExportFile>\n";
        let extracted = extract_from_xml_text(xml, "c", "m.xml", None).unwrap();
        assert_eq!(extracted.objects.len(), 1);
        let obj = &extracted.objects[0];
        assert_eq!(obj.segments.len(), 2);
        assert_eq!(obj.segments[0].kind, "Events");
        assert_eq!(obj.segments[1].kind, "Rules");
        assert_eq!(obj.segments[0].member_start_line, 5);
        assert_eq!(obj.segments[1].member_start_line, 8);
        assert_eq!(obj.segments[1].text_start_line, 5);
        assert_eq!(obj.member_line(2), 6, "&a = 1 está en la línea 6");
        assert_eq!(obj.member_line(5), 8, "Parm(&x) está en la línea 8");
    }

    /// A03: el CDATA de documentación con apariencia de código NO es fuente.
    #[test]
    fn documentation_cdata_cannot_become_code() {
        let xml = "<ExportFile>\n\
                   <GXObject><Procedure><Info><Name>P1</Name></Info>\n\
                   <Documentation><Source><![CDATA[<Events>sub 'Malo'\n\
                   &i = &i + 1\n\
                   </Events>]]></Source></Documentation>\n\
                   </Procedure></GXObject>\n\
                   </ExportFile>\n";
        let extracted = extract_from_xml_text(xml, "c", "m.xml", None).unwrap();
        assert_eq!(extracted.gx_objects, 1, "el GXObject se reconoce");
        assert!(
            extracted.objects.is_empty(),
            "documentación no aporta código: {:?}",
            extracted.objects
        );
    }

    /// A03: comentario de bloque dentro de un string no altera el texto.
    #[test]
    fn string_with_block_comment_marker_is_preserved() {
        let xml = "<Root name=\"P\"><Events><![CDATA[\n\
                   &x = '/* no es comentario */'\n\
                   ]]></Events></Root>";
        let extracted = extract_from_xml_text(xml, "c", "m.xml", None).unwrap();
        assert!(extracted.objects[0].text.contains("/* no es comentario */"));
    }

    /// E01: XML mutado (truncado, insertado, reemplazado) nunca paniquea:
    /// devuelve Ok con lo parseado o Err explícito.
    #[test]
    fn malformed_xml_never_panics_and_is_total() {
        let base = real_export_xml();
        assert!(
            extract_from_xml_text(&base, "c", "m.xml", None).is_ok(),
            "el XML base debe parsear"
        );

        let mut state: u64 = 0xDEAD_BEEF_CAFE_F00D;
        let next = |state: &mut u64| -> u64 {
            let mut x = *state;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            *state = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };

        for _ in 0..1500 {
            let mut bytes = base.clone().into_bytes();
            if bytes.is_empty() {
                continue;
            }
            let picks = next(&mut state);
            let index = (picks as usize) % bytes.len();
            match picks % 5 {
                0 => bytes.truncate(index),
                1 => {
                    bytes.remove(index);
                }
                2 => bytes.insert(index, b"<>\"'&/"[((picks >> 8) as usize) % 6]),
                3 => {
                    let len = bytes.len();
                    bytes[index] = bytes[(index + 1) % len];
                }
                _ => {
                    let marker = b"</GXObject>";
                    let at = index.min(bytes.len().saturating_sub(1));
                    bytes.splice(at..at, marker.iter().copied());
                }
            }
            let candidate = String::from_utf8_lossy(&bytes).into_owned();
            // Totalidad: Ok o Err, jamás panic.
            let _ = extract_from_xml_text(&candidate, "c", "m.xml", None);
        }
    }

    /// E01/A04: límite de miembro en ZIP devuelve `partial` (no error).
    #[test]
    fn zip_member_limit_is_partial() {
        let p = tmp("gx_zip_limit.zip");
        {
            let file = std::fs::File::create(&p).unwrap();
            let mut zw = zip::ZipWriter::new(file);
            let opts = zip::write::SimpleFileOptions::default();
            use std::io::Write;
            zw.start_file("KB/KB_1.xml", opts).unwrap();
            zw.write_all(real_export_xml().as_bytes()).unwrap();
            zw.finish().unwrap();
        }
        let budget = ExecutionBudget {
            max_member_bytes: 16,
            ..Default::default()
        };
        let outcome = extract_source_objects_with_budget(&p, &budget, None).unwrap();
        assert!(outcome.limit.is_some(), "debe cortar por presupuesto");
        assert!(outcome.objects.is_empty());
        let _ = std::fs::remove_file(&p);
    }

    /// E01/A04: token de cancelación pre-seteado detiene la extracción.
    #[test]
    fn cancelled_extraction_reports_cancelled() {
        let p = tmp("gx_cancel_xml.xml");
        std::fs::write(&p, real_export_xml()).unwrap();
        let cancel = AtomicBool::new(true);
        let outcome =
            extract_source_objects_with_budget(&p, &ExecutionBudget::default(), Some(&cancel))
                .unwrap();
        assert!(outcome.cancelled);
        assert!(outcome.objects.is_empty());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn list_package_members_zip() {
        let p = tmp("gx_zip_members.zip");
        {
            let file = std::fs::File::create(&p).unwrap();
            let mut zw = zip::ZipWriter::new(file);
            let opts = zip::write::SimpleFileOptions::default();
            use std::io::Write;
            zw.start_file("KB/KB_1.xml", opts).unwrap();
            zw.write_all(b"<x/>").unwrap();
            zw.finish().unwrap();
        }
        let names = list_package_members(&p).unwrap();
        assert_eq!(names, vec!["KB/KB_1.xml".to_string()]);
        let _ = std::fs::remove_file(&p);
    }
}
