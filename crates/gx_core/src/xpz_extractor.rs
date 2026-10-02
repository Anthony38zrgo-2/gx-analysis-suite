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

use anyhow::{bail, Result};
use regex::Regex;
use std::sync::LazyLock;

use crate::models::{ObjectRef, SourceObject};

/// Máximo de miembros por paquete (protección contra paquetes anómalos).
pub const MAX_XPZ_MEMBERS: usize = 4096;
/// Máximo de bytes descomprimidos por miembro.
pub const MAX_MEMBER_BYTES: usize = 32 * 1024 * 1024;
/// Máximo de bytes descomprimidos totales por artefacto.
pub const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;

/// Matches `<Events><![CDATA[ ... ]]></Events>` (DOTALL + IGNORECASE).
pub static EVENTS_CDATA_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<Events>\s*<!\[CDATA\[(.*?)]]>\s*</Events>").unwrap());

/// Bloque `<GXObject>…</GXObject>` del formato real de export.
static GXOBJECT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<GXObject\b[^>]*>\s*(.*?)\s*</GXObject>").unwrap());

/// Primer tag dentro del bloque GXObject: el tipo de objeto.
static GXOBJECT_TYPE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)^\s*<([A-Za-z][A-Za-z0-9_]*)").unwrap());

/// Bloque `<Info>…</Info>` (nombre/folder del objeto).
static INFO_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?is)<Info>(.*?)</Info>").unwrap());
static INFO_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<Name>\s*([^<]*?)\s*</Name>").unwrap());
static INFO_FOLDER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<Folder>\s*([^<]*?)\s*</Folder>").unwrap());

/// Secciones de CÓDIGO dentro de un objeto, en orden documental.
static CODE_SECTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)<(Events|Rules|Subroutines)>\s*<!\[CDATA\[(.*?)]]>").unwrap()
});

/// Primer tag del XML del miembro: tipo de objeto + atributos (layout legacy).
static ROOT_TAG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<([A-Za-z][A-Za-z0-9_]*)\b([^>]*)>").unwrap());

/// Extrae los objetos fuente de un artefacto GeneXus (GX-006).
pub fn extract_source_objects(file_path: &Path) -> Result<Vec<SourceObject>> {
    if !file_path.is_file() {
        bail!("El archivo no existe: {}", file_path.display());
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
                objects_from_rar(file_path)
            } else {
                objects_from_zip(file_path)
            }
        }
        "xml" => objects_from_xml(file_path),
        "txt" | "prg" | "gxd" | "src" => objects_from_text(file_path),
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

fn objects_from_text(file_path: &Path) -> Result<Vec<SourceObject>> {
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
    let name = file_name_lossy(file_path);
    let id = file_stem_lossy(file_path).unwrap_or_else(|| name.clone());
    Ok(vec![SourceObject {
        object: ObjectRef {
            id,
            object_type: "Source".to_string(),
            container_path: file_path.to_string_lossy().to_string(),
            member: name,
            package: String::new(),
        },
        text,
        code_start_line: 1,
    }])
}

// ─────────────────────────────────────────────────────────────────────────
// XML
// ─────────────────────────────────────────────────────────────────────────

fn objects_from_xml(xml_path: &Path) -> Result<Vec<SourceObject>> {
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
    let extracted = extract_from_xml_text(&xml_text, &container, &name);

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
    Ok(extracted.objects)
}

// ─────────────────────────────────────────────────────────────────────────
// Paquete ZIP
// ─────────────────────────────────────────────────────────────────────────

fn objects_from_zip(xpz_path: &Path) -> Result<Vec<SourceObject>> {
    let file = std::fs::File::open(xpz_path)?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| anyhow::anyhow!("ZIP inválido '{}': {e}", xpz_path.display()))?;
    if archive.is_empty() {
        bail!("El archivo '{}' está vacío.", xpz_path.display());
    }
    if archive.len() > MAX_XPZ_MEMBERS {
        bail!(
            "El archivo '{}' supera el máximo de miembros permitidos ({}).",
            xpz_path.display(),
            MAX_XPZ_MEMBERS
        );
    }

    let container = xpz_path.to_string_lossy().to_string();
    let mut objects: Vec<SourceObject> = Vec::new();
    let mut gx_objects: usize = 0;
    let mut total_bytes: usize = 0;

    for i in 0..archive.len() {
        let mut member = archive.by_index(i)?;
        let member_name = member.name().replace('\\', "/");
        if member_name.ends_with('/') {
            continue;
        }
        let member_size = member.size() as usize;
        if member_size > MAX_MEMBER_BYTES {
            bail!(
                "El miembro '{member_name}' de '{}' supera el tamaño máximo permitido ({} bytes).",
                xpz_path.display(),
                MAX_MEMBER_BYTES
            );
        }
        total_bytes += member_size;
        if total_bytes > MAX_TOTAL_BYTES {
            bail!(
                "El archivo '{}' supera el tamaño descomprimido máximo permitido ({} bytes).",
                xpz_path.display(),
                MAX_TOTAL_BYTES
            );
        }
        let mut raw = Vec::with_capacity(member_size.min(8 * 1024 * 1024));
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

        let extracted = extract_from_xml_text(&xml_text, &container, &member_name);
        gx_objects += extracted.gx_objects;
        objects.extend(extracted.objects);
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
    Ok(objects)
}

// ─────────────────────────────────────────────────────────────────────────
// Paquete RAR (GeneXus con WinRAR)
// ─────────────────────────────────────────────────────────────────────────

fn objects_from_rar(xpz_path: &Path) -> Result<Vec<SourceObject>> {
    let container = xpz_path.to_string_lossy().to_string();
    let mut objects: Vec<SourceObject> = Vec::new();
    let mut gx_objects: usize = 0;

    let mut archive = unrar::Archive::new(xpz_path)
        .open_for_processing()
        .map_err(|e| anyhow::anyhow!("RAR inválido '{}': {e}", xpz_path.display()))?;

    let mut member_seen = 0usize;
    let mut total_bytes: usize = 0;
    while let Some(state) = archive
        .read_header()
        .map_err(|e| anyhow::anyhow!("Miembro RAR ilegible de '{}': {e}", xpz_path.display()))?
    {
        let member_name = state.entry().filename.to_string_lossy().replace('\\', "/");
        if member_name.ends_with('/') {
            archive = state.skip().map_err(|e| {
                anyhow::anyhow!("Miembro RAR ilegible de '{}': {e}", xpz_path.display())
            })?;
            continue;
        }
        member_seen += 1;
        if member_seen > MAX_XPZ_MEMBERS {
            bail!(
                "El archivo '{}' supera el máximo de miembros permitidos ({}).",
                xpz_path.display(),
                MAX_XPZ_MEMBERS
            );
        }
        let size = state.entry().unpacked_size;
        if size > MAX_MEMBER_BYTES as u64 {
            bail!(
                "El miembro '{member_name}' de '{}' supera el tamaño máximo permitido ({} bytes).",
                xpz_path.display(),
                MAX_MEMBER_BYTES
            );
        }
        total_bytes += size as usize;
        if total_bytes > MAX_TOTAL_BYTES {
            bail!(
                "El archivo '{}' supera el tamaño descomprimido máximo permitido ({} bytes).",
                xpz_path.display(),
                MAX_TOTAL_BYTES
            );
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

        let extracted = extract_from_xml_text(&xml_text, &container, &member_name);
        gx_objects += extracted.gx_objects;
        objects.extend(extracted.objects);
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
    Ok(objects)
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
}

/// Extrae objetos de un texto XML: primero formato real (`GXObject`), y si
/// no hay ninguno, layout legacy con `<Events>` directos.
fn extract_from_xml_text(xml_text: &str, container: &str, member: &str) -> Extracted {
    let mut objects: Vec<SourceObject> = Vec::new();
    let mut gx_objects: usize = 0;

    for caps in GXOBJECT_RE.captures_iter(xml_text) {
        gx_objects += 1;
        let block = match caps.get(1) {
            Some(m) => m,
            None => continue,
        };
        let block_text = block.as_str();
        let block_offset = block.start();

        let object_type = GXOBJECT_TYPE_RE
            .captures(block_text)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "Source".to_string());

        let info = INFO_RE.captures(block_text).and_then(|c| c.get(1));
        let info_text = info.as_ref().map(|m| m.as_str()).unwrap_or("");
        let name = INFO_NAME_RE
            .captures(info_text)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_default();
        let package = INFO_FOLDER_RE
            .captures(info_text)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_default();

        let sections = code_sections(xml_text, block_offset, block_text);
        if sections.is_empty() {
            continue;
        }
        let code_start_line = sections.first().map(|s| s.2).unwrap_or(1);
        let text = sections
            .iter()
            .map(|s| s.1.as_str())
            .collect::<Vec<_>>()
            .join("\n\n");

        objects.push(SourceObject {
            object: ObjectRef {
                id: if name.is_empty() {
                    member_stem(member)
                } else {
                    name
                },
                object_type,
                container_path: container.to_string(),
                member: member.to_string(),
                package,
            },
            text,
            code_start_line,
        });
    }

    if gx_objects == 0 {
        // Layout legacy (fixtures sintéticos / exports antiguos): `<Events>`
        // directos con identidad desde los atributos del root.
        objects.extend(legacy_events_objects(xml_text, container, member));
    }

    Extracted {
        objects,
        gx_objects,
    }
}

/// Secciones de código de un objeto: `(kind, texto, línea en el miembro)`.
fn code_sections(
    xml_text: &str,
    block_offset: usize,
    block_text: &str,
) -> Vec<(String, String, u32)> {
    let mut sections = Vec::new();
    for caps in CODE_SECTION_RE.captures_iter(block_text) {
        let kind = caps
            .get(1)
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        let cdata = match caps.get(2) {
            Some(m) => m.as_str(),
            None => continue,
        };
        if cdata.trim().is_empty() {
            continue;
        }
        let abs_start = block_offset + caps.get(0).map(|m| m.start()).unwrap_or(0);
        let line = xml_text[..abs_start.min(xml_text.len())]
            .matches('\n')
            .count() as u32
            + 1;
        sections.push((kind, cdata.to_string(), line));
    }
    sections
}

/// Layout legacy: un objeto por `<Events><![CDATA[...]]>` con identidad del
/// root (atributos `name`/`package`) o del stem del miembro.
fn legacy_events_objects(xml_text: &str, container: &str, member: &str) -> Vec<SourceObject> {
    let root = root_info(xml_text);
    let mut objects = Vec::new();
    for caps in EVENTS_CDATA_RE.captures_iter(xml_text) {
        let whole_start = caps.get(0).map(|m| m.start()).unwrap_or(0);
        let cdata = match caps.get(1) {
            Some(m) => m.as_str(),
            None => continue,
        };
        if cdata.trim().is_empty() {
            continue;
        }
        let code_start_line = xml_text[..whole_start].matches('\n').count() as u32 + 1;
        let id = if root.name.is_empty() {
            member_stem(member)
        } else {
            root.name.clone()
        };
        objects.push(SourceObject {
            object: ObjectRef {
                id,
                object_type: root.kind.clone(),
                container_path: container.to_string(),
                member: member.to_string(),
                package: root.package.clone(),
            },
            text: cdata.to_string(),
            code_start_line,
        });
    }
    objects
}

struct RootInfo {
    kind: String,
    name: String,
    package: String,
}

fn root_info(xml_text: &str) -> RootInfo {
    let (kind, attrs) = ROOT_TAG_RE
        .captures(xml_text)
        .map(|c| {
            (
                c.get(1).map(|m| m.as_str().to_string()),
                c.get(2).map(|m| m.as_str().to_string()),
            )
        })
        .unwrap_or((None, None));
    let attrs = attrs.unwrap_or_default();
    let attr = |key: &str| -> String {
        Regex::new(&format!(r#"(?i)\b{key}\s*=\s*"([^"]*)""#))
            .ok()
            .and_then(|re| re.captures(&attrs))
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_default()
    };
    RootInfo {
        kind: kind.unwrap_or_else(|| "Source".to_string()),
        name: attr("name"),
        package: attr("package"),
    }
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
