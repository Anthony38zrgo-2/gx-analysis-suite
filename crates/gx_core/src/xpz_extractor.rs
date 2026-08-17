//! Unified GeneXus source extraction for `.txt`, `.xml` and `.xpz`.
//!
//! Port of `gx_linter/app/core/xpz_extractor.py`. The `<Events>` CDATA
//! block holds the real GeneXus source; `.xpz` files are ZIP packages
//! of XML members.

use std::path::Path;

use anyhow::{bail, Result};
use regex::Regex;
use std::sync::LazyLock;

/// Extensions that require CDATA extraction.
#[allow(dead_code)]
const STRUCTURED_EXTENSIONS: &[&str] = &[".xpz", ".xml"];

/// Matches `<Events><![CDATA[ ... ]]></Events>` (DOTALL + IGNORECASE).
pub static EVENTS_CDATA_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<Events>\s*<!\[CDATA\[(.*?)]]>\s*</Events>").unwrap());

/// Unified entry point: dispatch by file extension.
pub fn extract_genexus_source(file_path: &Path) -> Result<String> {
    if !file_path.is_file() {
        bail!("El archivo no existe: {}", file_path.display());
    }
    let ext = file_path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_default();

    if ext == "xpz" {
        extract_source_from_xpz(file_path)
    } else if ext == "xml" {
        extract_source_from_xml(file_path)
    } else {
        let bytes = std::fs::read(file_path)?;
        Ok(decode_bytes(&bytes, "utf-8").unwrap_or_default())
    }
}

/// List member names inside an `.xpz` (ZIP) file.
pub fn list_xpz_members(xpz_path: &Path) -> Result<Vec<String>> {
    let file = std::fs::File::open(xpz_path)?;
    let mut archive = zip::ZipArchive::new(file)?;
    let mut names = Vec::new();
    for i in 0..archive.len() {
        if let Ok(member) = archive.by_index(i) {
            names.push(member.name().to_string());
        }
    }
    Ok(names)
}

/// Extract source from a `.xpz` (ZIP) package.
pub fn extract_source_from_xpz(xpz_path: &Path) -> Result<String> {
    let file = std::fs::File::open(xpz_path)?;
    let mut archive = zip::ZipArchive::new(file)?;
    if archive.is_empty() {
        bail!("El archivo XPZ '{}' está vacío.", xpz_path.display());
    }

    let mut blocks: Vec<String> = Vec::new();
    let mut fallback: Option<String> = None;

    for i in 0..archive.len() {
        let mut member = archive.by_index(i)?;
        let member_name = member.name().to_string();
        if member_name.ends_with('/') {
            continue;
        }
        let mut raw = Vec::new();
        use std::io::Read;
        if member.read_to_end(&mut raw).is_err() {
            continue;
        }
        let xml_text = match decode_bytes(&raw, "utf-8") {
            Some(t) => t,
            None => continue,
        };
        if fallback.is_none() && !xml_text.trim().is_empty() {
            fallback = Some(xml_text.clone());
        }
        if let Some(cdata) = extract_cdata(&xml_text) {
            blocks.push(format!("// === [XPZ] Objeto: {member_name} ===\n{cdata}"));
        }
    }

    if !blocks.is_empty() {
        return Ok(blocks.join("\n\n"));
    }
    if let Some(fb) = fallback {
        tracing::warn!(
            "[XPZ] No se encontró bloque <Events><![CDATA[...]]>. \
             Usando contenido del miembro como fallback."
        );
        return Ok(fb);
    }
    bail!(
        "No se pudo extraer contenido fuente del archivo '{}'.",
        xpz_path.display()
    );
}

/// Extract source from a plain `.xml` file.
pub fn extract_source_from_xml(xml_path: &Path) -> Result<String> {
    let raw = std::fs::read(xml_path)?;
    let xml_text = decode_bytes(&raw, "utf-8").ok_or_else(|| {
        anyhow::anyhow!(
            "No se pudo decodificar el archivo '{}'. Pruebe con otra codificación.",
            xml_path.display()
        )
    })?;
    if xml_text.trim().is_empty() {
        bail!("El archivo XML '{}' está vacío.", xml_path.display());
    }

    let matches: Vec<&str> = EVENTS_CDATA_RE
        .captures_iter(&xml_text)
        .filter_map(|c| c.get(1))
        .map(|m| m.as_str())
        .collect();
    if !matches.is_empty() {
        let object_name = xml_path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let header = format!("// === [XML] Objeto: {object_name} ===\n");
        return Ok(format!("{header}{}", matches.join("\n\n")));
    }

    tracing::warn!(
        "[XML] No se encontró bloque <Events><![CDATA[...]]> en '{}'. \
         Usando contenido XML completo como fallback.",
        xml_path.display()
    );
    Ok(xml_text)
}

/// Return the first `<Events>` CDATA body, if any.
fn extract_cdata(xml_text: &str) -> Option<String> {
    EVENTS_CDATA_RE
        .captures(xml_text)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

/// Try several encodings in order; returns the first successful decode.
fn decode_bytes(data: &[u8], primary: &str) -> Option<String> {
    for enc in [primary, "utf-8-sig", "latin-1", "cp1252"] {
        if let Some(decoded) = decode_with(enc, data) {
            return Some(decoded);
        }
    }
    None
}

fn decode_with(enc_label: &str, data: &[u8]) -> Option<String> {
    match enc_label {
        "utf-8" => std::str::from_utf8(data).ok().map(|s| s.to_string()),
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

    #[test]
    fn txt_extract_is_identity() {
        let tmp = std::env::temp_dir().join("gx_xpz_test.txt");
        std::fs::write(&tmp, "for each Customer\n  &x = 1\n").unwrap();
        let out = extract_genexus_source(&tmp).unwrap();
        assert!(out.contains("for each Customer"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn xml_extract_cdata() {
        let xml = "<Root><Events><![CDATA[\nfor each Customer\n]]></Events></Root>";
        let tmp = std::env::temp_dir().join("gx_xpz_test.xml");
        std::fs::write(&tmp, xml).unwrap();
        let out = extract_genexus_source(&tmp).unwrap();
        assert!(out.contains("for each Customer"));
        let _ = std::fs::remove_file(&tmp);
    }
}
