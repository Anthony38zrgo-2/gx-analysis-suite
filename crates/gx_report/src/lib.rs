//! gx_report — informe PDF source-aware desde `AnalysisResult` (GX-019).
//!
//! El PDF se genera SIN re-ejecutar el engine: consume el contrato
//! serializado (`AnalysisResult`) y nunca altera el veredicto del lint.
//!
//! El layout se calcula primero como líneas de texto puras ([`layout`]) y
//! luego se serializa con `printpdf` (fuentes builtin Helvetica). Esa
//! separación permite testear paginación y contenido sin depender del
//! formato binario.

use std::path::Path;

use anyhow::{bail, Context, Result};
use gx_core::models::{AnalysisResult, QgPolicy, QgVerdict, Severity};
use printpdf::{
    BuiltinFont, Color, Mm, Op, PdfDocument, PdfFontHandle, PdfPage, PdfSaveOptions, Point, Pt,
    Rgb, TextItem,
};

/// A4 en milímetros.
pub const PAGE_WIDTH_MM: f32 = 210.0;
pub const PAGE_HEIGHT_MM: f32 = 297.0;
const MARGIN_MM: f32 = 16.0;
const BODY_PT: f32 = 9.0;
const TITLE_PT: f32 = 18.0;
const SUBTITLE_PT: f32 = 10.5;
const LINE_HEIGHT_MM: f32 = 4.4;
const TITLE_ADVANCE_MM: f32 = 9.0;
const FOOTER_MM: f32 = 10.0;
const MAX_LINES_PER_PAGE: usize = 56;
const DESC_WRAP_COLS: usize = 112;

const COLOR_BODY: [f32; 3] = [0.10, 0.10, 0.12];
const COLOR_MUTED: [f32; 3] = [0.38, 0.38, 0.42];
const COLOR_ERROR: [f32; 3] = [0.65, 0.08, 0.08];
const COLOR_WARNING: [f32; 3] = [0.55, 0.35, 0.0];
const COLOR_INFO: [f32; 3] = [0.05, 0.30, 0.50];

/// Una línea del informe (texto + estilo).
#[derive(Debug, Clone, PartialEq)]
pub struct ReportLine {
    pub text: String,
    pub size_pt: f32,
    pub bold: bool,
    pub color: [f32; 3],
}

impl ReportLine {
    fn styled(text: impl Into<String>, size_pt: f32, bold: bool, color: [f32; 3]) -> Self {
        Self {
            text: text.into(),
            size_pt,
            bold,
            color,
        }
    }

    fn body(text: impl Into<String>) -> Self {
        Self::styled(text, BODY_PT, false, COLOR_BODY)
    }

    fn muted(text: impl Into<String>) -> Self {
        Self::styled(text, BODY_PT, false, COLOR_MUTED)
    }

    fn error(text: impl Into<String>) -> Self {
        Self::styled(text, BODY_PT, false, COLOR_ERROR)
    }

    fn subtitle(text: impl Into<String>) -> Self {
        Self::styled(text, SUBTITLE_PT, true, COLOR_BODY)
    }

    fn title(text: impl Into<String>) -> Self {
        Self::styled(text, TITLE_PT, true, COLOR_BODY)
    }

    fn finding(severity: Severity, text: impl Into<String>) -> Self {
        let color = match severity {
            Severity::Error => COLOR_ERROR,
            Severity::Warning => COLOR_WARNING,
            Severity::Info => COLOR_INFO,
        };
        Self::styled(text, BODY_PT, true, color)
    }
}

/// Calcula el layout completo (páginas de líneas) del informe.
///
/// La página 1 incluye portada (política, veredicto, métricas, fallos) y la
/// tabla de hallazgos; las siguientes continúan la tabla. Cada hallazgo
/// aporta una línea de cabecera + descripción envuelta.
pub fn layout(result: &AnalysisResult) -> Vec<Vec<ReportLine>> {
    let mut blocks: Vec<Vec<ReportLine>> = Vec::new();

    blocks.push(vec![ReportLine::title("GX Linter — Informe de auditoría")]);
    blocks.push(vec![ReportLine::subtitle(format!(
        "Generado: {}",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
    ))]);
    blocks.push(vec![ReportLine::body(format!(
        "Política: {}",
        policy_label(&result.policy)
    ))]);
    blocks.push(vec![ReportLine::body(format!(
        "Veredicto: {}",
        verdict_label(result.verdict)
    ))]);
    blocks.push(vec![ReportLine::body(format!(
        "Archivos escaneados: {} | Hallazgos: {} ({} ERROR / {} WARNING / {} INFO)",
        result.scanned_files,
        result.metrics.total_findings,
        result.metrics.errors,
        result.metrics.warnings,
        result.metrics.info
    ))]);

    if result.failures.is_empty() {
        blocks.push(vec![ReportLine::muted("Fallos de scan: ninguno.")]);
    } else {
        blocks.push(vec![ReportLine::error(format!(
            "Fallos de scan ({}):",
            result.failures.len()
        ))]);
        for failure in &result.failures {
            for line in wrap(
                &format!("{} — {}", failure.path.display(), failure.error),
                DESC_WRAP_COLS,
            ) {
                blocks.push(vec![ReportLine::error(format!("  {line}"))]);
            }
        }
    }

    blocks.push(vec![ReportLine::body("")]);
    blocks.push(vec![ReportLine::subtitle(format!(
        "Hallazgos ({})",
        result.findings.len()
    ))]);

    for issue in &result.findings {
        let mut block = Vec::new();
        let object = match &issue.object {
            Some(o) => format!("{} ({}) — {}", o.id, o.object_type, o.member),
            None => "—".to_string(),
        };
        block.push(ReportLine::finding(
            issue.severity,
            format!(
                "{}  {}  línea {}  {}",
                issue.severity.as_str(),
                issue.rule_id,
                issue.line_number,
                object
            ),
        ));
        for line in wrap(&issue.description, DESC_WRAP_COLS) {
            block.push(ReportLine::muted(format!("    {line}")));
        }
        blocks.push(block);
    }

    paginate(blocks)
}

fn paginate(blocks: Vec<Vec<ReportLine>>) -> Vec<Vec<ReportLine>> {
    let mut pages: Vec<Vec<ReportLine>> = Vec::new();
    let mut current: Vec<ReportLine> = Vec::new();

    for block in blocks {
        if !current.is_empty() && current.len() + block.len() > MAX_LINES_PER_PAGE {
            pages.push(current);
            current = vec![ReportLine::muted("GX Linter — continuación")];
        }
        current.extend(block);
    }
    if !current.is_empty() {
        pages.push(current);
    }
    if pages.is_empty() {
        pages.push(Vec::new());
    }
    pages
}

/// Genera el PDF en memoria desde un [`AnalysisResult`].
pub fn render_bytes(result: &AnalysisResult) -> Result<Vec<u8>> {
    let pages = layout(result);
    let total_pages = pages.len();
    let mut pdf_pages = Vec::with_capacity(total_pages);

    for (index, lines) in pages.iter().enumerate() {
        let mut ops = vec![Op::StartTextSection];
        let mut y = PAGE_HEIGHT_MM - MARGIN_MM;
        for line in lines {
            let advance = if line.size_pt > 12.0 {
                TITLE_ADVANCE_MM
            } else {
                LINE_HEIGHT_MM
            };
            y -= advance;
            push_text(&mut ops, y, line);
        }
        push_text(
            &mut ops,
            FOOTER_MM,
            &ReportLine::muted(format!("Página {} de {}", index + 1, total_pages)),
        );
        ops.push(Op::EndTextSection);
        pdf_pages.push(PdfPage::new(Mm(PAGE_WIDTH_MM), Mm(PAGE_HEIGHT_MM), ops));
    }

    let mut document = PdfDocument::new("GX Linter — Informe de auditoría");
    document.with_pages(pdf_pages);
    let mut warnings = Vec::new();
    let bytes = document.save(&PdfSaveOptions::default(), &mut warnings);
    if !bytes.starts_with(b"%PDF") {
        bail!(
            "printpdf no produjo un PDF válido ({} advertencias)",
            warnings.len()
        );
    }
    Ok(bytes)
}

/// Genera y escribe el PDF en `out_path` (creando el directorio si falta).
pub fn render(result: &AnalysisResult, out_path: &Path) -> Result<()> {
    let bytes = render_bytes(result)?;
    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("no se pudo crear el directorio '{}'", parent.display())
            })?;
        }
    }
    std::fs::write(out_path, bytes)
        .with_context(|| format!("no se pudo escribir el PDF '{}'", out_path.display()))?;
    Ok(())
}

fn push_text(ops: &mut Vec<Op>, y_mm: f32, line: &ReportLine) {
    let text = sanitize(&line.text);
    if text.is_empty() {
        return;
    }
    ops.push(Op::SetFillColor {
        col: Color::Rgb(Rgb::new(line.color[0], line.color[1], line.color[2], None)),
    });
    ops.push(Op::SetFont {
        font: PdfFontHandle::Builtin(if line.bold {
            BuiltinFont::HelveticaBold
        } else {
            BuiltinFont::Helvetica
        }),
        size: Pt(line.size_pt),
    });
    ops.push(Op::SetTextCursor {
        pos: Point::new(Mm(MARGIN_MM), Mm(y_mm)),
    });
    ops.push(Op::ShowText {
        items: vec![TextItem::Text(text)],
    });
}

/// Normaliza puntuación tipográfica y controles al repertorio WinAnsi de las
/// fuentes builtin (las vocales acentuadas se conservan).
fn sanitize(text: &str) -> String {
    text.replace('…', "...")
        .replace(['—', '–', '·'], "-")
        .replace(['“', '”'], "\"")
        .replace(['‘', '’'], "'")
        .replace('→', ">")
        .chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .collect()
}

/// Envuelve texto a `max_cols` columnas respetando palabras (corta palabras
/// larguísimas como paths).
fn wrap(text: &str, max_cols: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();

    for word in text.split_whitespace() {
        let mut word = word.to_string();
        while word.chars().count() > max_cols {
            let split_at = word
                .char_indices()
                .nth(max_cols)
                .map(|(i, _)| i)
                .unwrap_or(word.len());
            let rest = word.split_off(split_at);
            if !current.is_empty() {
                lines.push(std::mem::take(&mut current));
            }
            lines.push(word);
            word = rest;
        }
        let candidate = if current.is_empty() {
            word.chars().count()
        } else {
            current.chars().count() + 1 + word.chars().count()
        };
        if candidate > max_cols && !current.is_empty() {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(&word);
    }

    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

fn policy_label(policy: &QgPolicy) -> String {
    match policy {
        QgPolicy::Absolute {
            max_errors,
            max_warnings,
        } => format!("absolute (max_errors={max_errors}, max_warnings={max_warnings})"),
        QgPolicy::Percentage { max_error_pct } => {
            format!("percentage (max_error_pct={max_error_pct})")
        }
    }
}

fn verdict_label(verdict: QgVerdict) -> &'static str {
    match verdict {
        QgVerdict::Pass => "PASS",
        QgVerdict::Reject => "REJECT",
        QgVerdict::Error => "ERROR (fallos de scan)",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gx_core::models::{AnalysisRequest, AuditMetrics, Issue, ObjectRef, ScanFailure};
    use std::path::PathBuf;

    fn sample_request() -> AnalysisRequest {
        AnalysisRequest {
            schema_version: 1,
            inputs: vec![PathBuf::from("tests/fixtures/sources/ejemplo_codigo.txt")],
            enabled_rule_ids: vec!["GX.2.6".to_string()],
            policy: QgPolicy::Absolute {
                max_errors: 0,
                max_warnings: 999_999,
            },
            record_history: false,
        }
    }

    fn issue(index: usize) -> Issue {
        Issue {
            rule_id: format!("GX.2.{}", index % 7),
            severity: match index % 3 {
                0 => Severity::Error,
                1 => Severity::Warning,
                _ => Severity::Info,
            },
            line_number: (index + 1) as u32,
            line_content: "&x = 1".to_string(),
            description: format!(
                "Hallazgo sintético {index} con acentos í á é ñ y una descripción razonablemente larga"
            ),
            file_path: PathBuf::from("tests/fixtures/sources/ejemplo_codigo.txt"),
            object: Some(ObjectRef {
                id: format!("Proc{index}"),
                object_type: "Procedure".to_string(),
                container_path: "tests/fixtures/sources/sample_package.xpz".to_string(),
                member: "PkgDemo/ProcMalo.xml".to_string(),
                package: "PkgDemo".to_string(),
            }),
            category: None,
            confidence: None,
            cwe: None,
        }
    }

    fn sample_result(count: usize) -> AnalysisResult {
        let findings: Vec<Issue> = (0..count).map(issue).collect();
        let metrics = AuditMetrics::from_issues(&findings);
        AnalysisResult {
            schema_version: 1,
            request: sample_request(),
            scanned_files: 1,
            findings,
            metrics,
            failures: Vec::new(),
            policy: QgPolicy::Absolute {
                max_errors: 0,
                max_warnings: 999_999,
            },
            verdict: QgVerdict::Reject,
            coverage: Default::default(),
            completion: Default::default(),
            pack_coverage: Vec::new(),
            security: None,
        }
    }

    fn finding_lines(pages: &[Vec<ReportLine>]) -> Vec<&ReportLine> {
        pages
            .iter()
            .flatten()
            .filter(|line| {
                line.color == COLOR_ERROR || line.color == COLOR_WARNING || line.color == COLOR_INFO
            })
            .filter(|line| line.text.contains("línea "))
            .collect()
    }

    #[test]
    fn layout_includes_every_finding() {
        let result = sample_result(5);
        let pages = layout(&result);
        assert_eq!(finding_lines(&pages).len(), 5);
    }

    #[test]
    fn render_produces_valid_pdf_header() {
        let result = sample_result(3);
        let bytes = render_bytes(&result).unwrap();
        assert!(bytes.starts_with(b"%PDF"), "debe empezar con %PDF");
        assert!(bytes.ends_with(b"%%EOF\n") || bytes.ends_with(b"%%EOF"));
        assert!(bytes.len() > 1_000, "pdf demasiado pequeño");
    }

    #[test]
    fn unicode_accents_and_long_paths_are_preserved() {
        let mut result = sample_result(1);
        result.findings[0].description =
            "Validación í á é ñ ó ú de acentos en la descripción".to_string();
        result.failures = vec![ScanFailure {
            path: PathBuf::from(format!("C:/{}", "directorio_muy_largo/".repeat(20))),
            error: "archivo no soportado".to_string(),
        }];
        let pages = layout(&result);
        let flat: String = pages
            .iter()
            .flatten()
            .map(|line| line.text.clone())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(flat.contains("í á é ñ ó ú"), "acentos en el PDF: {flat}");
        for line in pages.iter().flatten() {
            assert!(
                line.text.chars().count() <= DESC_WRAP_COLS + 8,
                "línea sin envolver: {} chars",
                line.text.chars().count()
            );
        }
    }

    #[test]
    fn large_finding_lists_paginate() {
        let result = sample_result(1000);
        let pages = layout(&result);
        assert!(
            pages.len() > 10,
            "1000 hallazgos deben paginar: {}",
            pages.len()
        );
        assert_eq!(finding_lines(&pages).len(), 1000);
        assert!(pages.iter().all(|page| page.len() <= MAX_LINES_PER_PAGE));
        let bytes = render_bytes(&result).unwrap();
        assert!(bytes.starts_with(b"%PDF"));
    }
}
