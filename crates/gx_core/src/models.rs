//! Dominio puro: SourceLine, Issue, Severity, AuditMetrics, AuditContext, ParsedLine.
//! Port de `gx_linter/app/core/models.py` + `gx_linter/app/rules/base.py::ParsedLine`.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::regex_cache::STRING_COMMENT_PATTERN;

/// Una línea de código fuente GeneXus con su número.
#[derive(Debug, Clone, Default)]
pub struct SourceLine {
    pub number: u32,
    pub content: String,
}

/// Severidad de un hallazgo. Serializa a "ERROR" / "WARNING" / "INFO".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

impl Severity {
    /// Texto en mayúsculas usado en reportes y PDEs.
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Error => "ERROR",
            Severity::Warning => "WARNING",
            Severity::Info => "INFO",
        }
    }
}

/// Identidad de un objeto GeneXus dentro del artefacto escaneado (GX-006).
///
/// Cada hallazgo lleva esta referencia para que CLI/desktop apunten al
/// objeto real, nunca a coordenadas sintéticas de concatenación.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ObjectRef {
    /// Nombre del objeto (attr `name` del XML o stem del archivo).
    pub id: String,
    /// Tipo de objeto (elemento raíz del XML, ej: "Procedure") o "Source".
    pub object_type: String,
    /// Path del artefacto contenedor (el archivo escaneado).
    pub container_path: String,
    /// Miembro origen dentro del contenedor (entrada del ZIP o nombre de
    /// archivo para .txt/.xml).
    pub member: String,
    /// Package/folder declarado en el XML (vacío si no aplica).
    pub package: String,
}

/// Un objeto fuente extraído de un artefacto (.xpz/.xml/.txt) (GX-006).
///
/// Se evalúa de forma INDEPENDIENTE: el estado de reglas y el corte por
/// "generated subroutines (public)" no cruzan objetos.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SourceObject {
    pub object: ObjectRef,
    /// Texto fuente crudo del objeto (CDATA de Events o el archivo entero).
    pub text: String,
    /// Línea (1-based) del miembro XML donde comienza el código extraído;
    /// 1 para archivos de texto plano.
    pub code_start_line: u32,
}

/// Un hallazgo (issue) del análisis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Issue {
    pub rule_id: String,
    pub severity: Severity,
    pub line_number: u32,
    pub line_content: String,
    pub description: String,
    pub file_path: PathBuf,
    /// Identidad del objeto Genexus origen (stamped por el runtime; GX-006).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<ObjectRef>,
}

/// Métricas consolidadas del análisis.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditMetrics {
    pub total_findings: usize,
    pub errors: usize,
    pub warnings: usize,
    pub info: usize,
}

impl AuditMetrics {
    pub fn from_issues(issues: &[Issue]) -> Self {
        let mut metrics = AuditMetrics {
            total_findings: issues.len(),
            ..Default::default()
        };
        for issue in issues {
            match issue.severity {
                Severity::Error => metrics.errors += 1,
                Severity::Warning => metrics.warnings += 1,
                Severity::Info => metrics.info += 1,
            }
        }
        metrics
    }
}

/// Contexto de configuración de una corrida de auditoría.
#[derive(Debug, Clone)]
pub struct AuditContext {
    pub project_path: PathBuf,
    pub rules_path: PathBuf,
    pub max_errors: u32,
    pub max_warnings: u32,
    pub qg_threshold_pct: f32,
    pub extra_settings: HashMap<String, String>,
}

/// Política de quality gate con nombre (GX-010).
///
/// El veredicto SIEMPRE registra la política que lo produjo.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum QgPolicy {
    /// CLI: umbrales absolutos de errores y warnings.
    Absolute { max_errors: u32, max_warnings: u32 },
    /// GUI legada: porcentaje máximo de errores sobre el total de hallazgos.
    Percentage { max_error_pct: f32 },
}

impl QgPolicy {
    /// Nombre estable de la política (trazabilidad en JSON y reportes).
    pub fn name(&self) -> &'static str {
        match self {
            QgPolicy::Absolute { .. } => "absolute",
            QgPolicy::Percentage { .. } => "percentage",
        }
    }

    /// Evalúa la política sobre las métricas.
    ///
    /// Definiciones (GX-010): cero hallazgos = PASS; los fallos de scan
    /// fallan SIEMPRE el gate (se mapean a `QgVerdict::Error` aparte).
    pub fn evaluate(&self, metrics: &AuditMetrics) -> QgVerdict {
        match self {
            QgPolicy::Absolute {
                max_errors,
                max_warnings,
            } => {
                let max_errors = *max_errors as usize;
                let max_warnings = *max_warnings as usize;
                if metrics.errors <= max_errors && metrics.warnings <= max_warnings {
                    QgVerdict::Pass
                } else {
                    QgVerdict::Reject
                }
            }
            QgPolicy::Percentage { max_error_pct } => {
                if metrics.total_findings == 0 {
                    return QgVerdict::Pass;
                }
                let pct = metrics.errors as f32 * 100.0 / metrics.total_findings as f32;
                if pct <= *max_error_pct {
                    QgVerdict::Pass
                } else {
                    QgVerdict::Reject
                }
            }
        }
    }
}

/// Veredicto del quality gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QgVerdict {
    /// Dentro de la política.
    Pass,
    /// Fuera de la política (rechazado).
    Reject,
    /// La corrida tiene fallos de scan: el gate siempre falla.
    Error,
}

/// Solicitud de análisis serializable (GX-010).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalysisRequest {
    /// Versión del esquema del contrato (actualmente 1).
    pub schema_version: u32,
    /// Archivos o directorios de entrada.
    pub inputs: Vec<PathBuf>,
    /// Reglas habilitadas, explícitas y ordenadas (procedencia del set).
    pub enabled_rule_ids: Vec<String>,
    /// Política de quality gate para el veredicto.
    pub policy: QgPolicy,
    /// Persistir historial de auditoría (modo CI/read-only = false).
    pub record_history: bool,
}

/// Fallo de scan de un input concreto (nunca se reporta como escaneo limpio).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanFailure {
    pub path: PathBuf,
    pub error: String,
}

/// Resultado completo de un análisis (GX-010): hallazgos en orden
/// determinista, métricas, fallos y veredicto con su política.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub schema_version: u32,
    pub request: AnalysisRequest,
    /// Archivos escaneados con éxito.
    pub scanned_files: usize,
    /// Hallazgos: orden artefacto → objeto → línea → registro de regla.
    pub findings: Vec<Issue>,
    pub metrics: AuditMetrics,
    /// Fallos por archivo (un archivo fallido nunca aporta hallazgos).
    pub failures: Vec<ScanFailure>,
    /// Política que produjo el veredicto (igual a request.policy).
    pub policy: QgPolicy,
    pub verdict: QgVerdict,
}

/// Línea preprocesada, compartida por todas las reglas.
/// `clean` / `clean_lower` se calculan UNA sola vez aquí.
#[derive(Debug, Clone)]
pub struct ParsedLine {
    pub source: SourceLine,
    pub content: String,
    pub number: u32,
    pub raw: String,
    pub stripped: String,
    pub lower: String,
    pub clean: String,
    pub clean_lower: String,
    pub clean_no_comments: String,
    pub has_ampersand: bool,
    pub has_equal: bool,
    pub has_where: bool,
    pub has_for_each: bool,
    pub has_sub: bool,
    pub has_if: bool,
    pub has_case: bool,
    pub has_do: bool,
}

impl ParsedLine {
    pub fn from_source(source: SourceLine) -> Self {
        let raw = source.content.clone();
        let stripped = raw.trim().to_string();
        let lower = stripped.to_lowercase();

        // Sanitización: strings + comentarios se borran UNA sola vez.
        let clean_raw = STRING_COMMENT_PATTERN.replace_all(&raw, "");
        let clean = clean_raw.trim().to_string();
        let clean_lower = clean.to_lowercase();

        let has_ampersand = clean_lower.contains('&');
        let has_equal = clean_lower.contains('=');
        let has_where = clean_lower.contains("where");
        let has_for_each = clean_lower.contains("for each");
        let has_sub = clean_lower.contains("sub");
        let has_if = clean_lower.contains("if");
        let has_case = clean_lower.contains("case");
        let has_do = clean_lower.contains("do");

        ParsedLine {
            source,
            content: raw.clone(),
            number: 0, // se sobrescribe abajo con source.number
            raw,
            stripped,
            lower,
            clean: clean.clone(),
            clean_lower: clean_lower.clone(),
            clean_no_comments: clean,
            has_ampersand,
            has_equal,
            has_where,
            has_for_each,
            has_sub,
            has_if,
            has_case,
            has_do,
        }
        .with_number()
    }

    fn with_number(mut self) -> Self {
        self.number = self.source.number;
        self
    }

    pub fn line_number(&self) -> u32 {
        self.number
    }

    pub fn line_content(&self) -> &str {
        &self.content
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_metrics_counts_severities() {
        let issues = vec![
            Issue {
                rule_id: "GX.1".into(),
                severity: Severity::Error,
                line_number: 1,
                line_content: "".into(),
                description: "".into(),
                file_path: PathBuf::from("x"),
                object: None,
            },
            Issue {
                rule_id: "GX.2".into(),
                severity: Severity::Error,
                line_number: 2,
                line_content: "".into(),
                description: "".into(),
                file_path: PathBuf::from("x"),
                object: None,
            },
            Issue {
                rule_id: "GX.3".into(),
                severity: Severity::Warning,
                line_number: 3,
                line_content: "".into(),
                description: "".into(),
                file_path: PathBuf::from("x"),
                object: None,
            },
            Issue {
                rule_id: "GX.4".into(),
                severity: Severity::Info,
                line_number: 4,
                line_content: "".into(),
                description: "".into(),
                file_path: PathBuf::from("x"),
                object: None,
            },
        ];
        let m = AuditMetrics::from_issues(&issues);
        assert_eq!(m.total_findings, 4);
        assert_eq!(m.errors, 2);
        assert_eq!(m.warnings, 1);
        assert_eq!(m.info, 1);
    }

    #[test]
    fn parsed_line_basic() {
        let src = SourceLine {
            number: 1,
            content: "  For Each Customer // comment".into(),
        };
        let p = ParsedLine::from_source(src);
        assert_eq!(p.stripped, "For Each Customer // comment");
        assert_eq!(p.clean, "For Each Customer");
        assert!(p.has_for_each);
        assert!(!p.has_where);
        assert_eq!(p.line_number(), 1);
    }

    #[test]
    fn parsed_line_strips_strings_and_comments() {
        let src = SourceLine {
            number: 1,
            content: r#"&MyVar = "hello // not comment" // real comment"#.into(),
        };
        let p = ParsedLine::from_source(src);
        assert!(!p.clean.contains("hello"));
        assert!(!p.clean.contains("real comment"));
        assert!(p.has_ampersand);
        assert!(p.has_equal);
    }
}
