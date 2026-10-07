//! Validación compartida de solicitudes de análisis (A01/F01).
//!
//! Una única frontera para CLI, desktop y librería: un request malformado
//! NUNCA puede producir un PASS silencioso. La validación de IDs de reglas
//! contra el registry vive en `gx_engine` (que conoce `gx_rules`); aquí se
//! validan esquema, inputs y política.

use serde::{Deserialize, Serialize};

use crate::models::{AnalysisRequest, QgPolicy};

/// Versión de esquema soportada por el engine.
pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// Rango admitido para el umbral porcentual del quality gate.
pub const MAX_ERROR_PCT: f32 = 100.0;

/// Error de validación estructurado (código estable + mensaje humano).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationError {
    pub code: String,
    pub message: String,
}

impl ValidationError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ValidationError {}

/// Valida la forma del request: esquema, inputs, set de reglas y política.
///
/// Decisión explícita (A01): un set de reglas vacío es inválido. Un escaneo
/// sin reglas no puede producir un veredicto con significado; si se desea
/// deliberadamente "sólo descubrir cobertura", debe usarse una API distinta.
pub fn validate_request_shape(request: &AnalysisRequest) -> Result<(), ValidationError> {
    if request.schema_version != SUPPORTED_SCHEMA_VERSION {
        return Err(ValidationError::new(
            "unsupported_schema",
            format!(
                "schema_version {} no soportada (esperada {}).",
                request.schema_version, SUPPORTED_SCHEMA_VERSION
            ),
        ));
    }
    if request.inputs.is_empty() {
        return Err(ValidationError::new(
            "invalid_input",
            "No hay archivos ni directorios de entrada.",
        ));
    }
    for input in &request.inputs {
        if input.as_os_str().is_empty() {
            return Err(ValidationError::new(
                "invalid_input",
                "Hay una ruta de entrada vacía.",
            ));
        }
    }
    if request.enabled_rule_ids.is_empty() {
        return Err(ValidationError::new(
            "invalid_rules",
            "No hay reglas habilitadas: un escaneo sin reglas no produce hallazgos.",
        ));
    }
    for id in &request.enabled_rule_ids {
        if id.trim().is_empty() {
            return Err(ValidationError::new(
                "invalid_rules",
                "Hay un id de regla vacío en el set habilitado.",
            ));
        }
    }
    {
        let mut seen = std::collections::HashSet::new();
        for id in &request.enabled_rule_ids {
            if !seen.insert(id.as_str()) {
                return Err(ValidationError::new(
                    "invalid_rules",
                    format!("Regla duplicada en el set habilitado: '{id}'."),
                ));
            }
        }
    }
    match request.policy {
        QgPolicy::Absolute { .. } => {}
        QgPolicy::Percentage { max_error_pct } => {
            if !max_error_pct.is_finite() || !(0.0..=MAX_ERROR_PCT).contains(&max_error_pct) {
                return Err(ValidationError::new(
                    "invalid_policy",
                    format!(
                        "Porcentaje de errores inválido ({max_error_pct}); se espera un valor finito entre 0 y {MAX_ERROR_PCT}."
                    ),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::DiscoveryPolicy;
    use std::path::PathBuf;

    fn base_request() -> AnalysisRequest {
        AnalysisRequest {
            schema_version: SUPPORTED_SCHEMA_VERSION,
            inputs: vec![PathBuf::from("x.txt")],
            enabled_rule_ids: vec!["GX.1".to_string()],
            policy: QgPolicy::Absolute {
                max_errors: 0,
                max_warnings: 0,
            },
            record_history: false,
            retain_sensitive_evidence: false,
            discovery: DiscoveryPolicy::default(),
        }
    }

    #[test]
    fn valid_request_passes() {
        assert!(validate_request_shape(&base_request()).is_ok());
    }

    #[test]
    fn unsupported_schema_is_rejected() {
        let mut r = base_request();
        r.schema_version = 99;
        let err = validate_request_shape(&r).unwrap_err();
        assert_eq!(err.code, "unsupported_schema");
    }

    #[test]
    fn empty_inputs_are_rejected() {
        let mut r = base_request();
        r.inputs.clear();
        assert_eq!(
            validate_request_shape(&r).unwrap_err().code,
            "invalid_input"
        );
    }

    #[test]
    fn empty_rule_set_is_rejected() {
        let mut r = base_request();
        r.enabled_rule_ids.clear();
        assert_eq!(
            validate_request_shape(&r).unwrap_err().code,
            "invalid_rules"
        );
    }

    #[test]
    fn duplicate_rules_are_rejected() {
        let mut r = base_request();
        r.enabled_rule_ids = vec!["GX.1".into(), "GX.1".into()];
        assert_eq!(
            validate_request_shape(&r).unwrap_err().code,
            "invalid_rules"
        );
    }

    #[test]
    fn percentage_out_of_range_or_non_finite_is_rejected() {
        for pct in [-1.0, 100.1, f32::NAN, f32::INFINITY] {
            let mut r = base_request();
            r.policy = QgPolicy::Percentage { max_error_pct: pct };
            assert_eq!(
                validate_request_shape(&r).unwrap_err().code,
                "invalid_policy",
                "pct={pct}"
            );
        }
        let mut r = base_request();
        r.policy = QgPolicy::Percentage {
            max_error_pct: 100.0,
        };
        assert!(validate_request_shape(&r).is_ok());
    }
}
