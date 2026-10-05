//! Presupuesto de ejecución de un análisis (A04/F07).
//!
//! Límites run-wide que acotan memoria, trabajo y tiempo. Reaching any limit
//! produces a `partial`/resource-limited outcome: NUNCA un PASS silencioso.

use std::time::{Duration, Instant};

/// Límites por corrida. Los valores por defecto son los del review (A04):
/// lectura acotada para texto/XML, expansión acotada para paquetes y un
/// presupuesto de proceso de ~512 MiB activo.
#[derive(Debug, Clone)]
pub struct ExecutionBudget {
    /// Máximo de bytes de un artefacto de entrada (texto/XML y también el
    /// archivo comprimido de un paquete).
    pub max_input_bytes: u64,
    /// Máximo de bytes descomprimidos totales por paquete.
    pub max_expanded_bytes: u64,
    /// Máximo de bytes descomprimidos por miembro.
    pub max_member_bytes: u64,
    /// Máximo de miembros por paquete.
    pub max_members: usize,
    /// Máximo de objetos fuente extraídos por corrida.
    pub max_objects: usize,
    /// Máximo de findings retenidos; al alcanzarlo se corta en `partial`.
    pub max_findings: usize,
    /// Deadline absoluto de la corrida (opcional).
    pub deadline: Option<Instant>,
    /// Cantidad de workers (None = default de Rayon).
    pub workers: Option<usize>,
}

impl Default for ExecutionBudget {
    fn default() -> Self {
        Self {
            max_input_bytes: 64 * 1024 * 1024,
            max_expanded_bytes: 64 * 1024 * 1024,
            max_member_bytes: 32 * 1024 * 1024,
            max_members: 4096,
            max_objects: 200_000,
            max_findings: 1_000_000,
            deadline: None,
            workers: None,
        }
    }
}

impl ExecutionBudget {
    /// Presupuesto con deadline relativo a ahora.
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            deadline: Some(Instant::now() + timeout),
            ..Default::default()
        }
    }

    /// `true` si el deadline ya venció.
    pub fn is_expired(&self) -> bool {
        self.deadline
            .map(|deadline| Instant::now() >= deadline)
            .unwrap_or(false)
    }

    /// `true` si el presupuesto tiene deadline (documentación/telemetría).
    pub fn has_deadline(&self) -> bool {
        self.deadline.is_some()
    }
}

impl PartialEq for ExecutionBudget {
    fn eq(&self, other: &Self) -> bool {
        self.max_input_bytes == other.max_input_bytes
            && self.max_expanded_bytes == other.max_expanded_bytes
            && self.max_member_bytes == other.max_member_bytes
            && self.max_members == other.max_members
            && self.max_objects == other.max_objects
            && self.max_findings == other.max_findings
            && self.workers == other.workers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_expires() {
        let budget = ExecutionBudget::with_timeout(Duration::from_millis(0));
        assert!(budget.is_expired());
        let no_deadline = ExecutionBudget::default();
        assert!(!no_deadline.is_expired());
        assert!(!no_deadline.has_deadline());
    }
}
