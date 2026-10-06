//! Contadores de operaciones del engine (A02.5).
//!
//! Permiten que un benchmark detecte regresiones de TRABAJO (parsers, reglas,
//! líneas) aunque el timing de CI sea ruidoso. Los contadores son globales,
//! atómicos y de costo despreciable frente a una evaluación de regla.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use serde::{Deserialize, Serialize};

/// Snapshot de contadores de una corrida.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanStats {
    /// Invocaciones al parser XML (una por miembro XML con contenido).
    pub parser_invocations: u64,
    /// Objetos fuente extraídos.
    pub objects_extracted: u64,
    /// Instancias de reglas construidas por el registry.
    pub rule_factory_invocations: u64,
    /// Rule-sets instanciados (plan por job de Rayon/archivo) (B02).
    pub rule_set_instantiations: u64,
    /// Líneas no vacías entregadas al pipeline de reglas.
    pub lines_evaluated: u64,
    /// Pares (línea, regla candidata) evaluados.
    pub rule_evaluations: u64,
    /// Hallazgos emitidos (incluye corridas parciales).
    pub findings_emitted: u64,
    /// Tiempo hasta el PRIMER hallazgo desde [`reset`], en micros (A02).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_finding_micros: Option<u64>,
}

static PARSER_INVOCATIONS: AtomicU64 = AtomicU64::new(0);
static OBJECTS_EXTRACTED: AtomicU64 = AtomicU64::new(0);
static RULE_FACTORY_INVOCATIONS: AtomicU64 = AtomicU64::new(0);
static RULE_SET_INSTANTIATIONS: AtomicU64 = AtomicU64::new(0);
static LINES_EVALUATED: AtomicU64 = AtomicU64::new(0);
static RULE_EVALUATIONS: AtomicU64 = AtomicU64::new(0);
static FINDINGS_EMITTED: AtomicU64 = AtomicU64::new(0);
static FIRST_FINDING_MICROS: AtomicU64 = AtomicU64::new(u64::MAX);
static RUN_START: Mutex<Option<Instant>> = Mutex::new(None);

/// Lee los contadores actuales.
pub fn snapshot() -> ScanStats {
    ScanStats {
        parser_invocations: PARSER_INVOCATIONS.load(Ordering::Relaxed),
        objects_extracted: OBJECTS_EXTRACTED.load(Ordering::Relaxed),
        rule_factory_invocations: RULE_FACTORY_INVOCATIONS.load(Ordering::Relaxed),
        rule_set_instantiations: RULE_SET_INSTANTIATIONS.load(Ordering::Relaxed),
        lines_evaluated: LINES_EVALUATED.load(Ordering::Relaxed),
        rule_evaluations: RULE_EVALUATIONS.load(Ordering::Relaxed),
        findings_emitted: FINDINGS_EMITTED.load(Ordering::Relaxed),
        first_finding_micros: first_finding_micros(),
    }
}

/// Reinicia los contadores y la base de tiempo (el benchmark lo hace antes
/// de cada fase; `first_finding_micros` se mide desde este punto).
pub fn reset() {
    PARSER_INVOCATIONS.store(0, Ordering::Relaxed);
    OBJECTS_EXTRACTED.store(0, Ordering::Relaxed);
    RULE_FACTORY_INVOCATIONS.store(0, Ordering::Relaxed);
    RULE_SET_INSTANTIATIONS.store(0, Ordering::Relaxed);
    LINES_EVALUATED.store(0, Ordering::Relaxed);
    RULE_EVALUATIONS.store(0, Ordering::Relaxed);
    FINDINGS_EMITTED.store(0, Ordering::Relaxed);
    FIRST_FINDING_MICROS.store(u64::MAX, Ordering::Relaxed);
    if let Ok(mut start) = RUN_START.lock() {
        *start = Some(Instant::now());
    }
}

/// Tiempo hasta el primer hallazgo desde el último [`reset`] (A02).
pub fn first_finding_micros() -> Option<u64> {
    match FIRST_FINDING_MICROS.load(Ordering::Relaxed) {
        u64::MAX => None,
        micros => Some(micros),
    }
}

/// Registra (una sola vez) el tiempo del primer hallazgo de la corrida.
///
/// Fast-path sin lock: si ya hay un primer hallazgo registrado, no hace nada.
pub fn note_first_finding() {
    if FIRST_FINDING_MICROS.load(Ordering::Relaxed) != u64::MAX {
        return;
    }
    let micros = match RUN_START.lock() {
        Ok(start) => match *start {
            Some(start) => start.elapsed().as_micros() as u64,
            None => return,
        },
        Err(_) => return,
    };
    let _ = FIRST_FINDING_MICROS.compare_exchange(
        u64::MAX,
        micros,
        Ordering::Relaxed,
        Ordering::Relaxed,
    );
}

pub fn count_parser_invocation() {
    PARSER_INVOCATIONS.fetch_add(1, Ordering::Relaxed);
}

pub fn count_objects(count: usize) {
    OBJECTS_EXTRACTED.fetch_add(count as u64, Ordering::Relaxed);
}

pub fn count_rule_factories(count: usize) {
    RULE_FACTORY_INVOCATIONS.fetch_add(count as u64, Ordering::Relaxed);
}

pub fn count_rule_set_instantiation() {
    RULE_SET_INSTANTIATIONS.fetch_add(1, Ordering::Relaxed);
}

pub fn count_line() {
    LINES_EVALUATED.fetch_add(1, Ordering::Relaxed);
}

pub fn count_rule_evaluations(count: usize) {
    RULE_EVALUATIONS.fetch_add(count as u64, Ordering::Relaxed);
}

pub fn count_findings(count: usize) {
    FINDINGS_EMITTED.fetch_add(count as u64, Ordering::Relaxed);
}

// Los tests de contadores viven en `tests/stats_contract.rs` (proceso propio):
// el estado es global y los tests del lib corren en paralelo.
