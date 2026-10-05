//! Contrato de los contadores de operaciones (A02.5).
//!
//! Se ejecutan en un binario de test propio: los contadores son globales y
//! los tests del lib corren en paralelo entre sí.

use gx_core::stats::{self, ScanStats};

#[test]
fn counters_accumulate_reset_and_first_finding() {
    stats::reset();
    assert_eq!(stats::snapshot(), ScanStats::default());

    stats::count_parser_invocation();
    stats::count_objects(3);
    stats::count_rule_factories(2);
    stats::count_line();
    stats::count_rule_evaluations(5);
    stats::count_findings(1);
    let after = stats::snapshot();
    assert_eq!(after.parser_invocations, 1);
    assert_eq!(after.objects_extracted, 3);
    assert_eq!(after.rule_factory_invocations, 2);
    assert_eq!(after.lines_evaluated, 1);
    assert_eq!(after.rule_evaluations, 5);
    assert_eq!(after.findings_emitted, 1);
    assert_eq!(after.first_finding_micros, None, "sin hallazgos aún");

    stats::note_first_finding();
    let first = stats::snapshot()
        .first_finding_micros
        .expect("primer hallazgo");
    std::thread::sleep(std::time::Duration::from_millis(2));
    stats::note_first_finding();
    assert_eq!(
        stats::snapshot().first_finding_micros,
        Some(first),
        "el primer hallazgo no se sobreescribe"
    );

    stats::reset();
    assert_eq!(stats::snapshot(), ScanStats::default());
    assert_eq!(stats::first_finding_micros(), None);
}
