"""
EPIC-00 baseline generators.

Run with the Python engine venv:
    .venv/Scripts/python.exe scripts/gen_baseline.py

Produces, under tests/fixtures/:
    golden_issues.json   — every finding from evaluating ejemplo_codigo.txt
                           with the REAL enabled ruleset (load_rules()).
    rule_manifest.json   — truth table of ALL 30 rules (incl. abstract):
                           id, name, severity, description, triggers,
                           is_abstract, has_finalize, has_state.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# ---- make the Python engine importable -------------------------------
_PY_REPO = Path(__file__).resolve().parents[1].parent / "genexus-linter-python"
sys.path.insert(0, str(_PY_REPO))

from gx_linter.app.engine.runtime import (  # noqa: E402
    load_rules,
    evaluate_file,
    build_metrics,
    discover_rule_classes,
    DEFAULT_TRIGGER,
)
from gx_linter.app.core.models import AuditContext, SourceLine  # noqa: E402
from gx_linter.app.rules.base import ParsedLine, Rule  # noqa: E402

FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
SAMPLE = _PY_REPO / "ejemplo_codigo.txt"


def instance_attr_names(obj) -> set:
    """Collect all instance attribute names (dict + slots)."""
    names: set = set()
    if hasattr(obj, "__dict__"):
        names |= set(vars(obj).keys())
    cls = type(obj)
    while cls is not object:
        slots = getattr(cls, "__slots__", ())
        if isinstance(slots, str):
            slots = (slots,)
        names |= set(slots)
        cls = cls.__bases__[0]
    return names


def detect_state(rule: Rule) -> bool:
    """Best-effort: does the rule accumulate per-file instance state?"""
    base = {"current_file_path"}
    probe = ParsedLine.from_source(SourceLine(number=1, content="&x = 1 // c"))
    ctx = AuditContext(
        project_path=SAMPLE, rules_path=SAMPLE, max_errors=0, max_warnings=999999
    )
    before = instance_attr_names(rule)
    rule.reset(str(SAMPLE))
    after_reset = instance_attr_names(rule)
    try:
        rule.evaluate(probe, ctx)
        rule.evaluate(probe, ctx)
    except Exception:
        pass
    after_eval = instance_attr_names(rule)
    new_attrs = (after_reset | after_eval) - before - base
    return bool(new_attrs)


def gen_issues() -> dict:
    rules, dispatch = load_rules()
    ctx = AuditContext(
        project_path=SAMPLE, rules_path=SAMPLE, max_errors=0, max_warnings=999999
    )
    for r in rules:
        r.reset(str(SAMPLE))
    issues = evaluate_file(SAMPLE, rules, dispatch, ctx)
    metrics = build_metrics(issues)
    payload = {
        "source_file": SAMPLE.name,
        "metrics": {
            "total_findings": metrics.total_findings,
            "errors": metrics.errors,
            "warnings": metrics.warnings,
            "info": metrics.info,
        },
        "rules_loaded": len(rules),
        "issues": [
            {
                "rule_id": i.rule_id,
                "severity": i.severity,
                "line_number": i.line_number,
                "description": i.description,
                "line_content": i.line_content,
            }
            for i in issues
        ],
    }
    return payload


def gen_manifest() -> dict:
    entries = []
    for cls in discover_rule_classes():
        rule = cls()
        triggers = list(getattr(rule, "triggers", ()) or ())
        trigger_kind = "DEFAULT" if not triggers else triggers
        has_finalize = type(rule).finalize is not Rule.finalize
        has_state = detect_state(rule)
        entries.append(
            {
                "rule_id": rule.rule_id,
                "name": rule.name,
                "severity": rule.severity,
                "description": rule.description,
                "triggers": trigger_kind,
                "is_abstract": bool(getattr(rule, "abstract", False)),
                "has_finalize": has_finalize,
                "has_state": has_state,
            }
        )
    entries.sort(key=lambda e: e["rule_id"])
    return {"rules": entries}


def main() -> None:
    FIXTURES.mkdir(parents=True, exist_ok=True)

    issues = gen_issues()
    (FIXTURES / "golden_issues.json").write_text(
        json.dumps(issues, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"golden_issues.json: {issues['metrics']} "
          f"({len(issues['issues'])} issues, {issues['rules_loaded']} rules)")

    manifest = gen_manifest()
    (FIXTURES / "rule_manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    rules = manifest["rules"]
    concrete = [r for r in rules if not r["is_abstract"]]
    abstract = [r for r in rules if r["is_abstract"]]
    warnings = [r for r in rules if r["severity"] == "WARNING"]
    errors = [r for r in rules if r["severity"] == "ERROR"]
    finalize = [r for r in rules if r["has_finalize"]]
    stateful = [r for r in rules if r["has_state"]]
    print("rule_manifest.json counts:")
    print(f"  total={len(rules)} concrete={len(concrete)} "
          f"abstract={len(abstract)}")
    print(f"  WARNING={len(warnings)} ERROR={len(errors)}")
    print(f"  has_finalize={len(finalize)} has_state={len(stateful)}")


if __name__ == "__main__":
    main()
