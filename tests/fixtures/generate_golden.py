#!/usr/bin/env python
"""
Generate the golden parity baseline from the Python engine.

Writes into this directory (tests/fixtures/):
  - golden_snapshot_cli.txt   CLI output (approved + rejected QG scenarios)
  - golden_issues.json        every finding (rule_id, line, severity, desc)
  - rule_manifest.json        30-rule table of truth (triggers, severity, ...)

Run from anywhere:
    python generate_golden.py
"""
from __future__ import annotations

import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
PY_REPO = Path(__file__).resolve().parents[3] / "genexus-linter-python"
EXAMPLE = PY_REPO / "ejemplo_codigo.txt"

sys.path.insert(0, str(PY_REPO))

from gx_linter.app.engine import runtime  # noqa: E402
from gx_linter.app.core.models import AuditContext  # noqa: E402
import main as cli  # noqa: E402


def stub_pdf():
    """Replace the real PDF reporter so capturing CLI output has no
    filesystem side effects."""
    class _Stub:
        def generate(self, *a, **k):
            return Path("Reporte_Auditoria_stub.pdf")

    cli.PdfAuditReporter = _Stub


def capture_cli(max_errors: int) -> str:
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli.run_cli(str(EXAMPLE), max_errors, 999999)
    return buf.getvalue()


def build_issues() -> list[dict]:
    rules, dispatch = runtime.load_rules()
    ctx = AuditContext(
        project_path=EXAMPLE,
        rules_path=EXAMPLE,
        max_errors=0,
        max_warnings=999999,
    )
    for r in rules:
        r.reset(str(EXAMPLE))
    issues = runtime.evaluate_file(
        file_path=EXAMPLE,
        rules=rules,
        dispatch_map=dispatch,
        context=ctx,
    )
    return [
        {
            "rule_id": i.rule_id,
            "line_number": i.line_number,
            "severity": i.severity,
            "description": i.description,
        }
        for i in issues
    ]


def build_manifest() -> dict:
    entries = []
    for cls in runtime.discover_rule_classes():
        abstract = bool(getattr(cls, "abstract", False))
        triggers = list(getattr(cls, "triggers", ()) or ())
        entries.append(
            {
                "rule_id": cls.rule_id,
                "name": getattr(cls, "name", ""),
                "severity": cls.severity,
                "abstract": abstract,
                "effective_triggers": triggers if triggers else ["*"],
                "raw_triggers": triggers,
                "has_finalize": "finalize" in cls.__dict__,
                "has_state": ("reset" in cls.__dict__)
                or ("__init__" in cls.__dict__),
            }
        )
    entries.sort(key=lambda e: e["rule_id"])
    concrete = [e for e in entries if not e["abstract"]]
    return {
        "generated_from": str(EXAMPLE),
        "toolchain": "Python genexus-linter-python",
        "counts": {
            "total": len(entries),
            "abstract": sum(1 for e in entries if e["abstract"]),
            "concrete": len(concrete),
            "error": sum(1 for e in entries if e["severity"] == "ERROR"),
            "warning": sum(1 for e in entries if e["severity"] == "WARNING"),
            "finalize": sum(1 for e in entries if e["has_finalize"]),
            "state": sum(1 for e in entries if e["has_state"]),
        },
        "entries": entries,
    }


def main() -> None:
    if not EXAMPLE.is_file():
        sys.exit(f"example file not found: {EXAMPLE}")

    stub_pdf()

    issues = build_issues()
    with open(HERE / "golden_issues.json", "w", encoding="utf-8") as f:
        json.dump(
            {"example": str(EXAMPLE), "issues": issues},
            f,
            indent=2,
            ensure_ascii=False,
        )

    snapshot = []
    snapshot.append("===== SCENARIO: max-errors=0 (Quality Gate APROBADO) =====")
    snapshot.append(capture_cli(0))
    snapshot.append("")
    snapshot.append("===== SCENARIO: max-errors=5 (Quality Gate RECHAZADO) =====")
    snapshot.append(capture_cli(5))
    with open(HERE / "golden_snapshot_cli.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(snapshot))

    manifest = build_manifest()
    with open(HERE / "rule_manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    c = manifest["counts"]
    print("Golden baseline generated:")
    print(f"  issues: {len(issues)}")
    print(f"  rules:  total={c['total']} abstract={c['abstract']} "
          f"concrete={c['concrete']}")
    print(f"  severity: ERROR={c['error']} WARNING={c['warning']}")
    print(f"  finalize={c['finalize']} state={c['state']}")


if __name__ == "__main__":
    main()
