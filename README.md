# gx-linter-rs

Rust reimplementation of the GeneXus Static Analysis Linter
(`genexus-linter-python`), with functional 1:1 parity.

## Status

| Iteration | Scope | Status |
|-----------|-------|--------|
| 00 | Baseline de paridad (golden snapshot, rule_manifest) | ✅ Done |
| 01 | Cargo workspace, toolchain, CI | ✅ Done |
| 02 | `gx_core` domain (models, regex cache, `ParsedLine`) | ✅ Done |
| 03 | SQLite storage + DAOs + seed | ⏳ Next |

See `plan/migration-rust.json` for the full
migration plan (EPIC-00 … EPIC-10).

## Workspace layout

```
gx-linter-rs/
  crates/
    gx_core/      # domain models, regex cache, ParsedLine (ST-02)
    gx_rules/     # rule catalog (EPIC-06)
    gx_engine/    # orchestrator / runtime (EPIC-05)
    gx_storage/   # SQLite persistence (EPIC-03)
    gx_report/    # PDF generation (EPIC-07)
    gx_app/       # CLI + GUI binaries (EPIC-08 / EPIC-09)
  xtask/          # dev task runner (replaces build.ps1)
  tests/fixtures/ # golden snapshots captured from the Python engine
```

## Prerequisites

- Rust stable 1.77+ (toolchain pinned via `rust-toolchain.toml`)
- No Python runtime required

## Common commands

```bash
cargo check --workspace
cargo fmt --all
cargo clippy --workspace -- -D warnings
cargo test --workspace

cargo xtask build            # release build
cargo run -p gx_app --bin gx -- --file <path>   # CLI (EPIC-08)
cargo run -p gx_app --bin gx_linter_gui         # GUI (EPIC-09)
```

## Regenerating golden snapshots

The Python engine output is captured once as the parity baseline:

```bash
python ../genexus-linter-python/.venv/Scripts/python.exe scripts/gen_baseline.py
```

This writes `tests/fixtures/golden_snapshot_cli.txt`,
`golden_issues.json` and `rule_manifest.json`.
