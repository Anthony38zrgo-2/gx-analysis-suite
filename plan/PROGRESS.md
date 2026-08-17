# GX Linter — Migración Python → Rust

Este repositorio (`gx-linter-rs`) es el **port 1:1** de
`genexus-linter-python` (app de análisis estático de código GeneXus).

- **Repo origen:** `D:\dev\osobobo\genexus-linter-python` (Python, completo y commiteado; `dist/GX_Linter.exe` ya construido).
- **Repo destino:** `D:\dev\osobobo\gx-linter-rs` (Rust, en construcción).
- **Especificación:** `plan/migration-rust.json` (backlog con 11 EPICs / 31 stories).

---

## Estado actual (checkpoint)

| EPIC | Tema | Estado |
|------|------|--------|
| 00 | Baseline de paridad (golden snapshot) | ✅ Hecho |
| 01 | Workspace Cargo + toolchain + CI | ✅ Hecho |
| 02 | Dominio core (models, ParsedLine, regex_cache) | ✅ Hecho |
| 03 | SQLite storage (rusqlite) + DAOs | ⏳ Siguiente |
| 04 | Filesystem + XPZ extractor | Pendiente |
| 05 | Trait Rule + registry + runtime/dispatch | Pendiente |
| 06 | Catálogo 30 reglas | Pendiente |
| 07 | Reporte PDF | Pendiente |
| 08 | CLI (clap) | Pendiente |
| 09 | GUI (eframe/egui) | Pendiente |
| 10 | QA/paridad, migración datos, empaquetado MSI | Pendiente |

### Lo ya construido en `gx-linter-rs`
- Workspace Cargo con 6 crates + `xtask`, `rust-toolchain.toml`, `.cargo/config.toml`.
- CI GitHub Actions (fmt/clippy/test/audit/build-release).
- `gx_core`:
  - `models.rs`: `SourceLine`, `Issue`, `Severity` (serde `UPPERCASE`), `AuditMetrics` (+`from_issues`), `AuditContext`, `ParsedLine` (+`from_source`, getters legacy).
  - `regex_cache.rs`: todos los patrones centralizados como `LazyLock` (incl. `STRING_COMMENT_PATTERN` fiel al origen `"[^"]*"|'[^']*'|//.*$|/\*.*?\*/`), y `has_logical_operator` que emula el lookbehind `(?<!&)` ausente en Rust.
- `tests/fixtures/`:
  - `golden_snapshot_cli.txt` — salida CLI real (15 reglas cargadas, 17 hallazgos: 12 errores / 5 warnings).
  - `golden_issues.json` — 17 hallazgos con `rule_id/line/severity/description/line_content`.
  - `rule_manifest.json` — las 30 reglas (24 concretas + 6 abstractas).
- `scripts/gen_baseline.py` — regenera los fixtures desde el engine Python.

### ⚠️ Corrección respecto al backlog
El backlog estimaba **14 WARNING / 10 ERROR**. El `rule_manifest.json` real
(extraído del código fuente) dice **18 WARNING / 12 ERROR**. El manifest es
la fuente de verdad para el port; el Rust debe coincidir con el conteo real,
no con la estimación del backlog.

### Decisiones tomadas
- **Ubicación:** repo git **separado** hermano del Python (no subcarpeta).
- **Dependencias pesadas** (`eframe`/`egui`/`rfd`, `printpdf`/`lopdf`) se
  añaden en EPIC-07/09 para mantener el build rápido en las fases tempranas.
- `LazyLock` se usa desde `std::sync` (once_cell 1.19 no lo exporta); `std` es
  estable desde 1.80 y el toolchain es 1.95.

---

## Cómo regenerar el baseline (EPIC-00)
```powershell
cd genexus-linter-python
python -m venv .venv
.venv\Scripts\pip install fpdf2
cd ..
python genexus-linter-python/.venv/Scripts/python.exe `
  gx-linter-rs/scripts/gen_baseline.py
```
Requiere el engine Python (lee `config/rules.json` para el conjunto de reglas
habilitadas). El snapshot y el manifest deben coincidir con los fixtures
commiteados salvo que cambie el origen.

---

## Siguiente hito: EPIC-03 (SQLite)
- `gx_storage::db` — `get_db_path` (`%APPDATA%/GX/Linter/gx_linter.db`, fallback
  `./data/`), `init_db` con `rusqlite_migration` (migrations `V001`/`V002`
  literales del backlog), `get_pool` (r2d2).
- DAOs: `rules_dao` (incl. `is_rule_enabled` con default-disabled
  `{GX.1.1, GX.1.2, GX.1.3.1, GX.1.4.1, GX.1.4.2, GX.1.6.1, GX.1.6.2, GX.1.7.1}`),
  `settings_dao` (`qg_threshold_pct` default 10.0), `audit_dao`.
- `seed::import_reglas_csv` (UPSERT desde `Reglas.csv` con tabla de triggers del backlog).
- Tests: `init_db` crea 4 tablas + view + triggers; `SELECT count(*) FROM rules >= 30`.

## Notas de paridad (recordatorio del backlog)
- **Quality Gate DUAL**: CLI = umbrales absolutos
  (`errors<=max_errors AND warnings<=max_warnings`, `main.py:96-99`);
  GUI = porcentual (`error_pct = errors*100/total <= qg_threshold_pct`,
  `main_window.py:85-91`). Ambos algoritmos se implementan y se seleccionan
  según el entrypoint.
- `evaluate_file` corta en `generated subroutines (public)` y llama `reset()`
  por regla antes del loop (en Python lo hace el caller; en Rust se consolida
  en el engine).
