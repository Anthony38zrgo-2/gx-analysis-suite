# gx-linter-rs

Rust reimplementation of the GeneXus Static Analysis Linter
(`genexus-linter-python`), with functional 1:1 parity.

## Status

| Hitos del backlog | Scope | Status |
|-----------|-------|--------|
| M0 | GATE-BASELINE: fixture reproducible + harness de regresiones (GX-001/002) | ✅ Done |
| M1 | GATE-ENGINE: ciclo de vida, dispatch, determinismo, fidelidad XPZ, dialectos (GX-003..008) | ✅ Done |
| M2 | GATE-QA + GATE-CLI: catálogo confiable, AnalysisRequest/Result + quality gates, persistencia atómica, CLI productivo (GX-009..014) | ✅ Done |
| M3 | GATE-DESKTOP: Tauri 2 + Vue 3, comandos async, UI de auditoría, PDF y release NSIS (GX-015..020) | ✅ Done |
| Roadmap A–E | Performance, modularidad y seguridad: presupuesto de ejecución, discovery explícito, persistencia acotada, packs semánticos/seguridad, gates de evidencia (A01–A04, B01–B04, C01–C04, D01–D04, E01) | ✅ Done |

See `plan/backlog-engine-cli-tauri.json` for the full backlog,
`plan/PROGRESS.md` for detailed checkpoints and
`plan/performance-modularity-security-roadmap.md` (§8–§18) for the
implementation logs, calibration and measured evidence.

Pendientes externos (no de código): capturar el baseline de timing en el
runner self-hosted `gx-benchmark` (`.github/workflows/bench-consistent.yml`)
y la medición interactiva de latencias WebView2; el gate automatizable del
boundary IPC vive en `desktop/src-tauri/tests/latency.rs`.

## Workspace layout

```
gx-linter-rs/
  crates/
    gx_core/      # dominio: models, contrato/validación, semantics, budget, stats
    gx_sources/   # discovery (globs/ignore/symlinks) + extracción ZIP/RAR/XML
    gx_rules/     # catálogo de 34 reglas (28 concretas + 6 abstractas)
    gx_engine/    # runtime/dispatch/analyze + presupuesto run-wide
    gx_storage/   # SQLite persistence, catálogo e historial (GX-009/011)
    gx_report/    # PDF source-aware (GX-019)
    gx_app/       # CLI `gx`
    xtask/        # dev task runner (build, bench, check-boundaries)
  desktop/        # Tauri 2 + Vue 3 desktop app (workspace propio, GX-015+)
  migrations/     # esquema SQLite V001..V006
  tests/fixtures/ # golden snapshot + adjudications + corpus de regresión
```

## Prerequisites

- Rust: MSRV 1.89 (workspace del engine) y 1.90 (workspace desktop). CI lo
  verifica con `cargo +1.89.0 check --workspace --all-targets --locked` y
  `cargo +1.90.0 check --manifest-path desktop/src-tauri/Cargo.toml --locked`;
  `rust-toolchain.toml` selecciona `stable` con rustfmt/clippy.
- Node 20+ solo para desarrollar/compilar el desktop.
- No Python runtime required.

## Common commands

```bash
cargo check --workspace
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --manifest-path desktop/src-tauri/Cargo.toml --locked

cargo xtask build              # release build + dist/gx.exe
cargo xtask check-boundaries   # engine mínimo sin SQLite/Tauri/PDF/zip/unrar
cargo run --release -p xtask -- bench --check --scenario small-files --scaling --max-peak-mib 512
cargo run -p gx_app --bin gx -- --help
```

## CLI (`gx`) — GX-012/013/014

Códigos de salida: `0` pass · `1` reject (quality gate) · `2` invocación
inválida · `3` fallo de scan/infraestructura.

```bash
# Escaneo de archivo (JSON en stdout, progreso/errores en stderr)
cargo run -p gx_app --bin gx -- scan --file tests/fixtures/sources/ejemplo_codigo.txt --format json

# Escaneo de directorio (recursivo, extensiones fuente)
cargo run -p gx_app --bin gx -- scan tests/fixtures/dialects

# Quality gate CLI (umbrales absolutos) o política GUI legada (%)
cargo run -p gx_app --bin gx -- scan --file <path> --max-errors 0 --max-warnings 100
cargo run -p gx_app --bin gx -- scan --file <path> --error-pct 10

# Whitelist / blacklist de reglas y perfil del set (A01)
cargo run -p gx_app --bin gx -- scan --file <path> --enable GX.2.3,GX.2.6
cargo run -p gx_app --bin gx -- scan --file <path> --disable GX.2.7.2
cargo run -p gx_app --bin gx -- scan <dir> --rules-profile local   # toggles locales

# Discovery explícito (A01.5): globs relativos al root + ignore file
cargo run -p gx_app --bin gx -- scan <dir> --include '**/*.xpz' --exclude 'generated/**'
cargo run -p gx_app --bin gx -- scan <dir> --ignore-file .gxignore --follow-symlinks

# Streaming NDJSON (un finding por línea + línea final de resumen; C01)
cargo run -p gx_app --bin gx -- scan --file <path> --format ndjson

# Evidencia sensible sin redactar (opt-in explícito; D03)
cargo run -p gx_app --bin gx -- scan --file <path> --retain-sensitive-evidence

# Catálogo
cargo run -p gx_app --bin gx -- rules list --rules-csv Reglas.csv
cargo run -p gx_app --bin gx -- rules enable GX.1.1   # base local
cargo run -p gx_app --bin gx -- rules disable GX.2.6

# Historial de auditoría (opt-in; los scans CI no escriben)
cargo run -p gx_app --bin gx -- scan --file <path> --record-history

# PDF source-aware (GX-019): junto al scan o desde un JSON ya emitido
cargo run -p gx_app --bin gx -- scan --file <path> --pdf informe.pdf
cargo run -p gx_app --bin gx -- export-pdf --result-file result.json --out informe.pdf
```

**Entradas soportadas:** `.txt`/`.prg`/`.gxd`/`.src`, `.xml` (export
GeneXus `ExportFile`/`GXObject` o layout con `<Events>`), y paquetes
`.xpz`/`.zip`/`.rar` (ZIP o RAR detectado por contenido). Los exports con
objetos sin código escanean como PASS con 0 hallazgos (aviso en stderr);
los layouts sin objetos GeneXus se rechazan como no soportados.

Ejemplos reales incluidos: `tests/fixtures/sources/real/` (WebPanel,
Procedure, Transaction; contenedores ZIP y RAR) con snapshot adjudicado en
`tests/fixtures/real_exports/manifest.json`.

**Nota de licencia:** el soporte RAR usa la librería UnRAR (vendored vía el
crate `unrar`), cuya licencia permite extraer archivos RAR pero no crear
archivos RAR. El fix de linkeo vive en `crates/gx_core/build.rs`.

**Nota de cancelación (A04.6):** la descompresión RAR es una operación nativa
no interrumpible dentro de un miembro. La cancelación se observa en los
límites de miembro (y antes de cada objeto), y el tamaño declarado de cada
miembro se verifica contra `max_member_bytes` ANTES de descomprimirlo, por lo
que la ventana no interrumpible queda acotada por un solo miembro. No se usa
un proceso worker cancelable; se reconsideraría si el límite por miembro
creciera hasta exceder el objetivo de parada cooperativa (~500 ms).

Sample JSON (recortado):

```json
{
  "schema_version": 1,
  "verdict": "reject",
  "metrics": { "total_findings": 23, "errors": 15, "warnings": 8, "info": 0 },
  "findings": [
    {
      "rule_id": "GX.2.6",
      "severity": "ERROR",
      "line_number": 3,
      "object": { "id": "ProcMalo", "object_type": "Procedure",
                  "package": "PkgDemo", "member": "PkgDemo/ProcMalo.xml" },
      "description": "Mala práctica crítica en Subrutina 'Inicializar': …"
    }
  ]
}
```

Golden efectivo del fixture: **23 hallazgos (15 ERROR / 8 WARNING)** = 17 del
output Python (`golden_issues.json`, intacto) + 6 adjudicados con razonamiento
en `tests/fixtures/golden_adjudications.json` (ver `tests/fixtures/BASELINE.md`).

## Desktop (`desktop/`) — GX-015..GX-018

Aplicación **Tauri 2 + Vue 3 + TypeScript + Vite + Tailwind** que reutiliza
el MISMO engine (`AnalysisRequest`/`AnalysisResult`) que el CLI; el frontend
no duplica lógica de lint.

### Prerequisitos

- Rust stable con toolchain MSVC (el mismo del workspace).
- Node 20+ (solo para desarrollar/compilar el frontend).
- WebView2 Runtime: preinstalado en Windows 10/11 recientes; si falta,
  instalar el *Evergreen WebView2 Runtime* de Microsoft.

### Comandos

```bash
cd desktop
npm install            # primera vez
npm run tauri dev      # desarrollo (Vite en 5173 + app Tauri)
npm run tauri build    # instalador NSIS (release)
npm run build          # solo frontend: typecheck + vite build
```

El workspace del engine NO depende del toolchain frontend:
`cargo test --workspace` sigue pasando sin Node.

### Comandos Rust expuestos (GX-016, actualizado por C01/C02)

| Comando | Descripción |
|---|---|
| `ping` | Health check del puente Rust↔Vue |
| `scan(request, onProgress)` | Escaneo asíncrono con progreso por archivo (Channel), cancelación y sesión acotada; devuelve el resumen |
| `cancel_scan` | Solicita cancelar el scan en curso |
| `pick_source_files` | Diálogo nativo; valida extensiones fuente en Rust |
| `list_rules` / `set_rule_enabled` | Catálogo y configuración en la base local |
| `get_settings` / `set_settings` | Umbrales del quality gate |
| `list_audit_runs` / `get_audit_issues_page` | Historial con keyset pagination e identidad de objeto |
| `get_findings_page` | Página de findings con filtros server-side (C01/C03) |
| `render_text_summary` | Mismo resumen textual que `gx scan --format text` |
| `read_object_window` / `read_history_object_window` | Ventana acotada del miembro con scope de sesión/corrida (C02) |
| `save_pdf` | Diálogo nativo + PDF desde la sesión (GX-019) |

El comando sin restricciones `read_object_source` ya **no** se expone por IPC
(C02): el visor usa las ventanas con scope validado. Errores del backend:
`{ code, message }` (nunca panic); un input no soportado aparece como fallo
destacado, jamás como resultado limpio.

### Datos locales

`%APPDATA%\GX\Linter\data\gx_linter.db` (fallback `./data/gx_linter.db`).
Las migraciones V001→V006 preservan reglas, settings e historial entre
upgrades; el historial guarda cobertura, completitud, conteo real de archivos
escaneados, configuración efectiva, versiones y digest de la fuente (C01).

### Troubleshooting

- Ventana en blanco en `tauri dev`: verificar que Vite escucha en el puerto
  5173 (el `devUrl` de `tauri.conf.json`).
- Error de WebView2 al iniciar: instalar el runtime Evergreen.
- El instalador NSIS no está firmado: si el antivirus lo bloquea, agregar la
  excepción (firma de código pendiente).

## Parity baseline

- `tests/fixtures/BASELINE.md` — contrato de comparación, provenencia
  machine-checked (SHA-256), adjudicaciones y matriz de dialectos.
- `tests/fixtures/golden_issues.json` — output Python (intacto).
- `tests/fixtures/golden_adjudications.json` — deltas adjudicados (GX-004).
- Los XPZ de prueba se regeneran con
  `cargo run -p gx_sources --example make_xpz_fixture`.

## Regenerating golden snapshots (histórico)

The Python engine output was captured once as the parity baseline:

```bash
python ../genexus-linter-python/.venv/Scripts/python.exe scripts/gen_baseline.py
```

This wrote `tests/fixtures/golden_snapshot_cli.txt`,
`golden_issues.json` and `rule_manifest.json`. Los tests ya NO requieren
Python ni el repositorio hermano.
