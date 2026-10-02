# GX Linter — Migración Python → Rust

Este repositorio (`gx-linter-rs`) es el **port 1:1** de
`genexus-linter-python` (app de análisis estático de código GeneXus).

- **Repo origen:** `D:\dev\osobobo\genexus-linter-python` (Python, completo y commiteado; `dist/GX_Linter.exe` ya construido).
- **Repo destino:** `D:\dev\osobobo\gx-linter-rs` (Rust, en construcción).
- **Especificación:** `plan/migration-rust.json` (backlog con 11 EPICs / 31 stories).

---

## Estado actual (checkpoint)

**Backlog activo:** `plan/backlog-engine-cli-tauri.json` (M0→M3 con gates).
**Último hito completado: M0 (GATE-BASELINE)** — ver sección "M0" abajo.

| EPIC | Tema | Estado |
|------|------|--------|
| 00 | Baseline de paridad (golden snapshot) | ✅ Hecho |
| 01 | Workspace Cargo + toolchain + CI | ✅ Hecho |
| 02 | Dominio core (models, ParsedLine, regex_cache) | ✅ Hecho |
| M0 | GX-001/002: fixture reproducible + harness engine/reglas | ✅ Hecho |
| 03 | SQLite storage (rusqlite) + DAOs | ⏳ Siguiente (GX-009: catálogo/seeding confiable) |
| 04 | Filesystem + XPZ extractor | Pendiente (GX-006/007) |
| 05 | Trait Rule + registry + runtime/dispatch | Pendiente (GX-003/004/005) |
| 06 | Catálogo 30 reglas | Parcial (24 concretas + audit GX-008) |
| 07 | Reporte PDF | Pendiente (GX-019, P3) |
| 08 | CLI (clap) | Pendiente (GX-012/013/014) |
| 09 | GUI → reemplazada por **Tauri 2** | Pendiente (GX-015..018) |
| 10 | QA/paridad, migración datos, empaquetado | Cubierto por backlog nuevo |

---

## M0 — GATE-BASELINE ✅ (2026-10-02)

### Entregado (GX-001)
- `tests/fixtures/sources/ejemplo_codigo.txt` — fixture fuente commiteado
  (ASCII puro, LF), copia de `ejemplo_codigo.txt` del repo Python.
- `tests/fixtures/sources/baseline_manifest.json` — procedencia machine-checked:
  SHA-256 de fuente/goldens, Python 3.14.5, las 15 reglas habilitadas
  (=`config/rules.json`), campos de comparación y defectos conocidos.
- `tests/fixtures/BASELINE.md` — contrato de comparación y protocolo de
  regeneración/adjudicación.
- `gx_storage::seed::default_enabled_ids()` — set canónico de 15 reglas.
- Los tests ya **no** dependen del repo hermano ni de venv.

### Entregado (GX-002)
- `crates/gx_engine/tests/parity_golden.rs` — paridad multiconjunto canónica
  contra `golden_issues.json` (17 hallazgos: 12 ERROR / 5 WARNING),
  machine-check de SHA-256 y cobertura del manifest (30 reglas).
- `crates/gx_engine/tests/engine_behavior.rs` — determinismo entre escaneos,
  independencia entre archivos, filtrado de reglas habilitadas, archivo limpio
  sin hallazgos, paralelo≡secuencial, archivo inexistente falla explícito.
- `crates/gx_engine/tests/rule_cases.rs` — ~50 fixtures positivos/negativos
  (`tests/fixtures/cases/`) cubriendo las **24 reglas concretas** (una regla
  habilitada por corrida), con variantes de estado y anidación.
- API de engine sin SQLite: `gx_engine::runtime::{build_rules, scan_file}`.

### Correcciones adjudicadas durante M0 (bugs de porteo, con test de regresión)
1. **GX.2.5 panic** (`rule_gx_2_5.rs`): el regex consolidado tiene 1 grupo de
   captura pero el código leía `get(2)` (el Python original usaba un regex
   local de 2 grupos) → panic en cualquier `where` con valor duro. Fix:
   `get(1)`. visible: el harness entero dejaba de correr.
2. **GX.2.7.1 doble espacio** (`rule_gx_2_7_1.rs`): `starts_with_kw(lower,
   "do while ")`/`"for "` — `starts_with_kw` ya agrega el espacio → exigía
   doble espacio → tracking de loops muerto. Python usa `startswith("do
   while ")` directamente. Fix: sin espacio duplicado.
3. **GX.1.4.3 match completo** (`rule_gx_1_4_3.rs`): el port usaba
   `find().as_str()` (incluye `parm(`) donde Python usa `group(1)` (contenido
   interno) → falso positivo con parámetros ya direccionados. Fix:
   `captures()` + `get(1)`.

### Defectos conocidos expuestos (NO corregidos — M1/GX-008)
Los tests están `#[ignore]` (CI en verde) y **fallan al ejecutarlos**,
demostrando el defecto antes de corregirlo:

```powershell
cargo test -p gx_engine -- --ignored    # 8 tests, todos fallan hoy
```

> **Estado M1 (2026-10-02): los 8 demos quedaron des-ignorados y en verde.**
> Ver sección "M1" abajo. La tabla se conserva como registro histórico del
> estado M0.

| Demo | Backlog | Defecto |
|---|---|---|
| `reset_state_leak_between_scans` | GX-003 | `run_file` no llama `reset()` → estado entre escaneos. |
| `issues_carry_real_file_path` | GX-003 | `file_path` queda `"Unknown"`. |
| `rule_1_3_endfor/defined_by_*` | GX-004 | Dispatch nunca entrega `where`/`endfor` a GX.1.3. |
| `rule_1_3_3_with_otherwise` | GX-004 | `otherwise` no llega a GX.1.3.3 → falso positivo. |
| `rule_2_6_nullvalue` | GX-004 | cuerpo del `sub` no llega a GX.2.6. |
| `rule_1_6_2_comment` | GX-004 | comentario tras `sub` no llega a GX.1.6.2. |
| `rule_1_6_1_comment_before_do` | GX-004+GX-008 | comentario previo al `do` no se despacha + flag se limpia antes de consultarse. |

Nota de depuración: en modo de **una sola regla habilitada**, el fallback
"todas las reglas" del dispatch enmascara los huecos; los demos usan
`scan_with_anchor` (regla + GX.2.3 como ancla DEFAULT) para reproducir el
comportamiento del set completo. El fallback defectuoso se elimina en GX-004.

### Verificación M0
- `cargo fmt --all -- --check` ✅
- `cargo clippy --workspace --all-targets -- -D warnings` ✅
- `cargo test --workspace` ✅ (22 tests, 8 ignored)
- `cargo test -p gx_engine -- --ignored` ❌ rojo (8 demos de defectos — así debe estar hasta M1)

---

## M1 (parcial: E01 completo) — GX-003/GX-004/GX-005 ✅ (2026-10-02)

### GX-003 — Ciclo de vida
- `run_file` llama `Rule::reset(path)` por regla antes de evaluar cualquier
  línea; secuencial y paralelo comparten el contrato (ambos pasan por
  `run_file`). Sin fugas de estado entre escaneos; `file_path` real.

### GX-004 — Dispatch por plan (reemplaza TRIGGER_MAP/fallback)
- `Rule::dispatch_route() -> DispatchRoute::{AllLines, Tokens(tokens)}` con
  default seguro `AllLines`; el macro `define_rule!` acepta `route = tokens`.
- 17 reglas con estado → `AllLines` (1.2, 1.3, 1.3.1, 1.3.2, 1.3.3, 1.4.3,
  1.6.1, 1.6.2, 1.7.1, 1.7.2, 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7.1); 7 sin
  estado → `Tokens` (1.1, 1.4.1, 1.4.2, 1.5, 2.7.2, 2.7.3, 2.7.4).
- Fallback "sin candidatos ⇒ todas las reglas" **eliminado**.
- Token sin mapeo de flag → error explícito del plan, nunca regla sorda.
- Test de equivalencia: dispatch vs referencia all-rules-per-line sobre todo
  el corpus (golden + clean + ~40 fixtures de casos) ✅.
- **Corrección adicional GX-008 (parcial):** GX.1.6.1 consultaba el flag
  DESPUÉS de limpiarlo; ahora consulta primero (paridad
  `rule_gx_1_6_1.py:111`).
- **Orden determinista de textos (GX-005):** GX.1.1 (vars en join),
  GX.1.4.2 (atributos detectados) y GX.2.7.4 (vars muertas en finalize)
  ahora ordenan sus sets antes de emitir.

### GX-005 — Determinismo y errores transparentes
- Emisión determinista: líneas en orden de fuente; reglas candidatas en
  orden ascendente de registro (antes: HashSet con orden aleatorio por línea).
- `evaluate_files_parallel` → `Vec<FileScanOutcome>` con `error: Option<String>`
  por archivo; un archivo fallido ya no pasa como éxito vacío.
- Test de orden exacto entre escaneos repetidos (ya no sólo multiconjunto).

### Adjudicación del golden (regla de ejecución 5)
El despacho Python tenía ramas muertas demostrables; con el despacho
corregido el golden gana 5 hallazgos reales sobre el fixture
(2×GX.2.7.1 en 55/56, 2×endfor sin tabla en 69/70, DEFINED BY faltante en 61).
- `golden_issues.json` (output Python) **queda intacto** como referencia.
- `golden_adjudications.json` documenta los 5 deltas con hallazgo completo y
  razonamiento; `baseline_manifest.json` registra su SHA-256.
- Baseline efectivo: **22 hallazgos (14 ERROR / 8 WARNING)**; la paridad y
  la contención (Python ⊆ Rust) quedan cubiertas por tests.

### Verificación M1 (E01)
- `cargo fmt --all -- --check` ✅ · `clippy -D warnings` ✅ ·
  `cargo test --workspace` ✅ (33 tests, 0 ignored) ✅
- Los 8 demos del M0 quedaron en verde al corregir los defectos.

**Pendiente de M1 (E02):** GX-006 (modelo SourceObject / ubicaciones
originales por miembro XPZ), GX-007 (discovery/decoding/XPZ hardening),
GX-008 (matriz de dialectos + audit completo de reglas). GATE-ENGINE cierra
con esas tres.

---

## M1 (E02) — GX-006/GX-007/GX-008 ✅ (2026-10-02) — GATE-ENGINE listo

### GX-006 — Objetos fuente y ubicaciones originales
- `gx_core::models`: `ObjectRef` (id/tipo/package/member/container) +
  `SourceObject` (texto + `code_start_line`) + `Issue.object` (stamp del
  runtime, serializado sólo cuando existe).
- `extract_source_objects`: .xpz → un objeto por miembro ZIP con `<Events>`;
  .xml → un objeto por bloque `<Events>` con identidad del root; .txt → un
  objeto `Source`. FIN de la concatenación: los `line_number` son reales
  dentro del miembro; el estado de reglas y el corte
  `generated subroutines (public)` NO cruzan objetos; finalize por objeto.
- Fixtures: `sample_package.xpz` (2 miembros; ProcMalo con GX.2.6@3 y
  GX.2.7.2@7 miembro-local; ProcBueno limpio), `proc_malo.xml`
  (equivalencia XML↔XPZ verificada por test), `unusable_package.xpz`.
  Regenerables con `cargo run -p gx_core --example make_xpz_fixture`.
- Tests `xpz_fidelity.rs` (6): líneas miembro-local, identidad completa
  (id/tipo/package/member/contenedor), equivalencia XML↔XPZ, XPZ sin
  fuente rechazado, determinismo con stamp.

### GX-007 — Discovery/decoding/XPZ endurecidos
- `filesystem.rs`: discovery incluye `.xml`; **fallback "cualquier archivo"
  eliminado** (los archivos ajenos no se lintean; test cubre .csv/.pdf).
- `xpz_extractor.rs`: validación de ZIP (miembro ilegible o miembro sin
  decodificar → error con nombre del miembro), límites documentados
  (MAX_XPZ_MEMBERS=4096, MAX_MEMBER_BYTES=32MiB, MAX_TOTAL_BYTES=64MiB),
  BOM UTF-8 removido, matriz de encodings `UTF-8 → UTF-8-BOM → CP1252 →
  Latin-1` documentada y testeada (unit tests), **raw-XML fallback
  eliminado**: layout sin `<Events>` → error "no soportado" explícito
  (unit test: XML sin Events; XPZ sin usable: `unusable_package.xpz`).

### GX-008 — Matriz de dialectos y semántica de reglas
- 8 fixtures dialecto (`tests/fixtures/dialects/`): bloques anidados, parm
  multilínea, comentarios de bloque, panel web, transacción, reporte,
  when itemizado (violación), violación tras bloque → con las **24 reglas
  habilitadas**: limpios → 0 hallazgos; violaciones → hallazgos exactos.
- Correcciones adjudicadas (diferencias con Python documentadas en
  BASELINE.md):
  1. Bloques `/* */` multilínea: el runtime enmascara el bloque completo
     preservando números de línea (Python linteaba código deshabilitado).
  2. `when/or/and/in/like/between` en línea propia dentro de `where`: ya no
     cierran el bloque → GX.2.1/2.2/2.4/2.5 los examinan (Python los
     interpretaba como asignación → falsos negativos).
- Audit de reglas completado vía fixtures: paridad de política mantenida
  donde el comportamiento Python es correcto (ej: `elseif` sin `else`,
  un hallazgo por bloque where).

### Verificación GATE-ENGINE
- `cargo fmt --all -- --check` ✅ · `clippy -D warnings` ✅ ·
  `cargo test --workspace` ✅ **50 tests, 0 ignored**
- Paridad golden intacta: 22 hallazgos (14E/8W) con contención Python ⊆ Rust.

**Siguiente hito: M2 (E03)** — GX-009 catálogo/seeding confiable,
GX-010 AnalysisRequest/Result con quality gates, GX-011 evaluación de
objetivos del resultado.

---

## M2 — GX-009..GX-011 (E03) + GX-012..GX-014 (E04) ✅ (2026-10-02) — GATE-CLI listo

### GX-009 — Catálogo confiable
- `seed_from_registry` / `seed_and_validate`: la inicialización pobla el
  catálogo DESDE EL REGISTRY COMPILADO (30 registros, 24 concretas) —
  imposible que el catálogo diverja del código; `init_db`/`init_db_at`/
  `init_memory_db` siempre seedean y validan (adiós al estado 0-reglas).
- `INSERT OR IGNORE` ⇒ reseed idempotente que PRESERVA flags de usuario
  (test con DB temporal: toggle + re-apertura = flag intacto).
- `is_rule_enabled` → `Result<bool>` fail-closed: fila faltante =
  DESHABILITADA; errores de SQL SE PROPAGAN (nunca "todas habilitadas").
- `missing_catalog_ids` valida el catálogo contra el registry.
- Import CSV (Reglas.csv) queda como vía opcional en memoria
  (`--rules-csv`), idempotente.

### GX-010 — Contrato separado de persistencia
- `gx_core::models`: `QgPolicy::{Absolute, Percentage}` (evaluación de
  umbrales con veredicto), `QgVerdict::{Pass, Reject, Error}`,
  `AnalysisRequest` (inputs, reglas explícitas, política, record_history),
  `ScanFailure` y `AnalysisResult` (hallazgos deterministas, métricas,
  fallos, política, veredicto).
- `gx_engine::runtime::analyze`: descubre archivos (directorio recursivo
  con extensiones fuente explícitas), evalúa en paralelo con el MISMO
  contrato, y los fallos de scan van a `failures` con veredicto `Error`
  (nunca éxito vacío). Cero hallazgos = `Pass`.
- El engine sigue siendo invocable sin SQLite (`build_rules`/`scan_file`)
  y el resultado NO depende de `record_history` (test de igualdad).
- Tests `analyze_contract.rs` (5): pass/reject/cero-hallazgos/fallos en
  ambas políticas + determinismo multi-input.

### GX-011 — Historial atómico y con identidad
- Migración `V003__audit_object_identity.sql`: columnas de objeto en
  `audit_issues` + `policy`/`verdict`/`failures_json` en `audit_runs`
  (ALTER TABLE, preserva datos; test migra V1→V3 con datos del usuario).
- `persist_run`: metadata + issues en UNA transacción; trigger RAISE en el
  test fuerza el fallo de issues → rollback completo (0 corridas).
- `get_issues_for_run` reconstruye la identidad de objeto (member del XPZ
  preservado para reabrir el miembro en el visor).
- Historial OPT-IN: los scans CI no escriben (`record_history=false` por
  defecto; `--db` para pruebas).

### GX-012/013 — CLI productivo
- `gx scan <ruta>` (posicional o `--file`, compat): JSON/text en stdout,
  progreso y fallos en stderr, `--max-errors/--max-warnings` (absolute),
  `--error-pct` (percentage legada), `--enable` (whitelist) / `--disable`,
  `--rules-csv` (catálogo en memoria), `--record-history` + `--db`.
- `gx rules list|enable|disable` (catálogo local; list muestra 24
  operativas y reporta total del catálogo).
- Códigos de salida documentados en `--help` y README:
  0 pass · 1 reject · 2 invocación inválida · 3 fallo de scan.

### GX-014 — Matriz de aceptación (14 tests, binario real)
- golden .txt (JSON completo: 22 hallazgos, reject, provenencia) · clean
  (pass, 0 hallazgos) · directorio limpio (6 archivos, pass) · XPZ
  multi-objeto (2 hallazgos miembro-local con identidad) · XPZ sin fuente
  usable (exit 3 "no soportado") · ZIP corrupto (exit 3 contextual) · path
  inexistente (exit 3) · invocación sin ruta (exit 2) · --help preciso ·
  text-mode con veredicto · determinismo byte a byte del JSON · filtros de
  reglas · catálogo CSV · `--record-history` escribe con veredicto.
- CI: job `cli-matrix` (release) agregado a `.github/workflows/ci.yml`;
  README con comandos, exit codes y ejemplo JSON.

### Verificación GATE-CLI
- `cargo fmt --all -- --check` ✅ · `cargo clippy --workspace --all-targets
  -- -D warnings` ✅ · `cargo test --workspace` ✅ **73 tests, 0 ignored** ·
  `cargo build --workspace --release` ✅
- Checkout limpio ejecuta el corpus golden+legacy sin Python ni repo hermano.

**Siguiente hito: M3 (GATE-DESKTOP)** — GX-015..GX-018: Tauri 2 + Vue 3
(usar el mismo engine), GX-019 PDF (P3) y GX-020 cierre de documentación.

---

## Post-M2 — Exports reales (2026-10-02): RAR, ExportFile/GXObject y contrato sin código

Validación con los exports reales de `examples/` (4 archivos):

| Export | Formato | Resultado |
|---|---|---|
| `HJFCP716.xpz` | RAR5 | WebPanel `JFCP716` → 102 hallazgos (40E/62W), líneas del Events reales |
| `JBMP018.xpz` | ZIP | WebPanel + Procedure `JBMP018` (sección Rules) → 47 (9E/38W) |
| `HJFCQ350.xpz` | ZIP | 3 objetos sin código → PASS 0 + aviso stderr |
| `jngz293.xpz` | ZIP | Transaction/Table sin código → PASS 0 + aviso stderr |

### Correcciones y features
1. **Contenedores por magic bytes**: `.xpz`/`.zip`/`.rar` → ZIP o RAR
   (`unrar` vendored). `.zip` se acepta por archivo explícito; el
   descubrimiento de directorios sigue con `.xpz`.
2. **Linkeo Windows**: `crates/gx_core/build.rs` emite
   advapi32/crypt32/userenv (sin esto `unrar_sys` rompía el linkeo de
   tests/examples con LNK2019).
3. **Regresión corregida**: extensiones no soportadas vuelven a fallar con
   "no soportado" (antes se linteaba cualquier archivo como texto).
4. **Parser del formato real `ExportFile`/`GXObject`**: identidad por
   objeto (tipo = primer hijo, `Info/Name`, `Info/Folder`); código desde
   `Events` + `Rules` + `Subroutines` concatenados; excluye
   `Documentation/Source`, `Layout/Source`, `Help`, `Structure`. El id de
   respaldo ya no es "la primera línea de código" (ids basura) sino el stem
   del miembro.
5. **Contrato sin código (GX-007 refinado)**: objetos reconocidos sin
   secciones de código = PASS con 0 hallazgos + warning a stderr (tracing
   inicializado en el CLI); layout sin `GXObject`/`Events` sigue siendo
   "no soportado".
6. **Snapshot adjudicado**: `tests/fixtures/real_exports/manifest.json`
   (SHA-256, conteos por regla, spot-checks verificados línea a línea
   contra el CDATA original) + `crates/gx_engine/tests/real_exports.rs` (5
   tests) + 3 casos nuevos en la matriz CLI.

### Verificación
- `cargo fmt --all -- --check` ✅ · `cargo clippy --workspace --all-targets -- -D warnings` ✅
- `cargo test --workspace` ✅ **85 tests, 0 ignored** (gx_core 22 · gx_engine 41
  incl. real_exports 5 · gx_app 17 incl. 3 casos reales · gx_storage 5)
- `cargo build --workspace --release` ✅
- CLI final sobre los 4 ejemplos: 102/reject · 0/pass · 47/reject · 0/pass ✓

---

## Handoff a nueva sesión (2026-10-02)

M0–M2 completados (14 historias, gates GATE-BASELINE/GATE-ENGINE/GATE-CLI).
El detalle de M3 quedó especificado en `plan/backlog-engine-cli-tauri.json`:

- `executionState` — hitos cerrados, verificación vigente (73 tests, 0
  ignored, fmt/clippy/release ✓), adjudicaciones activas y `sessionHandoff`
  con el snapshot de APIs/contratos (startHere + knowBeforeStarting).
- Historias GX-015..GX-020 con campo `handoffSpec` — pasos concretos,
  archivos objetivo, comandos, riesgos y fixtures de desarrollo para cada
  historia de Tauri 2/Vue, PDF y cierre documental.

Cómo retomar: leer `executionState.sessionHandoff` del backlog → iniciar
GX-015 (shell Tauri 2) → GX-016 (comandos async sobre
AnalysisRequest/Result) → GX-017 (UI de auditoría) → GX-018 (release) —
GX-019/GX-020 son P3 y no bloquean GATE-DESKTOP.

---

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
