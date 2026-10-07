# GX Linter — Migración Python → Rust

Este repositorio (`gx-linter-rs`) es el **port 1:1** de
`genexus-linter-python` (app de análisis estático de código GeneXus).

- **Repo origen:** `D:\dev\osobobo\genexus-linter-python` (Python, completo y commiteado; `dist/GX_Linter.exe` ya construido).
- **Repo destino:** `D:\dev\osobobo\gx-linter-rs` (Rust, en construcción).
- **Especificación:** `plan/migration-rust.json` (backlog con 11 EPICs / 31 stories).

---

## Estado actual (checkpoint)

**Backlog activo:** `plan/backlog-engine-cli-tauri.json` (M0→M3 con gates).
**Estado: M0–M3 completados (20/20 historias) — GATE-BASELINE,
GATE-ENGINE, GATE-CLI y GATE-DESKTOP en verde (2026-10-02).**
**Roadmap performance/modularidad/seguridad (fases A–E): cerrado
(2026-10-06); logs y evidencia medida en
`plan/performance-modularity-security-roadmap.md` §8–§18.**

| EPIC | Tema | Estado |
|------|------|--------|
| 00 | Baseline de paridad (golden snapshot) | ✅ Hecho |
| 01 | Workspace Cargo + toolchain + CI | ✅ Hecho |
| 02 | Dominio core (models, ParsedLine, regex_cache) | ✅ Hecho |
| M0 | GX-001/002: fixture reproducible + harness engine/reglas | ✅ Hecho |
| 03 | SQLite storage (rusqlite) + DAOs | ✅ Hecho (GX-009..011; migraciones V001–V006) |
| 04 | Filesystem + XPZ extractor | ✅ Hecho (GX-006/007; hoy en `gx_sources`) |
| 05 | Trait Rule + registry + runtime/dispatch | ✅ Hecho (GX-003/004/005) |
| 06 | Catálogo de reglas | ✅ Hecho (34: 28 concretas + 6 abstractas) |
| 07 | Reporte PDF | ✅ Hecho (GX-019: printpdf, CLI + desktop) |
| 08 | CLI (clap) | ✅ Hecho (GX-012/013/014) |
| 09 | GUI → reemplazada por **Tauri 2** | ✅ Hecho (GX-015..018) |
| 10 | QA/paridad, migración datos, empaquetado | ✅ Hecho (NSIS + CI desktop) |

> Las secciones **M0–M3** siguientes son el registro histórico de su fecha
> (conteos, comandos y migraciones de entonces); el estado vigente es el de
> esta cabecera y el "Estado final" al pie.

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

## M3 — GX-015..GX-020 ✅ (2026-10-02) — GATE-DESKTOP listo

### GX-015 — Shell Tauri 2 + Vue
- `desktop/` con Vue 3.5 + TypeScript + Vite 6 + Tailwind 4 (Pinia);
  `desktop/src-tauri/` es workspace propio con path deps a las crates, de
  modo que `cargo test --workspace` del engine NO depende de Node.
- `tauri.conf.json` (1280x800, devUrl 5173, frontendDist ../dist, bundle
  NSIS, capabilities `core:default` + `dialog:allow-open`), iconos generados.
- Scaffold egui eliminado (`crates/gx_app/src/main.rs` y su `[[bin]]`);
  README sin referencias a eframe/egui.
- Smoke test del release: arranca y crea `%APPDATA%\GX\Linter\data\gx_linter.db`.

### GX-016 — Contrato de comandos
- `gx_engine::runtime::{analyze_with_progress, FileProgress}` con progreso
  por archivo y cancelación (`AtomicBool`); `analyze()` delega sin cambios
  (paridad golden intacta). `runtime::is_known_rule` para validar ids.
- `gx_core::summary::text_summary` compartido con el CLI (salida idéntica);
  `AuditRun::from_analysis` como única procedencia de historial CLI/desktop;
  `rules_dao::exists`; `audit_dao::list_runs` devuelve `AuditRunSummary`.
- Comandos: `scan` (spawn_blocking + Channel), `cancel_scan`,
  `pick_source_files` (valida extensiones en Rust), `list_rules` /
  `set_rule_enabled`, `get_settings` / `set_settings`, `list_audit_runs` /
  `get_audit_issues`, `render_text_summary`, `read_object_source`, `save_pdf`.
- Validación de frontera (schema, paths, set vacío, reglas desconocidas) →
  `CommandError {code, message}`; nunca panic. 7 tests Rust del desktop:
  paridad GUI↔engine, progreso + historial atómico, fallo nunca limpio,
  validación, visor, upgrade.

### GX-017 — UI de auditoría
- Tabs Scan / Reglas / Historial. ScanView (picker nativo + ruta manual,
  política absoluta o porcentual, progreso por archivo, cancelar),
  ResultsView (banner de veredicto, métricas, fallos separados de los
  hallazgos), FindingsTable (filtros severidad/regla/texto, paginación de
  100 filas, j/k/flechas + Enter, `aria-activedescendant`), SourceViewer
  (línea real del miembro, navegación anterior/siguiente, Escape),
  RulesView (toggles con `role=switch` + rerun sin reiniciar),
  HistoryView (corridas + hallazgos históricos con identidad de objeto).
- Accesibilidad: roles tab/switch/dialog/status, labels aria, focus visible,
  contraste AA, estados de carga/vacío. Paginación en vez de virtualización
  (evita dependencia extra; DOM acotado).

### GX-018 — Release
- Instalador NSIS: `target/release/bundle/nsis/gx-linter_1.0.0_x64-setup.exe`
  (3.62 MiB) con assets de Vue embebidos (sin Node en runtime).
- CI: job `desktop` (Node 20, `npm ci`, `npm run build`, `cargo test`,
  `npm run tauri build`, artifact NSIS); los jobs del engine/CLI no cambian.
- Upgrade verificado por test: flags de usuario e historial sobreviven la
  reapertura de la base (migraciones V1→V3).
- README: prerequisitos (WebView2/MSVC), comandos dev/build, datos locales,
  troubleshooting.

### GX-019 — PDF (P3)
- `gx_report::{render, render_bytes, layout}` con printpdf 0.12 (Helvetica
  builtin): portada con métricas/veredicto/política, fallos destacados y
  hallazgos paginados con descripción envuelta; el layout es texto puro
  testeable y el PDF se genera SIN re-ejecutar el engine.
- CLI: `--pdf` en `scan` (un fallo del PDF NO altera el exit code) y
  `gx export-pdf --result-file <json> --out <pdf>`.
- Desktop: botón «Exportar PDF» en ResultsView → `save_pdf` con diálogo
  nativo.
- Tests: todos los hallazgos en el layout, header `%PDF`, acentos y paths
  largos, 1000 hallazgos paginan; matriz CLI con `--pdf` y `export-pdf`.

### GX-020 — Documentación/CI (P3)
- `cargo xtask build` / `build-debug` implementados (release + copia a
  `dist/gx.exe`); `remote.txt` eliminado; `migration-rust.json` marcado como
  referencia histórica.
- CI con jobs fmt/clippy/test/cli-matrix/audit/build-release/desktop.

### Adjudicación M3
- `code_start_line` ahora apunta a la línea del `<![CDATA[` (inicio del
  texto) y `SourceObject::member_line(text_line)` mapea 1:1 texto→miembro
  para el visor; no afecta el golden (campo interno, sin cambios en
  hallazgos).

### Verificación GATE-DESKTOP
- `cargo fmt --all -- --check` ✅ · `clippy -D warnings` ✅ ·
  `cargo test --workspace` ✅ (~90 tests, 0 ignored) ·
  `cargo build --workspace --release` ✅
- Desktop: `npm run build` ✅ · `cargo test` ✅ (7 tests) ·
  `npm run tauri build` ✅ (NSIS) · smoke del release ✅
- `cargo xtask build` ✅ (release + dist/gx.exe)

---

## Estado final (2026-10-06)

- **M0–M3 completos** (20/20 historias del backlog activo; GATE-BASELINE,
  GATE-ENGINE, GATE-CLI y GATE-DESKTOP en verde).
- **Roadmap performance/modularidad/seguridad (fases A–E) cerrado**:
  presupuesto de ejecución con límites run-wide calibrados, discovery
  explícito (globs/ignore/symlinks), persistencia acotada con snapshot
  completo del historial, packs semánticos/seguridad, contratos generados y
  gates de evidencia (operation-counts, escalado ~2x, envelope 512 MiB,
  latencia IPC p95). Logs y números medidos:
  `plan/performance-modularity-security-roadmap.md` §8–§18.
- **Pendientes externos (no de código):** baseline de timing en el runner
  self-hosted `gx-benchmark` (`.github/workflows/bench-consistent.yml`) y
  captura interactiva de latencias WebView2 (el boundary IPC ya está gateado
  en `desktop/src-tauri/tests/latency.rs`).
- **Documentación alineada:** README actualizado (MSRV 1.89/1.90, flags de
  discovery, NDJSON, perfiles de reglas, comandos desktop con scope,
  migraciones V001→V006 y 34 reglas).

---

## Cómo regenerar el baseline (EPIC-00, histórico)

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

## Notas de paridad (histórico)
- **Quality Gate DUAL**: CLI = umbrales absolutos
  (`errors<=max_errors AND warnings<=max_warnings`, `main.py:96-99`);
  GUI = porcentual (`error_pct = errors*100/total <= qg_threshold_pct`,
  `main_window.py:85-91`). Ambos algoritmos se implementan y se seleccionan
  según el entrypoint.
- `evaluate_file` corta en `generated subroutines (public)` y llama `reset()`
  por regla antes del loop (en Python lo hace el caller; en Rust se consolida
  en el engine).
