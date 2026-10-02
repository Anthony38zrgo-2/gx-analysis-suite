# Baseline de paridad (GX-001 / GATE-BASELINE)

Este directorio contiene el baseline reproducible contra el engine Python de
referencia (`genexus-linter-python`). Un checkout limpio debe poder ejecutar
los tests de paridad **sin Python, sin venv y sin el repositorio hermano**.

## Contenido

| Archivo | Rol |
|---|---|
| `sources/ejemplo_codigo.txt` | Fuente GeneXus (export de reglas) que produce el golden. Committeada, redistribuible, ASCII puro con finales LF. |
| `sources/baseline_manifest.json` | Procedencia machine-checked: SHA-256 de la fuente y de los goldens, versión Python, reglas habilitadas (15), campos comparados, bugs de porteo corregidos y defectos resueltos. |
| `../golden_issues.json` | Output ORIGINAL del engine Python sobre la fuente (17 hallazgos: 12 ERROR / 5 WARNING). Intacto — es la referencia de compatibilidad. |
| `../golden_adjudications.json` | Adjudicaciones GX-004: los 5 hallazgos adicionales que produce el engine Rust corregido, con su razonamiento (huecos demostrables del despacho Python). El baseline efectivo = Python + adjudicaciones (22 hallazgos: 14 ERROR / 8 WARNING). |
| `../golden_snapshot_cli.txt` | Salida CLI capturada (UTF-16LE por artifact de PowerShell; solo referencia humana, no la comparan los tests). |
| `../rule_manifest.json` | Tabla de verdad de las 30 reglas (24 concretas + 6 abstractas). |

## Contrato de comparación

- Campos comparados: `rule_id`, `severity`, `line_number`, `description`, `line_content`.
- Clave canónica: ambos lados se ordenan por `(line_number, rule_id)` y se
  comparan como multiconjuntos. El orden de emisión intra-línea del engine
  Python depende del orden de un `set`, por lo que NO es parte del contrato
  (el orden determinista es historia propia: GX-005).
- Excluido del contrato: `file_path` (el Python usa el placeholder `"Unknown"`
  si el caller no llama `reset()`; GX-003 lo corregirá), tiempos, contadores
  de evaluaciones y rutas de PDF.

## Regla de oro

**No editar a mano `golden_issues.json`.** Es el output Python de referencia.
Los cambios de comportamiento admitidos se adjudican como decisión explícita
de regresión (ver `executionRules` del backlog) agregando una entrada en
`golden_adjudications.json` con su hallazgo completo y su razonamiento, y se
documentan en `plan/PROGRESS.md`.

## Adjudicaciones vigentes (GX-004, 2026-10-02)

El despacho Python (TRIGGER_MAP por token aislado) nunca entregaba ciertas
líneas a reglas con estado: ramas muertas demostrables. Con el despacho
corregido, el engine Rust emite 5 hallazgos más sobre el fixture golden:

| Línea | Regla | Hueco Python demostrable |
|---|---|---|
| 55 | GX.2.7.1 | `for &i = 1 to 10` nunca despachado (solo triggers for each/do) → rama is_for_loop muerta. |
| 56 | GX.2.7.1 | cuerpo del for abierto en 55, ídem. |
| 69 | GX.1.3 | `endfor` nunca despachado → chequeo de tabla/comentario muerto. |
| 70 | GX.1.3 | ídem. |
| 61 | GX.1.3 | `where` nunca despachado → requisito DEFINED BY imposible de detectar. |

## Contrato de mapeo de origen (GX-006)

Cada artefacto escaneado produce `SourceObject`s (uno por objeto):

- `.xpz` → un objeto por miembro ZIP con bloque `<Events><![CDATA[...]]>`.
- `.xml` → un objeto por bloque `<Events>`; identidad desde el elemento raíz
  (tipo = nombre del root; `name`/`package` desde sus atributos).
- `.txt`/`.prg`/`.gxd`/`.src` → un objeto `Source` (package vacío).

Cada `Issue` incluye `object: Option<ObjectRef>` con `id`, `object_type`,
`package`, `member` (miembro ZIP o nombre de archivo) y `container_path`.
Los `line_number` son **líneas reales dentro del miembro** (1-based sobre el
CDATA, líneas en blanco incluidas); nunca coordenadas de concatenación. El
estado de reglas y el corte `generated subroutines (public)` no cruzan
objetos. Fixture de referencia: `sources/sample_package.xpz` (ProcBueno
limpio; ProcMalo con GX.2.6@3 y GX.2.7.2@7 miembro-local) y
`sources/unusable_package.xpz` (layout no soportado → error explícito).
Los .xpz se regeneran con `cargo run -p gx_core --example make_xpz_fixture`.

## Matriz de dialectos (GX-008, adjudicada 2026-10-02)

| Dialecto | Fixture | Decisión |
|---|---|---|
| Bloques anidados (for each ×2, if/else, do case, sub) | `dialects/dialect_nested_blocks_clean.txt` | Limpio con las 24 reglas. |
| Parm multilínea con direcciones | `dialects/dialect_parm_multiline_clean.txt` | Limpio (1.4.3 usa `group(1)`, paridad Python). |
| Comentario de bloque multilínea con código deshabilitado | `dialects/dialect_block_comments_clean.txt` | Rust ENMASCARA el bloque (`blank_multiline_block_comments`): no lentea el código deshabilitado y preserva números de línea. **Diferencia intencional vs Python** (Python linteaba el bloque → falsos positivos). |
| Violación real tras comentario de bloque | `dialects/dialect_block_comments_violation.txt` | Exactamente GX.1.1@9, GX.2.7.2@9, GX.1.1@10. |
| When itemizado (línea propia dentro del where) | `dialects/dialect_when_itemized_violation.txt` | `is_where_continuation` mantiene el where abierto para `when/or/and/in/like/between` (GX-008: falsos negativos de Python corregidos). Exactamente GX.2.1@12 + GX.2.5@12 (hardcode en when también se marca; un hallazgo por bloque where). |
| Panel WEB (msg/do/sub + comentarios) | `dialects/dialect_web_panel_clean.txt` | Limpio con las 24 reglas. |
| Transacción TRN (parm + for each + defined by) | `dialects/dialect_trn_clean.txt` | Limpio con las 24 reglas. |
| Reporte (print + for each) | `dialects/dialect_report_clean.txt` | Limpio con las 24 reglas. |

**Exclusiones conocidas de la matriz:**

- Bloque `/*` sin cierre (`*/`): el contenido se lentea (heurística
  conservadora; sin regla posible).
- Subrutinas GeneXus no declaran parámetros en el source (los `parm` viven
  en la sección `rules:`); el dialecto queda cubierto por
  `dialect_trn_clean.txt` / `gx_1_4_3_multiline_positive.txt`.
- `elseif` sin `else`: GX.1.3.2 lo sigue marcando (igual que Python;
  decisión de política mantenida).
- Codificación (GX-007): UTF-8 (con y sin BOM) → CP1252 → Latin-1; el
  orden está documentado en `ENCODING_FALLBACK` (CP1252 precede a Latin-1;
  Latin-1 acepta cualquier byte y es el último recurso). Archivos corruptos
  o sin fuente usable fallan con error contextual, nunca cero hallazgos
  silenciosos.

## Exports reales (GX-007/GX-008, 2026-10-02)

Fixtures en `sources/real/` con snapshot adjudicado en
`real_exports/manifest.json` (SHA-256 + conteos por regla + spot-checks
verificados contra la fuente):

| Export | Contenedor | Objetos con código | Hallazgos |
|---|---|---|---|
| `HJFCP716.xpz` | **RAR** (GeneXus con WinRAR) | WebPanel `JFCP716` | 102 (40E/62W) |
| `JBMP018.xpz` | ZIP | WebPanel + Procedure `JBMP018` (Rules) | 47 (9E/38W) |
| `HJFCQ350.xpz` | ZIP | — (3 objetos sin código) | 0 → PASS |
| `jngz293.xpz` | ZIP | — (2 objetos sin código) | 0 → PASS |

**Contenedores:** `.xpz`/`.zip`/`.rar` se detectan por magic bytes (ZIP o
RAR); `.zip` se acepta por archivo explícito y no entra al descubrimiento
de directorios. `unrar` (UnRAR vendored) requiere el fix de linkeo en
`crates/gx_core/build.rs` (advapi32/crypt32/userenv). Licencia UnRAR: uso
permitido para extraer, no para crear archivos RAR.

**Formato real de export (`ExportFile`):** identidad por objeto desde el
primer elemento hijo (`WebPanel`/`Procedure`/…), `<Info><Name>` y
`<Info><Folder>` (package). Secciones de CÓDIGO lintadas, en orden
documental y concatenadas por objeto: `<Events>`, `<Rules>`,
`<Subroutines>` (CDATA). **Excluidas explícitamente:**
`Documentation/Source` (HTML de documentación), `Layout/Source` (form),
`Help`, `Structure` y variables. Los objetos sin secciones de código son
un escaneo VÁLIDO con 0 hallazgos (warning a stderr); un layout sin
`GXObject` ni `<Events>` se rechaza como "no soportado" (nunca se lintea
XML de marca).

**Corte de subrutinas generadas:** `run_file` corta en
`generated subroutines (public)`; las secciones `(USER)` sí se lintan
(son editables por el usuario).

## Defectos del M0 — ya resueltos en M1

Los tests que en M0 estaban `#[ignore]` (demostraciones fallidas) quedaron
activos y en verde al corregir cada defecto:

- **GX-003** → `run_file` llama `Rule::reset(path)` antes de evaluar; sin
  fugas de estado entre escaneos; `file_path` real en cada hallazgo.
- **GX-004** → dispatch por plan (`AllLines`/`Tokens`); sin fallback;
  equivalencia contra referencia all-rules-per-line cubierta por test sobre
  todo el corpus.
- **GX-008 (parcial)** → GX.1.6.1 consulta el flag de comentario antes de
  limpiarlo (paridad `rule_gx_1_6_1.py:111`). El audit completo de reglas
  sigue siendo historia GX-008.
