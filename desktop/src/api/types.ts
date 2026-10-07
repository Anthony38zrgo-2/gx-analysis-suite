// Espejo TypeScript del contrato Rust (GX-016). Mantener en sincronía con
// `gx_core::models` y `desktop/src-tauri/src/commands.rs`.

export type Severity = "ERROR" | "WARNING" | "INFO";

export interface ObjectRef {
  id: string;
  object_type: string;
  package: string;
  member: string;
  container_path: string;
}

export interface Issue {
  rule_id: string;
  severity: Severity;
  line_number: number;
  line_content: string;
  description: string;
  file_path: string;
  object?: ObjectRef;
  /** D03: "security" se evalúa aparte de la política de estilo. */
  category?: string;
  /** D03: high/medium/low. */
  confidence?: string;
  /** D03: CWE cuando está justificado. */
  cwe?: number;
  /** D03: traza acotada source→sink de un hallazgo de dataflow. */
  trace?: TraceStep[];
}

/** D01: cobertura de un pack semántico/seguridad. */
export interface PackCoverage {
  id: string;
  version: string;
  objects_analyzed: number;
  skipped_unsupported: number;
  findings: number;
  /** D03: llamadas no modeladas sobre valores contaminados. */
  unsupported_sanitizers?: number;
}

/** D03: resumen de seguridad separado del veredicto de estilo. */
export interface SecuritySummary {
  findings: number;
  errors: number;
  verdict: QgVerdict;
}

export interface AuditMetrics {
  total_findings: number;
  errors: number;
  warnings: number;
  info: number;
}

export type QgPolicy =
  | { kind: "absolute"; max_errors: number; max_warnings: number }
  | { kind: "percentage"; max_error_pct: number };

export type QgVerdict = "pass" | "reject" | "error";

/** A01.5: política explícita de descubrimiento de fuentes. */
export interface DiscoveryPolicy {
  /** Globs de inclusión relativos al root (vacío = todos los fuente). */
  include?: string[];
  /** Globs de exclusión (dominan sobre include). */
  exclude?: string[];
  /** Archivo de patrones de ignorado (uno por línea, `#` comenta). */
  ignore_file?: string;
  /** Seguir symlinks a directorios (default false). */
  follow_symlinks?: boolean;
  /** Incluir archivos y directorios ocultos (default false). */
  include_hidden?: boolean;
}

export interface AnalysisRequest {
  schema_version: number;
  inputs: string[];
  enabled_rule_ids: string[];
  policy: QgPolicy;
  record_history: boolean;
  /** D03: retención opt-in de evidencia sensible (default false: redactada). */
  retain_sensitive_evidence?: boolean;
  /** A01.5: política explícita de descubrimiento (include/exclude/ignore). */
  discovery?: DiscoveryPolicy;
}

/** D03: paso de una traza acotada source→sink. */
export interface TraceStep {
  kind: string;
  line: number;
  detail: string;
}

export interface ScanFailure {
  path: string;
  error: string;
}

export interface ScanCoverage {
  inputs_declared: number;
  inputs_scanned: number;
  files_discovered: number;
  files_excluded: number;
  files_deduplicated: number;
  source_free_inputs: number;
}

export type ScanCompletion = "complete" | "partial" | "cancelled" | "failed";

export interface AnalysisResult {
  schema_version: number;
  request: AnalysisRequest;
  scanned_files: number;
  findings: Issue[];
  metrics: AuditMetrics;
  failures: ScanFailure[];
  policy: QgPolicy;
  verdict: QgVerdict;
  coverage?: ScanCoverage;
  completion?: ScanCompletion;
  pack_coverage?: PackCoverage[];
  security?: SecuritySummary;
}

/** C01: cabecera de una sesión de resultados; los findings se piden por
 * página y nunca viajan completos en una respuesta IPC. */
export interface ScanSummary {
  session_id: number;
  schema_version: number;
  request: AnalysisRequest;
  scanned_files: number;
  metrics: AuditMetrics;
  failures: ScanFailure[];
  policy: QgPolicy;
  verdict: QgVerdict;
  coverage: ScanCoverage;
  completion: ScanCompletion;
  findings_total: number;
  history_error: string | null;
  pack_coverage?: PackCoverage[];
  security?: SecuritySummary;
}

/** C01/C03: página de findings con filtros resueltos en Rust. */
export interface FindingsPage {
  session_id: number;
  offset: number;
  limit: number;
  filtered_total: number;
  total: number;
  items: Issue[];
  rules: string[];
}

/** C01: página keyset del historial. */
export interface HistoryIssuesPage {
  run_id: number;
  items: Issue[];
  next_cursor: string | null;
}

/** C02: línea de una ventana del visor con su línea física en el miembro. */
export interface SourceWindowLine {
  text: string;
  text_line: number;
  member_line: number;
}

/** C02: ventana acotada de un objeto del visor. */
export interface ObjectWindow {
  session_id: number;
  id: string;
  object_type: string;
  package: string;
  member: string;
  container_path: string;
  code_start_line: number;
  segments: ObjectSegment[];
  total_lines: number;
  window_start: number;
  window_end: number;
  lines: SourceWindowLine[];
  source_modified: boolean;
  cached: boolean;
}

export interface RuleRecord {
  id: string;
  raw_id: string;
  name: string;
  description: string;
  severity: Severity;
  category_id: string | null;
  enabled: boolean;
  is_abstract: boolean;
  triggers: string;
}

export interface Settings {
  qg_threshold_pct: number;
  max_errors: number;
  max_warnings: number;
}

export interface AuditRunSummary {
  id: number;
  file_path: string;
  file_name: string;
  started_at: string;
  total_findings: number;
  errors: number;
  warnings: number;
  info: number;
  verdict: string | null;
  policy: string | null;
  qg_passed: boolean;
  /** C01: completitud de la corrida; null en bases anteriores a V006. */
  completion?: ScanCompletion | null;
  /** C01: archivos realmente escaneados. */
  scanned_files: number;
}

export type ScanProgressEvent =
  | { status: "pending"; path: string }
  | { status: "ok"; path: string; findings_count: number }
  | { status: "error"; path: string; error: string };

export interface ObjectSegment {
  kind: string;
  text_start_line: number;
  member_start_line: number;
}

export interface ObjectSource {
  id: string;
  object_type: string;
  package: string;
  member: string;
  container_path: string;
  text: string;
  code_start_line: number;
  segments?: ObjectSegment[];
}

export interface CommandError {
  code: string;
  message: string;
}
