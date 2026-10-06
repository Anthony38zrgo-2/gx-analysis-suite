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

export interface AnalysisRequest {
  schema_version: number;
  inputs: string[];
  enabled_rule_ids: string[];
  policy: QgPolicy;
  record_history: boolean;
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
