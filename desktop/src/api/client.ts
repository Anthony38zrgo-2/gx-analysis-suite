import { Channel, invoke } from "@tauri-apps/api/core";

import type {
  AnalysisRequest,
  AuditRunSummary,
  FindingsPage,
  HistoryIssuesPage,
  ObjectSource,
  ObjectWindow,
  RuleRecord,
  ScanProgressEvent,
  ScanSummary,
  Settings,
} from "./types";

/** GX-015: health check del puente Rust↔Vue. */
export function ping(): Promise<string> {
  return invoke<string>("ping");
}

/** GX-016/C01: escaneo asíncrono con progreso; devuelve el resumen de la
 * sesión (los findings se piden por `getFindingsPage`). */
export function scan(
  request: AnalysisRequest,
  onProgress: (event: ScanProgressEvent) => void,
): Promise<ScanSummary> {
  const channel = new Channel<ScanProgressEvent>();
  channel.onmessage = onProgress;
  return invoke<ScanSummary>("scan", { request, onProgress: channel });
}

export function cancelScan(): Promise<boolean> {
  return invoke<boolean>("cancel_scan");
}

export function pickSourceFiles(): Promise<string[]> {
  return invoke<string[]>("pick_source_files");
}

export function listRules(rulesCsv?: string): Promise<RuleRecord[]> {
  return invoke<RuleRecord[]>("list_rules", { rulesCsv: rulesCsv ?? null });
}

export function setRuleEnabled(id: string, enabled: boolean): Promise<void> {
  return invoke<void>("set_rule_enabled", { id, enabled });
}

export function getSettings(): Promise<Settings> {
  return invoke<Settings>("get_settings");
}

export function setSettings(settings: Settings): Promise<void> {
  return invoke<void>("set_settings", { settings });
}

/** C01: página de findings de una sesión con filtros server-side. */
export function getFindingsPage(
  sessionId: number,
  options: {
    offset?: number;
    limit?: number;
    severity?: string;
    ruleId?: string;
    search?: string;
  } = {},
): Promise<FindingsPage> {
  return invoke<FindingsPage>("get_findings_page", {
    sessionId,
    offset: options.offset ?? null,
    limit: options.limit ?? null,
    severity: options.severity ?? null,
    ruleId: options.ruleId ?? null,
    search: options.search ?? null,
  });
}

/** C01: historial con paginación keyset. */
export function listAuditRuns(beforeId?: number, limit = 50): Promise<AuditRunSummary[]> {
  return invoke<AuditRunSummary[]>("list_audit_runs", {
    beforeId: beforeId ?? null,
    limit,
  });
}

export function getAuditIssuesPage(
  runId: number,
  cursor?: string,
  limit = 100,
): Promise<HistoryIssuesPage> {
  return invoke<HistoryIssuesPage>("get_audit_issues_page", {
    runId,
    cursor: cursor ?? null,
    limit,
  });
}

export function renderTextSummary(sessionId: number): Promise<string> {
  return invoke<string>("render_text_summary", { sessionId });
}

export function readObjectSource(
  containerPath: string,
  member: string,
  id?: string,
): Promise<ObjectSource> {
  return invoke<ObjectSource>("read_object_source", {
    containerPath,
    member,
    id: id ?? null,
  });
}

/** C02: ventana acotada del visor, validada contra la sesión aprobada. */
export function readObjectWindow(
  sessionId: number,
  containerPath: string,
  member: string,
  id: string,
  startLine?: number,
  endLine?: number,
): Promise<ObjectWindow> {
  return invoke<ObjectWindow>("read_object_window", {
    sessionId,
    containerPath,
    member,
    id,
    startLine: startLine ?? null,
    endLine: endLine ?? null,
  });
}

/** C04: ventana histórica, limitada a los contenedores registrados por la
 * corrida (nunca un path arbitrario). */
export function readHistoryObjectWindow(
  runId: number,
  containerPath: string,
  member: string,
  id: string,
  startLine?: number,
  endLine?: number,
): Promise<ObjectWindow> {
  return invoke<ObjectWindow>("read_history_object_window", {
    runId,
    containerPath,
    member,
    id,
    startLine: startLine ?? null,
    endLine: endLine ?? null,
  });
}

/** GX-019/C01: exporta la sesión a PDF; devuelve la ruta o "" si se cancela. */
export function savePdf(sessionId: number): Promise<string> {
  return invoke<string>("save_pdf", { sessionId });
}
