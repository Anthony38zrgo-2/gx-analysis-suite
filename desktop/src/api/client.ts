import { Channel, invoke } from "@tauri-apps/api/core";

import type {
  AnalysisRequest,
  AnalysisResult,
  AuditRunSummary,
  Issue,
  ObjectSource,
  RuleRecord,
  ScanProgressEvent,
  Settings,
} from "./types";

/** GX-015: health check del puente Rust↔Vue. */
export function ping(): Promise<string> {
  return invoke<string>("ping");
}

/** GX-016: escaneo asíncrono con progreso por archivo. */
export function scan(
  request: AnalysisRequest,
  onProgress: (event: ScanProgressEvent) => void,
): Promise<AnalysisResult> {
  const channel = new Channel<ScanProgressEvent>();
  channel.onmessage = onProgress;
  return invoke<AnalysisResult>("scan", { request, onProgress: channel });
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

export function listAuditRuns(limit = 50): Promise<AuditRunSummary[]> {
  return invoke<AuditRunSummary[]>("list_audit_runs", { limit });
}

export function getAuditIssues(runId: number): Promise<Issue[]> {
  return invoke<Issue[]>("get_audit_issues", { runId });
}

export function renderTextSummary(result: AnalysisResult): Promise<string> {
  return invoke<string>("render_text_summary", { result });
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

/** GX-019: diálogo nativo + render PDF; devuelve la ruta o "" si se cancela. */
export function savePdf(result: AnalysisResult): Promise<string> {
  return invoke<string>("save_pdf", { result });
}
