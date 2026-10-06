import { defineStore } from "pinia";
import { computed, reactive, ref } from "vue";

import { cancelScan, getFindingsPage, scan } from "../api/client";
import { toCommandError } from "../api/errors";
import type {
  AnalysisRequest,
  CommandError,
  FindingsPage,
  QgPolicy,
  ScanProgressEvent,
  ScanSummary,
} from "../api/types";

/** C03: el progreso visible se acota y se aplica en lote. */
const PROGRESS_LIMIT = 1000;
const PROGRESS_FLUSH_MS = 50;
/** C03: tamaño de página de findings (server-side). */
export const FINDINGS_PAGE_SIZE = 100;

/** Estado del escaneo en curso y de la sesión de resultados (GX-017/C01). */
export const useScanStore = defineStore("scan", () => {
  const inputs = ref<string[]>([]);
  const usePercentage = ref(false);
  const maxErrors = ref(0);
  const maxWarnings = ref(999_999);
  const errorPct = ref(10);
  const recordHistory = ref(true);

  const running = ref(false);
  const cancelled = ref(false);
  const error = ref<CommandError | null>(null);

  // C01: resumen + página de findings (los findings completos viven en Rust).
  const summary = ref<ScanSummary | null>(null);
  const page = ref<FindingsPage | null>(null);
  const pageLoading = ref(false);
  /** C03: telemetría local de página/filtros (ms) y heap best-effort. */
  const pageLatencyMs = ref<number | null>(null);
  const lastHeapBytes = ref<number | null>(null);
  const filters = reactive<{
    severity: string;
    ruleId: string;
    search: string;
  }>({ severity: "ALL", ruleId: "ALL", search: "" });
  let pageGeneration = 0;

  // C03: progreso acotado, contadores incrementales y flush por lote.
  const progress = reactive(new Map<string, ScanProgressEvent>());
  const progressTotal = ref(0);
  const progressFinished = ref(0);
  const progressFailures = ref(0);
  let pending: ScanProgressEvent[] = [];
  let flushTimer: ReturnType<typeof setTimeout> | null = null;

  const policy = computed<QgPolicy>(() =>
    usePercentage.value
      ? { kind: "percentage", max_error_pct: errorPct.value }
      : {
          kind: "absolute",
          max_errors: maxErrors.value,
          max_warnings: maxWarnings.value,
        },
  );

  const progressEntries = computed(() => Array.from(progress.values()));
  const progressTruncated = computed(() => progressTotal.value > progress.size);
  const progressPct = computed(() =>
    progressTotal.value === 0
      ? 0
      : Math.round((progressFinished.value * 100) / progressTotal.value),
  );
  const finished = computed(() => progressFinished.value);
  const total = computed(() => progressTotal.value);

  function applyProgress(event: ScanProgressEvent) {
    if (event.status === "pending") {
      progressTotal.value += 1;
    } else {
      progressFinished.value += 1;
      if (event.status === "error") progressFailures.value += 1;
    }
    if (progress.has(event.path) || progress.size < PROGRESS_LIMIT) {
      progress.set(event.path, event);
    }
  }

  function queueProgress(event: ScanProgressEvent) {
    pending.push(event);
    if (flushTimer === null) {
      flushTimer = setTimeout(() => {
        flushTimer = null;
        const batch = pending;
        pending = [];
        for (const item of batch) applyProgress(item);
      }, PROGRESS_FLUSH_MS);
    }
  }

  function flushProgressNow() {
    if (flushTimer !== null) {
      clearTimeout(flushTimer);
      flushTimer = null;
    }
    const batch = pending;
    pending = [];
    for (const item of batch) applyProgress(item);
  }

  function resetProgress() {
    flushProgressNow();
    progress.clear();
    progressTotal.value = 0;
    progressFinished.value = 0;
    progressFailures.value = 0;
  }

  function addInputs(paths: string[]) {
    for (const path of paths) {
      if (path && !inputs.value.includes(path)) inputs.value.push(path);
    }
  }

  function removeInput(path: string) {
    inputs.value = inputs.value.filter((p) => p !== path);
  }

  /** C03: filtros con guard de generación (respuestas viejas no pisan la
   * selección nueva). */
  async function fetchFindings(offset = 0): Promise<void> {
    const current = summary.value;
    if (!current) return;
    const generation = ++pageGeneration;
    pageLoading.value = true;
    const started = performance.now();
    try {
      const result = await getFindingsPage(current.session_id, {
        offset,
        limit: FINDINGS_PAGE_SIZE,
        severity: filters.severity === "ALL" ? undefined : filters.severity,
        ruleId: filters.ruleId === "ALL" ? undefined : filters.ruleId,
        search: filters.search.trim() || undefined,
      });
      if (generation === pageGeneration) page.value = result;
    } catch (e) {
      if (generation === pageGeneration) error.value = toCommandError(e);
    } finally {
      if (generation === pageGeneration) {
        pageLoading.value = false;
        pageLatencyMs.value = performance.now() - started;
        const memory = (
          performance as unknown as { memory?: { usedJSHeapSize: number } }
        ).memory;
        lastHeapBytes.value = memory ? memory.usedJSHeapSize : null;
      }
    }
  }

  function setFilters(next: Partial<{ severity: string; ruleId: string; search: string }>) {
    Object.assign(filters, next);
    void fetchFindings(0);
  }

  function goToPage(offset: number) {
    void fetchFindings(offset);
  }

  async function start(enabledRuleIds: string[]): Promise<void> {
    error.value = null;
    summary.value = null;
    page.value = null;
    cancelled.value = false;
    resetProgress();
    pageGeneration += 1; // invalida fetches en vuelo del scan anterior

    const request: AnalysisRequest = {
      schema_version: 1,
      inputs: [...inputs.value],
      enabled_rule_ids: [...enabledRuleIds],
      policy: policy.value,
      record_history: recordHistory.value,
    };

    running.value = true;
    try {
      summary.value = await scan(request, queueProgress);
      flushProgressNow();
      if (summary.value) await fetchFindings(0);
    } catch (e) {
      error.value = toCommandError(e);
    } finally {
      running.value = false;
    }
  }

  async function cancel(): Promise<void> {
    cancelled.value = true;
    try {
      await cancelScan();
    } catch (e) {
      error.value = toCommandError(e);
    }
  }

  return {
    inputs,
    usePercentage,
    maxErrors,
    maxWarnings,
    errorPct,
    recordHistory,
    running,
    cancelled,
    error,
    summary,
    page,
    pageLoading,
    pageLatencyMs,
    lastHeapBytes,
    filters,
    progressEntries,
    progressTruncated,
    progressPct,
    progressFailures,
    finished,
    total,
    policy,
    addInputs,
    removeInput,
    fetchFindings,
    setFilters,
    goToPage,
    start,
    cancel,
  };
});
