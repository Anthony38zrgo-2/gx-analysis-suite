import { defineStore } from "pinia";
import { computed, ref } from "vue";

import { cancelScan, scan } from "../api/client";
import { toCommandError } from "../api/errors";
import type {
  AnalysisRequest,
  AnalysisResult,
  CommandError,
  QgPolicy,
  ScanProgressEvent,
} from "../api/types";

/** Estado del escaneo en curso y del último resultado (GX-017). */
export const useScanStore = defineStore("scan", () => {
  const inputs = ref<string[]>([]);
  const usePercentage = ref(false);
  const maxErrors = ref(0);
  const maxWarnings = ref(999_999);
  const errorPct = ref(10);
  const recordHistory = ref(true);

  const running = ref(false);
  const cancelled = ref(false);
  const progress = ref<Record<string, ScanProgressEvent>>({});
  const result = ref<AnalysisResult | null>(null);
  const error = ref<CommandError | null>(null);

  const policy = computed<QgPolicy>(() =>
    usePercentage.value
      ? { kind: "percentage", max_error_pct: errorPct.value }
      : {
          kind: "absolute",
          max_errors: maxErrors.value,
          max_warnings: maxWarnings.value,
        },
  );

  const progressEntries = computed(() => Object.values(progress.value));
  const finished = computed(
    () => progressEntries.value.filter((e) => e.status !== "pending").length,
  );
  const total = computed(() => progressEntries.value.length);

  function addInputs(paths: string[]) {
    for (const path of paths) {
      if (path && !inputs.value.includes(path)) inputs.value.push(path);
    }
  }

  function removeInput(path: string) {
    inputs.value = inputs.value.filter((p) => p !== path);
  }

  async function start(enabledRuleIds: string[]): Promise<void> {
    error.value = null;
    result.value = null;
    cancelled.value = false;
    progress.value = {};

    const request: AnalysisRequest = {
      schema_version: 1,
      inputs: [...inputs.value],
      enabled_rule_ids: [...enabledRuleIds],
      policy: policy.value,
      record_history: recordHistory.value,
    };

    running.value = true;
    try {
      result.value = await scan(request, (event) => {
        progress.value = { ...progress.value, [event.path]: event };
      });
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
    progress,
    progressEntries,
    finished,
    total,
    result,
    error,
    policy,
    addInputs,
    removeInput,
    start,
    cancel,
  };
});
