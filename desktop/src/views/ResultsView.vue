<script setup lang="ts">
import { computed } from "vue";

import FailuresPanel from "../components/FailuresPanel.vue";
import FindingsTable from "../components/FindingsTable.vue";
import type {
  AuditMetrics,
  FindingsPage,
  Issue,
  QgVerdict,
  ScanCompletion,
  ScanFailure,
} from "../api/types";

const props = defineProps<{
  metrics: AuditMetrics;
  verdict: QgVerdict | null;
  policyLabel: string;
  failures: ScanFailure[];
  scannedFiles: number;
  page: FindingsPage | null;
  loading: boolean;
  filters: { severity: string; ruleId: string; search: string };
  historyError?: string | null;
  completion?: ScanCompletion | null;
}>();

const emit = defineEmits<{
  select: [issue: Issue];
  filters: [filters: { severity: string; ruleId: string; search: string }];
  page: [offset: number];
}>();

const banner = computed(() => {
  switch (props.verdict) {
    case "pass":
      return {
        label: "APROBADO PARA DESPLIEGUE",
        classes: "border-emerald-600 bg-emerald-950/40 text-emerald-200",
      };
    case "reject":
      return {
        label: "RECHAZADO",
        classes: "border-red-600 bg-red-950/40 text-red-200",
      };
    case "error":
      return {
        label: "ERROR DE SCAN — resultado no confiable",
        classes: "border-red-600 bg-red-950/40 text-red-200",
      };
    default:
      return {
        label: "SIN VEREDICTO",
        classes: "border-slate-700 bg-slate-900 text-slate-300",
      };
  }
});

const completionLabel = computed(() => {
  if (props.completion === "partial") return "Resultado PARCIAL: se alcanzó un límite de recursos.";
  if (props.completion === "cancelled") return "Escaneo CANCELADO: cobertura incompleta.";
  if (props.completion === "failed") return "Escaneo FALLIDO: revise los fallos.";
  return null;
});

const cards = computed(() => [
  { label: "Hallazgos", value: props.metrics.total_findings },
  { label: "Errores", value: props.metrics.errors },
  { label: "Warnings", value: props.metrics.warnings },
  { label: "Info", value: props.metrics.info },
  { label: "Archivos", value: props.scannedFiles },
]);
</script>

<template>
  <div class="space-y-4" data-testid="results-view">
    <div
      class="flex flex-wrap items-center justify-between gap-3 rounded-lg border px-4 py-3 text-sm font-semibold"
      :class="banner.classes"
    >
      <span role="status">
        {{ banner.label }}
        <span class="ml-2 font-normal opacity-80">(política {{ policyLabel }})</span>
      </span>
      <span class="flex items-center gap-2 font-normal">
        <slot name="actions" />
      </span>
    </div>

    <p
      v-if="completionLabel"
      class="rounded border border-amber-700 bg-amber-950/30 px-4 py-2 text-xs text-amber-200"
      role="status"
    >
      {{ completionLabel }}
    </p>

    <p
      v-if="historyError"
      class="rounded border border-amber-700 bg-amber-950/30 px-4 py-2 text-xs text-amber-200"
      role="status"
    >
      Los hallazgos se calcularon correctamente, pero no se pudo guardar el
      historial: {{ historyError }}
    </p>

    <div class="grid grid-cols-2 gap-3 sm:grid-cols-5">
      <div
        v-for="card in cards"
        :key="card.label"
        class="rounded-lg border border-slate-800 bg-slate-900 p-3"
      >
        <div class="text-xs text-slate-400">{{ card.label }}</div>
        <div class="mt-1 text-xl font-semibold">{{ card.value }}</div>
      </div>
    </div>

    <FailuresPanel :failures="failures" />

    <FindingsTable
      :items="page?.items ?? []"
      :total="page?.total ?? 0"
      :filtered-total="page?.filtered_total ?? 0"
      :rules="page?.rules ?? []"
      :offset="page?.offset ?? 0"
      :page-size="page?.limit ?? 100"
      :loading="loading"
      :filters="filters"
      empty-message="Sin hallazgos: el resultado está limpio."
      @select="emit('select', $event)"
      @filters="emit('filters', $event)"
      @page="emit('page', $event)"
    />
  </div>
</template>
