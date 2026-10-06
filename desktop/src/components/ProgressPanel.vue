<script setup lang="ts">
import { computed } from "vue";

import type { ScanProgressEvent } from "../api/types";

const props = defineProps<{
  entries: ScanProgressEvent[];
  running: boolean;
  /** C03: contadores incrementales (no dependen de la lista acotada). */
  total: number;
  finished: number;
  failures: number;
  truncated: boolean;
}>();

const pct = computed(() =>
  props.total === 0 ? 0 : Math.round((props.finished / props.total) * 100),
);

function baseName(path: string): string {
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] ?? path;
}

function dotClass(status: ScanProgressEvent["status"]): string {
  if (status === "ok") return "bg-emerald-400";
  if (status === "error") return "bg-red-400";
  return "bg-slate-500";
}

function statusLabel(event: ScanProgressEvent): string {
  if (event.status === "ok") return `${event.findings_count} hallazgos`;
  if (event.status === "error") return event.error;
  return "pendiente";
}
</script>

<template>
  <section
    class="rounded-lg border border-slate-800 bg-slate-900 p-4"
    aria-label="Progreso del escaneo"
  >
    <div class="flex items-center justify-between gap-4">
      <h3 class="text-sm font-medium">
        Progreso
        <span class="text-slate-400">
          ({{ finished }}/{{ total }} archivos{{ failures ? `, ${failures} con fallo` : "" }})
        </span>
      </h3>
      <span class="text-xs text-slate-400">{{ pct }}%</span>
    </div>

    <div
      class="mt-2 h-1.5 w-full overflow-hidden rounded bg-slate-800"
      role="progressbar"
      :aria-valuenow="pct"
      aria-valuemin="0"
      aria-valuemax="100"
    >
      <div
        class="h-full bg-emerald-500 transition-all"
        :style="{ width: `${pct}%` }"
      />
    </div>

    <ul class="mt-3 max-h-48 space-y-1 overflow-auto text-xs" aria-live="polite">
      <li
        v-for="entry in entries"
        :key="entry.path"
        class="flex items-start gap-2"
      >
        <span
          class="mt-1 inline-block h-2 w-2 shrink-0 rounded-full"
          :class="dotClass(entry.status)"
          aria-hidden="true"
        />
        <span class="min-w-0 flex-1 truncate font-mono" :title="entry.path">
          {{ baseName(entry.path) }}
        </span>
        <span
          class="max-w-[50%] truncate"
          :class="entry.status === 'error' ? 'text-red-300' : 'text-slate-400'"
          :title="statusLabel(entry)"
        >
          {{ statusLabel(entry) }}
        </span>
      </li>
      <li v-if="entries.length === 0 && running" class="text-slate-400">
        Descubriendo archivos…
      </li>
      <li v-if="truncated" class="text-slate-500">
        … mostrando los primeros {{ entries.length }} de {{ total }} archivos.
      </li>
    </ul>
  </section>
</template>
