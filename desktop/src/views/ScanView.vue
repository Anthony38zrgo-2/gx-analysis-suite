<script setup lang="ts">
import { computed, onMounted, ref } from "vue";

import { getSettings, pickSourceFiles, savePdf } from "../api/client";
import { toCommandError } from "../api/errors";
import ProgressPanel from "../components/ProgressPanel.vue";
import SourceViewer from "../components/SourceViewer.vue";
import { useRulesStore } from "../store/rules";
import { useScanStore } from "../store/scan";
import type { Issue, QgPolicy } from "../api/types";
import ResultsView from "./ResultsView.vue";

const emit = defineEmits<{ openRules: [] }>();

const scan = useScanStore();
const rules = useRulesStore();

const manualPath = ref("");
const localError = ref<string | null>(null);
const viewerIndex = ref<number | null>(null);
const exporting = ref(false);
const exportMessage = ref<string | null>(null);

const pageItems = computed(() => scan.page?.items ?? []);
const selectedIssue = computed(() =>
  viewerIndex.value === null ? null : (pageItems.value[viewerIndex.value] ?? null),
);

const policyLabel = computed(() => formatPolicy(scan.policy));

function formatPolicy(policy: QgPolicy): string {
  return policy.kind === "absolute"
    ? `absolute (max_errors=${policy.max_errors}, max_warnings=${policy.max_warnings})`
    : `percentage (max_error_pct=${policy.max_error_pct})`;
}

onMounted(async () => {
  try {
    const settings = await getSettings();
    scan.maxErrors = settings.max_errors;
    scan.maxWarnings = settings.max_warnings;
    scan.errorPct = settings.qg_threshold_pct;
  } catch {
    // Sin base local se usan los defaults en memoria.
  }
});

async function browse() {
  localError.value = null;
  try {
    scan.addInputs(await pickSourceFiles());
  } catch (e) {
    localError.value = toCommandError(e).message;
  }
}

function addManual() {
  const path = manualPath.value.trim();
  if (!path) return;
  scan.addInputs([path]);
  manualPath.value = "";
}

async function start() {
  localError.value = null;
  viewerIndex.value = null;
  if (scan.inputs.length === 0) {
    localError.value = "Seleccione al menos un archivo o directorio.";
    return;
  }
  if (rules.enabledIds.length === 0) {
    localError.value = "No hay reglas habilitadas: configúrelas antes de escanear.";
    return;
  }
  await scan.start(rules.enabledIds);
}

function openViewer(issue: Issue) {
  const index = pageItems.value.indexOf(issue);
  viewerIndex.value = index >= 0 ? index : null;
}

async function exportPdf() {
  const sessionId = scan.summary?.session_id;
  if (sessionId === undefined) return;
  exportMessage.value = null;
  exporting.value = true;
  try {
    const path = await savePdf(sessionId);
    exportMessage.value = path ? `PDF guardado en ${path}` : "Exportación cancelada.";
  } catch (e) {
    exportMessage.value = toCommandError(e).message;
  } finally {
    exporting.value = false;
  }
}

function moveViewer(delta: number) {
  if (viewerIndex.value === null) return;
  const next = viewerIndex.value + delta;
  if (next >= 0 && next < pageItems.value.length) viewerIndex.value = next;
}
</script>

<template>
  <div class="space-y-4">
    <section class="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <div class="flex flex-wrap items-center justify-between gap-2">
        <h2 class="text-sm font-medium">Entradas</h2>
        <div class="flex items-center gap-2">
          <button
            type="button"
            class="rounded border border-slate-700 px-3 py-1 text-xs hover:bg-slate-800"
            @click="browse"
          >
            Elegir archivos…
          </button>
          <button
            type="button"
            class="text-xs text-emerald-300 underline-offset-2 hover:underline"
            @click="emit('openRules')"
          >
            Configurar reglas ({{ rules.enabledCount }} activas)
          </button>
        </div>
      </div>

      <form class="mt-3 flex gap-2" @submit.prevent="addManual">
        <label class="sr-only" for="manual-path">Ruta de archivo o directorio</label>
        <input
          id="manual-path"
          v-model="manualPath"
          type="text"
          placeholder="Ruta manual (.xpz, .xml, .txt o directorio)"
          class="min-w-0 flex-1 rounded border border-slate-700 bg-slate-950 px-2 py-1 text-xs"
        />
        <button
          type="submit"
          class="rounded border border-slate-700 px-3 py-1 text-xs hover:bg-slate-800"
        >
          Añadir
        </button>
      </form>

      <ul v-if="scan.inputs.length > 0" class="mt-3 space-y-1">
        <li
          v-for="input in scan.inputs"
          :key="input"
          class="flex items-center gap-2 rounded bg-slate-950 px-2 py-1 text-xs"
        >
          <span class="min-w-0 flex-1 truncate font-mono" :title="input">{{ input }}</span>
          <button
            type="button"
            class="text-slate-400 hover:text-red-300"
            :aria-label="`Quitar ${input}`"
            @click="scan.removeInput(input)"
          >
            Quitar
          </button>
        </li>
      </ul>
      <p v-else class="mt-3 text-xs text-slate-400">
        Sin entradas todavía. Elija archivos o escriba una ruta.
      </p>
    </section>

    <section class="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <h2 class="text-sm font-medium">Opciones del scan</h2>
      <div class="mt-3 flex flex-wrap items-center gap-4 text-xs">
        <fieldset class="flex items-center gap-3">
          <legend class="sr-only">Política del quality gate</legend>
          <label class="flex items-center gap-1">
            <input v-model="scan.usePercentage" type="radio" :value="false" name="policy" />
            Umbrales absolutos
          </label>
          <label class="flex items-center gap-1">
            <input v-model="scan.usePercentage" type="radio" :value="true" name="policy" />
            Porcentaje de errores (GUI legada)
          </label>
        </fieldset>

        <template v-if="!scan.usePercentage">
          <label class="flex items-center gap-1">
            Máx. errores
            <input
              v-model.number="scan.maxErrors"
              type="number"
              min="0"
              class="w-20 rounded border border-slate-700 bg-slate-950 px-2 py-1"
            />
          </label>
          <label class="flex items-center gap-1">
            Máx. warnings
            <input
              v-model.number="scan.maxWarnings"
              type="number"
              min="0"
              class="w-24 rounded border border-slate-700 bg-slate-950 px-2 py-1"
            />
          </label>
        </template>
        <label v-else class="flex items-center gap-1">
          Máx. % errores
          <input
            v-model.number="scan.errorPct"
            type="number"
            min="0"
            max="100"
            class="w-20 rounded border border-slate-700 bg-slate-950 px-2 py-1"
          />
        </label>

        <label class="flex items-center gap-1">
          <input v-model="scan.recordHistory" type="checkbox" />
          Guardar en historial
        </label>
      </div>

      <div class="mt-4 flex items-center gap-3">
        <button
          type="button"
          class="rounded bg-emerald-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
          :disabled="scan.running"
          @click="start"
        >
          {{ scan.running ? "Escaneando…" : "Iniciar análisis" }}
        </button>
        <button
          v-if="scan.running"
          type="button"
          class="rounded border border-red-600 px-4 py-1.5 text-sm text-red-200 hover:bg-red-950/40"
          @click="scan.cancel"
        >
          Cancelar
        </button>
        <span v-if="scan.cancelled" class="text-xs text-amber-300">
          Cancelación solicitada…
        </span>
      </div>
    </section>

    <p
      v-if="localError || scan.error"
      class="rounded border border-red-700 bg-red-950/40 px-4 py-3 text-sm text-red-200"
      role="alert"
    >
      {{ localError ?? scan.error?.message }}
    </p>

    <ProgressPanel
      v-if="scan.running || scan.progressEntries.length > 0"
      :entries="scan.progressEntries"
      :running="scan.running"
      :total="scan.total"
      :finished="scan.finished"
      :failures="scan.progressFailures"
      :truncated="scan.progressTruncated"
    />

    <ResultsView
      v-if="scan.summary"
      :metrics="scan.summary.metrics"
      :verdict="scan.summary.verdict"
      :policy-label="policyLabel"
      :failures="scan.summary.failures"
      :scanned-files="scan.summary.scanned_files"
      :page="scan.page"
      :loading="scan.pageLoading"
      :filters="scan.filters"
      :history-error="scan.summary.history_error"
      :completion="scan.summary.completion"
      @select="openViewer"
      @filters="scan.setFilters"
      @page="scan.goToPage"
    >
      <template #actions>
        <button
          type="button"
          class="rounded border border-slate-600 px-3 py-1 text-xs hover:bg-slate-800/60 disabled:opacity-50"
          :disabled="exporting"
          @click="exportPdf"
        >
          {{ exporting ? "Generando PDF…" : "Exportar PDF" }}
        </button>
        <button
          type="button"
          class="rounded border border-slate-600 px-3 py-1 text-xs hover:bg-slate-800/60"
          :disabled="scan.running"
          @click="start"
        >
          Re-escanear
        </button>
      </template>
    </ResultsView>

    <p
      v-if="exportMessage"
      class="text-xs text-slate-300"
      role="status"
      aria-live="polite"
    >
      {{ exportMessage }}
    </p>

    <SourceViewer
      v-if="selectedIssue"
      :finding="selectedIssue"
      :session-id="scan.summary?.session_id"
      :has-prev="(viewerIndex ?? 0) > 0"
      :has-next="(viewerIndex ?? 0) < pageItems.length - 1"
      @close="viewerIndex = null"
      @prev="moveViewer(-1)"
      @next="moveViewer(1)"
    />
  </div>
</template>
