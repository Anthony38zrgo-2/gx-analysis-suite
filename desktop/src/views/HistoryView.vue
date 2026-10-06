<script setup lang="ts">
import { computed, onMounted, ref } from "vue";

import { getAuditIssuesPage, listAuditRuns } from "../api/client";
import { toCommandError } from "../api/errors";
import SourceViewer from "../components/SourceViewer.vue";
import type { AuditRunSummary, FindingsPage, Issue, QgVerdict } from "../api/types";
import ResultsView from "./ResultsView.vue";

const RUNS_PAGE = 50;
const ISSUES_PAGE = 100;

const runs = ref<AuditRunSummary[]>([]);
const loading = ref(false);
const loadingMoreRuns = ref(false);
const error = ref<string | null>(null);

const selected = ref<AuditRunSummary | null>(null);
const issues = ref<Issue[]>([]);
const nextCursor = ref<string | null>(null);
const loadingIssues = ref(false);
const viewerIndex = ref<number | null>(null);
const filters = ref({ severity: "ALL", ruleId: "ALL", search: "" });

const metrics = computed(() => ({
  total_findings: selected.value?.total_findings ?? 0,
  errors: selected.value?.errors ?? 0,
  warnings: selected.value?.warnings ?? 0,
  info: selected.value?.info ?? 0,
}));

const verdict = computed<QgVerdict | null>(() => {
  const value = selected.value?.verdict;
  return value === "pass" || value === "reject" || value === "error" ? value : null;
});

const policyLabel = computed(() => selected.value?.policy ?? "n/d");

/** C03: filtros client-side sobre las páginas cargadas del historial. */
const filteredIssues = computed(() => {
  const term = filters.value.search.trim().toLowerCase();
  return issues.value.filter((issue) => {
    if (filters.value.severity !== "ALL" && issue.severity !== filters.value.severity) {
      return false;
    }
    if (filters.value.ruleId !== "ALL" && issue.rule_id !== filters.value.ruleId) {
      return false;
    }
    if (term) {
      const object = issue.object
        ? `${issue.object.id} ${issue.object.object_type} ${issue.object.member}`
        : "";
      const haystack = `${issue.rule_id} ${issue.description} ${object}`.toLowerCase();
      if (!haystack.includes(term)) return false;
    }
    return true;
  });
});

const historyPage = computed<FindingsPage | null>(() => {
  if (!selected.value) return null;
  const rules = Array.from(new Set(issues.value.map((issue) => issue.rule_id))).sort();
  return {
    session_id: 0,
    offset: 0,
    limit: Math.max(1, filteredIssues.value.length),
    filtered_total: filteredIssues.value.length,
    total: selected.value.total_findings,
    items: filteredIssues.value,
    rules,
  };
});

const selectedIssue = computed(() =>
  viewerIndex.value === null ? null : (filteredIssues.value[viewerIndex.value] ?? null),
);

async function loadRuns(beforeId?: number) {
  if (beforeId === undefined) loading.value = true;
  else loadingMoreRuns.value = true;
  error.value = null;
  try {
    const page = await listAuditRuns(beforeId, RUNS_PAGE);
    runs.value = beforeId === undefined ? page : [...runs.value, ...page];
  } catch (e) {
    error.value = toCommandError(e).message;
  } finally {
    loading.value = false;
    loadingMoreRuns.value = false;
  }
}

async function loadIssuesPage(cursor?: string) {
  if (!selected.value) return;
  loadingIssues.value = true;
  error.value = null;
  try {
    const page = await getAuditIssuesPage(selected.value.id, cursor, ISSUES_PAGE);
    issues.value = cursor === undefined ? page.items : [...issues.value, ...page.items];
    nextCursor.value = page.next_cursor;
  } catch (e) {
    error.value = toCommandError(e).message;
  } finally {
    loadingIssues.value = false;
  }
}

async function openRun(run: AuditRunSummary) {
  selected.value = run;
  issues.value = [];
  nextCursor.value = null;
  viewerIndex.value = null;
  filters.value = { severity: "ALL", ruleId: "ALL", search: "" };
  await loadIssuesPage();
}

function backToList() {
  selected.value = null;
  issues.value = [];
  nextCursor.value = null;
  viewerIndex.value = null;
}

function setFilters(next: { severity: string; ruleId: string; search: string }) {
  filters.value = next;
}

function openViewer(issue: Issue) {
  const index = filteredIssues.value.indexOf(issue);
  viewerIndex.value = index >= 0 ? index : null;
}

function moveViewer(delta: number) {
  if (viewerIndex.value === null) return;
  const next = viewerIndex.value + delta;
  if (next >= 0 && next < filteredIssues.value.length) viewerIndex.value = next;
}

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

onMounted(() => void loadRuns());
</script>

<template>
  <div class="space-y-4" data-testid="history-view">
    <section class="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <div class="flex items-center justify-between gap-2">
        <h2 class="text-sm font-medium">Historial de auditorías</h2>
        <button
          v-if="!selected"
          type="button"
          class="rounded border border-slate-700 px-3 py-1 text-xs hover:bg-slate-800"
          @click="loadRuns()"
        >
          Recargar
        </button>
        <button
          v-else
          type="button"
          class="rounded border border-slate-700 px-3 py-1 text-xs hover:bg-slate-800"
          @click="backToList"
        >
          ← Volver al historial
        </button>
      </div>
      <p class="mt-1 text-xs text-slate-400">
        Las corridas se guardan en la base local cuando «Guardar en historial» está activo
        (retención: las más recientes).
      </p>
    </section>

    <p
      v-if="error"
      class="rounded border border-red-700 bg-red-950/40 px-4 py-3 text-sm text-red-200"
      role="alert"
    >
      {{ error }}
    </p>

    <template v-if="!selected">
      <section class="rounded-lg border border-slate-800 bg-slate-900">
        <p v-if="loading" class="p-6 text-sm text-slate-400" aria-live="polite">
          Cargando historial…
        </p>
        <p v-else-if="runs.length === 0" class="p-6 text-sm text-slate-400">
          Todavía no hay auditorías registradas.
        </p>
        <template v-else>
          <table class="w-full text-left text-xs">
            <thead class="border-b border-slate-800 text-slate-400">
              <tr>
                <th class="px-4 py-2 font-medium">Fecha</th>
                <th class="px-4 py-2 font-medium">Entrada</th>
                <th class="px-4 py-2 font-medium">Hallazgos</th>
                <th class="px-4 py-2 font-medium">E/W</th>
                <th class="px-4 py-2 font-medium">Veredicto</th>
                <th class="px-4 py-2 font-medium" />
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="run in runs"
                :key="run.id"
                class="border-t border-slate-800/60"
              >
                <td class="px-4 py-2 whitespace-nowrap">{{ formatDate(run.started_at) }}</td>
                <td class="max-w-[20rem] truncate px-4 py-2" :title="run.file_path">
                  {{ run.file_name }}
                </td>
                <td class="px-4 py-2 font-mono">{{ run.total_findings }}</td>
                <td class="px-4 py-2 font-mono">{{ run.errors }}/{{ run.warnings }}</td>
                <td class="px-4 py-2">
                  <span
                    class="rounded px-1.5 py-0.5 font-mono text-[10px]"
                    :class="
                      run.verdict === 'pass'
                        ? 'bg-emerald-900/60 text-emerald-200'
                        : run.verdict === 'reject' || run.verdict === 'error'
                          ? 'bg-red-900/60 text-red-200'
                          : 'bg-slate-800 text-slate-300'
                    "
                  >
                    {{ run.verdict ?? "n/d" }}
                  </span>
                </td>
                <td class="px-4 py-2 text-right">
                  <button
                    type="button"
                    class="rounded border border-slate-700 px-2 py-1 hover:bg-slate-800"
                    @click="openRun(run)"
                  >
                    Ver hallazgos
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
          <div class="border-t border-slate-800 p-3 text-center">
            <button
              type="button"
              class="rounded border border-slate-700 px-3 py-1 text-xs hover:bg-slate-800 disabled:opacity-40"
              :disabled="loadingMoreRuns || runs.length < RUNS_PAGE"
              @click="loadRuns(runs[runs.length - 1]?.id)"
            >
              {{ loadingMoreRuns ? "Cargando…" : "Cargar más" }}
            </button>
          </div>
        </template>
      </section>
    </template>

    <template v-else>
      <p v-if="loadingIssues" class="text-sm text-slate-400" aria-live="polite">
        Cargando hallazgos de la corrida…
      </p>
      <template v-else>
        <ResultsView
          :metrics="metrics"
          :verdict="verdict"
          :policy-label="policyLabel"
          :failures="[]"
          :scanned-files="1"
          :page="historyPage"
          :loading="false"
          :filters="filters"
          @select="openViewer"
          @filters="setFilters"
          @page="() => {}"
        />
        <div v-if="nextCursor" class="text-center">
          <button
            type="button"
            class="rounded border border-slate-700 px-3 py-1 text-xs hover:bg-slate-800 disabled:opacity-40"
            :disabled="loadingIssues"
            @click="loadIssuesPage(nextCursor)"
          >
            Cargar más hallazgos
          </button>
        </div>
      </template>
    </template>

    <SourceViewer
      v-if="selectedIssue"
      :finding="selectedIssue"
      :run-id="selected?.id"
      :has-prev="(viewerIndex ?? 0) > 0"
      :has-next="(viewerIndex ?? 0) < filteredIssues.length - 1"
      @close="viewerIndex = null"
      @prev="moveViewer(-1)"
      @next="moveViewer(1)"
    />
  </div>
</template>
