<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, ref, watch } from "vue";

import type { Issue, Severity } from "../api/types";

/** C01/C03: la tabla sólo recibe la página pedida; filtros y conteos se
 * resuelven en Rust y el frontend nunca materializa el resultado completo. */
const props = defineProps<{
  items: Issue[];
  total: number;
  filteredTotal: number;
  rules: string[];
  offset: number;
  pageSize: number;
  loading: boolean;
  filters: { severity: string; ruleId: string; search: string };
  emptyMessage?: string;
}>();

const emit = defineEmits<{
  select: [issue: Issue];
  filters: [filters: { severity: string; ruleId: string; search: string }];
  page: [offset: number];
}>();

const localSearch = ref(props.filters.search);
const activeIndex = ref(-1);
let debounceTimer: ReturnType<typeof setTimeout> | null = null;

watch(
  () => props.filters.search,
  (value) => {
    if (value !== localSearch.value) localSearch.value = value;
  },
);

watch(localSearch, (value) => {
  if (debounceTimer !== null) clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    debounceTimer = null;
    emit("filters", { ...props.filters, search: value });
  }, 200);
});

onBeforeUnmount(() => {
  if (debounceTimer !== null) clearTimeout(debounceTimer);
});

const pageCount = computed(() =>
  Math.max(1, Math.ceil(props.filteredTotal / props.pageSize)),
);
const pageIndex = computed(() => Math.floor(props.offset / props.pageSize));
const rangeFrom = computed(() =>
  props.filteredTotal === 0 ? 0 : props.offset + 1,
);
const rangeTo = computed(() =>
  Math.min(props.offset + props.pageSize, props.filteredTotal),
);

watch(
  () => props.items,
  () => {
    activeIndex.value = -1;
  },
);

function rowId(index: number): string {
  return `finding-row-${props.offset}-${index}`;
}

function severityClass(severity: Severity): string {
  if (severity === "ERROR") return "bg-red-900/60 text-red-200";
  if (severity === "WARNING") return "bg-amber-900/60 text-amber-200";
  return "bg-sky-900/60 text-sky-200";
}

function changeSeverity(event: Event) {
  const value = (event.target as HTMLSelectElement).value;
  emit("filters", { ...props.filters, severity: value });
}

function changeRule(event: Event) {
  const value = (event.target as HTMLSelectElement).value;
  emit("filters", { ...props.filters, ruleId: value });
}

function previousPage() {
  emit("page", Math.max(0, props.offset - props.pageSize));
}

function nextPage() {
  emit("page", props.offset + props.pageSize);
}

function onKeydown(event: KeyboardEvent) {
  if (event.key === "j" || event.key === "ArrowDown") {
    event.preventDefault();
    activeIndex.value = Math.min(activeIndex.value + 1, props.items.length - 1);
  } else if (event.key === "k" || event.key === "ArrowUp") {
    event.preventDefault();
    activeIndex.value = Math.max(activeIndex.value - 1, 0);
  } else if (event.key === "Enter" && activeIndex.value >= 0) {
    const issue = props.items[activeIndex.value];
    if (issue) emit("select", issue);
  }
  void nextTick(() => {
    if (activeIndex.value >= 0) {
      document
        .getElementById(rowId(activeIndex.value))
        ?.scrollIntoView({ block: "nearest" });
    }
  });
}
</script>

<template>
  <section
    class="rounded-lg border border-slate-800 bg-slate-900"
    aria-label="Hallazgos"
  >
    <div class="flex flex-wrap items-center gap-3 border-b border-slate-800 p-4">
      <h3 class="text-sm font-medium">
        Hallazgos ({{ filteredTotal }}<template v-if="filteredTotal !== total">
          de {{ total }}</template
        >)
      </h3>
      <div class="ml-auto flex flex-wrap items-center gap-2 text-xs">
        <label class="sr-only" for="findings-severity">Filtrar por severidad</label>
        <select
          id="findings-severity"
          :value="filters.severity"
          class="rounded border border-slate-700 bg-slate-950 px-2 py-1"
          @change="changeSeverity"
        >
          <option value="ALL">Todas las severidades</option>
          <option value="ERROR">ERROR</option>
          <option value="WARNING">WARNING</option>
          <option value="INFO">INFO</option>
        </select>

        <label class="sr-only" for="findings-rule">Filtrar por regla</label>
        <select
          id="findings-rule"
          :value="filters.ruleId"
          class="rounded border border-slate-700 bg-slate-950 px-2 py-1"
          @change="changeRule"
        >
          <option value="ALL">Todas las reglas</option>
          <option v-for="rule in rules" :key="rule" :value="rule">
            {{ rule }}
          </option>
        </select>

        <label class="sr-only" for="findings-search">Buscar hallazgos</label>
        <input
          id="findings-search"
          v-model="localSearch"
          type="search"
          placeholder="Buscar…"
          class="w-44 rounded border border-slate-700 bg-slate-950 px-2 py-1"
        />
      </div>
    </div>

    <div
      class="max-h-[60vh] overflow-auto"
      tabindex="0"
      role="grid"
      aria-label="Tabla de hallazgos: j/k o flechas para navegar, Enter para abrir el visor"
      :aria-activedescendant="activeIndex >= 0 ? rowId(activeIndex) : undefined"
      @keydown="onKeydown"
    >
      <table class="w-full text-left text-xs">
        <thead class="sticky top-0 z-10 bg-slate-900 text-slate-400">
          <tr>
            <th class="px-4 py-2 font-medium">Severidad</th>
            <th class="px-4 py-2 font-medium">Regla</th>
            <th class="px-4 py-2 font-medium">Objeto</th>
            <th class="px-4 py-2 font-medium">Línea</th>
            <th class="px-4 py-2 font-medium">Descripción</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="(issue, index) in items"
            :id="rowId(index)"
            :key="`${issue.rule_id}-${issue.file_path}-${issue.line_number}-${index}`"
            class="cursor-pointer border-t border-slate-800/60 hover:bg-slate-800/60"
            :class="index === activeIndex ? 'bg-slate-800' : ''"
            :aria-selected="index === activeIndex"
            @click="emit('select', issue)"
          >
            <td class="px-4 py-2">
              <span
                class="rounded px-1.5 py-0.5 font-mono text-[10px]"
                :class="severityClass(issue.severity)"
              >
                {{ issue.severity }}
              </span>
            </td>
            <td class="px-4 py-2 font-mono">{{ issue.rule_id }}</td>
            <td class="max-w-[16rem] truncate px-4 py-2" :title="issue.object?.member">
              <template v-if="issue.object">
                {{ issue.object.id }}
                <span class="text-slate-400">({{ issue.object.object_type }})</span>
              </template>
              <span v-else class="text-slate-500">—</span>
            </td>
            <td class="px-4 py-2 font-mono">{{ issue.line_number }}</td>
            <td class="px-4 py-2">{{ issue.description }}</td>
          </tr>
          <tr v-if="items.length === 0">
            <td colspan="5" class="px-4 py-8 text-center text-slate-400">
              {{ loading ? "Cargando hallazgos…" : (emptyMessage ?? "Sin hallazgos para los filtros actuales.") }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div
      v-if="pageCount > 1 || filteredTotal > 0"
      class="flex items-center justify-between border-t border-slate-800 p-3 text-xs"
    >
      <button
        type="button"
        class="rounded border border-slate-700 px-3 py-1 disabled:opacity-40"
        :disabled="pageIndex === 0 || loading"
        @click="previousPage"
      >
        Anterior
      </button>
      <span>
        {{ rangeFrom }}–{{ rangeTo }} de {{ filteredTotal }}
        · página {{ pageIndex + 1 }} de {{ pageCount }}
      </span>
      <button
        type="button"
        class="rounded border border-slate-700 px-3 py-1 disabled:opacity-40"
        :disabled="pageIndex >= pageCount - 1 || loading"
        @click="nextPage"
      >
        Siguiente
      </button>
    </div>
  </section>
</template>
