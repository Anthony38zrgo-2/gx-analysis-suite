<script setup lang="ts">
import { computed, nextTick, ref, watch } from "vue";

import type { Issue, Severity } from "../api/types";

const props = defineProps<{
  findings: Issue[];
  emptyMessage?: string;
}>();

const emit = defineEmits<{ select: [issue: Issue] }>();

const PAGE_SIZE = 100;

const severityFilter = ref<"ALL" | Severity>("ALL");
const ruleFilter = ref("ALL");
const search = ref("");
const page = ref(0);
const activeIndex = ref(-1);

const rules = computed(() =>
  Array.from(new Set(props.findings.map((f) => f.rule_id))).sort(),
);

const filtered = computed(() => {
  const term = search.value.trim().toLowerCase();
  return props.findings.filter((issue) => {
    if (severityFilter.value !== "ALL" && issue.severity !== severityFilter.value) {
      return false;
    }
    if (ruleFilter.value !== "ALL" && issue.rule_id !== ruleFilter.value) {
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

const pageCount = computed(() =>
  Math.max(1, Math.ceil(filtered.value.length / PAGE_SIZE)),
);

const visible = computed(() =>
  filtered.value.slice(page.value * PAGE_SIZE, (page.value + 1) * PAGE_SIZE),
);

watch([severityFilter, ruleFilter, search], () => {
  page.value = 0;
});

watch([visible, pageCount], () => {
  if (activeIndex.value >= visible.value.length) {
    activeIndex.value = visible.value.length - 1;
  }
});

function rowId(index: number): string {
  return `finding-row-${page.value}-${index}`;
}

function severityClass(severity: Severity): string {
  if (severity === "ERROR") return "bg-red-900/60 text-red-200";
  if (severity === "WARNING") return "bg-amber-900/60 text-amber-200";
  return "bg-sky-900/60 text-sky-200";
}

function onKeydown(event: KeyboardEvent) {
  if (event.key === "j" || event.key === "ArrowDown") {
    event.preventDefault();
    activeIndex.value = Math.min(activeIndex.value + 1, visible.value.length - 1);
  } else if (event.key === "k" || event.key === "ArrowUp") {
    event.preventDefault();
    activeIndex.value = Math.max(activeIndex.value - 1, 0);
  } else if (event.key === "Enter" && activeIndex.value >= 0) {
    const issue = visible.value[activeIndex.value];
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
      <h3 class="text-sm font-medium">Hallazgos ({{ filtered.length }})</h3>
      <div class="ml-auto flex flex-wrap items-center gap-2 text-xs">
        <label class="sr-only" for="findings-severity">Filtrar por severidad</label>
        <select
          id="findings-severity"
          v-model="severityFilter"
          class="rounded border border-slate-700 bg-slate-950 px-2 py-1"
        >
          <option value="ALL">Todas las severidades</option>
          <option value="ERROR">ERROR</option>
          <option value="WARNING">WARNING</option>
          <option value="INFO">INFO</option>
        </select>

        <label class="sr-only" for="findings-rule">Filtrar por regla</label>
        <select
          id="findings-rule"
          v-model="ruleFilter"
          class="rounded border border-slate-700 bg-slate-950 px-2 py-1"
        >
          <option value="ALL">Todas las reglas</option>
          <option v-for="rule in rules" :key="rule" :value="rule">
            {{ rule }}
          </option>
        </select>

        <label class="sr-only" for="findings-search">Buscar hallazgos</label>
        <input
          id="findings-search"
          v-model="search"
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
            v-for="(issue, index) in visible"
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
          <tr v-if="visible.length === 0">
            <td colspan="5" class="px-4 py-8 text-center text-slate-400">
              {{ emptyMessage ?? "Sin hallazgos para los filtros actuales." }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div
      v-if="pageCount > 1"
      class="flex items-center justify-between border-t border-slate-800 p-3 text-xs"
    >
      <button
        type="button"
        class="rounded border border-slate-700 px-3 py-1 disabled:opacity-40"
        :disabled="page === 0"
        @click="page -= 1"
      >
        Anterior
      </button>
      <span>Página {{ page + 1 }} de {{ pageCount }}</span>
      <button
        type="button"
        class="rounded border border-slate-700 px-3 py-1 disabled:opacity-40"
        :disabled="page >= pageCount - 1"
        @click="page += 1"
      >
        Siguiente
      </button>
    </div>
  </section>
</template>
