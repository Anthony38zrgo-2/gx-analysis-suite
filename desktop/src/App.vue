<script setup lang="ts">
import { onMounted, ref } from "vue";

import { useRulesStore } from "./store/rules";
import { useScanStore } from "./store/scan";
import HistoryView from "./views/HistoryView.vue";
import RulesView from "./views/RulesView.vue";
import ScanView from "./views/ScanView.vue";

type Tab = "scan" | "rules" | "history";

const tabs: { id: Tab; label: string }[] = [
  { id: "scan", label: "Scan" },
  { id: "rules", label: "Reglas" },
  { id: "history", label: "Historial" },
];

const tab = ref<Tab>("scan");
const rules = useRulesStore();
const scan = useScanStore();

onMounted(() => {
  void rules.load();
});

async function rerun() {
  tab.value = "scan";
  if (scan.inputs.length > 0 && rules.enabledIds.length > 0) {
    await scan.start(rules.enabledIds);
  }
}
</script>

<template>
  <div class="flex min-h-screen flex-col bg-slate-950 text-slate-100">
    <header class="border-b border-slate-800 px-6 py-4">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 class="text-lg font-semibold tracking-wide">GX Linter</h1>
          <p class="text-xs text-slate-400">
            Análisis estático GeneXus · {{ rules.enabledCount }} reglas activas
          </p>
        </div>
        <nav role="tablist" aria-label="Secciones" class="flex gap-1">
          <button
            v-for="item in tabs"
            :key="item.id"
            type="button"
            role="tab"
            :aria-selected="tab === item.id"
            class="rounded px-3 py-1.5 text-sm transition-colors"
            :class="
              tab === item.id
                ? 'bg-slate-800 text-white'
                : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
            "
            @click="tab = item.id"
          >
            {{ item.label }}
          </button>
        </nav>
      </div>
    </header>

    <main class="mx-auto w-full max-w-6xl flex-1 p-6">
      <ScanView v-if="tab === 'scan'" @open-rules="tab = 'rules'" />
      <RulesView v-else-if="tab === 'rules'" @rerun="rerun" />
      <HistoryView v-else />
    </main>
  </div>
</template>
