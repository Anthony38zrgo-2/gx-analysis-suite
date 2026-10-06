<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from "vue";

import { readHistoryObjectWindow, readObjectWindow } from "../api/client";
import { toCommandError } from "../api/errors";
import type { Issue, ObjectWindow } from "../api/types";

/** C02/C03: el visor carga ventanas acotadas y sólo renderiza esas líneas. */
const WINDOW_SIZE = 400;

const props = defineProps<{
  finding: Issue;
  /** C02: sesión aprobada del scan. */
  sessionId?: number;
  /** C04: corrida histórica; el scope son sus contenedores registrados. */
  runId?: number;
  hasPrev: boolean;
  hasNext: boolean;
}>();

const emit = defineEmits<{ close: []; prev: []; next: [] }>();

const windowData = ref<ObjectWindow | null>(null);
const error = ref<string | null>(null);
const loading = ref(false);
const scrollContainer = ref<HTMLElement | null>(null);
/** C03: latencia de navegación del visor (ms). */
const windowLatencyMs = ref<number | null>(null);
let requestGeneration = 0;

const findingTextLine = computed(() => props.finding.line_number);

const findingMemberLine = computed(() => {
  const data = windowData.value;
  if (!data) return null;
  const line = data.lines.find((item) => item.text_line === findingTextLine.value);
  if (line) return line.member_line;
  return null;
});

async function loadWindow(start?: number, end?: number) {
  const object = props.finding.object;
  if (!object) {
    error.value = "El hallazgo no tiene identidad de objeto (artefacto sin miembro).";
    return;
  }
  if (props.sessionId === undefined && props.runId === undefined) {
    error.value = "El visor requiere una sesión de scan o una corrida histórica.";
    return;
  }
  const generation = ++requestGeneration;
  loading.value = true;
  error.value = null;
  const started = performance.now();
  const target = findingTextLine.value;
  const windowStart = start ?? Math.max(1, target - Math.floor(WINDOW_SIZE / 2));
  const windowEnd = end ?? windowStart + WINDOW_SIZE - 1;
  try {
    const data: ObjectWindow =
      props.sessionId !== undefined
        ? await readObjectWindow(
            props.sessionId,
            object.container_path,
            object.member,
            object.id,
            windowStart,
            windowEnd,
          )
        : await readHistoryObjectWindow(
            props.runId as number,
            object.container_path,
            object.member,
            object.id,
            windowStart,
            windowEnd,
          );
    if (generation !== requestGeneration) return;
    windowData.value = data;
    await nextTick();
    document
      .getElementById(`source-line-${findingMemberLine.value ?? ""}`)
      ?.scrollIntoView({ block: "center" });
  } catch (e) {
    if (generation === requestGeneration) {
      error.value = toCommandError(e).message;
      windowData.value = null;
    }
  } finally {
    if (generation === requestGeneration) {
      loading.value = false;
      windowLatencyMs.value = performance.now() - started;
    }
  }
}

/** C03: al acercarse a un borde se carga la ventana adyacente (bounded). */
function onScroll() {
  const element = scrollContainer.value;
  const data = windowData.value;
  if (!element || !data || loading.value) return;
  const nearTop = element.scrollTop < 40;
  const nearBottom =
    element.scrollTop + element.clientHeight > element.scrollHeight - 40;
  if (nearTop && data.window_start > 1) {
    const end = data.window_start - 1;
    void loadWindow(Math.max(1, end - WINDOW_SIZE + 1), end);
  } else if (nearBottom && data.window_end < data.total_lines) {
    const start = data.window_end + 1;
    void loadWindow(start, Math.min(data.total_lines, start + WINDOW_SIZE - 1));
  }
}

function onWindowKeydown(event: KeyboardEvent) {
  if (event.key === "Escape") {
    event.preventDefault();
    emit("close");
  } else if (event.altKey && event.key === "ArrowLeft") {
    event.preventDefault();
    emit("prev");
  } else if (event.altKey && event.key === "ArrowRight") {
    event.preventDefault();
    emit("next");
  }
}

onMounted(() => {
  window.addEventListener("keydown", onWindowKeydown);
  void loadWindow();
});

onBeforeUnmount(() => {
  window.removeEventListener("keydown", onWindowKeydown);
});

watch(() => props.finding, () => void loadWindow());
</script>

<template>
  <div
    class="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
    @click.self="emit('close')"
  >
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="source-viewer-title"
      class="flex max-h-[90vh] w-full max-w-5xl flex-col rounded-lg border border-slate-700 bg-slate-900 shadow-xl"
    >
      <header class="flex items-start gap-3 border-b border-slate-800 p-4">
        <div class="min-w-0 flex-1">
          <h2 id="source-viewer-title" class="text-sm font-semibold">
            {{ finding.object?.id ?? "Objeto" }}
            <span class="font-normal text-slate-400">
              · {{ finding.object?.object_type }}
              · {{ finding.object?.member }}
            </span>
          </h2>
          <p class="mt-1 text-xs text-slate-400">
            <span class="font-mono">{{ finding.rule_id }}</span>
            · línea {{ findingMemberLine ?? finding.line_number }} del miembro
            · {{ finding.description }}
          </p>
          <p
            v-if="windowData"
            class="mt-1 text-[11px] text-slate-500"
            role="status"
          >
            líneas {{ windowData.window_start }}–{{ windowData.window_end }} de
            {{ windowData.total_lines }} del objeto
            <template v-if="windowLatencyMs !== null">
              · {{ windowLatencyMs.toFixed(0) }} ms
            </template>
            <template v-if="windowData.cached"> · caché</template>
            <template v-if="windowData.source_modified">
              · <span class="text-amber-300">fuente modificada desde la primera lectura</span>
            </template>
          </p>
        </div>
        <div class="flex shrink-0 items-center gap-2">
          <button
            type="button"
            class="rounded border border-slate-700 px-2 py-1 text-xs disabled:opacity-40"
            :disabled="!hasPrev"
            aria-label="Hallazgo anterior (Alt+Izquierda)"
            @click="emit('prev')"
          >
            ← Anterior
          </button>
          <button
            type="button"
            class="rounded border border-slate-700 px-2 py-1 text-xs disabled:opacity-40"
            :disabled="!hasNext"
            aria-label="Hallazgo siguiente (Alt+Derecha)"
            @click="emit('next')"
          >
            Siguiente →
          </button>
          <button
            type="button"
            class="rounded border border-slate-700 px-2 py-1 text-xs"
            aria-label="Cerrar visor (Escape)"
            @click="emit('close')"
          >
            Cerrar
          </button>
        </div>
      </header>

      <div
        ref="scrollContainer"
        class="min-h-0 flex-1 overflow-auto p-4 font-mono text-xs"
        @scroll.passive="onScroll"
      >
        <p v-if="loading" class="text-slate-400">Cargando fuente…</p>
        <p v-else-if="error" class="rounded border border-red-700 bg-red-950/40 p-3 text-red-200">
          {{ error }}
        </p>
        <template v-else-if="windowData">
          <div
            v-for="row in windowData.lines"
            :id="`source-line-${row.member_line}`"
            :key="row.text_line"
            class="flex"
            :class="
              row.text_line === findingTextLine
                ? 'bg-amber-900/40 text-amber-100'
                : 'text-slate-200'
            "
          >
            <span class="w-14 shrink-0 select-none pr-3 text-right text-slate-500">
              {{ row.member_line }}
            </span>
            <code class="whitespace-pre">{{ row.text }}</code>
          </div>
        </template>
      </div>
    </div>
  </div>
</template>
