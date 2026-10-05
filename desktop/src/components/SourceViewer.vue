<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from "vue";

import { readObjectSource } from "../api/client";
import { toCommandError } from "../api/errors";
import type { Issue, ObjectSegment, ObjectSource } from "../api/types";

const props = defineProps<{
  finding: Issue;
  hasPrev: boolean;
  hasNext: boolean;
}>();

const emit = defineEmits<{ close: []; prev: []; next: [] }>();

const source = ref<ObjectSource | null>(null);
const error = ref<string | null>(null);
const loading = ref(false);

const lines = computed(() => source.value?.text.split(/\r?\n/) ?? []);

/**
 * Línea real del miembro para una línea 1-based del texto extraído (A03).
 * Con segmentos, cada sección (Events/Rules/Subroutines) mapea a su línea
 * física; sin segmentos se usa el offset legacy.
 */
function toMemberLine(textLine: number): number {
  const segments = source.value?.segments ?? [];
  let active: ObjectSegment | undefined;
  for (const segment of segments) {
    if (textLine >= segment.text_start_line) active = segment;
  }
  if (active) {
    return active.member_start_line + (textLine - active.text_start_line);
  }
  const base = source.value?.code_start_line ?? 1;
  return base + textLine - 1;
}

const memberLine = computed(() => toMemberLine(props.finding.line_number));

const rows = computed(() =>
  lines.value.map((text, index) => ({
    text,
    member: toMemberLine(index + 1),
  })),
);

async function load() {
  source.value = null;
  error.value = null;
  const object = props.finding.object;
  if (!object) {
    error.value = "El hallazgo no tiene identidad de objeto (artefacto sin miembro).";
    return;
  }
  loading.value = true;
  try {
    source.value = await readObjectSource(
      object.container_path,
      object.member,
      object.id,
    );
    await nextTick();
    document
      .getElementById(`source-line-${memberLine.value}`)
      ?.scrollIntoView({ block: "center" });
  } catch (e) {
    error.value = toCommandError(e).message;
  } finally {
    loading.value = false;
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
  void load();
});

onBeforeUnmount(() => {
  window.removeEventListener("keydown", onWindowKeydown);
});

watch(() => props.finding, () => void load());
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
            · línea {{ memberLine }} del miembro
            · {{ finding.description }}
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

      <div class="min-h-0 flex-1 overflow-auto p-4 font-mono text-xs">
        <p v-if="loading" class="text-slate-400">Cargando fuente…</p>
        <p v-else-if="error" class="rounded border border-red-700 bg-red-950/40 p-3 text-red-200">
          {{ error }}
        </p>
        <template v-else-if="source">
          <div
            v-for="row in rows"
            :id="`source-line-${row.member}`"
            :key="row.member"
            class="flex"
            :class="
              row.member === memberLine
                ? 'bg-amber-900/40 text-amber-100'
                : 'text-slate-200'
            "
          >
            <span class="w-14 shrink-0 select-none pr-3 text-right text-slate-500">
              {{ row.member }}
            </span>
            <code class="whitespace-pre">{{ row.text }}</code>
          </div>
        </template>
      </div>
    </div>
  </div>
</template>
