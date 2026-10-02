<script setup lang="ts">
import { useRulesStore } from "../store/rules";

const emit = defineEmits<{ rerun: [] }>();

const rules = useRulesStore();
</script>

<template>
  <div class="space-y-4" data-testid="rules-view">
    <section class="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <div class="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 class="text-sm font-medium">Catálogo de reglas</h2>
          <p class="mt-1 text-xs text-slate-400">
            {{ rules.enabledCount }} de {{ rules.rules.length }} reglas activas.
            Los cambios se guardan en la base local y aplican al próximo scan.
          </p>
        </div>
        <div class="flex items-center gap-2">
          <button
            type="button"
            class="rounded border border-slate-700 px-3 py-1 text-xs hover:bg-slate-800"
            @click="rules.load"
          >
            Recargar
          </button>
          <button
            type="button"
            class="rounded bg-emerald-600 px-3 py-1 text-xs font-medium text-white hover:bg-emerald-500"
            @click="emit('rerun')"
          >
            Re-ejecutar análisis
          </button>
        </div>
      </div>
    </section>

    <p
      v-if="rules.error"
      class="rounded border border-red-700 bg-red-950/40 px-4 py-3 text-sm text-red-200"
      role="alert"
    >
      {{ rules.error.message }}
    </p>

    <section class="rounded-lg border border-slate-800 bg-slate-900">
      <p v-if="rules.loading" class="p-6 text-sm text-slate-400" aria-live="polite">
        Cargando catálogo…
      </p>
      <p v-else-if="rules.rules.length === 0" class="p-6 text-sm text-slate-400">
        El catálogo está vacío.
      </p>
      <ul v-else class="divide-y divide-slate-800">
        <li
          v-for="rule in rules.rules"
          :key="rule.id"
          class="flex items-start gap-4 p-4"
        >
          <div class="min-w-0 flex-1">
            <div class="flex items-center gap-2">
              <span class="font-mono text-xs">{{ rule.id }}</span>
              <span
                class="rounded px-1.5 py-0.5 font-mono text-[10px]"
                :class="
                  rule.severity === 'ERROR'
                    ? 'bg-red-900/60 text-red-200'
                    : rule.severity === 'WARNING'
                      ? 'bg-amber-900/60 text-amber-200'
                      : 'bg-sky-900/60 text-sky-200'
                "
              >
                {{ rule.severity }}
              </span>
            </div>
            <div class="mt-1 text-sm">{{ rule.name }}</div>
            <div class="mt-1 text-xs text-slate-400">{{ rule.description }}</div>
          </div>
          <button
            type="button"
            role="switch"
            :aria-checked="rule.enabled"
            :aria-label="`${rule.enabled ? 'Deshabilitar' : 'Habilitar'} ${rule.id}`"
            class="relative h-6 w-11 shrink-0 rounded-full transition-colors disabled:opacity-50"
            :class="rule.enabled ? 'bg-emerald-600' : 'bg-slate-700'"
            :disabled="rules.savingId === rule.id"
            @click="rules.toggle(rule)"
          >
            <span
              class="absolute top-0.5 h-5 w-5 rounded-full bg-white transition-all"
              :class="rule.enabled ? 'left-[22px]' : 'left-0.5'"
              aria-hidden="true"
            />
          </button>
        </li>
      </ul>
    </section>
  </div>
</template>
