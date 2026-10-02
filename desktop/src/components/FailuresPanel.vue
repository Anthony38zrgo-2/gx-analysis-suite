<script setup lang="ts">
import type { ScanFailure } from "../api/types";

defineProps<{ failures: ScanFailure[] }>();
</script>

<template>
  <section
    v-if="failures.length > 0"
    class="rounded-lg border border-red-700 bg-red-950/40 p-4"
    aria-label="Fallos de scan"
  >
    <h3 class="text-sm font-semibold text-red-200">
      Fallos de scan ({{ failures.length }})
    </h3>
    <p class="mt-1 text-xs text-red-300">
      Estos archivos NO fueron analizados; el resultado nunca se considera limpio.
    </p>
    <ul class="mt-3 space-y-2 text-xs">
      <li v-for="failure in failures" :key="failure.path" class="rounded bg-red-900/30 p-2">
        <div class="font-mono text-red-100 break-all">{{ failure.path }}</div>
        <div class="mt-1 text-red-300">{{ failure.error }}</div>
      </li>
    </ul>
  </section>
</template>
