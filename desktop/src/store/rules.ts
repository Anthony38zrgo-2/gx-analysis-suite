import { defineStore } from "pinia";
import { computed, ref } from "vue";

import { listRules, setRuleEnabled } from "../api/client";
import { toCommandError } from "../api/errors";
import type { CommandError, RuleRecord } from "../api/types";

/** Catálogo de reglas y set efectivo (GX-017). */
export const useRulesStore = defineStore("rules", () => {
  const rules = ref<RuleRecord[]>([]);
  const loading = ref(false);
  const error = ref<CommandError | null>(null);
  const savingId = ref<string | null>(null);

  const enabledIds = computed(() =>
    rules.value.filter((rule) => rule.enabled).map((rule) => rule.id),
  );
  const enabledCount = computed(() => enabledIds.value.length);

  async function load(): Promise<void> {
    loading.value = true;
    error.value = null;
    try {
      rules.value = await listRules();
    } catch (e) {
      error.value = toCommandError(e);
    } finally {
      loading.value = false;
    }
  }

  async function toggle(rule: RuleRecord): Promise<void> {
    const next = !rule.enabled;
    savingId.value = rule.id;
    error.value = null;
    try {
      await setRuleEnabled(rule.id, next);
      rule.enabled = next;
    } catch (e) {
      error.value = toCommandError(e);
    } finally {
      savingId.value = null;
    }
  }

  return {
    rules,
    loading,
    error,
    savingId,
    enabledIds,
    enabledCount,
    load,
    toggle,
  };
});
