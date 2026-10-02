import type { CommandError } from "./types";

/** Normaliza cualquier error de `invoke` al contrato estructurado del backend. */
export function toCommandError(error: unknown): CommandError {
  if (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    "message" in error &&
    typeof (error as { code: unknown }).code === "string" &&
    typeof (error as { message: unknown }).message === "string"
  ) {
    return error as CommandError;
  }
  return { code: "internal", message: String(error) };
}
