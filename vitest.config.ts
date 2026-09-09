import { defineConfig } from "vitest/config";

// thisdid build profile: explicit config so vitest never falls back to the
// ThisDID repository root config (which externalizes the whole vendor tree).
export default defineConfig({ test: { include: ["src/**/*.test.ts"] } });
