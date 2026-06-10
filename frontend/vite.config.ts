/// <reference types="vitest/config" />
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  // Served from GitHub Pages under a repo subpath; relative base keeps assets working.
  base: "./",
  build: {
    rollupOptions: {
      input: {
        // The journal SPA plus the bare-bones attestation test page.
        main: fileURLToPath(new URL("./index.html", import.meta.url)),
        attest: fileURLToPath(new URL("./attest.html", import.meta.url)),
      },
    },
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
});
