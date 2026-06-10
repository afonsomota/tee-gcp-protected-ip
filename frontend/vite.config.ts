/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  // Served from GitHub Pages under a repo subpath; relative base keeps assets working.
  base: "./",
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
});
