import { defineConfig } from "vitest/config";
import { loadEnv } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, ".", "");
  return {
    base: env.VITE_STANDALONE_MODE === "true" ? "./" : "/",
    plugins: [react()],
    test: {
      environment: "jsdom",
    },
    server: {
      port: 5173,
      proxy: { "/api": "http://127.0.0.1:8000" },
    },
  };
});
