import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { backendProxy, localApiGuard } from "./dev-proxy.ts";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "AGENTGUARD_");
  const proxy = {
    "/api": backendProxy(env.AGENTGUARD_BACKEND_URL || "http://127.0.0.1:8000"),
  };
  return {
    plugins: [localApiGuard(), react(), tailwindcss()],
    server: { host: "127.0.0.1", port: 5173, strictPort: true, proxy },
    preview: { host: "127.0.0.1", port: 4173, strictPort: true, proxy },
    build: { chunkSizeWarningLimit: 800 },
  };
});
