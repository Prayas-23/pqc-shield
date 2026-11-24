import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// The UI only talks to the read-only API on 127.0.0.1:8000, through this dev/preview proxy (HTTP and WebSocket).
const api = { "/api": { target: "http://127.0.0.1:8000", ws: true, changeOrigin: false } };

export default defineConfig({
  plugins: [react()],
  server: { host: "127.0.0.1", port: 5173, proxy: api },
  preview: { host: "127.0.0.1", port: 5173, proxy: api },
  test: { environment: "node", include: ["src/**/*.test.ts"] },
});
