import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Control plane the dev server proxies /v1 to. Override when the API is not on
// the default port (e.g. VITE_API_PROXY=http://localhost:8001).
const apiTarget = process.env.VITE_API_PROXY ?? "http://localhost:8000";

export default defineConfig({
  base: "./",
  plugins: [react()],
  server: {
    proxy: {
      "/v1": { target: apiTarget, changeOrigin: true },
    },
  },
});
