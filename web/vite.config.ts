import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const apiUrl = process.env.VITE_API_URL || "http://localhost:8101";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: apiUrl,
        changeOrigin: true,
      },
      "/ws": {
        target: apiUrl.replace(/^http/, "ws"),
        ws: true,
      },
    },
  },
});
