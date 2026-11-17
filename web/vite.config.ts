import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // All /api requests are forwarded to the Express server.
      // This means the browser sees one origin (localhost:5173) and cookies
      // are set on that origin — no CORS issues, no cookie SameSite headaches.
      "/api": {
        target: "http://localhost:4000",
        changeOrigin: true, // rewrites the Host header to the target
      },
    },
  },
});
