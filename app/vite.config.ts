import path from "path"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"
import { inspectAttr } from 'kimi-plugin-inspect-react'

// Backend target: in Docker the UI container reaches the backend via the
// service name "agent". In local dev we use localhost:8080.
// Override with BACKEND_INTERNAL_URL env var if needed.
const BACKEND = process.env.BACKEND_INTERNAL_URL || 'http://localhost:8080';
const WS_BACKEND = BACKEND.replace(/^http/, 'ws');

// Shared proxy rules (used by both dev server and preview)
const proxyRules = {
  '/api': { target: BACKEND, changeOrigin: true, secure: false },
  '/analyze': { target: BACKEND, changeOrigin: true, secure: false },
  '/status': { target: BACKEND, changeOrigin: true, secure: false },
  '/query': { target: BACKEND, changeOrigin: true, secure: false },
  '/export': { target: BACKEND, changeOrigin: true, secure: false },
  '/write_mode': { target: BACKEND, changeOrigin: true, secure: false },
  '/health': { target: BACKEND, changeOrigin: true, secure: false },
  '/stream': { target: WS_BACKEND, ws: true, changeOrigin: true, secure: false },
};

// https://vite.dev/config/
export default defineConfig({
  base: './',
  plugins: [inspectAttr(), react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  // Dev server proxy (npm run dev)
  server: {
    proxy: proxyRules,
  },
  // Preview proxy (npm run preview — used by the Docker UI container)
  preview: {
    proxy: proxyRules,
  },
});
