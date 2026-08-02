import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { readFileSync } from "node:fs";

const pkg = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8"));

export default defineConfig({
  plugins: [react()],
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
    // Set by docker-compose build args (deploy.sh fills them in). The build context on the server
    // has no .git directory, so these are computed on the machine that triggers the build.
    __BUILD_SHA__: JSON.stringify(process.env.VITE_BUILD_SHA || "dev"),
    __BUILD_TIME__: JSON.stringify(process.env.VITE_BUILD_TIME || ""),
  },
  server: {
    host: true,
    port: 5173,
    proxy: {
      "/api": { target: process.env.VITE_BACKEND_URL || "http://localhost:8000", changeOrigin: true },
    },
  },
});
