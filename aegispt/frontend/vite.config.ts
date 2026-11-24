import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, ".", "");
  const apiTarget = env.VITE_API_TARGET || "http://127.0.0.1:8443";
  const wsTarget = apiTarget.replace(/^http/i, "ws");

  return {
    plugins: [react()],
    server: {
      host: "127.0.0.1",
      port: 5173,
      proxy: {
        "/api": {
          target: apiTarget,
          changeOrigin: true,
          ws: true,
        },
        "/ws": {
          target: wsTarget,
          ws: true,
        },
        "/oob": {
          target: apiTarget,
          changeOrigin: true,
        },
      },
    },
  };
});
