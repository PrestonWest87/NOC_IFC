import { readFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import type { Plugin } from "vite";
import react from "@vitejs/plugin-react";

const apiUrl = process.env.VITE_API_URL || "http://localhost:8101";
const maplibreDist = fileURLToPath(new URL("./node_modules/maplibre-gl/dist/", import.meta.url));
const maplibreWorkerFiles = ["maplibre-gl-worker.mjs", "maplibre-gl-shared.mjs"] as const;
const maplibreFirefoxFocusRule = /\.maplibregl-ctrl button::-moz-focus-inner\s*\{[^}]*\}/g;
const maplibreUserSelectRestore = /(\w+)\.docStyle\[\1\.selectProp\]=\1\.userSelect/g;
const lumaExtensionRequest = "getWebGLExtension(gl, 'WEBGL_debug_renderer_info', extensions);";
const lumaExtensionRead = "const ext = extensions.WEBGL_debug_renderer_info;";

function patchMaplibreUserSelect(source: string): string {
  const patched = source.replace(maplibreUserSelectRestore, "$1.docStyle[$1.selectProp]=$1.userSelect??\"\"");
  if (patched === source) {
    throw new Error("MapLibre drag-selection restore changed; review the Firefox user-select compatibility fix.");
  }
  return patched;
}

function patchLumaRendererInfo(source: string): string {
  if (!source.includes(lumaExtensionRequest) || !source.includes(lumaExtensionRead)) {
    throw new Error("luma.gl renderer detection changed; review the Firefox WebGL compatibility fix.");
  }

  return source
    .replace(
      lumaExtensionRequest,
      `const isFirefox = typeof navigator !== "undefined" && navigator.userAgent.includes("Firefox/");\n    if (!isFirefox) ${lumaExtensionRequest}`,
    )
    .replace(lumaExtensionRead, "const ext = isFirefox ? undefined : extensions.WEBGL_debug_renderer_info;");
}

function browserCompatibilityOptimizer() {
  return {
    name: "browser-compatibility-optimizer",
    setup(build) {
      build.onLoad({ filter: /\/maplibre-gl\/dist\/maplibre-gl\.mjs$/ }, ({ path }) => ({
        contents: patchMaplibreUserSelect(readFileSync(path, "utf8")),
        loader: "js",
      }));
      build.onLoad({ filter: /\/@luma\.gl\/webgl\/dist\/adapter\/device-helpers\/webgl-device-info\.js$/ }, ({ path }) => ({
        contents: patchLumaRendererInfo(readFileSync(path, "utf8")),
        loader: "js",
      }));
    },
  };
}

function lumaFirefoxRendererInfo(): Plugin {
  return {
    name: "luma-firefox-renderer-info",
    enforce: "pre",
    transform(code, id) {
      const sourcePath = id.split("?", 1)[0].replaceAll("\\", "/");
      if (!sourcePath.endsWith("/@luma.gl/webgl/dist/adapter/device-helpers/webgl-device-info.js")) return null;
      return patchLumaRendererInfo(code);
    },
  };
}

function maplibreAssets(): Plugin {
  const assets = maplibreWorkerFiles.map((fileName) => ({
    fileName,
    source: readFileSync(resolve(maplibreDist, fileName)),
  }));

  return {
    name: "maplibre-assets",
    enforce: "pre",
    transform(code, id) {
      const sourcePath = id.split("?", 1)[0].replaceAll("\\", "/");

      if (sourcePath.endsWith("/maplibre-gl/dist/maplibre-gl.css")) {
        // Firefox no longer recognizes this legacy selector; MapLibre already resets the button border and padding.
        const css = code.replace(maplibreFirefoxFocusRule, "");
        return css === code ? null : css;
      }

      if (sourcePath.endsWith("/maplibre-gl/dist/maplibre-gl.mjs")) {
        // Restore an empty inline value if the browser had no user-select value, rather than assigning undefined.
        return patchMaplibreUserSelect(code);
      }

      return null;
    },
    configureServer(server) {
      server.middlewares.use((request, response, next) => {
        const pathname = request.url?.split("?", 1)[0] || "";
        const asset = assets.find(({ fileName }) => basename(pathname) === fileName);
        if (!asset) {
          next();
          return;
        }

        response.setHeader("Content-Type", "text/javascript; charset=utf-8");
        response.end(asset.source);
      });
    },
    generateBundle() {
      for (const asset of assets) {
        this.emitFile({
          type: "asset",
          fileName: `assets/${asset.fileName}`,
          source: asset.source,
        });
      }
    },
  };
}

export default defineConfig({
  plugins: [react(), maplibreAssets(), lumaFirefoxRendererInfo()],
  optimizeDeps: {
    esbuildOptions: {
      plugins: [browserCompatibilityOptimizer()],
    },
  },
  server: {
    port: 5173,
    host: "0.0.0.0",
    allowedHosts: ["test.weasts.net"],
    watch: {
      usePolling: true,
      interval: 500,
    },
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
