# web/index.html — SPA Entry Point

**Path:** `/home/weast/docker/NOC_IFC/web/index.html`

## Purpose

Root HTML document for the React single-page application. Served as the entry point by both the Vite dev server (development) and Nginx (production). The file is minimal — it provides the mounting point for React, sets meta tags, and loads the application bundle.

## Elements

### `<html>`

| Attribute | Value | Description |
|-----------|-------|-------------|
| `lang` | `en` | Declares the document language as English. Assists screen readers and browser translation features. |

### `<head>`

#### `<meta charset>`

| Attribute | Value | Description |
|-----------|-------|-------------|
| `charset` | `UTF-8` | Sets character encoding to UTF-8, supporting the full Unicode character set. Must be the first element in `<head>`. |

#### `<meta name="viewport">**

| Attribute | Value | Description |
|-----------|-------|-------------|
| `name` | `viewport` | Controls viewport dimensions and scaling for responsive design. |
| `content` | `width=device-width, initial-scale=1.0` | Sets viewport width to the device width and initial zoom to 1.0. Ensures the application renders correctly on mobile and desktop. |

#### `<title>`

| Content | Description |
|---------|-------------|
| `NOC Intelligence Fusion Center` | Browser tab title and search result heading. Reflects the application's purpose as a NOC (Network Operations Center) intelligence dashboard. |

### `<body>`

#### `<div id="root">`

| Attribute | Value | Description |
|-----------|-------|-------------|
| `id` | `root` | **React mount point.** `ReactDOM.createRoot(document.getElementById("root"))` renders the component tree into this element. |

#### `<script type="module" src="/src/main.tsx">`

| Attribute | Value | Description |
|-----------|-------|-------------|
| `type` | `module` | Declares the script as an ES module — supports `import`/`export` statements. Browsers defer module scripts by default. |
| `src` | `/src/main.tsx` | Application entry point. Vite resolves this relative to the project root (`web/`). During development, Vite serves this file with HMR; during production builds, the entire module graph is bundled into output files in `dist/assets/`. |

## Processing by Vite

Vite treats `index.html` as the entry point of the application. During `vite build`, Vite:

1. Parses `index.html` to discover `<script type="module">` tags
2. Traces all `import` statements from `/src/main.tsx` to build the dependency graph
3. Bundles all modules into optimised output files in `dist/assets/`
4. Rewrites the `<script src>` attribute in the output `index.html` to point to the hashed bundle file

## Dependencies

| Dependency | Relationship |
|------------|-------------|
| `src/main.tsx` | Application entry point — must exist at the referenced path relative to `web/`. |
| `vite.config.ts` | Vite configuration; `index.html` is automatically detected when it exists at the project root. |
| `web/Dockerfile` | Copies `index.html` into the builder stage; the built `dist/index.html` is served by Nginx. |

## Usage

This file is not typically modified because it serves only as a bootstrap shell. All application content is rendered dynamically by React into the `<div id="root">` element.

The file is located at the web project root (`web/index.html`) because Vite requires `index.html` at the project root for its default entry-point detection.
