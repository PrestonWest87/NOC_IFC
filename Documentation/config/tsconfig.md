# web/tsconfig.json — TypeScript Compiler Configuration

**Path:** `/home/weast/docker/NOC_IFC/web/tsconfig.json`

## Purpose

Configures the TypeScript compiler for the React frontend project. Defines language features, module resolution, strictness rules, and build output settings. Sits alongside `vite.config.ts` and `package.json` to form the frontend build pipeline.

## `compilerOptions`

### Language & Environment

| Option | Value | Description |
|--------|-------|-------------|
| `target` | `ES2020` | ECMAScript target version. Output syntax targets ES2020 features (optional chaining, nullish coalescing, `Promise.allSettled`, etc.). All modern browsers support ES2020. |
| `lib` | `["ES2020", "DOM", "DOM.Iterable"]` | TypeScript declaration libraries to include. `ES2020` provides ES2020 stdlib types; `DOM` provides browser API types (`document`, `window`, etc.); `DOM.Iterable` provides iterable protocol types for DOM collections. |
| `jsx` | `react-jsx` | JSX transform mode. `react-jsx` uses the automatic JSX runtime (React 17+), which does not require `import React from "react"` in every file. |

### Module Resolution

| Option | Value | Description |
|--------|-------|-------------|
| `module` | `ESNext` | Module code generation. ESNext preserves `import`/`export` statements — Vite handles tree-shaking and bundling. |
| `moduleResolution` | `bundler` | Module resolution strategy. `bundler` is the modern option for use with bundlers like Vite — it supports `package.json` `exports`, `imports`, and extensionless imports. |
| `allowImportingTsExtensions` | `true` | Allows `.ts` and `.tsx` extensions in import paths (e.g., `import { foo } from "./bar.ts"`). Required by Vite. |
| `isolatedModules` | `true` | Ensures each file can be transpiled independently by non-TSC tools (like Vite's esbuild). Disallows features that require cross-file type information (e.g., `const enum` exports, re-export of types with `export *`). |
| `moduleDetection` | `force` | Forces all files to be treated as ES modules (modules with import/export), even if they lack `import`/`export` statements. Prevents issues with files being treated as scripts. |

### Build Output

| Option | Value | Description |
|--------|-------|-------------|
| `noEmit` | `true` | TypeScript does not emit compiled JS files. Vite/esbuild handles all output generation. TypeScript is used solely for type-checking (via `tsc -b` in the `build` script). |

### Type Checking Strictness

| Option | Value | Description |
|--------|-------|-------------|
| `strict` | `true` | Enables all strict type-checking options (`strictNullChecks`, `strictFunctionTypes`, `strictBindCallApply`, `strictPropertyInitialization`, `noImplicitAny`, `noImplicitThis`, `alwaysStrict`). |
| `noUnusedLocals` | `true` | Reports errors on unused local variables. Prevents dead code from being committed. |
| `noUnusedParameters` | `true` | Reports errors on unused function parameters. Prefix with underscore to exempt (e.g., `_unusedParam`). |
| `noFallthroughCasesInSwitch` | `true` | Reports errors on fallthrough cases in switch statements (unless explicitly marked with a `break`, `return`, `throw`, or `// falls through` comment). |
| `forceConsistentCasingInFileNames` | `true` | Ensures all import paths use consistent casing with the actual file path. Prevents cross-platform issues (macOS/Windows case-insensitive vs Linux case-sensitive). |

### Other

| Option | Value | Description |
|--------|-------|-------------|
| `useDefineForClassFields` | `true` | Uses the ECMAScript [[Define]] semantics for class field initialization (`Object.defineProperty`) instead of assignment semantics. Required for compatibility with modern class field transforms. |
| `skipLibCheck` | `true` | Skips type-checking of declaration files (`.d.ts`). Speeds up compilation by not checking third-party library types. |

## `include`

| Option | Value | Description |
|--------|-------|-------------|
| `include` | `["src"]` | Specifies the set of files to include for compilation. All `.ts` and `.tsx` files under the `src/` directory are compiled. |

## Dependencies

| Dependency | Relationship |
|------------|-------------|
| `typescript` | Compiler (`tsc`) listed in `devDependencies`. |
| `vite` | Bundler; uses TypeScript for type-checking (via `tsc -b`) before bundling in the `build` script. |
| `@types/react`, `@types/react-dom` | Type declarations for React. Implicitly used via `lib: ["DOM"]` and the type system. |

## Usage

Referenced by the `build` script in `package.json`:

```json
"build": "tsc -b && vite build"
```

`tsc -b` (project build mode) reads this config, performs type-checking, and emits type declaration info (but not JS because `noEmit: true`). If type-checking passes, Vite then bundles the application.

To check types without building:

```bash
npx tsc -b --noEmit
npx tsc --noEmit
```
