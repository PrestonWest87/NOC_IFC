# main.tsx

Application entry point. Initializes the theme, mounts the React root, and renders the App component inside StrictMode.

---

## Execution Flow

1. **`initTheme()`** is called synchronously from `../components/ThemeSelector` to apply the persisted theme before the first render, preventing flash of unstyled content.
2. **`ReactDOM.createRoot()`** is called on the DOM element with id `root`.
3. The root renders `<App />` wrapped in `<React.StrictMode>` for development-time checks (double-invocation of effects, deprecated API warnings).

## Imported Side Effects

| Import | Path | Purpose |
|--------|------|---------|
| `./styles/theme.css` | CSS | Dark-theme CSS custom properties |
| `./styles/components.css` | CSS | Shared component-level styles |
| `./themes/themes.css` | CSS | Additional theme variation overrides |

## Dependencies

- `React` from `react`
- `ReactDOM` from `react-dom/client`
- `App` from `./App` (default export)
- `initTheme` from `./components/ThemeSelector`
