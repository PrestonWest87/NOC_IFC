import { useState, useEffect } from "react";

const THEMES = [
  { id: "standard", label: "Standard" },
  { id: "noc-terminal", label: "NOC Terminal" },
  { id: "high-contrast", label: "High Contrast (Dark)" },
  { id: "cyberpunk", label: "Cyberpunk" },
  { id: "solarized-dark", label: "Solarized Dark" },
  { id: "midnight-ocean", label: "Midnight Ocean" },
];

const STORAGE_KEY = "noc_theme";

function getSavedTheme(): string {
  return localStorage.getItem(STORAGE_KEY) || "standard";
}

function applyTheme(themeId: string) {
  document.body.setAttribute("data-theme", themeId);
  localStorage.setItem(STORAGE_KEY, themeId);
}

export function ThemeSelector() {
  const [theme, setTheme] = useState(getSavedTheme);

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "0.6rem" }}>
      <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
        {THEMES.map((t) => (
          <button
            key={t.id}
            onClick={() => setTheme(t.id)}
            style={{
              background: theme === t.id ? "var(--accent-blue)" : "var(--bg-tertiary)",
              color: theme === t.id ? "#fff" : "var(--text-secondary)",
              border: `1px solid ${theme === t.id ? "var(--accent-blue)" : "var(--border-primary)"}`,
              borderRadius: "var(--radius-sm)",
              padding: "0.5rem 1rem",
              cursor: "pointer",
              fontWeight: theme === t.id ? 700 : 500,
              fontSize: "0.82rem",
              transition: "all 0.15s",
            }}
          >
            {t.label}
          </button>
        ))}
      </div>
      <p style={{ margin: "0.25rem 0 0", fontSize: "0.75rem", color: "var(--text-muted)" }}>
        Theme preference is saved locally.
      </p>
    </div>
  );
}

// Call on app mount to restore saved theme
export function initTheme() {
  const saved = getSavedTheme();
  applyTheme(saved);
}
