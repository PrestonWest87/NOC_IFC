import { useState, useEffect } from "react";
import api from "../utils/api";
import { useAuth } from "../utils/AuthContext";

export const THEMES = [
  { id: "standard", label: "Standard" },
  { id: "noc-terminal", label: "NOC Terminal" },
  { id: "high-contrast", label: "High Contrast (Dark)" },
  { id: "cyberpunk", label: "Cyberpunk" },
  { id: "solarized-dark", label: "Solarized Dark" },
  { id: "midnight-ocean", label: "Midnight Ocean" },
  { id: "arctic-command", label: "Arctic Command" },
  { id: "ember-watch", label: "Ember Watch" },
  { id: "forest-ops", label: "Forest Ops" },
  { id: "amethyst-grid", label: "Amethyst Grid" },
  { id: "slate-steel", label: "Slate Steel" },
  { id: "paper-light", label: "Paper Light" },
  { id: "nordic-frost", label: "Nordic Frost" },
  { id: "dracula-console", label: "Dracula Console" },
  { id: "synthwave", label: "Synthwave" },
  { id: "desert-signal", label: "Desert Signal" },
  { id: "olive-command", label: "Olive Command" },
  { id: "mono-ops", label: "Monochrome Ops" },
  { id: "rose-pine", label: "Rose Pine" },
  { id: "oceanic-teal", label: "Oceanic Teal" },
  { id: "copper-wire", label: "Copper Wire" },
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
  const { user } = useAuth();
  const [theme, setTheme] = useState(getSavedTheme);

  useEffect(() => {
    if (user?.theme) setTheme(user.theme);
  }, [user?.theme]);

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  const selectTheme = (themeId: string) => {
    setTheme(themeId);
    if (user) api.post("/auth/update-theme", { theme: themeId }).catch(() => {});
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "0.6rem" }}>
      <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
        {THEMES.map((t) => (
          <button
            key={t.id}
            onClick={() => selectTheme(t.id)}
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
