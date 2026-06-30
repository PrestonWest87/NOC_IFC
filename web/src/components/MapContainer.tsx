import { useState, useCallback, useEffect, useRef, type ReactNode } from "react";

interface MapContainerProps {
  height: string;
  children: ReactNode;
}

export function MapContainer({ height, children }: MapContainerProps) {
  const ref = useRef<HTMLDivElement>(null);
  const [ready, setReady] = useState(false);
  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (el.offsetHeight > 0 && el.offsetWidth > 0) {
      setReady(true);
      return;
    }
    const ro = new ResizeObserver((entries) => {
      for (const entry of entries) {
        if (entry.contentRect.height > 0 && entry.contentRect.width > 0) {
          setReady(true);
          ro.disconnect();
        }
      }
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const toggleFs = useCallback(() => {
    setExpanded((p) => !p);
  }, []);

  return (
    <div ref={ref} style={{
      background: "var(--bg-card)",
      borderRadius: expanded ? 0 : "var(--radius-md)",
      boxShadow: "var(--shadow-sm)",
      border: expanded ? "none" : "1px solid var(--border-primary)",
      padding: 0,
      overflow: "hidden",
      height: expanded ? "100vh" : height,
      width: expanded ? "100vw" : "100%",
      position: expanded ? "fixed" as const : "relative",
      top: expanded ? 0 : undefined,
      left: expanded ? 0 : undefined,
      zIndex: expanded ? 1000 : undefined,
      minHeight: 300,
    }}>
      {expanded && (
        <div style={{
          position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", zIndex: -1,
        }} onClick={() => setExpanded(false)} />
      )}
      <button
        onClick={toggleFs}
        title={expanded ? "Exit Fullscreen" : "Fullscreen"}
        style={{
          position: "absolute", top: 8, right: 8, zIndex: 20,
          background: "var(--bg-card, #1e293b)", border: "1px solid var(--border-primary, #334155)",
          borderRadius: "var(--radius-sm, 4px)", color: "var(--text-secondary, #94a3b8)",
          cursor: "pointer", padding: "4px 8px", fontSize: "0.78rem",
          display: "flex", alignItems: "center", gap: "4px",
        }}
      >
        {expanded ? "Exit" : "Fullscreen"}
      </button>
      {ready && children}
    </div>
  );
}
