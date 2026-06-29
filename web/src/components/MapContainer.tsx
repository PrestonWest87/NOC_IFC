import { useState, useCallback, useEffect, useRef, type ReactNode } from "react";

interface MapContainerProps {
  height: string;
  children: ReactNode;
}

export function MapContainer({ height, children }: MapContainerProps) {
  const ref = useRef<HTMLDivElement>(null);
  const [ready, setReady] = useState(false);
  const [fs, setFs] = useState(false);

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

  useEffect(() => {
    const onFsChange = () => setFs(document.fullscreenElement === ref.current);
    document.addEventListener("fullscreenchange", onFsChange);
    return () => document.removeEventListener("fullscreenchange", onFsChange);
  }, []);

  const toggleFs = useCallback(() => {
    if (!ref.current) return;
    if (document.fullscreenElement) {
      document.exitFullscreen();
    } else {
      ref.current.requestFullscreen();
    }
  }, []);

  return (
    <div ref={ref} style={{
      background: "var(--bg-card)",
      borderRadius: "var(--radius-md)",
      boxShadow: "var(--shadow-sm)",
      border: "1px solid var(--border-primary)",
      padding: 0,
      overflow: "hidden",
      height: fs ? "100vh" : height,
      position: "relative",
      width: "100%",
      minHeight: 300,
    }}>
      <button
        onClick={toggleFs}
        title={fs ? "Exit Fullscreen" : "Fullscreen"}
        style={{
          position: "absolute", top: 8, right: 8, zIndex: 20,
          background: "var(--bg-card, #1e293b)", border: "1px solid var(--border-primary, #334155)",
          borderRadius: "var(--radius-sm, 4px)", color: "var(--text-secondary, #94a3b8)",
          cursor: "pointer", padding: "4px 8px", fontSize: "0.78rem",
          display: "flex", alignItems: "center", gap: "4px",
        }}
      >
        {fs ? "Exit" : "Fullscreen"}
      </button>
      {ready && children}
    </div>
  );
}
