import { useState } from "react";
import { useAuth } from "../utils/AuthContext";
import {
  Activity, Globe, Crosshair, Shield, Radio, BookOpen,
  FileText, Settings, LogOut, Menu, User, ChevronLeft
} from "lucide-react";

const navItems = [
  { label: "Global Dashboards", icon: Activity, href: "/" },
  { label: "Threat Telemetry", icon: Globe, href: "/threat-telemetry" },
  { label: "Regional Grid", icon: Crosshair, href: "/regional-grid" },
  { label: "Threat Hunting & IOCs", icon: Shield, href: "/threat-hunting" },
  { label: "AIOps RCA", icon: Radio, href: "/aiops-rca" },
  { label: "Shift Logbook", icon: BookOpen, href: "/shift-logbook" },
  { label: "Reporting & Briefings", icon: FileText, href: "/reporting" },
  { label: "Settings & Admin", icon: Settings, href: "/settings" },
];

export function Layout({ children }: { children: React.ReactNode }) {
  const { user, logout } = useAuth();
  const [collapsed, setCollapsed] = useState(false);
  const [showProfile, setShowProfile] = useState(false);

  return (
    <div style={{ display: "flex", height: "100vh", background: "var(--bg-primary)", color: "var(--text-primary)", fontFamily: "var(--font-sans)" }}>
      <nav style={{
        width: collapsed ? 56 : 230, background: "var(--bg-secondary)",
        display: "flex", flexDirection: "column", flexShrink: 0,
        borderRight: "1px solid var(--border-primary)", transition: "width 0.2s",
        overflow: "hidden", zIndex: 100,
      }}>
        <div style={{
          padding: "0.75rem 1rem", display: "flex",
          alignItems: "center", justifyContent: "space-between",
          borderBottom: "1px solid var(--border-primary)",
          minHeight: 48,
        }}>
          {!collapsed && (
            <span style={{ fontWeight: 700, fontSize: "0.85rem", color: "var(--accent-cyan)", letterSpacing: "0.5px" }}>
              NOC FUSION
            </span>
          )}
          <button onClick={() => setCollapsed(!collapsed)}
            style={{ background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer", padding: 2 }}>
            {collapsed ? <Menu size={18} /> : <ChevronLeft size={18} />}
          </button>
        </div>

        <div style={{ flex: 1, overflowY: "auto", padding: "0.25rem 0" }}>
          {navItems.filter(item => {
            if (!user?.allowed_pages) return true;
            return user.allowed_pages.includes(item.label);
          }).map((item) => (
            <a key={item.href} href={`#${item.href}`}
              style={{
                display: "flex", alignItems: "center", gap: "0.6rem",
                padding: "0.55rem 1rem", color: "var(--text-secondary)",
                textDecoration: "none", fontSize: "0.82rem",
                whiteSpace: "nowrap", transition: "all 0.1s",
                borderLeft: "2px solid transparent",
              }}
              onMouseEnter={e => { e.currentTarget.style.background = "var(--bg-tertiary)"; e.currentTarget.style.color = "var(--text-primary)"; }}
              onMouseLeave={e => { e.currentTarget.style.background = "transparent"; e.currentTarget.style.color = "var(--text-secondary)"; }}>
              <item.icon size={16} style={{ flexShrink: 0 }} />
              {!collapsed && item.label}
            </a>
          ))}
        </div>

        <div style={{
          borderTop: "1px solid var(--border-primary)",
          padding: collapsed ? "0.5rem" : "0.5rem 0.75rem",
        }}>
          {!collapsed && user && (
            <>
              <div style={{ marginBottom: "0.5rem", cursor: "pointer" }}
                onClick={() => setShowProfile(!showProfile)}>
                <div style={{ fontWeight: 600, fontSize: "0.8rem", color: "var(--text-primary)", display: "flex", alignItems: "center", gap: 4 }}>
                  <User size={14} /> {user.full_name || user.username}
                </div>
                <div style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>{user.job_title || user.role}</div>
              </div>
            </>
          )}
          <button onClick={logout}
            style={{
              display: "flex", alignItems: "center", gap: "0.4rem",
              background: "none", border: "1px solid var(--border-primary)",
              color: "var(--text-muted)", padding: "0.35rem 0.65rem",
              borderRadius: "var(--radius-sm)", cursor: "pointer",
              width: "100%", fontSize: "0.78rem",
            }}>
            <LogOut size={13} />
            {!collapsed && "Log Out"}
          </button>
        </div>
      </nav>
      <main style={{ flex: 1, overflow: "auto", background: "var(--bg-primary)" }}>
        {children}
      </main>
    </div>
  );
}
