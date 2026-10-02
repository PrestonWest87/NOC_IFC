import { useState } from "react";
import { useAuth } from "../utils/AuthContext";
import { hasPagePermission } from "../utils/permissions";
import {
  Activity, Globe, Crosshair, Shield, Radio, BookOpen,
  FileText, Settings, LogOut, Menu, User, ChevronLeft, Search
} from "lucide-react";

const navItems = [
  { label: "Global Dashboards", icon: Activity, href: "/" },
  { label: "Threat Telemetry", icon: Globe, href: "/threat-telemetry" },
  { label: "Regional Grid", icon: Crosshair, href: "/regional-grid" },
  { label: "Threat Hunting & IOCs", icon: Shield, href: "/threat-hunting" },
  { label: "AIOps RCA", icon: Radio, href: "/aiops-rca" },
  { label: "Shift Logbook", icon: BookOpen, href: "/shift-logbook" },
  { label: "Reporting & Briefings", icon: FileText, href: "/reporting" },
  { label: "Keyword Analysis", icon: Search, href: "/keyword-analysis" },
  { label: "Settings & Admin", icon: Settings, href: "/settings" },
];

export function Layout({ children }: { children: React.ReactNode }) {
  const { user, logout } = useAuth();
  const [collapsed, setCollapsed] = useState(false);

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
            aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
            style={{ background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer", padding: 2 }}>
            {collapsed ? <Menu size={18} /> : <ChevronLeft size={18} />}
          </button>
        </div>

        <div style={{ flex: 1, overflowY: "auto", padding: "0.25rem 0" }}>
          {navItems.filter(item => {
            return hasPagePermission(user, item.label);
          }).map((item) => (
            <a key={item.href} href={`#${item.href}`} aria-label={collapsed ? item.label : undefined}
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
              <div style={{ marginBottom: "0.5rem" }}>
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
        {user?.account_type !== "display" && ["missing", "unverified", "pending_approval", "pending_verification"].includes(String(user?.recovery_email_status || (!user?.email ? "missing" : "unverified"))) && (
          <div role="status" style={{ margin: "1rem 1.5rem 0", padding: "0.8rem 1rem", border: "1px solid var(--accent-yellow)", borderRadius: "var(--radius-sm)", background: "var(--shade-yellow)", color: "var(--text-primary)", fontSize: "0.82rem" }}>
            <strong>Account recovery email:</strong>{" "}
            {user?.recovery_email_status === "pending_approval"
              ? `Your request for ${user.pending_email || "a recovery email"} is awaiting user-administrator approval.`
              : user?.recovery_email_status === "pending_verification"
                ? `Your request was approved. Verify ${user.pending_email || "the new email address"} to make it your recovery email.`
                : "Add a recovery email so an approved address is available if you forget your password. Email changes require user-administrator approval and mailbox verification."}
            {user?.recovery_email_status !== "pending_approval" && user?.recovery_email_status !== "pending_verification" && (
              <> <a href="#/settings" style={{ color: "var(--accent-blue)" }}>Review your profile</a>.</>
            )}
          </div>
        )}
        {children}
      </main>
    </div>
  );
}
