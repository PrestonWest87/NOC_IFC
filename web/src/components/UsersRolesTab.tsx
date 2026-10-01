import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Copy, KeyRound, Mail, Plus, RefreshCw, Save, Search, Shield, UserPlus, Users } from "lucide-react";
import api, { getApiErrorMessage } from "../utils/api";
import { formatInChicago } from "../utils/timezone";
import { hasActionPermission } from "../utils/permissions";

type UserRecord = {
  id: number;
  username: string;
  full_name?: string | null;
  job_title?: string | null;
  contact_info?: string | null;
  account_type: "individual" | "display";
  email?: string | null;
  email_verified: boolean;
  email_status: string;
  pending_email?: string | null;
  role: string;
  is_active: boolean;
  created_at?: string | null;
  last_login_at?: string | null;
  last_activity_at?: string | null;
  invitation_pending?: boolean;
};

type RoleRecord = { name: string; allowed_pages: string[]; allowed_actions: string[]; allowed_site_types: string[] };
type RoleEditorSection = "pages" | "tabs" | "actions" | "siteTypes";
type Catalog = {
  pages: { key: string; description: string }[];
  actions: { key: string; group: string; description: string; legacy?: boolean }[];
  tabs: Record<string, { key: string; label: string; tab: string }[]>;
};

const TAB_GROUP_LABELS: Record<string, string> = {
  dashboard: "Dashboards",
  threatTelemetry: "Threat Telemetry",
  regionalGrid: "Regional Grid",
  threatHunting: "Threat Hunting",
  aiopsRca: "AIOps RCA",
  shiftLogbook: "Shift Log",
  reporting: "Reporting",
  settings: "Settings",
};

const panel: React.CSSProperties = {
  background: "var(--bg-card)",
  border: "1px solid var(--border-primary)",
  borderRadius: "var(--radius-md)",
  padding: "1rem",
};
const input: React.CSSProperties = {
  width: "100%", boxSizing: "border-box", padding: "0.55rem 0.65rem",
  border: "1px solid var(--border-primary)", borderRadius: "var(--radius-sm)",
  color: "var(--text-primary)", background: "var(--bg-input)", fontSize: "0.82rem",
};
const button = (color = "var(--accent-blue)"): React.CSSProperties => ({
  border: 0, borderRadius: "var(--radius-sm)", padding: "0.5rem 0.75rem",
  background: color, color: "#fff", cursor: "pointer", fontWeight: 650,
  display: "inline-flex", alignItems: "center", gap: "0.35rem", fontSize: "0.78rem",
});

function localTime(value?: string | null) {
  return value ? formatInChicago(value) : "Not recorded";
}

export function UsersRolesTab({ user }: { user: { id?: number; role?: string; allowed_actions?: string[] } | null }) {
  const queryClient = useQueryClient();
  const canManageUsers = hasActionPermission(user, "Action: Manage Users");
  const canManageRoles = hasActionPermission(user, "Action: Manage Roles");
  const canReviewRecovery = hasActionPermission(user, "Action: Review Account Recovery Requests");
  const canApproveEmail = hasActionPermission(user, "Action: Approve Recovery Email Changes");
  const hasUserAdminAccess = canManageUsers || canManageRoles || canReviewRecovery || canApproveEmail;
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [invite, setInvite] = useState({ username: "", email: "", role: "analyst", ttl_hours: 72 });
  const [display, setDisplay] = useState({ username: "", full_name: "", password: "", role: "viewer" });
  const [inviteUrl, setInviteUrl] = useState("");
  const [resetTarget, setResetTarget] = useState("");
  const [resetPassword, setResetPassword] = useState("");
  const [editingUser, setEditingUser] = useState<UserRecord | null>(null);
  const [identityDraft, setIdentityDraft] = useState({ full_name: "", job_title: "", contact_info: "" });
  const [requestReasons, setRequestReasons] = useState<Record<number, string>>({});
  const [newRole, setNewRole] = useState<RoleRecord>({ name: "", allowed_pages: [], allowed_actions: [], allowed_site_types: [] });
  const [editRole, setEditRole] = useState("");
  const [roleDraft, setRoleDraft] = useState<RoleRecord | null>(null);
  const [permissionSection, setPermissionSection] = useState<RoleEditorSection>("pages");
  const [permissionSearch, setPermissionSearch] = useState("");

  const usersQuery = useQuery({
    queryKey: ["admin-users"],
    queryFn: () => api.get("/user-admin/users").then(r => r.data as UserRecord[]),
    enabled: canManageUsers,
  });
  const rolesQuery = useQuery({
    queryKey: ["admin-roles"],
    queryFn: () => api.get("/user-admin/roles").then(r => r.data as RoleRecord[]),
    enabled: canManageUsers,
  });
  const roleDefinitionsQuery = useQuery({
    queryKey: ["admin-role-definitions"],
    queryFn: () => api.get("/user-admin/role-definitions").then(r => r.data as RoleRecord[]),
    enabled: canManageRoles,
  });
  const catalogQuery = useQuery({
    queryKey: ["permission-catalog"],
    queryFn: () => api.get("/permissions/catalog").then(r => r.data as Catalog),
    enabled: canManageRoles,
    staleTime: 300000,
  });
  const siteTypesQuery = useQuery({
    queryKey: ["role-site-types"],
    queryFn: () => api.get("/user-admin/site-types").then(r => r.data as string[]),
    enabled: canManageRoles,
    staleTime: 300000,
  });
  const resetRequestsQuery = useQuery({
    queryKey: ["password-reset-requests"],
    queryFn: () => api.get("/user-admin/recovery-requests").then(r => r.data as any[]),
    enabled: canReviewRecovery,
    refetchInterval: 60000,
  });
  const emailRequestsQuery = useQuery({
    queryKey: ["recovery-email-requests"],
    queryFn: () => api.get("/user-admin/email-change-requests").then(r => r.data as any[]),
    enabled: canApproveEmail,
    refetchInterval: 60000,
  });
  const invitationsQuery = useQuery({
    queryKey: ["admin-invitations"],
    queryFn: () => api.get("/user-admin/invitations").then(r => r.data as any[]),
    enabled: canManageUsers,
  });

  const userRows = useMemo(() => {
    const q = search.trim().toLocaleLowerCase();
    return (usersQuery.data || []).filter(row => {
      if (typeFilter !== "all" && row.account_type !== typeFilter) return false;
      if (statusFilter === "active" && !row.is_active) return false;
      if (statusFilter === "disabled" && row.is_active) return false;
      if (statusFilter === "email-missing" && row.email_status !== "missing") return false;
      if (!q) return true;
      return [row.username, row.full_name, row.email, row.role, row.account_type]
        .some(value => String(value || "").toLocaleLowerCase().includes(q));
    });
  }, [usersQuery.data, search, typeFilter, statusFilter]);

  const runMutation = <T,>(
    mutationFn: (value: T) => Promise<any>,
    success: string,
    invalidate: string[] = ["admin-users"],
    onSuccessData?: (response: any) => void,
  ) => useMutation({
    mutationFn,
    onSuccess: (response) => {
      setError("");
      setNotice(success);
      invalidate.forEach(queryKey => queryClient.invalidateQueries({ queryKey: [queryKey] }));
      onSuccessData?.(response);
    },
    onError: (reason: any) => {
      setNotice("");
      setError(getApiErrorMessage(reason));
    },
  });

  const inviteMutation = runMutation(
    (data: typeof invite) => api.post("/user-admin/invitations", data),
    "Invitation created and email delivery queued.",
    ["admin-users", "admin-invitations"],
    response => {
      setInviteUrl(response.data.registration_url);
      if (response.data.delivery_status !== "sent") setNotice("Invitation created and email delivery queued. The registration link is available below if it needs to be shared manually.");
    },
  );
  const displayMutation = runMutation(
    (data: typeof display) => api.post("/user-admin/display-accounts", data),
    "Display account created.",
    ["admin-users"],
  );
  const roleMutation = runMutation(
    (data: { username: string; role: string }) => api.put(`/user-admin/users/${encodeURIComponent(data.username)}/role`, { role: data.role }),
    "User role updated.",
    ["admin-users"],
  );
  const statusMutation = runMutation(
    (data: { username: string; is_active: boolean }) => api.patch(`/user-admin/users/${encodeURIComponent(data.username)}/status`, { is_active: data.is_active }),
    "Account status updated.",
    ["admin-users"],
  );
  const accountTypeMutation = runMutation(
    (data: { username: string; account_type: string }) => api.patch(`/user-admin/users/${encodeURIComponent(data.username)}/account-type`, { account_type: data.account_type }),
    "Account type updated.",
    ["admin-users"],
  );
  const identityMutation = runMutation(
    (data: { username: string; full_name: string; job_title: string; contact_info: string }) => api.put(`/user-admin/users/${encodeURIComponent(data.username)}/profile`, data),
    "User profile updated.",
    ["admin-users"],
  );
  const resendInviteMutation = runMutation(
    (inviteId: number) => api.post(`/user-admin/invitations/${inviteId}/resend`),
    "Invitation email queued again.",
    ["admin-invitations"],
    response => setInviteUrl(response.data.registration_url),
  );
  const revokeInviteMutation = runMutation(
    (inviteId: number) => api.delete(`/user-admin/invitations/${inviteId}`),
    "Invitation revoked.",
    ["admin-invitations"],
  );
  const revokeMutation = runMutation(
    (username: string) => api.post(`/user-admin/users/${encodeURIComponent(username)}/revoke-sessions`),
    "All sessions revoked.",
    ["admin-users"],
  );
  const resetMutation = runMutation(
    (data: { username: string; new_password: string }) => api.post(`/user-admin/users/${encodeURIComponent(data.username)}/administrator-reset`, { new_password: data.new_password }),
    "Administrator-assisted password reset completed; prior sessions were revoked.",
    ["admin-users"],
    () => { setResetTarget(""); setResetPassword(""); },
  );
  const recoveryDecisionMutation = runMutation(
    (data: { id: number; approve: boolean; reason: string }) => api.post(`/user-admin/recovery-requests/${data.id}/decision`, { approve: data.approve, reason: data.reason }),
    "Password-reset request reviewed.",
    ["password-reset-requests"],
  );
  const emailDecisionMutation = runMutation(
    (data: { id: number; approve: boolean; reason: string }) => api.post(`/user-admin/email-change-requests/${data.id}/decision`, { approve: data.approve, reason: data.reason }),
    "Recovery-email request reviewed.",
    ["recovery-email-requests", "admin-users"],
  );
  const createRoleMutation = runMutation(
    (data: RoleRecord) => api.post("/user-admin/roles", data),
    "Role created.",
    ["admin-roles", "admin-role-definitions"],
    () => {
      setNewRole({ name: "", allowed_pages: [], allowed_actions: [], allowed_site_types: [] });
      setEditRole("");
      setRoleDraft(null);
      setPermissionSection("pages");
      setPermissionSearch("");
    },
  );
  const updateRoleMutation = runMutation(
    (data: RoleRecord) => api.put(`/user-admin/roles/${encodeURIComponent(data.name)}`, data),
    "Role permissions updated.",
    ["admin-roles", "admin-role-definitions"],
  );

  if (!hasUserAdminAccess) {
    return <div role="alert" style={{ ...panel, color: "var(--text-secondary)" }}>Your role does not include user-management access.</div>;
  }

  const roles = rolesQuery.data || roleDefinitionsQuery.data || [];
  const assignableRoles = roles.filter(role =>
    isAdministratorAccount(user) || !["admin", "administrator"].includes(role.name.toLowerCase())
  );
  const catalog = catalogQuery.data;
  const availableSites = siteTypesQuery.data || [];
  const togglePermission = (role: RoleRecord, key: "allowed_pages" | "allowed_actions" | "allowed_site_types", value: string) => {
    const selected = role[key] || [];
    return { ...role, [key]: selected.includes(value) ? selected.filter(item => item !== value) : [...selected, value] };
  };
  const permissionDraft = roleDraft || newRole;
  const updatePermissionDraft = (next: RoleRecord) => roleDraft ? setRoleDraft(next) : setNewRole(next);
  const tabEntries = catalog ? Object.entries(catalog.tabs).map(([group, items]) => ({
    group,
    label: TAB_GROUP_LABELS[group] || group,
    items,
  })) : [];
  const actionGroups = catalog ? Array.from(
    catalog.actions.filter(action => !action.legacy).reduce((groups, action) => {
      const group = groups.get(action.group) || [];
      group.push(action);
      groups.set(action.group, group);
      return groups;
    }, new Map<string, Catalog["actions"]>()),
  ) : [];
  const allTabKeys = tabEntries.flatMap(group => group.items.map(item => item.key));
  const allActionKeys = catalog?.actions.filter(action => !action.legacy).map(action => action.key) || [];
  const selectedPermissionCounts = {
    pages: permissionDraft.allowed_pages.length,
    tabs: permissionDraft.allowed_actions.filter(action => allTabKeys.includes(action)).length,
    actions: permissionDraft.allowed_actions.filter(action => allActionKeys.includes(action)).length,
    siteTypes: permissionDraft.allowed_site_types.length,
  };
  const permissionQuery = permissionSearch.trim().toLocaleLowerCase();
  const matchesPermission = (key: string, label = "", description = "") =>
    !permissionQuery || `${key} ${label} ${description}`.toLocaleLowerCase().includes(permissionQuery);
  const visiblePages = (catalog?.pages || []).filter(page => matchesPermission(page.key, page.key, page.description));
  const visibleTabGroups = tabEntries.map(group => ({
    ...group,
    items: group.items.filter(item => matchesPermission(item.key, item.label)),
  })).filter(group => group.items.length > 0);
  const visibleActionGroups = actionGroups.map(([group, items]) => [
    group,
    items.filter(item => matchesPermission(item.key, item.key.replace(/^Action: /, ""), item.description)),
  ] as [string, Catalog["actions"]]).filter(([, items]) => items.length > 0);
  const visibleSiteTypes = availableSites.filter(site => matchesPermission(site));
  const visiblePermissionCount = {
    pages: visiblePages.length,
    tabs: visibleTabGroups.reduce((sum, group) => sum + group.items.length, 0),
    actions: visibleActionGroups.reduce((sum, [, items]) => sum + items.length, 0),
    siteTypes: visibleSiteTypes.length,
  }[permissionSection];
  const renderPermission = (
    field: "allowed_pages" | "allowed_actions" | "allowed_site_types",
    key: string,
    label: string,
    description = "",
  ) => {
    const checked = permissionDraft[field].includes(key);
    return <label key={key} style={{
      display: "flex", alignItems: "flex-start", gap: "0.65rem", padding: "0.7rem 0.75rem",
      background: checked ? "var(--bg-tertiary)" : "var(--bg-card)",
      border: `1px solid ${checked ? "var(--accent-blue)" : "var(--border-primary)"}`,
      borderRadius: "var(--radius-sm)", cursor: "pointer", minWidth: 0,
    }}>
      <input
        type="checkbox"
        aria-label={`Grant ${label}`}
        checked={checked}
        onChange={() => updatePermissionDraft(togglePermission(permissionDraft, field, key))}
        style={{ marginTop: 2, accentColor: "var(--accent-blue)" }}
      />
      <span style={{ minWidth: 0, display: "grid", gap: "0.2rem" }}>
        <strong style={{ color: "var(--text-primary)", fontSize: "0.8rem", fontWeight: 650 }}>{label}</strong>
        {description && <span style={{ color: "var(--text-muted)", fontSize: "0.72rem", lineHeight: 1.4 }}>{description}</span>}
        {key !== label && <code style={{ color: "var(--text-muted)", fontSize: "0.65rem", overflowWrap: "anywhere" }}>{key}</code>}
      </span>
    </label>;
  };
  const permissionSectionOptions: { id: RoleEditorSection; label: string; count: number }[] = [
    { id: "pages", label: "Pages", count: selectedPermissionCounts.pages },
    { id: "tabs", label: "Tabs", count: selectedPermissionCounts.tabs },
    { id: "actions", label: "Actions", count: selectedPermissionCounts.actions },
    { id: "siteTypes", label: "Site types", count: selectedPermissionCounts.siteTypes },
  ];

  return (
    <div style={{ display: "grid", gap: "1rem" }}>
      {(notice || error) && (
        <div role={error ? "alert" : "status"} aria-live="polite" style={{ ...panel, padding: "0.75rem 1rem", color: error ? "var(--accent-red)" : "var(--accent-green)" }}>
          {error || notice}
          <button type="button" onClick={() => { setError(""); setNotice(""); }} aria-label="Dismiss message" style={{ float: "right", border: 0, background: "none", color: "inherit", cursor: "pointer" }}>×</button>
        </div>
      )}

      {canManageUsers && <section style={{ ...panel, display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "1rem" }}>
        <div>
          <h3 style={{ marginTop: 0, display: "flex", alignItems: "center", gap: "0.4rem" }}><Mail size={16} /> Invite an individual</h3>
          <p style={{ color: "var(--text-muted)", fontSize: "0.78rem" }}>An email address is required. The invitation is emailed and the user chooses their password.</p>
          <form onSubmit={event => { event.preventDefault(); setInviteUrl(""); inviteMutation.mutate(invite); }} style={{ display: "grid", gap: "0.5rem" }}>
            <input required minLength={3} maxLength={64} placeholder="Username" value={invite.username} onChange={e => setInvite({ ...invite, username: e.target.value })} style={input} />
            <input required type="email" maxLength={254} placeholder="Email address" value={invite.email} onChange={e => setInvite({ ...invite, email: e.target.value })} style={input} />
            <select required value={invite.role} onChange={e => setInvite({ ...invite, role: e.target.value })} style={input}>
              {assignableRoles.map(role => <option key={role.name} value={role.name}>{role.name}</option>)}
            </select>
            <select value={invite.ttl_hours} onChange={e => setInvite({ ...invite, ttl_hours: Number(e.target.value) })} style={input}>
              <option value={24}>Expires in 24 hours</option><option value={72}>Expires in 72 hours</option><option value={168}>Expires in 7 days</option>
            </select>
            <button type="submit" disabled={inviteMutation.isPending || !roles.length} style={button()}><Mail size={14} /> {inviteMutation.isPending ? "Sending invite..." : "Send invitation"}</button>
          </form>
          {inviteUrl && <div style={{ display: "flex", gap: "0.4rem", marginTop: "0.5rem" }}><input readOnly value={inviteUrl} aria-label="Invitation link" style={input} /><button type="button" style={button("var(--accent-green)")} onClick={() => navigator.clipboard.writeText(inviteUrl)}><Copy size={14} /> Copy</button></div>}
        </div>

        <div>
          <h3 style={{ marginTop: 0, display: "flex", alignItems: "center", gap: "0.4rem" }}><Users size={16} /> Create a display account</h3>
          <p style={{ color: "var(--text-muted)", fontSize: "0.78rem" }}>For TV and wall displays. Email is optional; forgotten passwords are handled by an administrator.</p>
          <form onSubmit={event => { event.preventDefault(); displayMutation.mutate(display); }} style={{ display: "grid", gap: "0.5rem" }}>
            <input required minLength={3} maxLength={64} placeholder="Account username" value={display.username} onChange={e => setDisplay({ ...display, username: e.target.value })} style={input} />
            <input maxLength={200} placeholder="Screen or location name" value={display.full_name} onChange={e => setDisplay({ ...display, full_name: e.target.value })} style={input} />
            <input required minLength={12} maxLength={256} type="password" autoComplete="new-password" placeholder="Initial password (12+ characters)" value={display.password} onChange={e => setDisplay({ ...display, password: e.target.value })} style={input} />
            <select required value={display.role} onChange={e => setDisplay({ ...display, role: e.target.value })} style={input}>
              {assignableRoles.map(role => <option key={role.name} value={role.name}>{role.name}</option>)}
            </select>
            <button type="submit" disabled={displayMutation.isPending || !roles.length} style={button("var(--accent-purple)")}><UserPlus size={14} /> {displayMutation.isPending ? "Creating..." : "Create display account"}</button>
          </form>
        </div>
      </section>}

      {canManageUsers && <section style={panel}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "0.75rem" }}>
          <div>
            <h3 style={{ margin: 0 }}>Account directory</h3>
            <p style={{ margin: "0.25rem 0 0", color: "var(--text-muted)", fontSize: "0.78rem" }}>Search and manage people and display accounts.</p>
          </div>
          <button type="button" onClick={() => usersQuery.refetch()} style={button("var(--bg-tertiary)")}><RefreshCw size={14} /> Refresh</button>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "minmax(180px, 2fr) repeat(3, minmax(130px, 1fr))", gap: "0.5rem", margin: "0.9rem 0" }}>
          <div style={{ position: "relative" }}><Search size={15} style={{ position: "absolute", left: 9, top: 11, color: "var(--text-muted)" }} /><input aria-label="Search users" placeholder="Search name, username, email, or role" value={search} onChange={e => setSearch(e.target.value)} style={{ ...input, paddingLeft: "2rem" }} /></div>
          <select aria-label="Account type filter" value={typeFilter} onChange={e => setTypeFilter(e.target.value)} style={input}><option value="all">All account types</option><option value="individual">Individuals</option><option value="display">Display accounts</option></select>
          <select aria-label="Status filter" value={statusFilter} onChange={e => setStatusFilter(e.target.value)} style={input}><option value="all">All statuses</option><option value="active">Active</option><option value="disabled">Disabled</option><option value="email-missing">Recovery email missing</option></select>
          <span style={{ alignSelf: "center", color: "var(--text-muted)", fontSize: "0.78rem" }}>{userRows.length} account{userRows.length === 1 ? "" : "s"}</span>
        </div>
        {usersQuery.isLoading ? <p>Loading users...</p> : usersQuery.isError ? <p role="alert" style={{ color: "var(--accent-red)" }}>{getApiErrorMessage(usersQuery.error, "Unable to load users.")}</p> : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", minWidth: 960, fontSize: "0.78rem" }}>
              <thead><tr style={{ textAlign: "left", color: "var(--text-muted)", borderBottom: "1px solid var(--border-primary)" }}>
                <th style={{ padding: "0.55rem" }}>User</th><th>Account</th><th>Email / recovery</th><th>Role</th><th>Status</th><th>Last sign-in</th><th>Last activity</th><th>Actions</th>
              </tr></thead>
              <tbody>
                {userRows.map(row => (
                  <tr key={row.id} style={{ borderBottom: "1px solid var(--border-primary)" }}>
                    <td style={{ padding: "0.65rem 0.55rem" }}><strong>{row.full_name || row.username}</strong><div style={{ color: "var(--text-muted)" }}>@{row.username}{row.job_title ? ` · ${row.job_title}` : ""}</div></td>
                    <td><select aria-label={`Account type for ${row.username}`} value={row.account_type} disabled={accountTypeMutation.isPending || (!isAdministratorAccount(user) && ["admin", "administrator"].includes(row.role.toLowerCase()))} onChange={e => accountTypeMutation.mutate({ username: row.username, account_type: e.target.value })} style={{ ...input, minWidth: 120, padding: "0.35rem" }}><option value="individual">Individual</option><option value="display">Display</option></select></td>
                    <td>{row.email || <span style={{ color: "var(--text-muted)" }}>No email</span>}<div style={{ color: row.email_status === "verified" ? "var(--accent-green)" : "var(--accent-orange)" }}>{row.email_status.replace(/_/g, " ")}</div>{row.pending_email && <div>Pending: {row.pending_email}</div>}</td>
                    <td><select aria-label={`Role for ${row.username}`} value={row.role} disabled={roleMutation.isPending || (!isAdministratorAccount(user) && ["admin", "administrator"].includes(row.role.toLowerCase()))} onChange={e => roleMutation.mutate({ username: row.username, role: e.target.value })} style={{ ...input, minWidth: 120, padding: "0.35rem" }}>{!roles.some(role => role.name === row.role) && <option value={row.role}>{row.role}</option>}{roles.map(role => <option key={role.name} value={role.name}>{role.name}</option>)}</select></td>
                    <td><span style={{ color: row.is_active ? "var(--accent-green)" : "var(--accent-red)" }}>{row.is_active ? "Active" : "Disabled"}</span>{row.invitation_pending && <div style={{ color: "var(--accent-orange)" }}>Invitation pending</div>}</td>
                    <td>{localTime(row.last_login_at)}</td><td>{localTime(row.last_activity_at)}</td>
                    <td><div style={{ display: "flex", flexWrap: "wrap", gap: "0.3rem" }}>
                      <button type="button" style={button(row.is_active ? "var(--accent-orange)" : "var(--accent-green)")} onClick={() => statusMutation.mutate({ username: row.username, is_active: !row.is_active })}>{row.is_active ? "Disable" : "Reactivate"}</button>
                      <button type="button" style={button("var(--bg-tertiary)")} onClick={() => { setEditingUser(row); setIdentityDraft({ full_name: row.full_name || "", job_title: row.job_title || "", contact_info: row.contact_info || "" }); }}>Edit details</button>
                      <button type="button" style={button("var(--bg-tertiary)")} onClick={() => revokeMutation.mutate(row.username)}>Revoke sessions</button>
                      {(row.account_type === "display" || isAdministratorAccount(user)) && <button type="button" style={button("var(--accent-red)")} onClick={() => { setResetTarget(row.username); setResetPassword(""); }}><KeyRound size={12} /> Admin reset</button>}
                    </div></td>
                  </tr>
                ))}
                {!userRows.length && <tr><td colSpan={8} style={{ padding: "1.25rem", textAlign: "center", color: "var(--text-muted)" }}>No accounts match these filters.</td></tr>}
              </tbody>
            </table>
          </div>
        )}
        {editingUser && <form onSubmit={event => { event.preventDefault(); identityMutation.mutate({ username: editingUser.username, ...identityDraft }); setEditingUser(null); }} style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "0.5rem", marginTop: "0.75rem", padding: "0.75rem", background: "var(--bg-tertiary)", borderRadius: "var(--radius-sm)" }}>
          <strong style={{ gridColumn: "1 / -1" }}>Edit @{editingUser.username}</strong>
          <input aria-label="Full name" maxLength={200} placeholder="Full name" value={identityDraft.full_name} onChange={e => setIdentityDraft({ ...identityDraft, full_name: e.target.value })} style={input} />
          <input aria-label="Job title" maxLength={200} placeholder="Job title" value={identityDraft.job_title} onChange={e => setIdentityDraft({ ...identityDraft, job_title: e.target.value })} style={input} />
          <input aria-label="Contact information" maxLength={500} placeholder="Contact information" value={identityDraft.contact_info} onChange={e => setIdentityDraft({ ...identityDraft, contact_info: e.target.value })} style={input} />
          <div style={{ display: "flex", gap: "0.4rem" }}><button type="submit" disabled={identityMutation.isPending} style={button()}>Save profile</button><button type="button" onClick={() => setEditingUser(null)} style={button("var(--bg-card)")}>Cancel</button></div>
        </form>}
        {resetTarget && <form onSubmit={event => { event.preventDefault(); resetMutation.mutate({ username: resetTarget, new_password: resetPassword }); }} style={{ display: "flex", alignItems: "end", gap: "0.5rem", marginTop: "0.75rem", flexWrap: "wrap" }}>
          <div style={{ flex: 1, minWidth: 220 }}><label htmlFor="display-reset-password" style={{ display: "block", marginBottom: 4 }}>Administrator-assisted reset for @{resetTarget}</label><input id="display-reset-password" required minLength={12} type="password" value={resetPassword} onChange={e => setResetPassword(e.target.value)} style={input} /></div>
          <button type="submit" style={button("var(--accent-red)")}>Reset and revoke sessions</button><button type="button" style={button("var(--bg-tertiary)")} onClick={() => setResetTarget("")}>Cancel</button>
        </form>}
      </section>}

      {canManageUsers && <section style={panel}>
        <h3 style={{ marginTop: 0 }}>Pending invitations</h3>
        {(invitationsQuery.data || []).length === 0 ? <p style={{ color: "var(--text-muted)", fontSize: "0.8rem" }}>No pending invitations.</p> : (
          <div style={{ overflowX: "auto" }}><table style={{ width: "100%", borderCollapse: "collapse", minWidth: 640, fontSize: "0.78rem" }}>
            <thead><tr style={{ textAlign: "left", color: "var(--text-muted)", borderBottom: "1px solid var(--border-primary)" }}><th style={{ padding: "0.55rem" }}>Username</th><th>Email</th><th>Role</th><th>Expires</th><th>Actions</th></tr></thead>
            <tbody>{(invitationsQuery.data || []).map(inviteRow => <tr key={inviteRow.id} style={{ borderBottom: "1px solid var(--border-primary)" }}>
              <td style={{ padding: "0.6rem 0.55rem" }}>{inviteRow.username}</td><td>{inviteRow.email}</td><td>{inviteRow.role}</td><td>{localTime(inviteRow.expires_at)}</td>
              <td style={{ display: "flex", gap: "0.35rem", padding: "0.45rem" }}><button type="button" style={button("var(--accent-purple)")} onClick={() => resendInviteMutation.mutate(inviteRow.id)} disabled={resendInviteMutation.isPending}><Mail size={13} /> Resend</button><button type="button" style={button("var(--accent-red)")} onClick={() => revokeInviteMutation.mutate(inviteRow.id)} disabled={revokeInviteMutation.isPending}>Revoke</button></td>
            </tr>)}</tbody>
          </table></div>
        )}
      </section>}

      {(canReviewRecovery || canApproveEmail) && <section style={panel}>
        <h3 style={{ marginTop: 0, display: "flex", alignItems: "center", gap: "0.4rem" }}><Shield size={16} /> Account security requests</h3>
        {canReviewRecovery && <div style={{ marginBottom: "1rem" }}>
          <h4>Password-reset requests</h4>
          {(resetRequestsQuery.data || []).length === 0 ? <p style={{ color: "var(--text-muted)", fontSize: "0.8rem" }}>No pending password-reset requests.</p> : (resetRequestsQuery.data || []).map(request => {
            const ownRequest = request.user_id === user?.id;
            return <div key={request.id} style={{ borderTop: "1px solid var(--border-primary)", padding: "0.65rem 0", display: "grid", gridTemplateColumns: "minmax(180px, 1fr) minmax(180px, 2fr) auto auto", gap: "0.5rem", alignItems: "center" }}>
            <div><strong>{request.full_name || request.username}</strong><div style={{ color: "var(--text-muted)" }}>@{request.username} · {request.account_type} · {request.email_verified ? request.email : "no approved email"}</div>{ownRequest && <div style={{ color: "var(--accent-orange)", fontSize: "0.7rem" }}>Another user administrator must review your own request.</div>}{(!request.email_verified || request.account_type === "display") && <div style={{ color: "var(--accent-orange)", fontSize: "0.7rem" }}>No reset email is available; use administrator-assisted reset.</div>}</div>
            <input aria-label={`Decision reason for reset ${request.username}`} placeholder="Denial reason (required to deny)" value={requestReasons[request.id] || ""} onChange={e => setRequestReasons({ ...requestReasons, [request.id]: e.target.value })} style={input} />
            <button type="button" disabled={ownRequest || !request.email_verified || request.account_type === "display"} style={button("var(--accent-green)")} onClick={() => recoveryDecisionMutation.mutate({ id: request.id, approve: true, reason: requestReasons[request.id] || "" })}><Check size={13} /> Approve</button>
            <button type="button" disabled={ownRequest || !(requestReasons[request.id] || "").trim()} style={button("var(--accent-red)")} onClick={() => recoveryDecisionMutation.mutate({ id: request.id, approve: false, reason: requestReasons[request.id] || "" })}>Deny</button>
          </div>;
          })}
        </div>}
        {canApproveEmail && <div>
          <h4>Recovery-email changes</h4>
          {(emailRequestsQuery.data || []).length === 0 ? <p style={{ color: "var(--text-muted)", fontSize: "0.8rem" }}>No pending recovery-email requests.</p> : (emailRequestsQuery.data || []).map(request => {
            const ownRequest = request.user_id === user?.id;
            return <div key={request.id} style={{ borderTop: "1px solid var(--border-primary)", padding: "0.65rem 0", display: "grid", gridTemplateColumns: "minmax(180px, 1fr) minmax(180px, 2fr) auto auto", gap: "0.5rem", alignItems: "center" }}>
            <div><strong>{request.full_name || request.username}</strong><div style={{ color: "var(--text-muted)" }}>@{request.username} · Current: {request.current_email || "none"}</div><div>Requested: {request.requested_email}</div>{ownRequest && <div style={{ color: "var(--accent-orange)", fontSize: "0.7rem" }}>Another user administrator must approve your own recovery-email request.</div>}</div>
            <input aria-label={`Decision reason for email change ${request.username}`} placeholder="Denial reason (required to deny)" value={requestReasons[-request.id] || ""} onChange={e => setRequestReasons({ ...requestReasons, [-request.id]: e.target.value })} style={input} />
            <button type="button" disabled={ownRequest} style={button("var(--accent-green)")} onClick={() => emailDecisionMutation.mutate({ id: request.id, approve: true, reason: requestReasons[-request.id] || "" })}><Check size={13} /> Approve</button>
            <button type="button" disabled={ownRequest || !(requestReasons[-request.id] || "").trim()} style={button("var(--accent-red)")} onClick={() => emailDecisionMutation.mutate({ id: request.id, approve: false, reason: requestReasons[-request.id] || "" })}>Deny</button>
          </div>;
          })}
        </div>}
      </section>}

      {canManageRoles && <section style={{ ...panel, padding: 0, overflow: "hidden" }}>
        <div style={{ padding: "1.1rem 1.25rem", borderBottom: "1px solid var(--border-primary)", background: "var(--bg-tertiary)" }}>
          <h3 style={{ margin: 0, display: "flex", alignItems: "center", gap: "0.5rem", color: "var(--text-primary)" }}><Shield size={17} /> Role &amp; permission editor</h3>
          <p style={{ margin: "0.35rem 0 0", color: "var(--text-muted)", fontSize: "0.78rem", lineHeight: 1.45 }}>
            Assign page access, tab visibility, actions, and site scope separately. Grants are default-deny and apply to every account assigned this role.
          </p>
        </div>
        {catalogQuery.isLoading || siteTypesQuery.isLoading ? <div role="status" style={{ padding: "1.25rem", color: "var(--text-muted)" }}>Loading permission catalog...</div> : catalogQuery.isError || siteTypesQuery.isError ? <div role="alert" style={{ padding: "1.25rem", color: "var(--accent-red)" }}>{getApiErrorMessage(catalogQuery.error || siteTypesQuery.error)}</div> : catalog && <>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", alignItems: "end", gap: "0.75rem", padding: "1rem 1.25rem" }}>
            <label htmlFor="role-to-edit" style={{ display: "grid", gap: "0.35rem", color: "var(--text-secondary)", fontSize: "0.74rem", fontWeight: 600 }}>
              Role to edit
              <select id="role-to-edit" value={editRole} onChange={event => {
                const name = event.target.value;
                setEditRole(name);
                setPermissionSection("pages");
                setPermissionSearch("");
                const role = roles.find(item => item.name === name);
                setRoleDraft(role ? {
                  ...role,
                  allowed_pages: [...(role.allowed_pages || [])],
                  allowed_actions: [...(role.allowed_actions || [])],
                  allowed_site_types: [...(role.allowed_site_types || [])],
                } : null);
                if (!name) setNewRole({ name: "", allowed_pages: [], allowed_actions: [], allowed_site_types: [] });
              }} style={input}>
                <option value="">Create a new role</option>
                {roles.filter(role => !["admin", "administrator"].includes(role.name.toLowerCase())).map(role => <option key={role.name} value={role.name}>{role.name}</option>)}
              </select>
            </label>
            <label htmlFor="role-name" style={{ display: "grid", gap: "0.35rem", color: "var(--text-secondary)", fontSize: "0.74rem", fontWeight: 600 }}>
              Role name
              <input id="role-name" disabled={!!roleDraft} maxLength={64} placeholder="e.g. regional-operator" value={permissionDraft.name} onChange={event => updatePermissionDraft({ ...permissionDraft, name: event.target.value })} style={input} />
            </label>
            <button type="button" style={{ ...button("var(--bg-card)"), border: "1px solid var(--border-primary)", color: "var(--text-primary)", justifyContent: "center" }} onClick={() => {
              setEditRole("");
              setRoleDraft(null);
              setNewRole({ name: "", allowed_pages: [], allowed_actions: [], allowed_site_types: [] });
              setPermissionSection("pages");
              setPermissionSearch("");
            }}><Plus size={14} /> New role</button>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))", gap: "0.55rem", padding: "0 1.25rem 1rem" }} aria-label="Selected permission counts">
            {permissionSectionOptions.map(section => <div key={section.id} style={{ padding: "0.55rem 0.7rem", border: "1px solid var(--border-primary)", borderRadius: "var(--radius-sm)", background: "var(--bg-card)" }}>
              <div style={{ color: "var(--text-muted)", fontSize: "0.68rem", textTransform: "uppercase", letterSpacing: "0.04em" }}>{section.label} granted</div>
              <strong style={{ display: "block", marginTop: 2, color: "var(--text-primary)", fontSize: "1rem" }}>{section.count}</strong>
            </div>)}
          </div>

          <div style={{ borderTop: "1px solid var(--border-primary)" }}>
            <div role="group" aria-label="Permission category" style={{ display: "flex", flexWrap: "wrap", gap: "0.4rem", padding: "0.75rem 1.25rem", background: "var(--bg-tertiary)", borderBottom: "1px solid var(--border-primary)" }}>
              {permissionSectionOptions.map(section => {
                const active = permissionSection === section.id;
                return <button key={section.id} type="button" aria-pressed={active} onClick={() => { setPermissionSection(section.id); setPermissionSearch(""); }} style={{
                  display: "inline-flex", alignItems: "center", gap: "0.45rem", padding: "0.48rem 0.7rem",
                  border: `1px solid ${active ? "var(--accent-blue)" : "var(--border-primary)"}`,
                  borderRadius: "var(--radius-sm)", background: active ? "var(--accent-blue)" : "var(--bg-card)",
                  color: active ? "#fff" : "var(--text-secondary)", cursor: "pointer", fontWeight: 650, fontSize: "0.76rem",
                }}>
                  {section.label}<span style={{ minWidth: 18, padding: "0.05rem 0.3rem", borderRadius: 999, background: active ? "rgba(255,255,255,0.2)" : "var(--bg-tertiary)", textAlign: "center", fontSize: "0.68rem" }}>{section.count}</span>
                </button>;
              })}
            </div>

            <div style={{ padding: "0.85rem 1.25rem 1rem" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: "0.75rem", flexWrap: "wrap", marginBottom: "0.85rem" }}>
                <div>
                  <strong style={{ color: "var(--text-primary)", fontSize: "0.85rem" }}>{permissionSectionOptions.find(section => section.id === permissionSection)?.label} permissions</strong>
                  <div style={{ color: "var(--text-muted)", fontSize: "0.72rem", marginTop: 2 }}>Select only the access this role needs.</div>
                </div>
                <div style={{ position: "relative", width: "min(100%, 320px)" }}>
                  <Search size={15} aria-hidden="true" style={{ position: "absolute", left: 10, top: 10, color: "var(--text-muted)" }} />
                  <input aria-label={`Search ${permissionSectionOptions.find(section => section.id === permissionSection)?.label} permissions`} value={permissionSearch} onChange={event => setPermissionSearch(event.target.value)} placeholder="Filter this category" style={{ ...input, paddingLeft: "2rem" }} />
                </div>
              </div>

              <div id="role-permissions-panel" style={{ display: "grid", gap: "0.85rem" }}>
                {permissionSection === "pages" && <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(250px, 1fr))", gap: "0.55rem" }}>
                  {visiblePages.map(page => renderPermission("allowed_pages", page.key, page.key, page.description))}
                </div>}

                {permissionSection === "tabs" && visibleTabGroups.map(group => <fieldset key={group.group} style={{ border: "1px solid var(--border-primary)", borderRadius: "var(--radius-sm)", padding: "0.75rem", margin: 0, minWidth: 0 }}>
                  <legend style={{ padding: "0 0.35rem", color: "var(--text-secondary)", fontSize: "0.74rem", fontWeight: 700 }}>{group.label}</legend>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(250px, 1fr))", gap: "0.55rem" }}>
                    {group.items.map(item => renderPermission("allowed_actions", item.key, item.label))}
                  </div>
                </fieldset>)}

                {permissionSection === "actions" && visibleActionGroups.map(([group, actions]) => <fieldset key={group} style={{ border: "1px solid var(--border-primary)", borderRadius: "var(--radius-sm)", padding: "0.75rem", margin: 0, minWidth: 0 }}>
                  <legend style={{ padding: "0 0.35rem", color: "var(--text-secondary)", fontSize: "0.74rem", fontWeight: 700 }}>{group}</legend>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(250px, 1fr))", gap: "0.55rem" }}>
                    {actions.map(action => renderPermission("allowed_actions", action.key, action.key.replace(/^Action: /, ""), action.description))}
                  </div>
                </fieldset>)}

                {permissionSection === "siteTypes" && <>
                  <p style={{ margin: 0, color: "var(--text-muted)", fontSize: "0.74rem" }}>Site types scope the facility data available to this role.</p>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "0.55rem" }}>
                    {visibleSiteTypes.map(site => renderPermission("allowed_site_types", site, site))}
                  </div>
                </>}

                {visiblePermissionCount === 0 && <p role="status" style={{ margin: 0, padding: "1rem", textAlign: "center", color: "var(--text-muted)", border: "1px dashed var(--border-primary)", borderRadius: "var(--radius-sm)" }}>No permissions match this filter.</p>}
              </div>
            </div>
          </div>

          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: "0.75rem", flexWrap: "wrap", padding: "0.85rem 1.25rem", borderTop: "1px solid var(--border-primary)", background: "var(--bg-tertiary)" }}>
            <span style={{ color: "var(--text-muted)", fontSize: "0.72rem" }}>Changes affect all accounts assigned to this role.</span>
            <button type="button" disabled={createRoleMutation.isPending || updateRoleMutation.isPending || !permissionDraft.name.trim()} style={button("var(--accent-green)")} onClick={() => roleDraft ? updateRoleMutation.mutate(permissionDraft) : createRoleMutation.mutate(permissionDraft)}>
              <Save size={14} /> {createRoleMutation.isPending || updateRoleMutation.isPending ? "Saving..." : roleDraft ? "Save permission changes" : "Create role"}
            </button>
          </div>
        </>}
      </section>}
    </div>
  );
}

function isAdministratorAccount(user: { role?: string } | null) {
  return ["admin", "administrator"].includes(String(user?.role || "").toLowerCase());
}
