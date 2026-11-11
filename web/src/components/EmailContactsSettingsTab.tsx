import { useEffect, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Plus, Save, Trash2 } from "lucide-react";
import api, { getApiErrorMessage } from "../utils/api";

type FiberContact = {
  id?: number;
  name: string;
  company: string;
  email: string;
  phone: string;
};
type OnpageContact = {
  id?: number;
  department: string;
  email: string;
};

const cardStyle: React.CSSProperties = {
  background: "var(--bg-card)", border: "1px solid var(--border-primary)",
  borderRadius: "var(--radius-md)", padding: "1rem", color: "var(--text-primary)",
};
const inputStyle: React.CSSProperties = {
  width: "100%", boxSizing: "border-box", padding: "0.45rem 0.55rem",
  borderRadius: "var(--radius-sm)", border: "1px solid var(--border-primary)",
  background: "var(--bg-input)", color: "var(--text-primary)", font: "inherit", fontSize: "0.78rem",
};
const buttonStyle: React.CSSProperties = {
  display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 6,
  padding: "0.45rem 0.7rem", border: 0, borderRadius: "var(--radius-sm)",
  background: "var(--accent-blue)", color: "#fff", fontWeight: 650, cursor: "pointer",
};

function ContactTable({
  title,
  emptyMessage,
  columns,
  rows,
  canManage,
  pending,
  onAdd,
  onChange,
  onRemove,
  onSave,
}: {
  title: string;
  emptyMessage: string;
  columns: { key: string; label: string; placeholder?: string; maxLength?: number }[];
  rows: any[];
  canManage: boolean;
  pending: boolean;
  onAdd: () => void;
  onChange: (index: number, key: string, value: string) => void;
  onRemove: (index: number) => void;
  onSave: () => void;
}) {
  return <section style={{ ...cardStyle, minWidth: 0 }}>
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, marginBottom: 12 }}>
      <h3 style={{ margin: 0, fontSize: "0.95rem" }}>{title}</h3>
      {canManage && <button type="button" style={buttonStyle} onClick={onAdd}><Plus size={14} />Add contact</button>}
    </div>
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", minWidth: 520, borderCollapse: "collapse", fontSize: "0.78rem" }}>
        <thead><tr>
          {columns.map(column => <th key={column.key} scope="col" style={{ textAlign: "left", padding: "0.5rem", borderBottom: "1px solid var(--border-primary)" }}>{column.label}</th>)}
          {canManage && <th scope="col" aria-label="Row actions" style={{ borderBottom: "1px solid var(--border-primary)" }} />}
        </tr></thead>
        <tbody>{rows.map((row, index) => <tr key={row.id ?? `new-${index}`}>
          {columns.map(column => <td key={column.key} style={{ padding: "0.4rem", borderBottom: "1px solid var(--border-primary)" }}>
            <input
              aria-label={`${title} ${column.label} ${index + 1}`}
              value={String(row[column.key] || "")}
              placeholder={column.placeholder || column.label}
              maxLength={column.maxLength || (column.key === "email" ? 254 : column.key === "phone" ? 64 : 200)}
              disabled={!canManage || pending}
              onChange={event => onChange(index, column.key, event.target.value)}
              style={{ ...inputStyle, opacity: canManage ? 1 : 0.8 }}
            />
          </td>)}
          {canManage && <td style={{ padding: "0.4rem", borderBottom: "1px solid var(--border-primary)" }}>
            <button type="button" aria-label={`Remove ${title} row ${index + 1}`} onClick={() => onRemove(index)} disabled={pending}
              style={{ background: "transparent", border: 0, color: "var(--accent-red)", cursor: "pointer" }}><Trash2 size={16} /></button>
          </td>}
        </tr>)}
        {!rows.length && <tr><td colSpan={columns.length + (canManage ? 1 : 0)} style={{ padding: "1rem", color: "var(--text-muted)", textAlign: "center" }}>{emptyMessage}</td></tr>}
        </tbody>
      </table>
    </div>
    {canManage && <div style={{ marginTop: 12 }}>
      <button type="button" onClick={onSave} disabled={pending} style={{ ...buttonStyle, opacity: pending ? 0.7 : 1 }}><Save size={14} />{pending ? "Saving..." : "Save contacts"}</button>
    </div>}
  </section>;
}

export function EmailContactsSettingsTab({ canManage }: { canManage: boolean }) {
  const [fiber, setFiber] = useState<FiberContact[]>([]);
  const [onpage, setOnpage] = useState<OnpageContact[]>([]);
  const [notice, setNotice] = useState<{ message: string; error?: boolean } | null>(null);
  const contactsQuery = useQuery({
    queryKey: ["settings-email-contacts"],
    queryFn: () => api.get("/settings/email-contacts").then(response => response.data),
  });

  useEffect(() => {
    if (!contactsQuery.data) return;
    setFiber((contactsQuery.data.fiber || []).map((row: FiberContact) => ({ ...row, phone: row.phone || "" })));
    setOnpage(contactsQuery.data.onpage || []);
  }, [contactsQuery.data]);

  const fiberMutation = useMutation({
    mutationFn: (contacts: FiberContact[]) => api.put("/admin/email-contacts/fiber", {
      contacts: contacts.map(({ name, company, email, phone }) => ({ name, company, email, phone: phone || null })),
    }).then(response => response.data),
    onSuccess: result => {
      setFiber(result.contacts.map((row: FiberContact) => ({ ...row, phone: row.phone || "" })));
      setNotice({ message: "Fiber contacts saved." });
    },
    onError: error => setNotice({ message: getApiErrorMessage(error, "Fiber contacts could not be saved."), error: true }),
  });
  const onpageMutation = useMutation({
    mutationFn: (contacts: OnpageContact[]) => api.put("/admin/email-contacts/onpage", {
      contacts: contacts.map(({ department, email }) => ({ department, email })),
    }).then(response => response.data),
    onSuccess: result => {
      setOnpage(result.contacts);
      setNotice({ message: "ONPAGE contacts saved." });
    },
    onError: error => setNotice({ message: getApiErrorMessage(error, "ONPAGE contacts could not be saved."), error: true }),
  });

  if (contactsQuery.isLoading) return <div style={{ color: "var(--text-secondary)" }}>Loading email contacts...</div>;
  if (contactsQuery.isError) return <div role="alert" style={{ color: "var(--accent-red)" }}>{getApiErrorMessage(contactsQuery.error, "Email contacts could not be loaded.")}</div>;

  return <div style={{ display: "grid", gap: "1rem" }}>
    <div>
      <h3 style={{ margin: "0 0 0.35rem", color: "var(--text-primary)" }}>Email Contacts</h3>
      <p style={{ margin: 0, color: "var(--text-muted)", fontSize: "0.78rem" }}>
        Maintain the Fiber company contact list and ONPAGE department email directory.
      </p>
    </div>
    {notice && <div role={notice.error ? "alert" : "status"} style={{ ...cardStyle, padding: "0.65rem", color: notice.error ? "var(--accent-red)" : "var(--accent-green)" }}>{notice.message}</div>}
    <ContactTable
      title="Fiber"
      emptyMessage="No Fiber contacts are configured."
      columns={[
        { key: "name", label: "Name", maxLength: 128 },
        { key: "company", label: "Company", maxLength: 200 },
        { key: "email", label: "Email", maxLength: 254 },
        { key: "phone", label: "Phone", placeholder: "Optional", maxLength: 64 },
      ]}
      rows={fiber}
      canManage={canManage}
      pending={fiberMutation.isPending}
      onAdd={() => { setFiber(rows => [...rows, { name: "", company: "", email: "", phone: "" }]); setNotice(null); }}
      onChange={(index, key, value) => setFiber(rows => rows.map((row, rowIndex) => rowIndex === index ? { ...row, [key]: value } : row))}
      onRemove={index => setFiber(rows => rows.filter((_row, rowIndex) => rowIndex !== index))}
      onSave={() => { setNotice(null); fiberMutation.mutate(fiber); }}
    />
    <ContactTable
      title="ONPAGE"
      emptyMessage="No ONPAGE contacts are configured."
      columns={[
        { key: "department", label: "Department", maxLength: 128 },
        { key: "email", label: "Email", maxLength: 254 },
      ]}
      rows={onpage}
      canManage={canManage}
      pending={onpageMutation.isPending}
      onAdd={() => { setOnpage(rows => [...rows, { department: "", email: "" }]); setNotice(null); }}
      onChange={(index, key, value) => setOnpage(rows => rows.map((row, rowIndex) => rowIndex === index ? { ...row, [key]: value } : row))}
      onRemove={index => setOnpage(rows => rows.filter((_row, rowIndex) => rowIndex !== index))}
      onSave={() => { setNotice(null); onpageMutation.mutate(onpage); }}
    />
  </div>;
}
