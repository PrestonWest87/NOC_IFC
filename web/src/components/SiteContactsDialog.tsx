import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2, Plus, RefreshCw, Save, Trash2, X } from "lucide-react";
import api, { getApiErrorMessage } from "../utils/api";

type ContactField = "name" | "phone" | "email";
type SiteContact = { id?: number; name: string; phone: string; email: string };
type SiteContactPayload = { name: string | null; phone: string | null; email: string | null };
type ContactErrors = Partial<Record<ContactField, string>>;

const emailPattern = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$/;
const phoneExtensionPattern = / *(?:ext\.?|x|#) *[0-9]{1,10}$/i;
const phoneCorePattern = /^\+?(?:[0-9]|\([0-9]{1,5}\))[0-9(). -]*$/;
const fieldLimits: Record<ContactField, number> = { name: 128, phone: 64, email: 254 };
const inputStyle: React.CSSProperties = {
  width: "100%",
  boxSizing: "border-box",
  padding: "0.5rem 0.6rem",
  border: "1px solid var(--border-primary)",
  borderRadius: "var(--radius-sm)",
  color: "var(--text-primary)",
  background: "var(--bg-input)",
  fontSize: "0.82rem",
};
const buttonStyle = (color: string): React.CSSProperties => ({
  border: 0,
  borderRadius: "var(--radius-sm)",
  padding: "0.5rem 0.75rem",
  background: color,
  color: "#fff",
  cursor: "pointer",
  fontWeight: 650,
  display: "inline-flex",
  alignItems: "center",
  justifyContent: "center",
  gap: "0.35rem",
  fontSize: "0.78rem",
});

function validateContactField(field: ContactField, rawValue: string): string | undefined {
  if (/[\x00-\x1f\x7f]/.test(rawValue)) return "Control characters are not allowed.";
  const value = rawValue.trim();
  if (!value) return undefined;
  if (value.length > fieldLimits[field]) return `Use at most ${fieldLimits[field]} characters.`;
  if (field === "email" && !emailPattern.test(value)) {
    return "Enter one valid email address.";
  }
  if (field !== "phone") return undefined;

  const extension = phoneExtensionPattern.exec(value);
  const number = (extension ? value.slice(0, extension.index) : value).trimEnd();
  if (!phoneCorePattern.test(number)) {
    return "Use digits, an optional leading +, common separators, and an optional extension.";
  }
  const openingCount = (number.match(/\(/g) || []).length;
  const closingCount = (number.match(/\)/g) || []).length;
  if (openingCount !== closingCount || openingCount > 1) {
    return "Use balanced parentheses.";
  }
  if (openingCount) {
    const opening = number.indexOf("(");
    const closing = number.indexOf(")", opening + 1);
    if (closing < 0 || number.indexOf(")") !== closing) return "Use balanced parentheses.";
    if (!/^\d+$/.test(number.slice(opening + 1, closing))) {
      return "Parentheses must contain digits.";
    }
  }
  const digitCount = (number.match(/[0-9]/g) || []).length;
  if (digitCount < 7 || digitCount > 15) {
    return "Use 7 to 15 phone digits, excluding an optional extension.";
  }
  return undefined;
}

/** Administrator-only editor for reference contacts attached to one site. */
export function SiteContactsDialog({
  siteId,
  siteName,
  onClose,
}: {
  siteId: number;
  siteName: string;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const titleRef = useRef<HTMLHeadingElement>(null);
  const [contacts, setContacts] = useState<SiteContact[]>([]);
  const [fieldErrors, setFieldErrors] = useState<Record<number, ContactErrors>>({});
  const [formError, setFormError] = useState("");
  const [saveStatus, setSaveStatus] = useState("");
  const queryKey = ["admin-site-contacts", siteId];

  const contactsQuery = useQuery({
    queryKey,
    queryFn: () => api.get(`/admin/location/${siteId}/contacts`).then((response) => response.data),
  });

  useEffect(() => {
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    titleRef.current?.focus();
    return () => previousFocus?.focus();
  }, [siteId]);

  useEffect(() => {
    if (!contactsQuery.data) return;
    setContacts((contactsQuery.data.contacts || []).map((contact: any) => ({
      id: contact.id,
      name: contact.name || "",
      phone: contact.phone || "",
      email: contact.email || "",
    })));
    setFieldErrors({});
  }, [contactsQuery.data]);

  const saveMutation = useMutation({
    mutationFn: (updatedContacts: SiteContactPayload[]) =>
      api.put(`/admin/location/${siteId}/contacts`, { contacts: updatedContacts }),
    onSuccess: (response) => {
      const saved = response.data.contacts || [];
      setContacts(saved.map((contact: any) => ({
        id: contact.id,
        name: contact.name || "",
        phone: contact.phone || "",
        email: contact.email || "",
      })));
      setFieldErrors({});
      setFormError("");
      setSaveStatus("Site contacts saved.");
      queryClient.setQueryData(queryKey, { contacts: saved });
    },
    onError: (error: any) => {
      setSaveStatus("");
      setFormError(getApiErrorMessage(error, "Site contacts could not be saved."));
    },
  });

  const updateContact = (index: number, field: ContactField, value: string) => {
    setContacts((current) => current.map((contact, currentIndex) =>
      currentIndex === index ? { ...contact, [field]: value } : contact,
    ));
    setFieldErrors((current) => ({
      ...current,
      [index]: { ...current[index], [field]: undefined },
    }));
    setFormError("");
    setSaveStatus("");
  };

  const saveContacts = () => {
    const errors: Record<number, ContactErrors> = {};
    contacts.forEach((contact, index) => {
      const rowErrors: ContactErrors = {};
      (Object.keys(fieldLimits) as ContactField[]).forEach((field) => {
        const error = validateContactField(field, contact[field]);
        if (error) rowErrors[field] = error;
      });
      if (Object.keys(rowErrors).length) errors[index] = rowErrors;
    });
    if (Object.keys(errors).length) {
      setFieldErrors(errors);
      setFormError("Correct the highlighted contact fields before saving.");
      setSaveStatus("");
      return;
    }

    const updatedContacts = contacts
      .map(({ name, phone, email }) => ({
        name: name.trim() || null,
        phone: phone.trim() || null,
        email: email.trim() || null,
      }))
      .filter((contact) => contact.name || contact.phone || contact.email);
    setFieldErrors({});
    setFormError("");
    setSaveStatus("");
    saveMutation.mutate(updatedContacts);
  };

  const addContact = () => {
    setContacts((current) => [...current, { name: "", phone: "", email: "" }]);
    setFormError("");
    setSaveStatus("");
  };

  const removeContact = (index: number) => {
    setContacts((current) => current.filter((_, currentIndex) => currentIndex !== index));
    setFieldErrors((current) => {
      const next: Record<number, ContactErrors> = {};
      Object.entries(current).forEach(([row, errors]) => {
        const oldIndex = Number(row);
        if (oldIndex < index) next[oldIndex] = errors;
        if (oldIndex > index) next[oldIndex - 1] = errors;
      });
      return next;
    });
    setFormError("");
    setSaveStatus("");
  };

  const field = (index: number, name: ContactField, label: string, type: string, placeholder: string) => {
    const error = fieldErrors[index]?.[name];
    const errorId = `site-contact-${siteId}-${index}-${name}-error`;
    return (
      <label style={{ display: "block", color: "var(--text-secondary)", fontSize: "0.76rem" }}>
        {label}
        <input
          style={{ ...inputStyle, marginTop: "0.25rem", borderColor: error ? "var(--accent-red)" : undefined }}
          type={type}
          value={contacts[index][name]}
          maxLength={fieldLimits[name]}
          placeholder={placeholder}
          autoComplete={name === "name" ? "name" : name === "email" ? "email" : "tel"}
          aria-invalid={Boolean(error)}
          aria-describedby={error ? errorId : undefined}
          onChange={(event) => updateContact(index, name, event.target.value)}
        />
        {error && <span id={errorId} role="alert" style={{ display: "block", marginTop: "0.2rem", color: "var(--accent-red)" }}>{error}</span>}
      </label>
    );
  };

  return (
    <div
      onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}
      style={{
        position: "fixed", inset: 0, zIndex: 1100, display: "flex", justifyContent: "center",
        alignItems: "center", padding: "1rem", background: "rgba(0,0,0,0.68)",
      }}
    >
      <section
        role="dialog"
        aria-modal="true"
        aria-labelledby={`site-contacts-title-${siteId}`}
        onKeyDown={(event) => { if (event.key === "Escape") onClose(); }}
        style={{
          width: "min(720px, 100%)", maxHeight: "90vh", overflowY: "auto",
          background: "var(--bg-card)", color: "var(--text-primary)",
          border: "1px solid var(--border-primary)", borderRadius: "var(--radius-md)",
          boxShadow: "0 16px 48px rgba(0,0,0,0.5)", padding: "1.1rem",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: "1rem" }}>
          <div>
            <h3
              id={`site-contacts-title-${siteId}`}
              ref={titleRef}
              tabIndex={-1}
              style={{ margin: 0, fontSize: "1rem" }}
            >
              Site Contacts — {siteName}
            </h3>
            <p style={{ margin: "0.45rem 0 0", color: "var(--text-muted)", fontSize: "0.78rem" }}>
              Contact details are reference information in automatic ONPAGE email bodies. IFC does not send email to these addresses.
            </p>
          </div>
          <button type="button" onClick={onClose} aria-label="Close site contacts" style={{ ...buttonStyle("var(--bg-tertiary)"), padding: "0.4rem" }}>
            <X size={16} />
          </button>
        </div>

        {contactsQuery.isLoading && <div role="status" style={{ padding: "1.5rem 0", color: "var(--text-muted)" }}><Loader2 size={15} className="spin" /> Loading contacts...</div>}
        {contactsQuery.isError && (
          <div role="alert" style={{ marginTop: "1rem", color: "var(--accent-red)", fontSize: "0.82rem" }}>
            {getApiErrorMessage(contactsQuery.error, "Site contacts could not be loaded.")}
            <button type="button" onClick={() => contactsQuery.refetch()} style={{ ...buttonStyle("var(--accent-blue)"), marginLeft: "0.75rem" }}>
              <RefreshCw size={14} /> Retry
            </button>
          </div>
        )}

        {contactsQuery.isSuccess && (
          <>
            <div style={{ display: "flex", flexDirection: "column", gap: "0.7rem", marginTop: "1rem" }}>
              {contacts.length === 0 && (
                <p style={{ margin: 0, color: "var(--text-muted)", fontSize: "0.82rem" }}>
                  No contacts are listed for this site.
                </p>
              )}
              {contacts.map((contact, index) => (
                <div key={contact.id ?? `new-${index}`} style={{
                  display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr)) auto", alignItems: "start",
                  gap: "0.65rem", padding: "0.75rem", border: "1px solid var(--border-primary)", borderRadius: "var(--radius-sm)",
                }}>
                  {field(index, "name", "Name (optional)", "text", "Site contact")}
                  {field(index, "phone", "Phone (optional)", "tel", "+1 (555) 555-0123 ext 4")}
                  {field(index, "email", "Email (optional)", "email", "contact@example.com")}
                  <button
                    type="button"
                    onClick={() => removeContact(index)}
                    aria-label={`Remove contact ${index + 1}`}
                    style={{ ...buttonStyle("var(--accent-red)"), marginTop: "1.2rem", padding: "0.45rem" }}
                  >
                    <Trash2 size={15} />
                  </button>
                </div>
              ))}
            </div>

            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: "0.75rem", flexWrap: "wrap", marginTop: "0.9rem" }}>
              <button
                type="button"
                onClick={addContact}
                disabled={contacts.length >= 50 || saveMutation.isPending}
                style={{ ...buttonStyle("var(--accent-blue)"), opacity: contacts.length >= 50 ? 0.6 : 1 }}
              >
                <Plus size={14} /> Add contact
              </button>
              <button
                type="button"
                onClick={saveContacts}
                disabled={!contactsQuery.isSuccess || saveMutation.isPending}
                style={buttonStyle("var(--accent-green)")}
              >
                {saveMutation.isPending ? <Loader2 size={14} className="spin" /> : <Save size={14} />}
                {saveMutation.isPending ? "Saving..." : "Save contacts"}
              </button>
            </div>
            {contacts.length >= 50 && <p role="status" style={{ color: "var(--text-muted)", fontSize: "0.74rem" }}>A site can have at most 50 contacts.</p>}
          </>
        )}

        {formError && <p role="alert" style={{ margin: "0.8rem 0 0", color: "var(--accent-red)", fontSize: "0.82rem" }}>{formError}</p>}
        {saveStatus && <p role="status" aria-live="polite" style={{ margin: "0.8rem 0 0", color: "var(--accent-green)", fontSize: "0.82rem" }}>{saveStatus}</p>}
      </section>
    </div>
  );
}
