import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CalendarClock, ClipboardList, Mail, Paperclip, Save, Send, Shield, X } from "lucide-react";
import api, { getApiErrorMessage } from "../utils/api";
import { useAuth } from "../utils/AuthContext";
import { isAdministrator } from "../utils/permissions";

type TemplateField = {
  key: string; label: string; required: boolean; max_length: number;
  options?: string[]; multiline?: boolean; visible?: boolean; input_type?: string;
};
type EmailTemplate = {
  key: string;
  label: string;
  description: string;
  fields: TemplateField[];
  allows_bcc: boolean;
  allows_cc: boolean;
  allows_attachments: boolean;
  default_subject: string;
  default_body: string;
  default_to: string;
  default_cc: string;
  default_bcc: string;
};
type EmailAttachment = { filename: string; content_type: string; content_base64: string; size_bytes?: number };
type EmailSignature = {
  id: number; name: string; content: string; is_active: boolean; is_default: boolean;
  created_at?: string | null; updated_at?: string | null;
};
type EmailSignatureDraft = {
  id: number | null; name: string; content: string; is_active: boolean; is_default: boolean;
};
type ContactOption = { key: string; label: string; email: string };
type ReferenceData = {
  fiber_contacts: { id: number; name: string; company: string; email: string; phone?: string | null }[];
  onpage_contacts: { id: number; department: string; email: string }[];
  network_orders: { id: number; a_location: string; z_location: string; circuit_network_order_id: string; company: string }[];
};

const inputStyle: React.CSSProperties = {
  width: "100%", boxSizing: "border-box", padding: "0.55rem 0.65rem", borderRadius: 6,
  border: "1px solid var(--border-primary)", background: "var(--bg-input)", color: "var(--text-primary)",
  font: "inherit", fontSize: "0.82rem",
};
const labelStyle: React.CSSProperties = { display: "block", marginBottom: 4, color: "var(--text-secondary)", fontSize: "0.76rem" };
const cardStyle: React.CSSProperties = {
  padding: "1rem", border: "1px solid var(--border-primary)", borderRadius: 8,
  background: "var(--bg-card)", color: "var(--text-primary)",
};
const buttonStyle: React.CSSProperties = {
  display: "inline-flex", alignItems: "center", gap: 6, padding: "0.55rem 0.8rem",
  border: "1px solid var(--border-primary)", borderRadius: 6, background: "var(--accent-blue)",
  color: "#fff", fontWeight: 650, cursor: "pointer",
};

function renderTemplate(text: string, fields: Record<string, string>): string {
  return String(text || "").replace(/\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}/g, (_match, key: string) => fields[key] || "");
}

function chicagoInputValue(date: Date): string {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "America/Chicago", year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", hourCycle: "h23",
  }).formatToParts(date);
  const part = (type: string) => parts.find(item => item.type === type)?.value || "00";
  return `${part("year")}-${part("month")}-${part("day")}T${part("hour")}:${part("minute")}`;
}

function chicagoInputToIso(value: string): string {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/.exec(value);
  if (!match) throw new Error("Select a valid Central date and time.");
  const wanted = match.slice(1).map(Number);
  let instant = Date.UTC(wanted[0], wanted[1] - 1, wanted[2], wanted[3], wanted[4]);
  const formatter = new Intl.DateTimeFormat("en-US", {
    timeZone: "America/Chicago", year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", hourCycle: "h23",
  });
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const parts = formatter.formatToParts(new Date(instant));
    const valueFor = (type: string) => Number(parts.find(item => item.type === type)?.value || 0);
    const shown = Date.UTC(valueFor("year"), valueFor("month") - 1, valueFor("day"), valueFor("hour"), valueFor("minute"));
    const delta = Date.UTC(wanted[0], wanted[1] - 1, wanted[2], wanted[3], wanted[4]) - shown;
    if (delta === 0) break;
    instant += delta;
  }
  const result = new Date(instant);
  if (chicagoInputValue(result) !== value) throw new Error("That Central time does not exist because of a daylight-saving transition.");
  return result.toISOString();
}

async function fileToAttachment(file: File): Promise<EmailAttachment> {
  if (file.size > 5 * 1024 * 1024) throw new Error(`${file.name} exceeds the 5 MiB per-file limit.`);
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = "";
  const chunkSize = 0x8000;
  for (let index = 0; index < bytes.length; index += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunkSize));
  }
  return {
    filename: file.name,
    content_type: file.type || "application/octet-stream",
    content_base64: btoa(binary),
    size_bytes: file.size,
  };
}

function formatTime(value?: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short", timeZone: "America/Chicago" }).format(date);
}

function uniqueAddresses(values: string[]): string[] {
  const seen = new Set<string>();
  return values.map(value => value.trim()).filter(value => {
    const key = value.toLocaleLowerCase();
    if (!value || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function mergeSelectedAddresses(current: string, previousAutomatic: string[], nextAutomatic: string[]): string {
  const oldAutomatic = new Set(previousAutomatic.map(value => value.toLocaleLowerCase()));
  const manuallyEntered = String(current || "").split(/[,;]/).map(value => value.trim())
    .filter(value => value && !oldAutomatic.has(value.toLocaleLowerCase()));
  return uniqueAddresses([...manuallyEntered, ...nextAutomatic]).join(", ");
}

function TemplateFieldInput({ field, value, onChange, readOnly = false }: {
  field: TemplateField; value: string; onChange: (value: string) => void; readOnly?: boolean;
}) {
  if (field.visible === false) return null;
  const controlStyle = { ...inputStyle, opacity: readOnly ? 0.75 : 1 };
  return <label style={{ display: "block" }}>
    <span style={labelStyle}>{field.label}{field.required ? " *" : ""}</span>
    {field.options ? <select
      style={controlStyle}
      value={value || ""}
      disabled={readOnly}
      required={field.required}
      onChange={event => onChange(event.target.value)}
    >
      <option value="">Select an option</option>
      {field.options.map(option => <option key={option} value={option}>{option}</option>)}
    </select> : field.multiline ? <textarea
      style={{ ...controlStyle, resize: "vertical", minHeight: 82 }}
      maxLength={field.max_length}
      value={value || ""}
      readOnly={readOnly}
      required={field.required}
      onChange={event => onChange(event.target.value)}
    /> : <input
      style={controlStyle}
      type={field.input_type || "text"}
      maxLength={field.input_type === "datetime-local" ? undefined : field.max_length}
      value={value || ""}
      readOnly={readOnly}
      required={field.required}
      onChange={event => onChange(event.target.value)}
    />}
  </label>;
}

export function OperationalEmailPage() {
  const { user } = useAuth();
  const isAdmin = isAdministrator(user);
  const queryClient = useQueryClient();
  const [selectedKey, setSelectedKey] = useState("maintenance_notice");
  const [activePanel, setActivePanel] = useState<"compose" | "scheduled" | "history" | "templates" | "signatures">("compose");
  const [fields, setFields] = useState<Record<string, string>>({});
  const [to, setTo] = useState("");
  const [cc, setCc] = useState("");
  const [bcc, setBcc] = useState("");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [subjectTouched, setSubjectTouched] = useState(false);
  const [bodyTouched, setBodyTouched] = useState(false);
  const [attachments, setAttachments] = useState<EmailAttachment[]>([]);
  const [maintenanceNoticeId, setMaintenanceNoticeId] = useState("");
  const [fiberOutageId, setFiberOutageId] = useState("");
  const [signatureChoice, setSignatureChoice] = useState("default");
  const [selectedNetworkOrderIds, setSelectedNetworkOrderIds] = useState<string[]>([]);
  const [selectedContactKeys, setSelectedContactKeys] = useState<string[]>([]);
  const [deliveryMode, setDeliveryMode] = useState<"send" | "schedule">("send");
  const [scheduleType, setScheduleType] = useState<"once" | "daily" | "weekly">("once");
  const [scheduledAt, setScheduledAt] = useState(() => chicagoInputValue(new Date(Date.now() + 30 * 60 * 1000)));
  const [recurrenceTime, setRecurrenceTime] = useState("07:00");
  const [weekday, setWeekday] = useState(0);
  const [notice, setNotice] = useState<{ message: string; error?: boolean } | null>(null);
  const [selectedDeliveryId, setSelectedDeliveryId] = useState<number | null>(null);
  const [templateDraft, setTemplateDraft] = useState<Partial<EmailTemplate>>({});
  const autoToEmailsRef = useRef<string[]>([]);
  const autoBccEmailsRef = useRef<string[]>([]);
  const [signatureDraft, setSignatureDraft] = useState<EmailSignatureDraft>({
    id: null, name: "", content: "", is_active: true, is_default: false,
  });

  const templatesQuery = useQuery({
    queryKey: ["operational-email-templates"],
    queryFn: () => api.get("/operational-email/templates").then(response => response.data),
    refetchInterval: selectedKey === "morning_report" ? 60000 : false,
  });
  const templates: EmailTemplate[] = templatesQuery.data?.templates || [];
  const selectedTemplate = useMemo(() => templates.find(template => template.key === selectedKey) || templates[0], [templates, selectedKey]);
  const signaturesQuery = useQuery({
    queryKey: ["operational-email-signatures", isAdmin],
    queryFn: () => api.get(`/operational-email/signatures${isAdmin ? "/manage" : ""}`).then(response => response.data),
  });
  const signatures: EmailSignature[] = signaturesQuery.data || [];
  const activeSignatures = signatures.filter(signature => signature.is_active);
  const defaultSignature = activeSignatures.find(signature => signature.is_default);
  const selectedSignature = signatureChoice === "default"
    ? defaultSignature
    : signatureChoice === "none"
      ? undefined
      : activeSignatures.find(signature => String(signature.id) === signatureChoice);
  const referenceDataQuery = useQuery({
    queryKey: ["operational-email-reference-data"],
    queryFn: () => api.get("/operational-email/reference-data").then(response => response.data as ReferenceData),
    enabled: activePanel === "compose",
  });
  const referenceData: ReferenceData = referenceDataQuery.data || { fiber_contacts: [], onpage_contacts: [], network_orders: [] };
  const hasNetworkOrderSelector = selectedKey === "fiber_maintenance_notice" || selectedKey === "fiber_outage";
  const onpageToOnly = selectedKey === "after_hours_onpage";
  const contactOptions: ContactOption[] = useMemo(() => {
    const onpage = referenceData.onpage_contacts.map(contact => ({
      key: `onpage:${contact.id}`,
      label: `${contact.department} — ${contact.email}`,
      email: contact.email,
    }));
    if (onpageToOnly) return onpage;
    const fiber = referenceData.fiber_contacts.map(contact => ({
      key: `fiber:${contact.id}`,
      label: `${contact.name} — ${contact.company} — ${contact.email}`,
      email: contact.email,
    }));
    return [...fiber, ...onpage];
  }, [referenceData.fiber_contacts, referenceData.onpage_contacts, onpageToOnly]);

  useEffect(() => {
    if (!selectedTemplate) return;
    const initialFields = Object.fromEntries(selectedTemplate.fields.map(field => [
      field.key,
      field.key === "timezone" ? (templatesQuery.data?.timezone_abbreviation || "CST")
        : field.key === "shift_analysis" ? (templatesQuery.data?.latest_shift_analysis || "")
          : "",
    ])) as Record<string, string>;
    setFields(initialFields);
    setTo(selectedTemplate.default_to || "");
    setCc(selectedTemplate.default_cc || "");
    setBcc(selectedTemplate.default_bcc || "");
    setSubjectTouched(false);
    setBodyTouched(false);
    setSubject(renderTemplate(selectedTemplate.default_subject, initialFields));
    setBody(selectedKey === "morning_report"
      ? (templatesQuery.data?.latest_shift_analysis || "")
      : renderTemplate(selectedTemplate.default_body, initialFields));
    setAttachments([]);
    setMaintenanceNoticeId("");
    setFiberOutageId("");
    setSignatureChoice("default");
    setSelectedNetworkOrderIds([]);
    setSelectedContactKeys([]);
    autoToEmailsRef.current = [];
    autoBccEmailsRef.current = [];
  }, [selectedTemplate?.key]);

  useEffect(() => {
    if (!selectedTemplate) return;
    if (!subjectTouched) setSubject(renderTemplate(selectedTemplate.default_subject, fields));
    if (!bodyTouched) setBody(selectedKey === "morning_report"
      ? (templatesQuery.data?.latest_shift_analysis || "")
      : renderTemplate(selectedTemplate.default_body, fields));
  }, [selectedTemplate, selectedKey, fields, subjectTouched, bodyTouched, templatesQuery.data?.latest_shift_analysis]);

  const maintenanceQuery = useQuery({
    queryKey: ["operational-email-maintenance-notices"],
    queryFn: () => api.get("/operational-email/maintenance-notices").then(response => response.data),
    enabled: selectedKey === "maintenance_complete",
  });
  const fiberOutagesQuery = useQuery({
    queryKey: ["operational-email-fiber-outages"],
    queryFn: () => api.get("/operational-email/fiber-outages").then(response => response.data),
    enabled: selectedKey === "fiber_outage_update" || selectedKey === "fiber_outage_resolution",
  });
  const scheduledQuery = useQuery({
    queryKey: ["operational-email-scheduled"],
    queryFn: () => api.get("/operational-email/scheduled").then(response => response.data),
    enabled: activePanel === "scheduled",
    refetchInterval: activePanel === "scheduled" ? 30000 : false,
  });
  const historyQuery = useQuery({
    queryKey: ["operational-email-history"],
    queryFn: () => api.get("/operational-email/history").then(response => response.data),
    enabled: activePanel === "history",
  });
  const deliveryDetailQuery = useQuery({
    queryKey: ["operational-email-delivery", selectedDeliveryId],
    queryFn: () => api.get(`/operational-email/history/${selectedDeliveryId}`).then(response => response.data),
    enabled: selectedDeliveryId != null,
  });

  const sendMutation = useMutation({
    mutationFn: (payload: any) => api.post("/operational-email/send", payload).then(response => response.data),
    onSuccess: result => {
      setNotice({ message: result.status === "sent" ? "Email sent successfully." : result.message || "Email delivery failed.", error: result.status !== "sent" });
      queryClient.invalidateQueries({ queryKey: ["operational-email-history"] });
    },
    onError: error => setNotice({ message: getApiErrorMessage(error, "Email could not be sent."), error: true }),
  });
  const scheduleMutation = useMutation({
    mutationFn: (payload: any) => api.post("/operational-email/schedule", payload).then(response => response.data),
    onSuccess: result => {
      setNotice({ message: `Email scheduled. Next send: ${formatTime(result.next_run_at)}.` });
      queryClient.invalidateQueries({ queryKey: ["operational-email-scheduled"] });
    },
    onError: error => setNotice({ message: getApiErrorMessage(error, "Email could not be scheduled."), error: true }),
  });
  const cancelMutation = useMutation({
    mutationFn: (id: number) => api.delete(`/operational-email/scheduled/${id}`).then(response => response.data),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["operational-email-scheduled"] }),
    onError: error => setNotice({ message: getApiErrorMessage(error, "Schedule could not be cancelled."), error: true }),
  });
  const saveTemplateMutation = useMutation({
    mutationFn: () => {
      const defaults = { ...templateDraft };
      if (!selectedTemplate?.allows_cc) {
        defaults.default_cc = "";
        defaults.default_bcc = "";
      }
      return api.put(`/operational-email/templates/${selectedKey}`, defaults).then(response => response.data);
    },
    onSuccess: () => {
      setNotice({ message: "Shared template defaults saved." });
      queryClient.invalidateQueries({ queryKey: ["operational-email-templates"] });
    },
    onError: error => setNotice({ message: getApiErrorMessage(error, "Template defaults could not be saved."), error: true }),
  });
  const saveSignatureMutation = useMutation({
    mutationFn: () => {
      const payload = {
        name: signatureDraft.name,
        content: signatureDraft.content,
        is_active: signatureDraft.is_active,
        is_default: signatureDraft.is_default,
      };
      return signatureDraft.id
        ? api.put(`/operational-email/signatures/${signatureDraft.id}`, payload).then(response => response.data)
        : api.post("/operational-email/signatures", payload).then(response => response.data);
    },
    onSuccess: () => {
      setNotice({ message: "Operational Email signature saved." });
      setSignatureDraft({ id: null, name: "", content: "", is_active: true, is_default: false });
      queryClient.invalidateQueries({ queryKey: ["operational-email-signatures"] });
    },
    onError: error => setNotice({ message: getApiErrorMessage(error, "Signature could not be saved."), error: true }),
  });
  const updateSignatureMutation = useMutation({
    mutationFn: (signature: EmailSignature) => api.put(`/operational-email/signatures/${signature.id}`, {
      name: signature.name,
      content: signature.content,
      is_active: signature.is_active,
      is_default: signature.is_default,
    }).then(response => response.data),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["operational-email-signatures"] }),
    onError: error => setNotice({ message: getApiErrorMessage(error, "Signature settings could not be updated."), error: true }),
  });
  const deactivateSignatureMutation = useMutation({
    mutationFn: (id: number) => api.delete(`/operational-email/signatures/${id}`).then(response => response.data),
    onSuccess: () => {
      setNotice({ message: "Signature deactivated. Historical delivery snapshots are retained." });
      queryClient.invalidateQueries({ queryKey: ["operational-email-signatures"] });
    },
    onError: error => setNotice({ message: getApiErrorMessage(error, "Signature could not be deactivated."), error: true }),
  });

  useEffect(() => {
    if (!selectedTemplate) return;
    setTemplateDraft({
      default_subject: selectedTemplate.default_subject,
      default_body: selectedTemplate.default_body,
      default_to: selectedTemplate.default_to,
      default_cc: selectedTemplate.default_cc,
      default_bcc: selectedTemplate.default_bcc,
    });
  }, [selectedTemplate]);

  const selectTemplate = (key: string) => {
    setSelectedKey(key);
    setNotice(null);
  };

  const composePayload = () => ({
    template_key: selectedKey,
    to,
    ...(selectedTemplate?.allows_cc ? { cc } : {}),
    ...(selectedTemplate?.allows_bcc ? { bcc } : {}),
    subject,
    body,
    fields,
    ...(signatureChoice === "default"
      ? { use_default_signature: true }
      : signatureChoice === "none"
        ? { use_default_signature: false }
        : { signature_id: Number(signatureChoice), use_default_signature: false }),
    attachments: attachments.map(({ filename, content_type, content_base64 }) => ({ filename, content_type, content_base64 })),
    ...(selectedKey === "maintenance_complete" ? { maintenance_notice_id: Number(maintenanceNoticeId) } : {}),
    ...((selectedKey === "fiber_outage_update" || selectedKey === "fiber_outage_resolution")
      ? { source_email_id: Number(fiberOutageId) }
      : {}),
  });

  const submit = () => {
    setNotice(null);
    const payload = composePayload();
    if (deliveryMode === "send") {
      sendMutation.mutate(payload);
      return;
    }
    try {
      const schedule = scheduleType === "once"
        ? { schedule_type: "once", scheduled_at: chicagoInputToIso(scheduledAt), timezone: "America/Chicago" }
        : {
            schedule_type: scheduleType,
            recurrence_time: recurrenceTime,
            recurrence_weekday: scheduleType === "weekly" ? weekday : undefined,
            timezone: "America/Chicago",
          };
      scheduleMutation.mutate({ ...payload, schedule });
    } catch (error: any) {
      setNotice({ message: error.message || "Schedule time is invalid.", error: true });
    }
  };

  const addAttachments = async (files: FileList | null) => {
    if (!files?.length) return;
    try {
      const next = [...attachments, ...await Promise.all(Array.from(files).map(fileToAttachment))];
      if (next.length > 5) throw new Error("No more than five attachments may be added.");
      if (next.reduce((sum, item) => sum + (item.size_bytes || 0), 0) > 20 * 1024 * 1024) {
        throw new Error("Combined attachments may not exceed 20 MiB.");
      }
      setAttachments(next);
      setNotice(null);
    } catch (error: any) {
      setNotice({ message: error.message || "Attachment could not be loaded.", error: true });
    }
  };

  const selectMaintenanceNotice = (id: string) => {
    setMaintenanceNoticeId(id);
    const noticeItem = (maintenanceQuery.data || []).find((item: any) => item.id === Number(id));
    if (!noticeItem) return;
    setFields(previous => ({ ...previous, ...noticeItem.fields }));
    if (!to.trim()) setTo((noticeItem.to || []).join(", "));
    if (!cc.trim()) setCc((noticeItem.cc || []).join(", "));
    if (!bcc.trim()) setBcc((noticeItem.bcc || []).join(", "));
    setSubjectTouched(false);
    setBodyTouched(false);
  };

  const selectFiberOutage = (id: string) => {
    setFiberOutageId(id);
    const outage = (fiberOutagesQuery.data || []).find((item: any) => item.id === Number(id));
    if (!outage || !selectedTemplate) return;
    setFields(previous => {
      const inherited: Record<string, string> = {};
      selectedTemplate.fields.forEach(field => {
        if (field.key === "timezone") {
          inherited[field.key] = templatesQuery.data?.timezone_abbreviation || "CST";
        } else if (Object.prototype.hasOwnProperty.call(outage.fields || {}, field.key)) {
          inherited[field.key] = String(outage.fields[field.key] || "");
        }
      });
      return { ...previous, ...inherited };
    });
    if (!to.trim()) setTo((outage.to || []).join(", "));
    if (!cc.trim()) setCc((outage.cc || []).join(", "));
    if (!bcc.trim()) setBcc((outage.bcc || []).join(", "));
    setSubjectTouched(false);
    setBodyTouched(false);
  };

  const selectDirectoryContacts = (keys: string[]) => {
    setSelectedContactKeys(keys);
    const selectedEmails = keys.flatMap(key => {
      const contact = contactOptions.find(option => option.key === key);
      return contact ? [contact.email] : [];
    });
    setTo(mergeSelectedAddresses(to, autoToEmailsRef.current, selectedEmails));
    autoToEmailsRef.current = selectedEmails;
  };

  const selectNetworkOrders = (ids: string[]) => {
    setSelectedNetworkOrderIds(ids);
    const orders = ids.flatMap(id => {
      const order = referenceData.network_orders.find(record => String(record.id) === id);
      return order ? [order] : [];
    });
    const aLocations = uniqueAddresses(orders.map(order => order.a_location));
    const zLocations = uniqueAddresses(orders.map(order => order.z_location));
    const orderIds = uniqueAddresses(orders.map(order => order.circuit_network_order_id));
    const companies = uniqueAddresses(orders.map(order => order.company));
    const companySet = new Set(companies.map(company => company.toLocaleLowerCase()));
    const matchingContacts = referenceData.fiber_contacts.filter(
      contact => companySet.has(contact.company.toLocaleLowerCase()),
    );
    const nextAutomaticBcc = uniqueAddresses(matchingContacts.map(contact => contact.email));
    setBcc(mergeSelectedAddresses(bcc, autoBccEmailsRef.current, nextAutomaticBcc));
    autoBccEmailsRef.current = nextAutomaticBcc;

    const inherited: Record<string, string> = {
      network_order_ids: ids.join(", "),
      network_orders: orderIds.join("; "),
      a_location: aLocations.join("; "),
      z_location: zLocations.join("; "),
      company: companies.join("; "),
      contact: matchingContacts.map(contact => contact.phone ? `${contact.name} (${contact.phone})` : contact.name).join("; "),
    };
    if (selectedTemplate?.fields.some(field => field.key === "site")) {
      inherited.site = orders.map(order => `${order.a_location} to ${order.z_location}`).join("; ");
    }
    setFields(previous => ({ ...previous, ...inherited }));
    setSubjectTouched(false);
    setBodyTouched(false);
  };

  if (templatesQuery.isLoading) return <div style={{ padding: "1.5rem", color: "var(--text-secondary)" }}>Loading operational email...</div>;
  if (templatesQuery.isError) return <div role="alert" style={{ margin: "1.5rem", color: "var(--accent-red)" }}>{getApiErrorMessage(templatesQuery.error, "Operational email templates could not be loaded.")}</div>;
  if (!selectedTemplate) return <div role="alert" style={{ padding: "1.5rem" }}>No operational email templates are available.</div>;

  const tabButton = (key: typeof activePanel, label: string, Icon: any) => (
    <button
      type="button"
      key={key}
      onClick={() => { setActivePanel(key); setNotice(null); }}
      aria-pressed={activePanel === key}
      style={{
        ...buttonStyle,
        background: activePanel === key ? "var(--accent-blue)" : "var(--bg-card)",
        color: activePanel === key ? "#fff" : "var(--text-secondary)",
      }}
    ><Icon size={15} />{label}</button>
  );

  return <main style={{ padding: "1.4rem", maxWidth: 1200, margin: "0 auto", color: "var(--text-primary)" }}>
    <header style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "1rem", flexWrap: "wrap", marginBottom: "1rem" }}>
      <div>
        <h1 style={{ display: "flex", alignItems: "center", gap: 8, margin: 0, fontSize: "1.35rem" }}><Mail size={22} />Operational Email</h1>
        <p style={{ margin: "0.35rem 0 0", color: "var(--text-muted)", fontSize: "0.8rem" }}>Compose operational notices, schedule sends, and review delivery history.</p>
      </div>
      <div style={{ ...cardStyle, padding: "0.6rem 0.8rem", fontSize: "0.78rem" }}>
        <strong>Global From:</strong> {templatesQuery.data?.sender_address || "Not configured"}
        {!templatesQuery.data?.smtp_enabled && <span style={{ color: "var(--accent-orange)" }}> · SMTP disabled</span>}
      </div>
    </header>

    <nav aria-label="Operational email sections" style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: "1rem" }}>
      {tabButton("compose", "Compose", Mail)}
      {tabButton("scheduled", "Scheduled", CalendarClock)}
      {tabButton("history", "Sent / History", ClipboardList)}
      {isAdmin && tabButton("templates", "Template Defaults", Shield)}
      {isAdmin && tabButton("signatures", "Signatures", Shield)}
    </nav>

    {notice && <div role={notice.error ? "alert" : "status"} style={{ ...cardStyle, marginBottom: "1rem", borderColor: notice.error ? "var(--accent-red)" : "var(--accent-green)", color: notice.error ? "var(--accent-red)" : "var(--text-primary)" }}>{notice.message}</div>}

    {activePanel === "compose" && <section style={{ display: "grid", gridTemplateColumns: "minmax(250px, 0.8fr) minmax(0, 2fr)", gap: "1rem", alignItems: "start" }}>
      <div style={{ ...cardStyle, display: "grid", gap: "0.75rem" }}>
        <label>
          <span style={labelStyle}>Email template</span>
          <select value={selectedKey} onChange={event => selectTemplate(event.target.value)} style={inputStyle}>
            {templates.map(template => <option key={template.key} value={template.key}>{template.label}</option>)}
          </select>
        </label>
        <p style={{ margin: 0, color: "var(--text-muted)", fontSize: "0.78rem", lineHeight: 1.5 }}>{selectedTemplate.description}</p>
        <div style={{ borderTop: "1px solid var(--border-primary)", paddingTop: "0.75rem" }}>
          <label style={{ display: "inline-flex", alignItems: "center", gap: 7, marginRight: 16, fontSize: "0.8rem" }}>
            <input type="radio" checked={deliveryMode === "send"} onChange={() => setDeliveryMode("send")} />Send now
          </label>
          <label style={{ display: "inline-flex", alignItems: "center", gap: 7, fontSize: "0.8rem" }}>
            <input type="radio" checked={deliveryMode === "schedule"} onChange={() => setDeliveryMode("schedule")} />Schedule
          </label>
        </div>
        {deliveryMode === "schedule" && <div style={{ display: "grid", gap: "0.65rem" }}>
          <label><span style={labelStyle}>Schedule type</span>
            <select value={scheduleType} onChange={event => setScheduleType(event.target.value as any)} style={inputStyle}>
              <option value="once">One-time</option><option value="daily">Daily recurring</option><option value="weekly">Weekly recurring</option>
            </select>
          </label>
          {scheduleType === "once" ? <label><span style={labelStyle}>Send at (America/Chicago)</span>
            <input type="datetime-local" value={scheduledAt} onChange={event => setScheduledAt(event.target.value)} style={inputStyle} />
          </label> : <>
            {scheduleType === "weekly" && <label><span style={labelStyle}>Day of week</span>
              <select value={weekday} onChange={event => setWeekday(Number(event.target.value))} style={inputStyle}>
                {["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"].map((day, index) => <option key={day} value={index}>{day}</option>)}
              </select>
            </label>}
            <label><span style={labelStyle}>Send time (America/Chicago)</span>
              <input type="time" value={recurrenceTime} onChange={event => setRecurrenceTime(event.target.value)} style={inputStyle} />
            </label>
          </>}
        </div>}
        <button type="button" onClick={submit} disabled={sendMutation.isPending || scheduleMutation.isPending} style={{ ...buttonStyle, justifyContent: "center", marginTop: 4 }}>
          {deliveryMode === "send" ? <Send size={15} /> : <CalendarClock size={15} />}
          {sendMutation.isPending ? "Sending..." : scheduleMutation.isPending ? "Scheduling..." : deliveryMode === "send" ? "Send Email" : "Save Schedule"}
        </button>
      </div>

      <div style={{ display: "grid", gap: "1rem" }}>
        {selectedKey === "maintenance_complete" && <div style={cardStyle}>
          <label><span style={labelStyle}>Previously sent maintenance notification *</span>
            <select value={maintenanceNoticeId} onChange={event => selectMaintenanceNotice(event.target.value)} style={inputStyle}>
              <option value="">Select a sent maintenance notice</option>
              {(maintenanceQuery.data || []).map((item: any) => <option key={item.id} value={item.id}>{formatTime(item.sent_at)} · {item.subject}</option>)}
            </select>
          </label>
          {maintenanceQuery.isLoading && <small>Loading sent maintenance notifications...</small>}
          {!maintenanceQuery.isLoading && !(maintenanceQuery.data || []).length && <small style={{ color: "var(--text-muted)" }}>No successfully sent maintenance notifications are available.</small>}
        </div>}
        {(selectedKey === "fiber_outage_update" || selectedKey === "fiber_outage_resolution") && <div style={cardStyle}>
          <label><span style={labelStyle}>Previously sent fiber outage ticket *</span>
            <select value={fiberOutageId} onChange={event => selectFiberOutage(event.target.value)} style={inputStyle}>
              <option value="">Select a sent fiber outage</option>
              {(fiberOutagesQuery.data || []).map((item: any) => <option key={item.id} value={item.id}>{formatTime(item.sent_at)} · {item.subject}</option>)}
            </select>
          </label>
          {fiberOutagesQuery.isLoading && <small>Loading sent fiber outage notices...</small>}
          {!fiberOutagesQuery.isLoading && !(fiberOutagesQuery.data || []).length && <small style={{ color: "var(--text-muted)" }}>No successfully sent fiber outage notices are available.</small>}
        </div>}

        {hasNetworkOrderSelector && <div style={{ ...cardStyle, display: "grid", gap: "0.6rem" }}>
          <label><span style={labelStyle}>Network Orders · select one or more</span>
            <select
              multiple
              size={Math.min(Math.max(referenceData.network_orders.length, 3), 7)}
              value={selectedNetworkOrderIds}
              onChange={event => selectNetworkOrders(Array.from(event.target.selectedOptions, option => option.value))}
              style={{ ...inputStyle, minHeight: 100 }}
              aria-label="Select Network Orders"
            >
              {referenceData.network_orders.map(order => <option key={order.id} value={String(order.id)}>
                {order.circuit_network_order_id} · {order.a_location} → {order.z_location} · {order.company}
              </option>)}
            </select>
          </label>
          {referenceDataQuery.isLoading && <small>Loading Network Orders and Fiber contacts...</small>}
          {referenceDataQuery.isError && <small role="alert" style={{ color: "var(--accent-orange)" }}>Reference lists could not be loaded. You can enter all details and BCC recipients manually.</small>}
          {!referenceDataQuery.isLoading && !referenceDataQuery.isError && !referenceData.network_orders.length && <small style={{ color: "var(--text-muted)" }}>No Network Orders are configured. Enter the order, A/Z locations, company, and contacts manually below.</small>}
          <small style={{ color: "var(--text-muted)" }}>Selecting records fills Network Orders, A/Z locations, company, and Fiber contact details. Matching Fiber contact emails are added to BCC; these values remain editable for manual corrections.</small>
        </div>}

        <div style={{ ...cardStyle, display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: "0.75rem" }}>
          <h2 style={{ gridColumn: "1 / -1", margin: 0, fontSize: "0.95rem" }}>Operational details</h2>
          {selectedTemplate.fields.map(field => <TemplateFieldInput
            key={field.key}
            field={field}
            value={fields[field.key] || ""}
            readOnly={field.key === "timezone"
              || (selectedKey === "maintenance_complete" && Boolean(maintenanceNoticeId) && !["completion_time", "work_performed", "service_status", "follow_up"].includes(field.key))
              || ((selectedKey === "fiber_outage_update" || selectedKey === "fiber_outage_resolution") && Boolean(fiberOutageId)
                && !(selectedKey === "fiber_outage_update"
                  ? ["update_time", "current_status", "update_details", "restoration_estimate", "next_update"].includes(field.key)
                  : ["resolution_time", "resolution_details", "service_status", "follow_up"].includes(field.key)))}
            onChange={value => setFields(previous => ({ ...previous, [field.key]: value }))}
          />)}
        </div>

        <div style={{ ...cardStyle, display: "grid", gap: "0.75rem" }}>
          <h2 style={{ margin: 0, fontSize: "0.95rem" }}>Recipients and message</h2>
          {!hasNetworkOrderSelector && <label style={{ display: "block" }}>
            <span style={labelStyle}>{onpageToOnly ? "ONPAGE contacts to add to To · select multiple" : "Contacts to add to To · select multiple"}</span>
            <select
              multiple
              size={Math.min(Math.max(contactOptions.length, 3), 6)}
              value={selectedContactKeys}
              onChange={event => selectDirectoryContacts(Array.from(event.target.selectedOptions, option => option.value))}
              style={{ ...inputStyle, minHeight: 90 }}
              aria-label={onpageToOnly ? "Select ONPAGE contacts" : "Select email contacts"}
            >
              {contactOptions.map(option => <option key={option.key} value={option.key}>{option.label}</option>)}
            </select>
            {!referenceDataQuery.isLoading && !referenceDataQuery.isError && !contactOptions.length && <small style={{ color: "var(--text-muted)" }}>No contact directory entries are configured. You can enter recipients manually.</small>}
          </label>}
          <label><span style={labelStyle}>Signature</span>
            <select value={signatureChoice} onChange={event => setSignatureChoice(event.target.value)} style={inputStyle}>
              <option value="default">Use administrator default{defaultSignature ? ` · ${defaultSignature.name}` : " · none configured"}</option>
              <option value="none">No signature</option>
              {activeSignatures.map(signature => <option key={signature.id} value={signature.id}>{signature.name}{signature.is_default ? " · default" : ""}</option>)}
            </select>
          </label>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: "0.75rem" }}>
            <label><span style={labelStyle}>To *</span><input value={to} onChange={event => setTo(event.target.value)} placeholder="person@example.com, team@example.com" style={inputStyle} /></label>
            {selectedTemplate.allows_cc && <label><span style={labelStyle}>Cc</span><input value={cc} onChange={event => setCc(event.target.value)} style={inputStyle} /></label>}
            {selectedTemplate.allows_bcc && <label style={{ gridColumn: "1 / -1" }}><span style={labelStyle}>Bcc (hidden from recipients)</span><input value={bcc} onChange={event => setBcc(event.target.value)} style={inputStyle} /></label>}
          </div>
          <label><span style={labelStyle}>Subject *</span><input value={subject} maxLength={500} onChange={event => { setSubjectTouched(true); setSubject(event.target.value); }} style={inputStyle} /></label>
          <label><span style={labelStyle}>{selectedKey === "morning_report" ? "Latest Global Dashboard shift analysis" : "Message *"}</span><textarea value={body} maxLength={200000} readOnly={selectedKey === "morning_report"} onChange={event => { setBodyTouched(true); setBody(event.target.value); }} rows={12} style={{ ...inputStyle, resize: selectedKey === "morning_report" ? "none" : "vertical", lineHeight: 1.45, fontFamily: "var(--font-mono)", opacity: selectedKey === "morning_report" ? 0.85 : 1 }} /></label>
          {selectedKey === "morning_report" && <p style={{ margin: "-0.4rem 0 0", color: "var(--text-muted)", fontSize: "0.74rem" }}>
            Sent exactly as currently stored in Global Dashboards{templatesQuery.data?.latest_shift_analysis_time ? ` · updated ${formatTime(templatesQuery.data.latest_shift_analysis_time)}` : ""}. The latest analysis is refreshed again at delivery time.
            {!String(templatesQuery.data?.latest_shift_analysis || "").trim() && <span style={{ color: "var(--accent-orange)" }}> No shift analysis is currently available.</span>}
          </p>}
          {selectedSignature && <div style={{ borderLeft: "3px solid var(--accent-blue)", padding: "0.45rem 0.65rem", color: "var(--text-muted)", fontSize: "0.76rem" }}>
            <strong>Signature appended · {selectedSignature.name}</strong><br /><span style={{ whiteSpace: "pre-wrap" }}>{selectedSignature.content}</span>
          </div>}
          {selectedTemplate.allows_attachments && <div>
            <label style={{ ...labelStyle, display: "flex", alignItems: "center", gap: 6 }}><Paperclip size={14} />Attachments · up to 5 files, 5 MiB each, 20 MiB total</label>
            <input type="file" multiple onChange={event => { void addAttachments(event.target.files); event.target.value = ""; }} />
            {attachments.map((file, index) => <div key={`${file.filename}-${index}`} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, marginTop: 6, fontSize: "0.78rem" }}>
              <span>{file.filename} · {((file.size_bytes || 0) / 1024 / 1024).toFixed(2)} MiB</span>
              <button type="button" aria-label={`Remove ${file.filename}`} onClick={() => setAttachments(previous => previous.filter((_item, itemIndex) => itemIndex !== index))} style={{ background: "transparent", border: 0, color: "var(--accent-red)", cursor: "pointer" }}><X size={15} /></button>
            </div>)}
          </div>}
          <p style={{ margin: 0, color: "var(--text-muted)", fontSize: "0.72rem" }}>All messages use the configured global From address. BCC recipients are hidden from other recipients. Template and signature changes affect new compositions, not saved schedules.</p>
        </div>
      </div>
    </section>}

    {activePanel === "scheduled" && <section style={cardStyle}>
      <h2 style={{ margin: "0 0 0.75rem", fontSize: "1rem" }}>Scheduled emails</h2>
      {scheduledQuery.isLoading ? <p>Loading schedules...</p> : scheduledQuery.isError ? <p role="alert">{getApiErrorMessage(scheduledQuery.error, "Schedules could not be loaded.")}</p> : (
        <div style={{ overflowX: "auto" }}><table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.78rem" }}>
          <thead><tr>{["Template / subject", "Recipients", "Cadence", "Next send", "Status", ""].map(label => <th key={label} style={{ textAlign: "left", padding: "0.5rem", borderBottom: "1px solid var(--border-primary)" }}>{label}</th>)}</tr></thead>
          <tbody>{(scheduledQuery.data || []).map((item: any) => <tr key={item.id}>
            <td style={{ padding: "0.55rem", borderBottom: "1px solid var(--border-primary)" }}><strong>{templates.find(template => template.key === item.template_key)?.label || item.template_key}</strong><br />{item.subject}</td>
            <td style={{ padding: "0.55rem", borderBottom: "1px solid var(--border-primary)" }}>{(item.to || []).join(", ")}</td>
            <td style={{ padding: "0.55rem", borderBottom: "1px solid var(--border-primary)" }}>{item.schedule_type === "once" ? "One-time" : item.schedule_type === "daily" ? `Daily ${item.recurrence_time} CT` : `Weekly ${["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][item.recurrence_weekday]} ${item.recurrence_time} CT`}</td>
            <td style={{ padding: "0.55rem", borderBottom: "1px solid var(--border-primary)" }}>{formatTime(item.next_run_at)}</td>
            <td style={{ padding: "0.55rem", borderBottom: "1px solid var(--border-primary)" }}>{item.status}{item.last_error ? <div style={{ color: "var(--accent-red)" }}>{item.last_error}</div> : null}</td>
            <td style={{ padding: "0.55rem", borderBottom: "1px solid var(--border-primary)" }}>{item.status !== "processing" && <button type="button" onClick={() => cancelMutation.mutate(item.id)} disabled={cancelMutation.isPending} style={{ ...buttonStyle, background: "var(--bg-card)", color: "var(--accent-red)", padding: "0.35rem 0.55rem" }}>Cancel</button>}</td>
          </tr>)}
          {!scheduledQuery.data?.length && <tr><td colSpan={6} style={{ padding: "1rem", color: "var(--text-muted)" }}>No active email schedules.</td></tr>}</tbody>
        </table></div>
      )}
    </section>}

    {activePanel === "history" && <section style={cardStyle}>
      <h2 style={{ margin: "0 0 0.75rem", fontSize: "1rem" }}>Delivery history</h2>
      {historyQuery.isLoading ? <p>Loading delivery history...</p> : historyQuery.isError ? <p role="alert">{getApiErrorMessage(historyQuery.error, "Delivery history could not be loaded.")}</p> : (
        <div style={{ overflowX: "auto" }}><table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.78rem" }}>
          <thead><tr>{["Sent / attempted", "Template", "Subject", "To", "Result", ""].map(label => <th key={label} style={{ textAlign: "left", padding: "0.5rem", borderBottom: "1px solid var(--border-primary)" }}>{label}</th>)}</tr></thead>
          <tbody>{(historyQuery.data || []).map((item: any) => <tr key={item.id}>
            <td style={{ padding: "0.55rem", borderBottom: "1px solid var(--border-primary)" }}>{formatTime(item.sent_at || item.attempted_at)}</td>
            <td style={{ padding: "0.55rem", borderBottom: "1px solid var(--border-primary)" }}>{templates.find(template => template.key === item.template_key)?.label || item.template_key}</td>
            <td style={{ padding: "0.55rem", borderBottom: "1px solid var(--border-primary)" }}>{item.subject}</td>
            <td style={{ padding: "0.55rem", borderBottom: "1px solid var(--border-primary)" }}>{(item.to || []).join(", ")}</td>
            <td style={{ padding: "0.55rem", borderBottom: "1px solid var(--border-primary)", color: item.status === "sent" ? "var(--accent-green)" : "var(--accent-red)" }}>{item.status}{item.error_message ? <div>{item.error_message}</div> : null}</td>
            <td style={{ padding: "0.55rem", borderBottom: "1px solid var(--border-primary)" }}><button type="button" onClick={() => setSelectedDeliveryId(item.id)} style={{ ...buttonStyle, padding: "0.35rem 0.55rem", background: "var(--bg-card)", color: "var(--text-primary)" }}>View</button></td>
          </tr>)}
          {!historyQuery.data?.length && <tr><td colSpan={6} style={{ padding: "1rem", color: "var(--text-muted)" }}>No email delivery attempts yet.</td></tr>}</tbody>
        </table></div>
      )}
      {selectedDeliveryId != null && <div role="dialog" aria-modal="true" aria-label="Email delivery details" style={{ position: "fixed", inset: 0, zIndex: 2000, background: "rgba(0,0,0,0.65)", display: "grid", placeItems: "center", padding: 16 }} onClick={() => setSelectedDeliveryId(null)}>
        <div style={{ ...cardStyle, width: "min(800px, 96vw)", maxHeight: "90vh", overflow: "auto" }} onClick={event => event.stopPropagation()}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10 }}><h3 style={{ margin: 0 }}>Email delivery details</h3><button type="button" onClick={() => setSelectedDeliveryId(null)} aria-label="Close" style={{ ...buttonStyle, background: "var(--bg-card)", color: "var(--text-primary)" }}><X size={15} /></button></div>
          {deliveryDetailQuery.isLoading ? <p>Loading...</p> : deliveryDetailQuery.data && <>
            <p><strong>From:</strong> {deliveryDetailQuery.data.sender_address || "—"}<br /><strong>To:</strong> {(deliveryDetailQuery.data.to || []).join(", ")}<br /><strong>Cc:</strong> {(deliveryDetailQuery.data.cc || []).join(", ")}<br /><strong>Bcc:</strong> {(deliveryDetailQuery.data.bcc || []).join(", ")}<br /><strong>Subject:</strong> {deliveryDetailQuery.data.subject}<br /><strong>Status:</strong> {deliveryDetailQuery.data.status}</p>
            <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", padding: 12, borderRadius: 6, background: "var(--bg-secondary)", fontSize: "0.8rem" }}>{deliveryDetailQuery.data.body}</pre>
          </>}
        </div>
      </div>}
    </section>}

    {activePanel === "templates" && isAdmin && <section style={{ ...cardStyle, display: "grid", gap: "0.8rem", maxWidth: 900 }}>
      <h2 style={{ margin: 0, fontSize: "1rem" }}>Shared template defaults</h2>
      <p style={{ margin: 0, color: "var(--text-muted)", fontSize: "0.78rem" }}>Administrators edit future defaults. Users with Operational Email access can still adjust each outgoing message before sending or scheduling.</p>
      <label><span style={labelStyle}>Template</span><select value={selectedKey} onChange={event => selectTemplate(event.target.value)} style={inputStyle}>{templates.map(template => <option key={template.key} value={template.key}>{template.label}</option>)}</select></label>
      <label><span style={labelStyle}>Default To</span><input value={String(templateDraft.default_to || "")} onChange={event => setTemplateDraft(previous => ({ ...previous, default_to: event.target.value }))} style={inputStyle} /></label>
      {selectedTemplate.allows_cc && <label><span style={labelStyle}>Default Cc</span><input value={String(templateDraft.default_cc || "")} onChange={event => setTemplateDraft(previous => ({ ...previous, default_cc: event.target.value }))} style={inputStyle} /></label>}
      {selectedTemplate.allows_bcc && <label><span style={labelStyle}>Default Bcc</span><input value={String(templateDraft.default_bcc || "")} onChange={event => setTemplateDraft(previous => ({ ...previous, default_bcc: event.target.value }))} style={inputStyle} /></label>}
      <label><span style={labelStyle}>Default subject · placeholders use {"{{field_name}}"}</span><input value={String(templateDraft.default_subject || "")} maxLength={500} onChange={event => setTemplateDraft(previous => ({ ...previous, default_subject: event.target.value }))} style={inputStyle} /></label>
      <label><span style={labelStyle}>Default message · available fields: {selectedTemplate.fields.map(field => `{{${field.key}}}`).join(", ")}</span><textarea value={String(templateDraft.default_body || "")} maxLength={200000} rows={14} onChange={event => setTemplateDraft(previous => ({ ...previous, default_body: event.target.value }))} style={{ ...inputStyle, resize: "vertical", lineHeight: 1.45, fontFamily: "var(--font-mono)" }} /></label>
      <div><button type="button" onClick={() => saveTemplateMutation.mutate()} disabled={saveTemplateMutation.isPending} style={buttonStyle}><Save size={15} />{saveTemplateMutation.isPending ? "Saving..." : "Save template defaults"}</button></div>
    </section>}

    {activePanel === "signatures" && isAdmin && <section style={{ display: "grid", gridTemplateColumns: "minmax(280px, 0.9fr) minmax(0, 1.5fr)", gap: "1rem", alignItems: "start" }}>
      <div style={{ ...cardStyle, display: "grid", gap: "0.75rem" }}>
        <h2 style={{ margin: 0, fontSize: "1rem" }}>{signatureDraft.id ? "Edit signature" : "Create signature"}</h2>
        <p style={{ margin: 0, color: "var(--text-muted)", fontSize: "0.76rem" }}>Administrators manage reusable plain-text signatures. The selected signature is captured with each message and scheduled send.</p>
        <label><span style={labelStyle}>Signature name *</span><input value={signatureDraft.name} maxLength={100} onChange={event => setSignatureDraft(previous => ({ ...previous, name: event.target.value }))} style={inputStyle} /></label>
        <label><span style={labelStyle}>Signature text *</span><textarea value={signatureDraft.content} maxLength={4000} rows={8} onChange={event => setSignatureDraft(previous => ({ ...previous, content: event.target.value }))} style={{ ...inputStyle, resize: "vertical", lineHeight: 1.45 }} /></label>
        <label style={{ display: "flex", alignItems: "center", gap: 7, fontSize: "0.8rem" }}>
          <input type="checkbox" checked={signatureDraft.is_active} onChange={event => setSignatureDraft(previous => ({ ...previous, is_active: event.target.checked, is_default: event.target.checked ? previous.is_default : false }))} />Active and available to Operational Email users
        </label>
        <label style={{ display: "flex", alignItems: "center", gap: 7, fontSize: "0.8rem" }}>
          <input type="checkbox" checked={signatureDraft.is_default} disabled={!signatureDraft.is_active} onChange={event => setSignatureDraft(previous => ({ ...previous, is_default: event.target.checked }))} />Use as the administrator default
        </label>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <button type="button" onClick={() => saveSignatureMutation.mutate()} disabled={saveSignatureMutation.isPending} style={buttonStyle}><Save size={15} />{saveSignatureMutation.isPending ? "Saving..." : signatureDraft.id ? "Save signature" : "Create signature"}</button>
          {signatureDraft.id && <button type="button" onClick={() => setSignatureDraft({ id: null, name: "", content: "", is_active: true, is_default: false })} style={{ ...buttonStyle, background: "var(--bg-card)", color: "var(--text-primary)" }}>Cancel edit</button>}
        </div>
      </div>
      <div style={{ ...cardStyle, overflowX: "auto" }}>
        <h2 style={{ margin: "0 0 0.75rem", fontSize: "1rem" }}>Configured signatures</h2>
        {signaturesQuery.isLoading ? <p>Loading signatures...</p> : signaturesQuery.isError ? <p role="alert">{getApiErrorMessage(signaturesQuery.error, "Signatures could not be loaded.")}</p> : <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.78rem" }}>
          <thead><tr>{["Name / text", "State", "Actions"].map(label => <th key={label} style={{ textAlign: "left", padding: "0.5rem", borderBottom: "1px solid var(--border-primary)" }}>{label}</th>)}</tr></thead>
          <tbody>{signatures.map(signature => <tr key={signature.id}>
            <td style={{ padding: "0.6rem", borderBottom: "1px solid var(--border-primary)", whiteSpace: "pre-wrap" }}><strong>{signature.name}</strong><br />{signature.content}</td>
            <td style={{ padding: "0.6rem", borderBottom: "1px solid var(--border-primary)" }}>{signature.is_active ? "Active" : "Inactive"}{signature.is_default ? " · Default" : ""}</td>
            <td style={{ padding: "0.6rem", borderBottom: "1px solid var(--border-primary)" }}>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                <button type="button" onClick={() => setSignatureDraft({ id: signature.id, name: signature.name, content: signature.content, is_active: signature.is_active, is_default: signature.is_default })} style={{ ...buttonStyle, padding: "0.35rem 0.55rem", background: "var(--bg-card)", color: "var(--text-primary)" }}>Edit</button>
                {signature.is_active && !signature.is_default && <button type="button" onClick={() => updateSignatureMutation.mutate({ ...signature, is_default: true })} disabled={updateSignatureMutation.isPending} style={{ ...buttonStyle, padding: "0.35rem 0.55rem" }}>Make default</button>}
                {signature.is_active && <button type="button" onClick={() => deactivateSignatureMutation.mutate(signature.id)} disabled={deactivateSignatureMutation.isPending} style={{ ...buttonStyle, padding: "0.35rem 0.55rem", background: "var(--bg-card)", color: "var(--accent-red)" }}>Deactivate</button>}
                {!signature.is_active && <button type="button" onClick={() => updateSignatureMutation.mutate({ ...signature, is_active: true })} disabled={updateSignatureMutation.isPending} style={{ ...buttonStyle, padding: "0.35rem 0.55rem" }}>Reactivate</button>}
              </div>
            </td>
          </tr>)}
          {!signatures.length && <tr><td colSpan={3} style={{ padding: "1rem", color: "var(--text-muted)" }}>No shared signatures configured.</td></tr>}</tbody>
        </table>}
      </div>
    </section>}
  </main>;
}
