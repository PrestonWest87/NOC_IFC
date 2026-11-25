import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CalendarClock, ClipboardList, Mail, Paperclip, Save, Send, Shield, X } from "lucide-react";
import api, { getApiErrorMessage } from "../utils/api";
import { SearchableMultiSelect } from "../components/SearchableMultiSelect";
import { useAuth } from "../utils/AuthContext";
import { isAdministrator } from "../utils/permissions";

type TemplateField = {
  key: string; label: string; required: boolean; max_length: number;
  options?: string[]; multiline?: boolean; visible?: boolean; input_type?: string; picker_type?: string;
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
  network_orders: {
    id: number; a_location: string; z_location: string; circuit_network_order_id: string; company: string;
    associated_circuit_network_order_ids: string[];
  }[];
};

const FIBER_SENDER_TO_KEYS = new Set([
  "fiber_outage", "fiber_outage_update", "fiber_outage_resolution",
]);
const FIBER_BCC_TEMPLATE_KEYS = new Set([
  "fiber_outage", "fiber_outage_resolution",
]);
const FIBER_CIRCUIT_BCC_KEYS = new Set([
  "fiber_outage", "fiber_outage_onpage", "fiber_outage_update", "fiber_outage_resolution",
  "maintenance_start", "maintenance_complete",
]);

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

function formatMessageDateTime(value: string): string {
  const match = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})$/.exec(value);
  if (!match) return value;
  const [, year, month, day, rawHour, minute] = match;
  const hour = Number(rawHour);
  if (hour > 23 || Number(minute) > 59) return value;
  return `${month}/${day}/${year.slice(-2)} ${String(hour % 12 || 12).padStart(2, "0")}:${minute} ${hour < 12 ? "AM" : "PM"}`;
}

function isDateTimePicker(field: TemplateField): boolean {
  return field.input_type === "datetime-local" || field.picker_type === "datetime-local";
}

/** Convert saved local timestamps (including legacy display strings) to datetime-local input values. */
function dateTimePickerValue(value: string): string {
  const local = /^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})(?::\d{2}(?:\.\d+)?)?(?:\s+(?:CT|CST|CDT))?$/i.exec(value.trim());
  if (local) return `${local[1]}T${local[2]}`;
  const formatted = /^(\d{2})\/(\d{2})\/(\d{2}) (\d{2}):(\d{2}) (AM|PM)$/i.exec(value.trim());
  if (!formatted) return value;
  const [, month, day, shortYear, rawHour, minute, period] = formatted;
  const shortYearNumber = Number(shortYear);
  const year = shortYearNumber + (shortYearNumber < 69 ? 2000 : 1900);
  const hour = Number(rawHour) % 12 + (period.toUpperCase() === "PM" ? 12 : 0);
  return `${year}-${month}-${day}T${String(hour).padStart(2, "0")}:${minute}`;
}

function renderTemplate(text: string, fields: Record<string, string>): string {
  return String(text || "").replace(/\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}/g, (_match, key: string) => formatMessageDateTime(fields[key] || ""));
}

function fiberMaintenanceDetails(fields: Record<string, string>): string {
  const circuitDetails = fiberCircuitDetails(fields);
  const details = [
    ["Network Orders/Circuit IDs and A/Z locations", circuitDetails],
    ["MOP Type", fields.mop_type],
  ].flatMap(([label, value]) => value?.trim() ? [`${label}: ${value.trim()}`] : []);
  return details.length ? `\nFIBER MAINTENANCE DETAILS\n${details.join("\n")}\n` : "";
}

function fiberCircuitDetails(fields: Record<string, string>): string {
  const networkOrders = String(fields.network_orders || "").trim();
  if (networkOrders.includes(" — A: ")) return networkOrders;
  const split = (value: string) => value.split(/[;\r\n]+/).map(item => item.trim()).filter(Boolean);
  const circuitIds = split(networkOrders);
  const aLocations = split(fields.a_location || "");
  const zLocations = split(fields.z_location || "");
  if (circuitIds.length && circuitIds.length === aLocations.length && circuitIds.length === zLocations.length) {
    return circuitIds.map((id, index) => `${id} — A: ${aLocations[index]} → Z: ${zLocations[index]}`).join("\n");
  }
  return [
    networkOrders && `Network Orders/Circuit IDs: ${networkOrders}`,
    fields.a_location && `A locations: ${fields.a_location}`,
    fields.z_location && `Z locations: ${fields.z_location}`,
  ].filter(Boolean).join("\n");
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

function includeImmediateAssociatedNetworkOrderIds(ids: string[], records: ReferenceData["network_orders"]): string[] {
  const byRowId = new Map(records.map(record => [String(record.id), record] as const));
  const byCircuitId = new Map(records.map(record => [record.circuit_network_order_id.trim().toLocaleLowerCase(), String(record.id)] as const));
  const immediateIds = uniqueAddresses(ids).flatMap(id =>
    (byRowId.get(id)?.associated_circuit_network_order_ids || []).flatMap(associatedId => {
      const relatedId = byCircuitId.get(associatedId.trim().toLocaleLowerCase());
      return relatedId ? [relatedId] : [];
    }),
  );
  return uniqueAddresses([...ids, ...immediateIds]);
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
  const inputType = field.picker_type || field.input_type || "text";
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
      type={inputType}
      maxLength={inputType === "datetime-local" ? undefined : field.max_length}
      value={value || ""}
      readOnly={readOnly}
      required={field.required}
      onChange={event => onChange(event.target.value)}
    />}
  </label>;
}

/** Compose, schedule, and review permissioned operational emails from the server-provided template catalog. */
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
  const [maintenanceSourceGrouped, setMaintenanceSourceGrouped] = useState(false);
  const [fiberOutageSourceGrouped, setFiberOutageSourceGrouped] = useState(false);
  const [signatureChoice, setSignatureChoice] = useState("default");
  const [selectedNetworkOrderRootIds, setSelectedNetworkOrderRootIds] = useState<string[]>([]);
  const [selectedNetworkOrderIds, setSelectedNetworkOrderIds] = useState<string[]>([]);
  const [excludedNetworkOrderIds, setExcludedNetworkOrderIds] = useState<string[]>([]);
  const [fiberContactSearch, setFiberContactSearch] = useState("");
  const [selectedContactKeys, setSelectedContactKeys] = useState<string[]>([]);
  const [selectedOnpageContactKeys, setSelectedOnpageContactKeys] = useState<string[]>([]);
  const [deliveryMode, setDeliveryMode] = useState<"send" | "schedule">("send");
  const [scheduleType, setScheduleType] = useState<"once" | "daily" | "weekly">("once");
  const [scheduledAt, setScheduledAt] = useState(() => chicagoInputValue(new Date(Date.now() + 30 * 60 * 1000)));
  const [recurrenceTime, setRecurrenceTime] = useState("07:00");
  const [weekday, setWeekday] = useState(0);
  const [notice, setNotice] = useState<{ message: string; error?: boolean } | null>(null);
  const [selectedDeliveryId, setSelectedDeliveryId] = useState<number | null>(null);
  const [templateDraft, setTemplateDraft] = useState<Partial<EmailTemplate>>({});
  const autoBccEmailsRef = useRef<string[]>([]);
  const autoContactBccEmailsRef = useRef<string[]>([]);
  const autoParentBccEmailsRef = useRef<string[]>([]);
  const autoParentCcEmailsRef = useRef<string[]>([]);
  const autoOnpageToEmailsRef = useRef<string[]>([]);
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
  const includeOnpageReference = selectedKey === "after_hours_onpage" || selectedKey === "fiber_outage_onpage";
  const referenceDataQuery = useQuery({
    queryKey: ["operational-email-reference-data", includeOnpageReference],
    queryFn: () => api.get("/operational-email/reference-data", {
      params: includeOnpageReference ? { include_onpage: true } : {},
    }).then(response => response.data as ReferenceData),
    enabled: activePanel === "compose",
  });
  const referenceData: ReferenceData = referenceDataQuery.data || { fiber_contacts: [], onpage_contacts: [], network_orders: [] };
  const networkOrderOptions = useMemo(() => referenceData.network_orders.map(order => ({
    value: String(order.id),
    label: `${order.circuit_network_order_id} · ${order.a_location} → ${order.z_location} · ${order.company}`,
  })), [referenceData.network_orders]);
  const fiberMaintenance = selectedKey === "fiber_maintenance_notice";
  const hasNetworkOrderSelector = selectedKey === "fiber_maintenance_notice" || selectedKey === "fiber_outage" || selectedKey === "fiber_outage_onpage";
  const onpageToOnly = selectedKey === "after_hours_onpage";
  const fiberOnpage = selectedKey === "fiber_outage_onpage";
  const fiberOutageCompanyRouted = selectedKey === "fiber_outage" && selectedNetworkOrderIds.length > 0;
  const groupedMaintenanceSource = maintenanceSourceGrouped
    && (selectedKey === "maintenance_start" || selectedKey === "maintenance_complete");
  const groupedFiberOutageSource = fiberOutageSourceGrouped
    && (selectedKey === "fiber_outage_update" || selectedKey === "fiber_outage_resolution");
  const groupedCompanyMessage = fiberMaintenance || fiberOutageCompanyRouted || groupedMaintenanceSource || groupedFiberOutageSource;
  const fiberToSender = FIBER_SENDER_TO_KEYS.has(selectedKey)
    && !fiberOutageCompanyRouted && !groupedFiberOutageSource;
  const showOnpageSelector = onpageToOnly || fiberOnpage;
  const showFiberContactSelector = FIBER_BCC_TEMPLATE_KEYS.has(selectedKey);
  const contactOptions: ContactOption[] = useMemo(() => {
    return referenceData.fiber_contacts.map(contact => ({
      key: `fiber:${contact.id}`,
      label: `${contact.name} — ${contact.company} — ${contact.email}`,
      email: contact.email,
    }));
  }, [referenceData.fiber_contacts]);
  const onpageOptions: ContactOption[] = useMemo(() => referenceData.onpage_contacts.map(contact => ({
    key: `onpage:${contact.id}`,
    label: `${contact.department} — ${contact.email}`,
    email: contact.email,
  })), [referenceData.onpage_contacts]);
  const visibleFiberContacts = useMemo(() => {
    const search = fiberContactSearch.trim().toLocaleLowerCase();
    const selected = new Set(selectedContactKeys);
    const toRecipients = new Set(String(to || "").split(/[,;]/).map(email => email.trim().toLocaleLowerCase()).filter(Boolean));
    return contactOptions.filter(option => selected.has(option.key)
      || (!toRecipients.has(option.email.toLocaleLowerCase())
        && (!search || option.label.toLocaleLowerCase().includes(search))));
  }, [contactOptions, fiberContactSearch, selectedContactKeys, to]);

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
    setMaintenanceSourceGrouped(false);
    setFiberOutageSourceGrouped(false);
    setSignatureChoice("default");
    setSelectedNetworkOrderRootIds([]);
    setSelectedNetworkOrderIds([]);
    setExcludedNetworkOrderIds([]);
    setFiberContactSearch("");
    setSelectedContactKeys([]);
    setSelectedOnpageContactKeys([]);
    autoBccEmailsRef.current = [];
    autoContactBccEmailsRef.current = [];
    autoParentBccEmailsRef.current = [];
    autoParentCcEmailsRef.current = [];
    autoOnpageToEmailsRef.current = [];
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
    enabled: selectedKey === "maintenance_complete" || selectedKey === "maintenance_start",
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
      setNotice({
        message: result.message || (result.status === "sent" ? "Email sent successfully." : "Email delivery failed."),
        error: result.status !== "sent",
      });
      queryClient.invalidateQueries({ queryKey: ["operational-email-history"] });
    },
    onError: error => setNotice({ message: getApiErrorMessage(error, "Email could not be sent."), error: true }),
  });
  const scheduleMutation = useMutation({
    mutationFn: (payload: any) => api.post("/operational-email/schedule", payload).then(response => response.data),
    onSuccess: result => {
      setNotice({ message: result.message || `Email scheduled. Next send: ${formatTime(result.next_run_at)}.` });
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
      if (FIBER_SENDER_TO_KEYS.has(selectedKey) || fiberOnpage || fiberMaintenance) delete defaults.default_to;
      if (fiberOnpage) delete defaults.default_cc;
      if (!selectedTemplate?.allows_bcc) delete defaults.default_bcc;
      if (!selectedTemplate?.allows_cc) {
        defaults.default_cc = "";
      }
      return api.put(`/operational-email/templates/${selectedKey}`, defaults).then(response => response.data);
    },
    onSuccess: () => {
      setNotice({ message: "Shared template defaults saved." });
      const sourceCc = ["maintenance_start", "maintenance_complete"].includes(selectedKey)
        ? (maintenanceQuery.data || []).find((item: any) => item.id === Number(maintenanceNoticeId))?.cc || []
        : [];
      setCc(selectedTemplate?.allows_cc
        ? uniqueAddresses([...String(templateDraft.default_cc || "").split(/[,;]/), ...sourceCc]).join(", ")
        : "");
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

  const composePayload = () => {
    const groupedSource = groupedMaintenanceSource || groupedFiberOutageSource;
    return {
      template_key: selectedKey,
      to: fiberMaintenance || fiberOutageCompanyRouted || groupedSource ? "" : to,
      ...(selectedTemplate?.allows_cc ? {
        cc: groupedSource ? mergeSelectedAddresses(cc, autoParentCcEmailsRef.current, []) : cc,
      } : {}),
      ...(selectedTemplate?.allows_bcc ? {
        bcc: groupedSource ? mergeSelectedAddresses(bcc, autoParentBccEmailsRef.current, []) : bcc,
      } : {}),
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
      ...(selectedKey === "maintenance_start" ? { source_email_id: Number(maintenanceNoticeId) } : {}),
      ...((selectedKey === "fiber_outage_update" || selectedKey === "fiber_outage_resolution")
        ? { source_email_id: Number(fiberOutageId) }
        : {}),
    };
  };

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
    if (!noticeItem || !selectedTemplate) return;
    const grouped = Boolean(noticeItem.grouped);
    setMaintenanceSourceGrouped(grouped);
    setFiberOutageSourceGrouped(false);
    const sourceFields: Record<string, string> = { ...(noticeItem.fields || {}) };
    if (!String(sourceFields.expected_impact || "").trim()) {
      sourceFields.expected_impact = [sourceFields.operational_impact, sourceFields.departmental_impact]
        .map(value => String(value || "").trim()).filter(Boolean).join("\n");
    }
    if (noticeItem.template_key === "fiber_maintenance_notice") {
      if (selectedKey === "maintenance_start" || selectedKey === "maintenance_complete") {
        sourceFields.network_orders = fiberCircuitDetails(sourceFields);
      }
      const route = [sourceFields.a_location, sourceFields.z_location].filter(Boolean).join(" to ");
      if (!sourceFields.site && route.length <= 200) sourceFields.site = route;
      if (selectedKey === "maintenance_complete") sourceFields.fiber_details = fiberMaintenanceDetails(sourceFields);
    } else if (selectedKey === "maintenance_complete") {
      sourceFields.fiber_details = "";
    }
    setFields(Object.fromEntries(selectedTemplate.fields.map(field => [
      field.key,
      field.key === "timezone"
        ? (templatesQuery.data?.timezone_abbreviation || "CST")
        : isDateTimePicker(field)
          ? dateTimePickerValue(String(sourceFields[field.key] || ""))
          : String(sourceFields[field.key] || ""),
    ])));
    if (selectedKey === "maintenance_start" || grouped) {
      setTo((noticeItem.to || []).join(", "));
    } else if (!to.trim()) {
      setTo((noticeItem.to || []).join(", "));
    }
    const parentCc = uniqueAddresses(noticeItem.cc || []);
    autoParentCcEmailsRef.current = parentCc;
    if (selectedKey === "maintenance_start" || selectedKey === "maintenance_complete") {
      setCc(grouped
        ? selectedTemplate.default_cc || ""
        : uniqueAddresses([...String(selectedTemplate.default_cc || "").split(/[,;]/), ...parentCc]).join(", "));
    } else if (!cc.trim()) setCc((noticeItem.cc || []).join(", "));
    const previousAutomaticBcc = uniqueAddresses([
      ...autoBccEmailsRef.current,
      ...autoContactBccEmailsRef.current,
      ...autoParentBccEmailsRef.current,
    ]);
    const parentBcc = uniqueAddresses(noticeItem.bcc || []);
    setBcc(current => mergeSelectedAddresses(current, previousAutomaticBcc, grouped ? [] : parentBcc));
    autoBccEmailsRef.current = [];
    autoContactBccEmailsRef.current = [];
    autoParentBccEmailsRef.current = parentBcc;
    setSelectedContactKeys([]);
    setFiberContactSearch("");
    setSubjectTouched(false);
    setBodyTouched(false);
  };

  const selectFiberOutage = (id: string) => {
    setFiberOutageId(id);
    const outage = (fiberOutagesQuery.data || []).find((item: any) => item.id === Number(id));
    if (!outage || !selectedTemplate) return;
    const grouped = Boolean(outage.grouped);
    setFiberOutageSourceGrouped(grouped);
    setMaintenanceSourceGrouped(false);
    setFields(previous => {
      const inherited: Record<string, string> = {};
      selectedTemplate.fields.forEach(field => {
        if (field.key === "timezone") {
          inherited[field.key] = templatesQuery.data?.timezone_abbreviation || "CST";
        } else if (Object.prototype.hasOwnProperty.call(outage.fields || {}, field.key)) {
          const value = String(outage.fields[field.key] || "");
          inherited[field.key] = isDateTimePicker(field) ? dateTimePickerValue(value) : value;
        }
      });
      return { ...previous, ...inherited };
    });
    setTo(grouped
      ? uniqueAddresses(outage.to || []).join(", ")
      : selectedTemplate.default_to || templatesQuery.data?.sender_address || "");
    autoParentCcEmailsRef.current = uniqueAddresses(outage.cc || []);
    setCc(selectedTemplate.default_cc || "");
    const previousAutomaticBcc = uniqueAddresses([
      ...autoBccEmailsRef.current,
      ...autoContactBccEmailsRef.current,
      ...autoParentBccEmailsRef.current,
    ]);
    const parentBcc = uniqueAddresses(outage.bcc || []);
    setBcc(current => mergeSelectedAddresses(current, previousAutomaticBcc, grouped ? [] : parentBcc));
    autoBccEmailsRef.current = [];
    autoParentBccEmailsRef.current = parentBcc;
    setSelectedContactKeys([]);
    setSelectedOnpageContactKeys([]);
    setFiberContactSearch("");
    autoContactBccEmailsRef.current = [];
    autoOnpageToEmailsRef.current = [];
    setSubjectTouched(false);
    setBodyTouched(false);
  };

  const updateAutomaticBcc = (networkEmails: string[], selectedEmails: string[]) => {
    const previous = uniqueAddresses([
      ...autoBccEmailsRef.current,
      ...autoContactBccEmailsRef.current,
      ...autoParentBccEmailsRef.current,
    ]);
    const nextNetwork = uniqueAddresses(networkEmails);
    const nextSelected = uniqueAddresses(selectedEmails);
    const parentBcc = autoParentBccEmailsRef.current;
    setBcc(current => mergeSelectedAddresses(
      current,
      previous,
      [...nextNetwork, ...nextSelected, ...parentBcc],
    ));
    autoBccEmailsRef.current = nextNetwork;
    autoContactBccEmailsRef.current = nextSelected;
  };

  const selectDirectoryContacts = (keys: string[]) => {
    setSelectedContactKeys(keys);
    const selectedEmails = keys.flatMap(key => {
      const contact = contactOptions.find(option => option.key === key);
      return contact ? [contact.email] : [];
    });
    updateAutomaticBcc(autoBccEmailsRef.current, selectedEmails);
  };

  const selectOnpageContacts = (keys: string[]) => {
    setSelectedOnpageContactKeys(keys);
    const selectedEmails = keys.flatMap(key => {
      const contact = onpageOptions.find(option => option.key === key);
      return contact ? [contact.email] : [];
    });
    setTo(mergeSelectedAddresses(to, autoOnpageToEmailsRef.current, selectedEmails));
    autoOnpageToEmailsRef.current = selectedEmails;
  };

  const selectNetworkOrders = (ids: string[], restoreAssociatedGroup = false) => {
    const nextSelection = uniqueAddresses(ids);
    const previousSelection = new Set(selectedNetworkOrderIds);
    const nextSelectionSet = new Set(nextSelection);
    const excluded = new Set(excludedNetworkOrderIds);
    const roots = new Set(restoreAssociatedGroup ? nextSelection : selectedNetworkOrderRootIds);
    if (restoreAssociatedGroup) {
      includeImmediateAssociatedNetworkOrderIds(nextSelection, referenceData.network_orders)
        .forEach(id => excluded.delete(id));
    } else {
      const newlySelected = nextSelection.filter(id => !previousSelection.has(id));
      newlySelected.forEach(id => { roots.add(id); excluded.delete(id); });
      includeImmediateAssociatedNetworkOrderIds(newlySelected, referenceData.network_orders)
        .forEach(id => excluded.delete(id));
      selectedNetworkOrderIds.forEach(id => {
        if (!nextSelectionSet.has(id)) {
          roots.delete(id);
          excluded.add(id);
        }
      });
    }
    const rootIds = Array.from(roots);
    const oneHopGroup = includeImmediateAssociatedNetworkOrderIds(rootIds, referenceData.network_orders);
    const relevantExclusions = new Set(oneHopGroup.filter(id => excluded.has(id) && !roots.has(id)));
    const expandedIds = oneHopGroup.filter(id => !relevantExclusions.has(id));
    setSelectedNetworkOrderRootIds(rootIds);
    setExcludedNetworkOrderIds(Array.from(relevantExclusions));
    setSelectedNetworkOrderIds(expandedIds);
    const orders = expandedIds.flatMap(id => {
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
    const fiberOutageCompanyRouted = selectedKey === "fiber_outage" && expandedIds.length > 0;
    if (fiberMaintenance) {
      setTo(uniqueAddresses(matchingContacts.map(contact => contact.email)).join(", "));
    } else if (selectedKey === "fiber_outage") {
      if (fiberOutageCompanyRouted) {
        const companyEmails = uniqueAddresses(matchingContacts.map(contact => contact.email));
        const companyEmailSet = new Set(companyEmails.map(email => email.toLocaleLowerCase()));
        const remainingBccKeys = selectedContactKeys.filter(key => {
          const contact = contactOptions.find(option => option.key === key);
          return contact && !companyEmailSet.has(contact.email.toLocaleLowerCase());
        });
        setSelectedContactKeys(remainingBccKeys);
        setTo(companyEmails.join(", "));
        updateAutomaticBcc([], remainingBccKeys.flatMap(key => {
          const contact = contactOptions.find(option => option.key === key);
          return contact ? [contact.email] : [];
        }));
      } else {
        setTo(selectedTemplate?.default_to || templatesQuery.data?.sender_address || "");
        updateAutomaticBcc([], autoContactBccEmailsRef.current);
      }
    } else {
      updateAutomaticBcc([], autoContactBccEmailsRef.current);
    }

    const inherited: Record<string, string> = {
      network_order_ids: rootIds.join(", "),
      excluded_network_order_ids: Array.from(relevantExclusions).join(", "),
      network_orders: fiberMaintenance
        ? orders.map(order =>
          `${order.circuit_network_order_id} — A: ${order.a_location} → Z: ${order.z_location}`,
        ).join("\n")
        : orderIds.join("\n"),
    };
    if (selectedTemplate?.fields.some(field => field.key === "a_location")) inherited.a_location = aLocations.join("; ");
    if (selectedTemplate?.fields.some(field => field.key === "z_location")) inherited.z_location = zLocations.join("; ");
    setFields(previous => ({ ...previous, ...inherited }));
    setSubjectTouched(false);
    setBodyTouched(false);
  };

  const updateTemplateField = (field: TemplateField, value: string) => {
    if (field.key === "network_orders" && hasNetworkOrderSelector) {
      const pastedIds = uniqueAddresses(value.split(/[,;\r\n]+/));
      const matches = pastedIds.map(orderId => referenceData.network_orders.filter(
        order => order.circuit_network_order_id.trim().toLocaleLowerCase() === orderId.toLocaleLowerCase(),
      ));
      if (pastedIds.length && matches.every(orders => orders.length === 1)) {
        selectNetworkOrders(matches.map(orders => String(orders[0].id)), true);
        return;
      }
    }
    setFields(previous => ({ ...previous, [field.key]: value }));
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
        {(selectedKey === "maintenance_complete" || selectedKey === "maintenance_start") && <div style={cardStyle}>
          <label><span style={labelStyle}>Previously sent Maintenance or Fiber Maintenance notification *</span>
            <select value={maintenanceNoticeId} onChange={event => selectMaintenanceNotice(event.target.value)} style={inputStyle}>
              <option value="">Select a sent maintenance notice</option>
              {(maintenanceQuery.data || []).map((item: any) => <option key={item.id} value={item.id}>{item.template_key === "fiber_maintenance_notice" ? "Fiber Maintenance" : "Maintenance"}{item.grouped ? ` · ${item.company_count} companies` : ""} · {formatTime(item.sent_at)} · {item.template_key === "fiber_maintenance_notice" ? item.fields?.network_orders || item.subject : item.subject}</option>)}
            </select>
          </label>
          {maintenanceQuery.isLoading && <small>Loading sent maintenance notifications...</small>}
          {!maintenanceQuery.isLoading && !(maintenanceQuery.data || []).length && <small style={{ color: "var(--text-muted)" }}>No successfully sent maintenance or Fiber Maintenance notifications are available.</small>}
        </div>}
        {(selectedKey === "fiber_outage_update" || selectedKey === "fiber_outage_resolution") && <div style={cardStyle}>
          <label><span style={labelStyle}>Previously sent fiber outage ticket *</span>
            <select value={fiberOutageId} onChange={event => selectFiberOutage(event.target.value)} style={inputStyle}>
              <option value="">Select a sent fiber outage</option>
              {(fiberOutagesQuery.data || []).map((item: any) => <option key={item.id} value={item.id}>{item.grouped ? `${item.company_count} companies · ` : ""}{formatTime(item.sent_at)} · {item.subject}</option>)}
            </select>
          </label>
          {fiberOutagesQuery.isLoading && <small>Loading sent fiber outage notices...</small>}
          {!fiberOutagesQuery.isLoading && !(fiberOutagesQuery.data || []).length && <small style={{ color: "var(--text-muted)" }}>No successfully sent fiber outage notices are available.</small>}
        </div>}

        {hasNetworkOrderSelector && <div style={{ ...cardStyle, display: "grid", gap: "0.6rem" }}>
          <div>
            <span style={labelStyle}>Network Orders/Circuit IDs · select one or more</span>
            <SearchableMultiSelect
              label="Network Orders/Circuit IDs"
              options={networkOrderOptions}
              value={selectedNetworkOrderIds}
              onChange={selectNetworkOrders}
              disabled={referenceDataQuery.isLoading || referenceDataQuery.isError}
              placeholder="Choose circuits"
              noOptionsMessage="No Network Orders/Circuit IDs match that search."
            />
          </div>
          {referenceDataQuery.isLoading && <small>Loading Network Orders and Fiber contacts...</small>}
          {referenceDataQuery.isError && <small role="alert" style={{ color: "var(--accent-orange)" }}>{fiberMaintenance ? "Reference data could not be loaded. Fiber Maintenance requires configured Network Orders and company contacts." : "Reference lists could not be loaded. You can enter all details and BCC recipients manually."}</small>}
          {!referenceDataQuery.isLoading && !referenceDataQuery.isError && !referenceData.network_orders.length && <small style={{ color: "var(--text-muted)" }}>{fiberMaintenance ? "No Network Orders/Circuit IDs are configured. Add the reference records and company contacts in Settings before sending." : "No Network Orders/Circuit IDs are configured. Enter the order, location details, and contacts manually below."}</small>}
          <small style={{ color: "var(--text-muted)" }}>Selecting a circuit adds only its immediate associations; associations of those circuits are not followed. You can uncheck an associated circuit or select it separately to include its own immediate associations. The Network Orders/Circuit IDs details field remains editable, and pasting configured IDs selects them. Fiber Maintenance requires configured records for company routing, and a send can include up to 50 circuits.</small>
          <small style={{ color: "var(--text-muted)" }}>{fiberMaintenance
            ? "Each selected company receives a separate email with only its selected circuits and A/Z locations. Mapped Fiber contacts are in To; Global From is always included on Cc alongside editable default and per-message recipients. Every selected company must have at least one Fiber email contact."
            : fiberOnpage
              ? "Selecting records or pasting configured IDs fills Network Orders/Circuit IDs. Enter the nearest crossroads in Location; Fiber contacts remain separate from ONPAGE To recipients."
              : "Selecting configured records sends a separate outage email to each selected company's mapped Fiber contacts, with only that company's Network Orders/Circuit IDs and Global From on Cc. Location remains manually entered, and BCC can be used for additional recipients."}</small>
        </div>}

        <div style={{ ...cardStyle, display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: "0.75rem" }}>
          <h2 style={{ gridColumn: "1 / -1", margin: 0, fontSize: "0.95rem" }}>Operational details</h2>
          {selectedTemplate.fields.map(field => <TemplateFieldInput
            key={field.key}
            field={field}
            value={fields[field.key] || ""}
            readOnly={field.key === "timezone"
              || (fiberOutageCompanyRouted && field.key === "network_orders")
              || (groupedMaintenanceSource && selectedKey === "maintenance_start")
              || (selectedKey === "maintenance_complete" && Boolean(maintenanceNoticeId) && !["completion_time", "work_performed", "service_status", "follow_up"].includes(field.key))
              || ((selectedKey === "fiber_outage_update" || selectedKey === "fiber_outage_resolution") && Boolean(fiberOutageId)
                && !(selectedKey === "fiber_outage_update"
                  ? ["update_time", "current_status", "update_details", "restoration_estimate", "next_update"].includes(field.key)
                  : ["resolution_time", "resolution_details", "service_status", "follow_up"].includes(field.key)))}
            onChange={value => updateTemplateField(field, value)}
          />)}
        </div>

        <div style={{ ...cardStyle, display: "grid", gap: "0.75rem" }}>
          <h2 style={{ margin: 0, fontSize: "0.95rem" }}>Recipients and message</h2>
          {showOnpageSelector && <label style={{ display: "block" }}>
            <span style={labelStyle}>ONPAGE contacts to add to To · select multiple</span>
            <select
              multiple
              size={Math.min(Math.max(onpageOptions.length, 3), 6)}
              value={selectedOnpageContactKeys}
              onChange={event => selectOnpageContacts(Array.from(event.target.selectedOptions, option => option.value))}
              style={{ ...inputStyle, minHeight: 90 }}
              aria-label="Select ONPAGE contacts"
            >
              {onpageOptions.map(option => <option key={option.key} value={option.key}>{option.label}</option>)}
            </select>
            {!referenceDataQuery.isLoading && !referenceDataQuery.isError && !onpageOptions.length && <small style={{ color: "var(--text-muted)" }}>No ONPAGE contacts are configured.</small>}
          </label>}
          {showFiberContactSelector && <div style={{ display: "grid", gap: "0.5rem" }}>
            <label><span style={labelStyle}>Search Fiber contacts for Bcc</span>
              <input
                aria-label="Search Fiber contacts for Bcc"
                placeholder="Search name, company, or email"
                value={fiberContactSearch}
                onChange={event => setFiberContactSearch(event.target.value)}
                style={inputStyle}
              />
            </label>
            <label style={{ display: "block" }}>
              <span style={labelStyle}>Fiber contacts to add to Bcc · select multiple</span>
              <select
                multiple
                size={Math.min(Math.max(visibleFiberContacts.length, 3), 6)}
                value={selectedContactKeys}
                onChange={event => selectDirectoryContacts(Array.from(event.target.selectedOptions, option => option.value))}
                style={{ ...inputStyle, minHeight: 90 }}
                aria-label="Select Fiber contacts for Bcc"
              >
                {visibleFiberContacts.map(option => <option key={option.key} value={option.key}>{option.label}</option>)}
              </select>
              {!referenceDataQuery.isLoading && !referenceDataQuery.isError && !contactOptions.length && <small style={{ color: "var(--text-muted)" }}>No Fiber contacts are configured. You can enter Bcc recipients manually.</small>}
              {fiberContactSearch.trim() && !visibleFiberContacts.length && <small>No Fiber contacts match that search.</small>}
            </label>
          </div>}
          <label><span style={labelStyle}>Signature</span>
            <select value={signatureChoice} onChange={event => setSignatureChoice(event.target.value)} style={inputStyle}>
              <option value="default">Use administrator default{defaultSignature ? ` · ${defaultSignature.name}` : " · none configured"}</option>
              <option value="none">No signature</option>
              {activeSignatures.map(signature => <option key={signature.id} value={signature.id}>{signature.name}{signature.is_default ? " · default" : ""}</option>)}
            </select>
          </label>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: "0.75rem" }}>
            <label><span style={labelStyle}>{fiberMaintenance || fiberOutageCompanyRouted ? "To · selected companies' Fiber contacts *" : groupedFiberOutageSource || groupedMaintenanceSource ? "To · source companies' recipients *" : fiberOnpage ? "To · ONPAGE contacts *" : fiberToSender ? "To · Global From *" : "To *"}</span><input value={to} onChange={event => setTo(event.target.value)} readOnly={fiberToSender || fiberOnpage || groupedCompanyMessage} placeholder="person@example.com, team@example.com" style={{ ...inputStyle, opacity: fiberToSender || fiberOnpage || groupedCompanyMessage ? 0.8 : 1 }} /></label>
            {selectedTemplate.allows_cc && <label><span style={labelStyle}>{fiberMaintenance || fiberOutageCompanyRouted ? "Cc · Global From always included" : groupedMaintenanceSource || groupedFiberOutageSource ? "Cc · per-company source Cc retained" : fiberOnpage ? "Cc · Global From" : "Cc"}</span><input value={cc} onChange={event => setCc(event.target.value)} readOnly={fiberOnpage} style={{ ...inputStyle, opacity: fiberOnpage ? 0.8 : 1 }} /></label>}
            {selectedTemplate.allows_bcc && <label style={{ gridColumn: "1 / -1" }}><span style={labelStyle}>Bcc (hidden from recipients)</span><input value={bcc} onChange={event => setBcc(event.target.value)} style={inputStyle} /></label>}
            {selectedTemplate.allows_bcc && FIBER_CIRCUIT_BCC_KEYS.has(selectedKey)
              && (!["maintenance_start", "maintenance_complete"].includes(selectedKey) || groupedMaintenanceSource)
              && <small style={{ gridColumn: "1 / -1", color: "var(--text-muted)" }}>BCC recipients receive circuit/network-order details only for circuits mapped to their Fiber-contact company; other BCC copies retain the rest of the message with those details omitted and use Global From in To.</small>}
          </div>
          <label><span style={labelStyle}>Subject *</span><input value={subject} maxLength={500} readOnly={groupedCompanyMessage} onChange={event => { setSubjectTouched(true); setSubject(event.target.value); }} style={{ ...inputStyle, opacity: groupedCompanyMessage ? 0.85 : 1 }} /></label>
          <label><span style={labelStyle}>{selectedKey === "morning_report" ? "Latest Global Dashboard shift analysis" : "Message *"}</span><textarea value={body} maxLength={200000} readOnly={selectedKey === "morning_report" || groupedCompanyMessage} onChange={event => { setBodyTouched(true); setBody(event.target.value); }} rows={12} style={{ ...inputStyle, resize: selectedKey === "morning_report" || groupedCompanyMessage ? "none" : "vertical", lineHeight: 1.45, fontFamily: "var(--font-mono)", opacity: selectedKey === "morning_report" || groupedCompanyMessage ? 0.85 : 1 }} /></label>
          {fiberMaintenance && <small style={{ color: "var(--text-muted)" }}>Subject and message previews are read-only and include the full selection. Each company-specific email is rendered with only that company's circuits and A/Z details; mapped Fiber contacts are recipients only, and contact names/phone numbers are not autofilled into the message. Administrators can edit the shared wording in Template Defaults.</small>}
          {fiberOutageCompanyRouted && <small style={{ color: "var(--text-muted)" }}>This outage will be sent separately to each selected company's Fiber contacts, with only that company's circuits. Global From is always on Cc; BCC recipients receive circuit details only for their mapped company.</small>}
          {(groupedMaintenanceSource || groupedFiberOutageSource) && <small style={{ color: "var(--text-muted)" }}>This source represents {maintenanceSourceGrouped ? "maintenance" : "outage"} notices sent to {maintenanceSourceGrouped ? (maintenanceQuery.data || []).find((item: any) => item.id === Number(maintenanceNoticeId))?.company_count || 1 : (fiberOutagesQuery.data || []).find((item: any) => item.id === Number(fiberOutageId))?.company_count || 1} companies. The linked update/closeout will be sent once per successful company delivery with that company's source details and recipients. Source Cc/Bcc are retained per company; BCC recipients from other companies receive the remaining message without circuit/network-order details.</small>}
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
            <td style={{ padding: "0.55rem", borderBottom: "1px solid var(--border-primary)" }}><strong>{templates.find(template => template.key === item.template_key)?.label || item.template_key}{item.bcc_copy_only ? " · BCC copy (circuit details filtered)" : ""}</strong><br />{item.subject}</td>
            <td style={{ padding: "0.55rem", borderBottom: "1px solid var(--border-primary)" }}>{(item.to || []).join(", ") || (item.bcc_copy_only ? "BCC-only" : "—")}</td>
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
            <td style={{ padding: "0.55rem", borderBottom: "1px solid var(--border-primary)" }}>{templates.find(template => template.key === item.template_key)?.label || item.template_key}{item.bcc_copy_only ? " · BCC copy (circuit details filtered)" : ""}</td>
            <td style={{ padding: "0.55rem", borderBottom: "1px solid var(--border-primary)" }}>{item.subject}</td>
            <td style={{ padding: "0.55rem", borderBottom: "1px solid var(--border-primary)" }}>{(item.to || []).join(", ") || (item.bcc_copy_only ? "BCC-only" : "—")}</td>
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
             <p><strong>Sender profile:</strong> {deliveryDetailQuery.data.smtp_provider === "gmail" ? "Gmail" : "Existing SMTP"}<br /><strong>From:</strong> {deliveryDetailQuery.data.sender_address || "—"}<br /><strong>To:</strong> {(deliveryDetailQuery.data.to || []).join(", ") || (deliveryDetailQuery.data.bcc_copy_only ? "BCC-only copy" : "—")}<br /><strong>Cc:</strong> {(deliveryDetailQuery.data.cc || []).join(", ")}<br /><strong>Bcc:</strong> {(deliveryDetailQuery.data.bcc || []).join(", ")}<br /><strong>Subject:</strong> {deliveryDetailQuery.data.subject}<br /><strong>Status:</strong> {deliveryDetailQuery.data.status}{deliveryDetailQuery.data.bcc_copy_only ? " · circuit details filtered" : ""}</p>
            <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", padding: 12, borderRadius: 6, background: "var(--bg-secondary)", fontSize: "0.8rem" }}>{deliveryDetailQuery.data.body}</pre>
          </>}
        </div>
      </div>}
    </section>}

    {activePanel === "templates" && isAdmin && <section style={{ ...cardStyle, display: "grid", gap: "0.8rem", maxWidth: 900 }}>
      <h2 style={{ margin: 0, fontSize: "1rem" }}>Shared template defaults</h2>
      <p style={{ margin: 0, color: "var(--text-muted)", fontSize: "0.78rem" }}>Administrators edit future defaults. Users with Operational Email access can still adjust each outgoing message before sending or scheduling.</p>
      <label><span style={labelStyle}>Template</span><select value={selectedKey} onChange={event => selectTemplate(event.target.value)} style={inputStyle}>{templates.map(template => <option key={template.key} value={template.key}>{template.label}</option>)}</select></label>
      {!FIBER_SENDER_TO_KEYS.has(selectedKey) && !fiberOnpage && !fiberMaintenance
        ? <label><span style={labelStyle}>Default To</span><input value={String(templateDraft.default_to || "")} onChange={event => setTemplateDraft(previous => ({ ...previous, default_to: event.target.value }))} style={inputStyle} /></label>
        : <p style={{ margin: 0, color: "var(--text-muted)", fontSize: "0.76rem" }}>{fiberMaintenance ? "Fiber Maintenance To is selected from each circuit company's Fiber contacts; Global From is always included in Cc." : fiberOnpage ? "Fiber Outage ONPAGE Cc uses the Global From address; To is selected from ONPAGE contacts." : "Fiber To uses the active Global From address."}</p>}
      {selectedTemplate.allows_cc && !fiberOnpage && <label><span style={labelStyle}>{fiberMaintenance ? "Default Cc · Global From is always included" : "Default Cc"}</span><input value={String(templateDraft.default_cc || "")} onChange={event => setTemplateDraft(previous => ({ ...previous, default_cc: event.target.value }))} style={inputStyle} /></label>}
      {selectedTemplate.allows_bcc && <label><span style={labelStyle}>Default Bcc</span><input value={String(templateDraft.default_bcc || "")} onChange={event => setTemplateDraft(previous => ({ ...previous, default_bcc: event.target.value }))} style={inputStyle} /></label>}
      <label><span style={labelStyle}>Default subject · placeholders use {"{{field_name}}"}</span><input value={String(templateDraft.default_subject || "")} maxLength={500} onChange={event => setTemplateDraft(previous => ({ ...previous, default_subject: event.target.value }))} style={inputStyle} /></label>
      <label><span style={labelStyle}>Default message · available fields: {selectedTemplate.fields.filter(field => field.visible !== false).map(field => `{{${field.key}}}`).join(", ")}{selectedTemplate.fields.some(field => field.key === "timezone") ? ", {{timezone}} (automatic)" : ""}</span><textarea value={String(templateDraft.default_body || "")} maxLength={200000} rows={14} onChange={event => setTemplateDraft(previous => ({ ...previous, default_body: event.target.value }))} style={{ ...inputStyle, resize: "vertical", lineHeight: 1.45, fontFamily: "var(--font-mono)" }} /></label>
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
