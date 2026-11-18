import { useEffect, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Plus, Save, Trash2, Upload } from "lucide-react";
import { SearchableMultiSelect, type SearchableMultiSelectOption } from "./SearchableMultiSelect";
import api, { getApiErrorMessage } from "../utils/api";

type NetworkOrderRow = {
  id?: number;
  a_location: string;
  z_location: string;
  circuit_network_order_id: string;
  company: string;
  associated_circuit_network_order_ids: string[];
};
type EditableNetworkOrderField = "a_location" | "z_location" | "circuit_network_order_id" | "company";
type CsvImportMode = "merge" | "replace";

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
const emptyRow: NetworkOrderRow = {
  a_location: "", z_location: "", circuit_network_order_id: "", company: "",
  associated_circuit_network_order_ids: [],
};
const columns: { key: EditableNetworkOrderField; label: string }[] = [
  { key: "a_location", label: "A location" },
  { key: "z_location", label: "Z location" },
  { key: "circuit_network_order_id", label: "Circuit/Network Order ID" },
  { key: "company", label: "Company" },
];

function CsvImportControl({ pending, onImport, onError }: {
  pending: boolean;
  onImport: (csvText: string, mode: CsvImportMode) => void;
  onError: (message: string) => void;
}) {
  const [mode, setMode] = useState<CsvImportMode>("merge");
  const readFile = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const input = event.currentTarget;
    const file = input.files?.[0];
    input.value = "";
    if (!file) return;
    if (file.size > 1_000_000) {
      onError("CSV files must be no more than 1 MB.");
      return;
    }
    try {
      onImport(await file.text(), mode);
    } catch {
      onError("The selected CSV file could not be read.");
    }
  };
  return <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
    <label style={{ display: "inline-flex", alignItems: "center", gap: 6, color: "var(--text-muted)", fontSize: "0.72rem" }}>
      Import mode
      <select value={mode} onChange={event => setMode(event.target.value as CsvImportMode)} disabled={pending} style={{ ...inputStyle, width: "auto" }}>
        <option value="merge">Merge / update matches</option>
        <option value="replace">Replace all rows</option>
      </select>
    </label>
    <label style={{ ...buttonStyle, opacity: pending ? 0.7 : 1 }}>
      <Upload size={14} />Import CSV
      <input type="file" accept=".csv,text/csv" aria-label="Import network orders and circuits CSV" onChange={event => { void readFile(event); }} disabled={pending} style={{ display: "none" }} />
    </label>
  </div>;
}

export function NetworkOrdersCircuitsTab({ canManage }: { canManage: boolean }) {
  const [records, setRecords] = useState<NetworkOrderRow[]>([]);
  const [notice, setNotice] = useState<{ message: string; error?: boolean } | null>(null);
  const recordsQuery = useQuery({
    queryKey: ["settings-network-orders"],
    queryFn: () => api.get("/settings/network-orders").then(response => response.data),
  });

  useEffect(() => {
    if (recordsQuery.data) setRecords(recordsQuery.data.records || []);
  }, [recordsQuery.data]);

  const saveMutation = useMutation({
    mutationFn: (rows: NetworkOrderRow[]) => api.put("/admin/network-orders", {
      records: rows.map(({ a_location, z_location, circuit_network_order_id, company, associated_circuit_network_order_ids }) => ({
        a_location, z_location, circuit_network_order_id, company, associated_circuit_network_order_ids,
      })),
    }).then(response => response.data),
    onSuccess: result => {
      setRecords(result.records);
      setNotice({ message: "Network orders and circuits saved." });
    },
    onError: error => setNotice({ message: getApiErrorMessage(error, "Network orders and circuits could not be saved."), error: true }),
  });
  const importMutation = useMutation({
    mutationFn: ({ csvText, mode }: { csvText: string; mode: CsvImportMode }) => api.post("/admin/network-orders/import", {
      csv_text: csvText, mode,
    }).then(response => response.data),
    onSuccess: result => {
      setRecords(result.rows);
      setNotice({ message: result.mode === "replace"
        ? `Network-order/circuit records replaced with ${result.total} CSV rows.`
        : `CSV imported: ${result.added} added, ${result.updated} updated.` });
    },
    onError: error => setNotice({ message: getApiErrorMessage(error, "Network orders and circuits CSV could not be imported."), error: true }),
  });

  const updateAssociatedCircuits = (rowIndex: number, associatedIds: string[]) => {
    setRecords(current => {
      const sourceId = current[rowIndex]?.circuit_network_order_id.trim();
      if (!sourceId) return current;
      const sourceKey = sourceId.toLocaleLowerCase();
      const previousIds = new Set((current[rowIndex].associated_circuit_network_order_ids || []).map(id => id.toLocaleLowerCase()));
      const uniqueIds = Array.from(new Map(associatedIds.map(id => [id.toLocaleLowerCase(), id])).values());
      const nextIds = new Set(uniqueIds.map(id => id.toLocaleLowerCase()));
      return current.map((record, index) => {
        if (index === rowIndex) return { ...record, associated_circuit_network_order_ids: uniqueIds };
        const recordKey = record.circuit_network_order_id.trim().toLocaleLowerCase();
        const wasAssociated = previousIds.has(recordKey);
        const isAssociated = nextIds.has(recordKey);
        if (!recordKey || wasAssociated === isAssociated) return record;
        const otherAssociations = record.associated_circuit_network_order_ids || [];
        return {
          ...record,
          associated_circuit_network_order_ids: isAssociated
            ? [...otherAssociations, sourceId]
            : otherAssociations.filter(id => id.toLocaleLowerCase() !== sourceKey),
        };
      });
    });
  };

  const changeField = (rowIndex: number, field: EditableNetworkOrderField, value: string) => {
    setRecords(current => {
      const oldId = field === "circuit_network_order_id" ? current[rowIndex].circuit_network_order_id.trim() : "";
      const newId = value.trim();
      const oldKey = oldId.toLocaleLowerCase();
      const newKey = newId.toLocaleLowerCase();
      return current.map((record, index) => {
        if (index === rowIndex) {
          const associations = field === "circuit_network_order_id" && newKey
            ? (record.associated_circuit_network_order_ids || []).filter(id => id.toLocaleLowerCase() !== newKey)
            : record.associated_circuit_network_order_ids || [];
          return { ...record, [field]: value, associated_circuit_network_order_ids: associations };
        }
        if (field !== "circuit_network_order_id" || !oldKey || oldId === newId) return record;
        return {
          ...record,
          associated_circuit_network_order_ids: (record.associated_circuit_network_order_ids || [])
            .flatMap(id => id.toLocaleLowerCase() !== oldKey ? [id] : newId ? [newId] : []),
        };
      });
    });
  };

  const removeRow = (rowIndex: number) => {
    setRecords(current => {
      const removedId = current[rowIndex]?.circuit_network_order_id.trim().toLocaleLowerCase();
      return current.filter((_record, index) => index !== rowIndex).map(record => ({
        ...record,
        associated_circuit_network_order_ids: (record.associated_circuit_network_order_ids || [])
          .filter(id => id.toLocaleLowerCase() !== removedId),
      }));
    });
  };

  const circuitIdCounts = new Map<string, number>();
  records.forEach(record => {
    const key = record.circuit_network_order_id.trim().toLocaleLowerCase();
    if (key) circuitIdCounts.set(key, (circuitIdCounts.get(key) || 0) + 1);
  });
  const associationOptions: SearchableMultiSelectOption[] = records.flatMap(record => {
    const circuitId = record.circuit_network_order_id.trim();
    if (!circuitId || circuitIdCounts.get(circuitId.toLocaleLowerCase()) !== 1) return [];
    return [{
      value: circuitId,
      label: `${circuitId} · ${record.company} · ${record.a_location} → ${record.z_location}`,
    }];
  });

  if (recordsQuery.isLoading) return <div style={{ color: "var(--text-secondary)" }}>Loading network orders and circuits...</div>;
  if (recordsQuery.isError) return <div role="alert" style={{ color: "var(--accent-red)" }}>{getApiErrorMessage(recordsQuery.error, "Network orders and circuits could not be loaded.")}</div>;

  return <div style={{ display: "grid", gap: "1rem" }}>
    <div>
      <h3 style={{ margin: "0 0 0.35rem", color: "var(--text-primary)" }}>Network Orders &amp; Circuits</h3>
      <p style={{ margin: 0, color: "var(--text-muted)", fontSize: "0.78rem" }}>Maintain A/Z circuit references. Associated circuit links are reciprocal and the email composer includes the full linked group. CSV supports an optional semicolon-separated Associated Circuit/Network Order IDs column.</p>
    </div>
    {notice && <div role={notice.error ? "alert" : "status"} style={{ ...cardStyle, padding: "0.65rem", color: notice.error ? "var(--accent-red)" : "var(--accent-green)" }}>{notice.message}</div>}
    <section style={{ ...cardStyle, minWidth: 0 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, marginBottom: 12 }}>
        <h4 style={{ margin: 0, fontSize: "0.9rem" }}>Circuit / Network Order Records</h4>
        {canManage && <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
          <CsvImportControl
            pending={saveMutation.isPending || importMutation.isPending}
            onImport={(csvText, mode) => { setNotice(null); importMutation.mutate({ csvText, mode }); }}
            onError={message => setNotice({ message, error: true })}
          />
          <button type="button" style={buttonStyle} onClick={() => { setRecords(rows => [...rows, { ...emptyRow }]); setNotice(null); }}><Plus size={14} />Add record</button>
        </div>}
      </div>
      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", minWidth: 1200, borderCollapse: "collapse", fontSize: "0.78rem" }}>
          <thead><tr>
            {columns.map(column => <th key={column.key} scope="col" style={{ textAlign: "left", padding: "0.5rem", borderBottom: "1px solid var(--border-primary)" }}>{column.label}</th>)}
            <th scope="col" style={{ textAlign: "left", padding: "0.5rem", borderBottom: "1px solid var(--border-primary)" }}>Associated Circuit/Network Order IDs</th>
            {canManage && <th scope="col" aria-label="Row actions" style={{ borderBottom: "1px solid var(--border-primary)" }} />}
          </tr></thead>
          <tbody>{records.map((row, index) => <tr key={row.id ?? `new-${index}`}>
            {columns.map(column => <td key={column.key} style={{ padding: "0.4rem", borderBottom: "1px solid var(--border-primary)" }}>
              <input
                aria-label={`${column.label} ${index + 1}`}
                value={row[column.key]}
                maxLength={column.key === "a_location" || column.key === "z_location" ? 250 : column.key === "circuit_network_order_id" ? 200 : 200}
                disabled={!canManage || saveMutation.isPending || importMutation.isPending}
                onChange={event => changeField(index, column.key, event.target.value)}
                style={{ ...inputStyle, opacity: canManage ? 1 : 0.8 }}
              />
            </td>)}
            <td style={{ padding: "0.4rem", borderBottom: "1px solid var(--border-primary)", minWidth: 280 }}>
              <SearchableMultiSelect
                label={`Associated Circuit/Network Order IDs for row ${index + 1}`}
                options={associationOptions.filter(option => option.value.toLocaleLowerCase() !== row.circuit_network_order_id.trim().toLocaleLowerCase())}
                value={row.associated_circuit_network_order_ids || []}
                onChange={values => updateAssociatedCircuits(index, values)}
                disabled={!canManage || saveMutation.isPending || importMutation.isPending || !row.circuit_network_order_id.trim()}
                placeholder="Choose associated circuits"
                noOptionsMessage="No other unique circuit IDs are available."
              />
            </td>
            {canManage && <td style={{ padding: "0.4rem", borderBottom: "1px solid var(--border-primary)" }}>
              <button type="button" aria-label={`Remove network order row ${index + 1}`} onClick={() => removeRow(index)} disabled={saveMutation.isPending || importMutation.isPending}
                style={{ background: "transparent", border: 0, color: "var(--accent-red)", cursor: "pointer" }}><Trash2 size={16} /></button>
            </td>}
          </tr>)}
          {!records.length && <tr><td colSpan={columns.length + 1 + (canManage ? 1 : 0)} style={{ padding: "1rem", color: "var(--text-muted)", textAlign: "center" }}>No network orders or circuits are configured.</td></tr>}
          </tbody>
        </table>
      </div>
      {canManage && <div style={{ marginTop: 12 }}><button type="button" onClick={() => { setNotice(null); saveMutation.mutate(records); }} disabled={saveMutation.isPending || importMutation.isPending} style={{ ...buttonStyle, opacity: saveMutation.isPending ? 0.7 : 1 }}><Save size={14} />{saveMutation.isPending ? "Saving..." : "Save records"}</button></div>}
    </section>
  </div>;
}
