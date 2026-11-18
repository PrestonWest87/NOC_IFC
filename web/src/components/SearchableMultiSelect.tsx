import { useId, useState } from "react";
import { Check, ChevronDown, X } from "lucide-react";

export type SearchableMultiSelectOption = { value: string; label: string };

export function SearchableMultiSelect({
  label, options, value, onChange, disabled = false, placeholder = "Choose items", noOptionsMessage = "No matching items.",
}: {
  label: string;
  options: SearchableMultiSelectOption[];
  value: string[];
  onChange: (value: string[]) => void;
  disabled?: boolean;
  placeholder?: string;
  noOptionsMessage?: string;
}) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const panelId = useId();
  const selected = new Set(value);
  const optionsByValue = new Map(options.map(option => [option.value, option] as const));
  const searchText = search.trim().toLocaleLowerCase();
  const visibleOptions = options.filter(option => !searchText
    || option.label.toLocaleLowerCase().includes(searchText));

  const toggle = (item: string) => onChange(selected.has(item)
    ? value.filter(valueItem => valueItem !== item)
    : [...value, item]);

  return <div style={{ display: "grid", gap: 6, minWidth: 0 }}>
    <button
      type="button"
      aria-expanded={open}
      aria-controls={open ? panelId : undefined}
      disabled={disabled}
      onClick={() => setOpen(current => !current)}
      style={{
        display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8,
        width: "100%", padding: "0.5rem 0.6rem", border: "1px solid var(--border-primary)",
        borderRadius: "var(--radius-sm)", background: "var(--bg-input)", color: "var(--text-primary)",
        font: "inherit", fontSize: "0.78rem", textAlign: "left", opacity: disabled ? 0.75 : 1,
      }}
    >
      <span>{value.length ? `${value.length} selected` : placeholder}</span>
      <ChevronDown size={15} aria-hidden="true" />
    </button>

    {!!value.length && <div aria-label={`${label} selected items`} style={{
      display: "flex", flexWrap: "wrap", gap: 5, maxHeight: 76, overflowY: "auto",
    }}>
      {value.map(item => {
        const option = optionsByValue.get(item);
        return <span key={item} style={{
          display: "inline-flex", alignItems: "center", gap: 5, maxWidth: "100%",
          padding: "0.2rem 0.35rem 0.2rem 0.5rem", borderRadius: 12,
          background: "var(--bg-tertiary)", color: "var(--text-primary)", fontSize: "0.72rem",
        }}>
          <span title={option?.label || item} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {option?.label || item}
          </span>
          {!disabled && <button
            type="button"
            aria-label={`Remove ${option?.label || item}`}
            onClick={() => toggle(item)}
            style={{ display: "inline-flex", padding: 0, border: 0, background: "transparent", color: "var(--text-secondary)" }}
          ><X size={12} aria-hidden="true" /></button>}
        </span>;
      })}
    </div>}

    {open && <div id={panelId} style={{ display: "grid", gap: 6, padding: 8, border: "1px solid var(--border-primary)", borderRadius: "var(--radius-sm)", background: "var(--bg-card)" }}>
      <input
        type="search"
        aria-label={`Search ${label}`}
        placeholder={`Search ${label.toLocaleLowerCase()}`}
        value={search}
        onChange={event => setSearch(event.target.value)}
        style={{ width: "100%", boxSizing: "border-box", padding: "0.4rem 0.5rem", borderRadius: 5, border: "1px solid var(--border-primary)", background: "var(--bg-input)", color: "var(--text-primary)", font: "inherit", fontSize: "0.76rem" }}
      />
      <div role="group" aria-label={`${label} options`} style={{ display: "grid", gap: 2, maxHeight: 240, overflowY: "auto" }}>
        {visibleOptions.map(option => <label key={option.value} style={{
          display: "flex", alignItems: "center", gap: 8, padding: "0.35rem 0.4rem",
          borderRadius: 4, background: selected.has(option.value) ? "var(--bg-tertiary)" : "transparent",
          color: "var(--text-primary)", fontSize: "0.76rem", cursor: "pointer",
        }}>
          <input
            className="searchable-multi-select-checkbox"
            type="checkbox"
            checked={selected.has(option.value)}
            disabled={disabled}
            onChange={() => toggle(option.value)}
          />
          <span style={{ overflowWrap: "anywhere" }}>{option.label}</span>
          {selected.has(option.value) && <Check size={14} aria-hidden="true" style={{ marginLeft: "auto", flex: "0 0 auto", color: "var(--accent-green)" }} />}
        </label>)}
        {!visibleOptions.length && <small style={{ padding: "0.5rem", color: "var(--text-muted)" }}>{noOptionsMessage}</small>}
      </div>
    </div>}
  </div>;
}
