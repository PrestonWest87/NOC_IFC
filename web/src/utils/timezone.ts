const CHICAGO = "America/Chicago";

const DEFAULT_OPTIONS: Intl.DateTimeFormatOptions = {
  month: "short", day: "numeric", year: "numeric",
  hour: "2-digit", minute: "2-digit", timeZone: CHICAGO,
};

const DATE_OPTIONS: Intl.DateTimeFormatOptions = {
  month: "short", day: "numeric", year: "numeric", timeZone: CHICAGO,
};

const TIME_OPTIONS: Intl.DateTimeFormatOptions = {
  hour: "2-digit", minute: "2-digit", timeZone: CHICAGO,
};

/**
 * Safely parses naive date strings from the database (e.g., "2026-06-30T22:35:00")
 * by appending a 'Z' suffix if no timezone indicator is present. This forces
 * JavaScript to treat it as UTC rather than falling back to local system time.
 */
function ensureUtcDate(d: string | Date): Date {
  if (d instanceof Date) return d;
  
  // If it's a string and doesn't contain a timezone marker (Z or +/- offset), append 'Z'
  if (typeof d === "string" && !d.endsWith("Z") && !/[+-]\d{2}:\d{2}$/.test(d)) {
    return new Date(`${d}Z`);
  }
  return new Date(d);
}

export function formatInChicago(
  d: string | Date | null | undefined,
  options?: Intl.DateTimeFormatOptions,
  fallback = "Unknown"
): string {
  if (!d) return fallback;
  try {
    const dateObj = ensureUtcDate(d);
    return dateObj.toLocaleString("en-US", options ?? DEFAULT_OPTIONS);
  } catch {
    return String(d);
  }
}

export function formatDateInChicago(
  d: string | Date | null | undefined,
  fallback = "Unknown"
): string {
  if (!d) return fallback;
  try {
    const dateObj = ensureUtcDate(d);
    return dateObj.toLocaleDateString("en-US", DATE_OPTIONS);
  } catch {
    return String(d);
  }
}

export function formatTimeInChicago(
  d: string | Date | null | undefined,
  fallback = ""
): string {
  if (!d) return fallback;
  try {
    const dateObj = ensureUtcDate(d);
    return dateObj.toLocaleTimeString("en-US", TIME_OPTIONS);
  } catch {
    return String(d);
  }
}

export function chicagoDateString(d?: string | Date): string {
  const date = d ? ensureUtcDate(d) : new Date();
  const parts = new Intl.DateTimeFormat("en-CA", { // en-CA formats as YYYY-MM-DD
    timeZone: CHICAGO, year: "numeric", month: "2-digit", day: "2-digit",
  }).formatToParts(date);
  const get = (t: string) => parts.find((p) => p.type === t)?.value ?? "00";
  return `${get("year")}-${get("month")}-${get("day")}`;
}

export function chicagoNow(): Date {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: CHICAGO,
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
  }).formatToParts(new Date());
  const get = (t: string) => parseInt(parts.find((p) => p.type === t)?.value ?? "0");
  return new Date(get("year"), get("month") - 1, get("day"), get("hour"), get("minute"), get("second"));
}

export function formatShortInChicago(
  d: string | Date | null | undefined,
  fallback = "—"
): string {
  if (!d) return fallback;
  try {
    const dateObj = ensureUtcDate(d);
    return dateObj.toLocaleDateString("en-US", {
      month: "short", day: "numeric", year: "numeric",
      hour: "2-digit", minute: "2-digit", timeZone: CHICAGO,
    });
  } catch {
    return String(d);
  }
}
