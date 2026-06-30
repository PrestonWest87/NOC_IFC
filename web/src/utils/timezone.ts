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

export function formatInChicago(
  d: string | Date | null | undefined,
  options?: Intl.DateTimeFormatOptions,
  fallback = "Unknown"
): string {
  if (!d) return fallback;
  try {
    return new Date(d).toLocaleString("en-US", options ?? DEFAULT_OPTIONS);
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
    return new Date(d).toLocaleDateString("en-US", DATE_OPTIONS);
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
    return new Date(d).toLocaleTimeString("en-US", TIME_OPTIONS);
  } catch {
    return String(d);
  }
}

export function chicagoDateString(d?: string | Date): string {
  const date = d ? new Date(d) : new Date();
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
    return new Date(d).toLocaleDateString("en-US", {
      month: "short", day: "numeric", year: "numeric",
      hour: "2-digit", minute: "2-digit", timeZone: CHICAGO,
    });
  } catch {
    return String(d);
  }
}
