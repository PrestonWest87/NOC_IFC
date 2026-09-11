# Module: `web/src/utils/timezone.ts`

Centralizes browser display and date-grouping behavior for `America/Chicago`.

## Functions

| Function | Behavior |
|---|---|
| `ensureUtcDate(value)` | Converts string/date input to a Date, treating timezone-less server timestamps as UTC. |
| `formatInChicago(value, options?)` | Formats a timestamp with `Intl.DateTimeFormat` in Central time. |
| `formatDateInChicago(value)` | Returns a Central-localized date string. |
| `formatTimeInChicago(value)` | Returns a Central-localized time string. |
| `chicagoDateString(value?)` | Returns `YYYY-MM-DD` in Central time; defaults to current time. |
| `chicagoNow()` | Returns the current Date object. |
| `formatShortInChicago(value)` | Produces compact date/time display for dense UI surfaces. |
| `formatEtrDate(isoStr)` | Formats a nullable maintenance ETR value or returns the configured empty-state text. |

All pages should use these helpers instead of implementing local timezone conversion.
