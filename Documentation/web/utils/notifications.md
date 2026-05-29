# Notifications

## Overview

Browser Notification API wrapper that triggers desktop notifications for critical/high-severity alerts. Implements deduplication by alert ID and auto-cleans old entries after one hour.

---

## Module-Level State

| Variable | Type | Description |
|----------|------|-------------|
| `seenIds` | `Set<string>` | Module-scoped set of notification IDs that have already been shown. Prevents duplicate notifications for the same alert. |

---

## Functions

### `triggerCriticalNotification(id, title, body)`

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | `string \| number` | Unique alert identifier used for deduplication |
| `title` | `string` | Notification title |
| `body` | `string` | Notification body text |

- **Returns**: `void`
- **Flow**:
  1. Converts `id` to string via `String(id)` and checks `seenIds`. If already present, returns immediately.
  2. Adds the key to `seenIds`.
  3. Checks `Notification` browser API availability.
  4. If permission is `"granted"`, immediately creates a `new Notification(title, { body })`.
  5. If permission is not `"denied"`, calls `Notification.requestPermission()` and creates the notification if granted.
  6. Schedules a `setTimeout` for 3,600,000 ms (1 hour) to remove the key from `seenIds`, preventing unbounded memory growth.

---

## Dependencies

| Dependency | Purpose |
|-----------|---------|
| None (browser `Notification` API) | Native browser desktop notifications |
