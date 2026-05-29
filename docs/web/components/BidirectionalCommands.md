# BidirectionalCommands

## Overview

Simple command interface that allows an operator to acknowledge a site by ID. Sends a PATCH request to the AIOps API and provides basic loading state feedback.

---

## Functions

### `BidirectionalCommands` (component)

- **Purpose**: Renders a numeric input and an "Acknowledge Site" button for manual site acknowledgment.
- **Flow**:
  1. Maintains `siteId` state bound to a number-type `<input>`.
  2. Maintains `sending` boolean to disable the button during the HTTP request.
  3. On button click, calls `handleAcknowledge` which sends `axios.patch` to `/api/v1/aiops/sites/{siteId}/acknowledge`.
  4. Ignores errors silently.
- **Returns**: A `<div>` containing an `<input type="number">` and a `<button>`.

---

### `handleAcknowledge()`

- **Returns**: `Promise<void>`
- **Flow**:
  1. Guards against `siteId === 0` (falsy).
  2. Sets `sending = true`.
  3. Sends `PATCH /api/v1/aiops/sites/${siteId}/acknowledge`.
  4. Resets `sending = false` in `finally` block. Errors are swallowed.

---

## State

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `siteId` | `number` | `0` | The site ID to acknowledge |
| `sending` | `boolean` | `false` | Whether an acknowledgment request is in-flight |

---

## Dependencies

| Dependency | Purpose |
|-----------|---------|
| `react` (useState) | Local component state |
| `axios` | HTTP client for API requests |
