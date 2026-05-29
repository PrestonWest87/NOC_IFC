# API Client

## Overview

Axios-based HTTP client pre-configured with the `/api/v1` base URL. Injects the authentication token from `sessionStorage` into every request as a query parameter, and handles 401 responses by clearing session data and redirecting to the login page.

---

## Module: `api`

### `api` (default export)

- **Type**: `AxiosInstance`
- **Created via**: `axios.create({ baseURL: "/api/v1" })`
- **Purpose**: Singleton Axios instance used by all page components and utilities to communicate with the FastAPI backend.

---

## Interceptors

### Request Interceptor

| Event | Behavior |
|-------|----------|
| **Before request** | Reads `noc_token` from `sessionStorage`. If present, merges it into the request params as `{ token }`. |

- **Flow**: Every outgoing request gets `?token=<stored_token>` appended to its query parameters.

### Response Interceptor

| Event | Behavior |
|-------|----------|
| **On error** | If `err.response.status === 401`, clears `noc_token` and `noc_user` from `sessionStorage` and sets `window.location.hash` to `#/login`. |

- **Flow**: Catches all response errors. On 401, logs the user out locally (clears session) and redirects to the login page. Always re-throws the error via `Promise.reject(err)` so callers can handle it further.

---

## Dependencies

| Dependency | Purpose |
|-----------|---------|
| `axios` | HTTP client library |
