# AuthContext

## Overview

React context provider and hook for authentication state management. Handles login, logout, session persistence via `sessionStorage`, and automatic user profile refresh on mount.

---

## Interfaces

### `User`

| Property | Type | Description |
|----------|------|-------------|
| `id` | `number` (optional) | User database ID |
| `username` | `string` | Login username |
| `full_name` | `string` (optional) | Display name |
| `job_title` | `string` (optional) | User's job title |
| `contact_info` | `string` (optional) | Contact details |
| `default_shift` | `string` (optional) | Default shift assignment |
| `role` | `string` (optional) | Role name (e.g. "admin", "observer") |
| `allowed_pages` | `string[]` (optional) | Page labels the user can access |
| `allowed_actions` | `string[]` (optional) | Action permission strings the user has |
| `allowed_site_types` | `string[]` (optional) | Site type filters the user can view |

### `AuthContextType`

| Property | Type | Description |
|----------|------|-------------|
| `user` | `User \| null` | Current authenticated user or null |
| `token` | `string` | Current session token (may be empty) |
| `login` | `(username: string, password: string) => Promise<void>` | Authenticate and store session |
| `logout` | `() => void` | Clear session and notify backend |

---

## Functions

### `AuthProvider` (component)

- **Props**: `{ children: ReactNode }`
- **Purpose**: Provides auth state to the entire React tree. Restores session from `sessionStorage` on mount.
- **Flow**:
  1. Initializes `user` state by reading `noc_user` from `sessionStorage` (JSON.parse).
  2. Initializes `token` state from `noc_token` in `sessionStorage`.
  3. On mount, calls `refreshUser()` to validate the token against the backend.
  4. Provides `{ user, token, login, logout }` via `AuthContext.Provider`.
- **Returns**: `<AuthContext.Provider>` wrapping `children`.

---

### `login(username, password)`

| Parameter | Type | Description |
|-----------|------|-------------|
| `username` | `string` | User login name |
| `password` | `string` | User password |

- **Returns**: `Promise<void>`
- **Flow**:
  1. Sends `POST /api/v1/auth/login` with `{ username, password }`.
  2. On success, stores `data.token` in `sessionStorage` under `noc_token`.
  3. Stores `JSON.stringify(data.user)` in `sessionStorage` under `noc_user`.
  4. Updates `user` and `token` state, triggering re-render of consuming components.

---

### `refreshUser()`

- **Returns**: `Promise<void>`
- **Flow**:
  1. Reads token from `sessionStorage`. If absent, returns early.
  2. Calls `GET /api/v1/auth/me` to fetch current user profile.
  3. On success, updates `sessionStorage` and `user` state.
  4. On failure (network error / 401), clears all session data and resets `user` to `null`.

---

### `logout()`

- **Returns**: `void`
- **Flow**:
  1. Sends `POST /api/v1/auth/logout?username=<user.username>` (fire-and-forget, errors caught).
  2. Removes `noc_token` and `noc_user` from `sessionStorage`.
  3. Sets `user` to `null` and `token` to `""`.

---

### `useAuth()` (hook)

- **Returns**: `AuthContextType`
- **Purpose**: Convenience hook to consume the `AuthContext`. Must be called within an `<AuthProvider>`.
- **Throws**: If called outside of `AuthProvider`.

---

## Dependencies

| Dependency | Purpose |
|-----------|---------|
| `react` (createContext, useContext, useState, useCallback, useEffect) | React context, state, lifecycle |
| `./api` | Axios API client for backend auth endpoints |
