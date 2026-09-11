# Module: `web/src/utils/AuthContext.tsx`

React authentication context for database-backed session tokens, user permissions, login persistence, profile refresh, and logout.

## `User`

Optional identity fields include `id`, `full_name`, `job_title`, `contact_info`, `default_shift`, `theme`, and `role`. Permission arrays are `allowed_pages`, `allowed_actions`, and `allowed_site_types`.

## `AuthContextType`

```ts
{
  user: User | null;
  token: string;
  login(username: string, password: string): Promise<User>;
  logout(): void;
  refreshUser(): Promise<void>;
}
```

## `AuthProvider({ children })`

Initializes `user` from `sessionStorage.noc_user` and `token` from `sessionStorage.noc_token`. On mount it registers a `noc:unauthorized` listener and calls `refreshUser()`.

### `login(username, password)`

Posts credentials to `/auth/login`. On success it stores the returned token and user under `noc_token` and `noc_user`, updates React state, and returns the user object.

### `refreshUser()`

If a stored token exists, calls `/auth/me` through the API client. Successful data replaces the stored user and state. A `401` clears both session keys and resets state; transient network/API errors log a warning and retain the session.

### `logout()`

Fire-and-forgets `POST /auth/logout`, catches any request failure, immediately removes both session keys, and clears user/token state. It does not require the logout request to succeed before updating the UI.

## `useAuth()`

Returns the context value and must be called beneath `AuthProvider`. The API client separately handles a `401` by dispatching `noc:unauthorized`; the provider listener then clears in-memory auth state.
