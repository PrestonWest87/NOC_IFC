# Module: `src.api.routes.auth`

Authentication and user profile management routes. Prefix: `/api/v1/auth`.

---

## Pydantic Models

### `LoginRequest`
| Field      | Type     | Description                |
|------------|----------|----------------------------|
| `username` | `str`    | User login name.           |
| `password` | `str`    | User password (plaintext). |

### `ProfileUpdate`
| Field            | Type     | Description                    |
|------------------|----------|--------------------------------|
| `full_name`      | `str`    | Updated full name.             |
| `job_title`      | `str`    | Updated job title.             |
| `contact_info`   | `str`    | Updated contact information.   |
| `default_shift`  | `str`    | Updated default shift period.  |
| `old_password`   | `str`    | Current password for verification. |
| `new_password`   | `str`    | Desired new password.          |

---

## Endpoint: `POST /login`

### Purpose
Authenticates a user by username and password, returning a user object and session token.

### Parameters
| Parameter | Type            | Description              |
|-----------|-----------------|--------------------------|
| `req`     | `LoginRequest`  | Login credentials (body).|

### Returns
```json
{
  "user": { ... },
  "token": "<session_token>"
}
```

### Raises
- `HTTPException 401` — if credentials are invalid.

### Flow
1. Calls `svc.authenticate_user(req.username, req.password)`.
2. If credentials fail, records the submitted username and client IP when failed-login alerts are enabled.
3. When the configured threshold is reached within its time window, schedules one background email for the configured recipient list with the attempted usernames and source IPs.
4. Returns the same generic 401 for invalid credentials; otherwise returns the user dict and token.

### Dependencies
- `src.services.authenticate_user()`
- `src.services.record_failed_login_attempt()`

---

## Endpoint: `GET /me`

### Purpose
Retrieves the authenticated user's profile by session token.

### Authentication
Uses the authenticated request context. Send `Authorization: Bearer <session-token>`; the legacy `token` and `session_token` query parameters remain accepted for compatibility.

### Returns
The user object dictionary.

### Raises
- `HTTPException 401` — if there is no valid session or the account is inactive.

### Flow
1. Authentication middleware resolves the bearer token or legacy query token and attaches the active user.
2. `get_current_user` returns that request-state user (or resolves a token for direct dependency callers).
3. The route returns `_public_user(user)`, excluding password and session-token fields.

### Dependencies
- `src.services.get_user_by_token()`

---

## Endpoint: `POST /logout`

### Purpose
Revokes the current authenticated session. The authenticated user and session token are taken from the request context.

### Returns
```json
{ "status": "ok" }
```

### Raises
None.

### Flow
1. Calls `svc.logout_user(user.username, request.state.auth_token)`.
2. Returns success status.

### Dependencies
- `src.services.logout_user()`

---

## Endpoint: `POST /update-profile`

### Purpose
Updates a user's profile fields and optionally changes the password.

### Parameters
| Parameter  | Type             | Description                       |
|------------|------------------|-----------------------------------|
| `body`     | `ProfileUpdate`  | Profile update fields (body).     |

### Returns
```json
{
  "status": "ok",
  "message": "<description>"
}
```

### Raises
- `HTTPException 400` — if the update fails (e.g., wrong old password, validation error).

### Flow
1. Calls `svc.update_user_profile()` with all fields from the request body.
2. If the operation returns `(False, msg)`, raises 400 with the message.
3. Otherwise returns success.

### Dependencies
- `src.services.update_user_profile()`
## Current Source Surface

Public endpoints are login, registration validation, and registration. Protected endpoints use `get_current_user`.

- `POST /login` returns a database-backed session token and public user object.
- `GET /register/validate` checks an invitation token without authenticating the caller.
- `POST /register` completes an invitation-based account with profile, password, shift, and theme data.
- `GET /me` returns the current user/permission payload.
- `POST /logout` revokes the current session.
- `POST /update-profile` validates profile/password changes.
- `POST /update-theme` persists the selected user theme.
