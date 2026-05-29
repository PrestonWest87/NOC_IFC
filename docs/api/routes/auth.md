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
2. If the result is falsy, raises 401.
3. Otherwise returns the user dict and token.

### Dependencies
- `src.services.authenticate_user()`

---

## Endpoint: `GET /me`

### Purpose
Retrieves the authenticated user's profile by session token.

### Parameters
| Parameter | Type   | Description                              |
|-----------|--------|------------------------------------------|
| `token`   | `str`  | Session token (query parameter).         |

### Returns
The user object dictionary.

### Raises
- `HTTPException 401` — if the token is invalid or expired.

### Flow
1. Calls `svc.get_user_by_token(token)`.
2. If no user is returned, raises 401.
3. Returns the user dict.

### Dependencies
- `src.services.get_user_by_token()`

---

## Endpoint: `POST /logout`

### Purpose
Logs out a user by clearing their session token.

### Parameters
| Parameter  | Type   | Description                  |
|------------|--------|------------------------------|
| `username` | `str`  | Username to log out (body).  |

### Returns
```json
{ "status": "ok" }
```

### Raises
None.

### Flow
1. Calls `svc.logout_user(username)`.
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
| `username` | `str`            | Username to update (body).        |
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
