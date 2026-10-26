# Route module: `src.api.routes.auth`

Router prefix: `/api/v1/auth`. Login, registration, password-reset request/completion, and recovery-email verification are public. Profile, theme, logout, recovery-email request, and verification resend use the authenticated session. Passwords and tokens are not returned by `_public_user()`.

## Request models

| Model | Fields |
|---|---|
| `LoginRequest` | Required `username`, `password`. |
| `RegistrationRequest` | Required `token`, `password`; optional/defaulted `full_name`, `job_title`, `contact_info`, `default_shift="No Shift"`, `theme="standard"`. |
| `ProfileUpdate` | `full_name`, `job_title`, `contact_info`, `default_shift`, `old_password`, `new_password`; all default to empty strings. |
| `PasswordResetRequest` | `identifier` (username or approved email). |
| `PasswordResetCompletion` | `token`, `new_password`. |
| `RecoveryEmailRequest` | `email`. |

## Route reference

| Method/path | Auth | Behavior and notable errors |
|---|---|---|
| `POST /login` | Public | Calls `authenticate_user`; returns `{user, token}`. Invalid credentials use a generic 401. If failed-login alerts are enabled with valid recipients, the request records the sanitized username/IP and queues an alert when the configured threshold is claimed. |
| `GET /register/validate?token=...` | Public | Returns pending invitation details or 400 if the invite is missing, expired, used, or revoked. |
| `POST /register` | Public | Completes an email-bound invite, sets mailbox verification at completion, creates a session, and returns `{user, token}`. Password must be at least 12 characters; invalid invite/theme/policy returns 400. |
| `POST /request-password-reset` | Public | Always returns a generic accepted message. Matching active accounts with reviewed recovery can enter the admin queue; unmatched identifiers are stored only as a hash for rate limiting. |
| `POST /reset-password` | Public | Accepts `{token,new_password}`. Requires a valid one-hour, single-use token and 12+ character password; success revokes every session for that account. |
| `GET /verify-recovery-email?token=...` | Public | Consumes an approved 24-hour verification token and changes the account's verified recovery address; invalid/expired token returns 400. |
| `POST /request-recovery-email` | Authenticated | Submits `{email}` as `pending_review`, rejects collisions/duplicate pending requests, and queues notice to eligible verified reviewers. A reviewer cannot approve their own request. |
| `POST /resend-recovery-email-verification` | Authenticated | Reissues the verification message for an approved pending request. Resend is rate-limited to one per five minutes; invalid state returns 409. |
| `GET /me` | Authenticated | Returns the authenticated public user object, including current grants and recovery-email state. |
| `POST /logout` | Authenticated | Revokes only the token used by this request. |
| `POST /update-profile` | Authenticated | Updates name/title/contact/default shift. A password change requires the old password and the shared 12-character minimum; failure returns 400. Recovery-email changes use the separate reviewed workflow. |
| `POST /update-theme` | Authenticated | Accepts `{theme}` from the 21 supported theme IDs and persists it on the account; invalid themes return 400. |

## Recovery and anti-enumeration behavior

- Reset requests are rate-limited to at most 10 requests per source IP per hour and 5 per identifier hash per hour. A matching pending request less than 30 minutes old is reused rather than duplicated.
- The public reset response does not disclose whether an identifier exists or whether that account has a verified recovery address.
- Active verified recovery reviewers are selected by the appropriate review action plus Settings page and Users & Roles tab access. The request owner is excluded from their own reviewer notification set.
- A denial requires a reason. Approval of an email change only creates a pending-verification token; it does not immediately replace the approved address.
- Display accounts and individual accounts without a verified recovery address require administrator-assisted recovery.
- Tokens are random, stored only as SHA-256 hashes, expire, and are single-use. Password reset invalidates all sessions and other outstanding reset tokens.

## Last activity

Successful sign-in writes `last_login_at` and `last_activity_at`. `get_user_by_token()` updates activity no more than once per five minutes. The browser presents these values in America/Chicago; the API returns timestamp values in its user object.
