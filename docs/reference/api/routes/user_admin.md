# Route module: `src.api.routes.user_admin`

All routes use the Settings page and Users & Roles tab. Endpoints additionally require user-management, role-management, recovery-review, or recovery-email-approval actions as listed below. Built-in administrators have the full-access override; delegated role editors cannot grant permissions they do not hold or manage administrator/elevated user-admin accounts.

## Directory, roles, and invitations

| Method/path | Action | Behavior |
|---|---|---|
| `GET /api/v1/user-admin/users` | `Manage Users` | Returns directory rows with account type, recovery status, active state, and access history for the frontend directory/search filters. |
| `GET /api/v1/user-admin/roles` | `Manage Users` | Assignable roles; delegated editors do not receive built-in or elevated user-admin roles. |
| `GET /api/v1/user-admin/role-definitions` | `Manage Roles` | Role definitions and grants available to the editor. |
| `GET /api/v1/user-admin/site-types` | `Manage Roles` | Current site-type choices. |
| `POST /api/v1/user-admin/display-accounts` | `Manage Users` | Creates an email-optional display account. Username is 3–64 characters; password is 12–256 characters. |
| `POST /api/v1/user-admin/invitations` | `Manage Users` | Creates an email-required individual invitation; `ttl_hours` is 1–336, default 72. Queues invitation email. |
| `GET /api/v1/user-admin/invitations` | `Manage Users` | Lists pending invitations. |
| `POST /api/v1/user-admin/invitations/{invite_id}/resend` | `Manage Users` | Creates/queues a replacement invitation link for a pending invitation. |
| `DELETE /api/v1/user-admin/invitations/{invite_id}` | `Manage Users` | Revokes a pending invitation and retains its audit history. |
| `POST /api/v1/user-admin/roles` | `Manage Roles` | Creates a role from page, action, and site-type grant arrays. |
| `PUT /api/v1/user-admin/roles/{name}` | `Manage Roles` | Updates grants; built-in administrator role cannot be edited. |

## Account maintenance

- `PUT /users/{username}/profile` updates full name, job title, and contact information.
- `PUT /users/{username}/role` changes an assignable role.
- `PATCH /users/{username}/status` body `{is_active}` disables/reactivates the account.
- `PATCH /users/{username}/account-type` body `{account_type: "individual"|"display"}` changes account type subject to business rules.
- `POST /users/{username}/revoke-sessions` revokes all of the target user's active sessions.
- `POST /users/{username}/administrator-reset` body `{new_password}` allows delegated managers to reset display accounts; only a built-in administrator may perform an assisted reset for an individual account, including an email-less individual. Password length is at least 12 characters.

All these routes require `Action: Manage Users` in addition to the router-level page/tab grants.

## Recovery review

- `GET /recovery-requests` and `POST /recovery-requests/{request_id}/decision` require `Action: Review Account Recovery Requests`.
- `GET /email-change-requests` and `POST /email-change-requests/{request_id}/decision` require `Action: Approve Recovery Email Changes`.
- Both decision bodies use `{approve: boolean, reason: string}`. Approval/denial is audited. Approved password resets send a short-lived single-use link to the approved verified address; approved recovery-email changes still require mailbox verification.

The API returns structured permission errors for denied writes and does not allow delegated editors to escalate their own grants.
