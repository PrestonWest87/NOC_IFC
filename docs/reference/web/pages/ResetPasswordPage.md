# Page: `ResetPasswordPage`

**Source:** `web/src/pages/ResetPasswordPage.tsx`

**Route:** `/reset-password` (public, reached through a link carrying `?token=`)

Reads the single-use token from the query string, checks that the new password is at least 12 characters and that confirmation matches, then submits `{token, new_password}` to `POST /auth/reset-password`. On success it clears both password fields and displays the API message; the user must sign in again because the server revokes existing sessions.
