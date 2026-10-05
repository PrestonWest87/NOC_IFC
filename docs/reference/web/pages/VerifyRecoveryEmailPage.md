# Page: `VerifyRecoveryEmailPage`

**Source:** `web/src/pages/VerifyRecoveryEmailPage.tsx`

**Route:** `/verify-email` (public, reached through a link carrying `?token=`)

On mount, submits the query token to `GET /auth/verify-recovery-email`. It displays a progress message, then the success response or an accessible invalid/expired-link error. It links back to sign-in and does not expose the token beyond the request URL.
