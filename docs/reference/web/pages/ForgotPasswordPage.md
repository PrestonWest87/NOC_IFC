# Page: `ForgotPasswordPage`

**Source:** `web/src/pages/ForgotPasswordPage.tsx`

**Route:** `/forgot-password` (public)

Submits the entered username or approved recovery email to `POST /auth/request-password-reset`. The API response is intentionally generic; matching requests enter the administrator review queue, and accounts without an approved recovery email require administrator-assisted recovery. The page displays success/error messages and links back to sign-in.
