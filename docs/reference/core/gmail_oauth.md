# Module: `src.core.gmail_oauth`

Refreshes Google OAuth access tokens for Gmail SMTP XOAUTH2 delivery.

## Constants and errors

- `GOOGLE_OAUTH_TOKEN_URL` is Google's `https://oauth2.googleapis.com/token` endpoint.
- `GmailOAuthError` reports credential-safe token refresh failures without including client secrets, refresh tokens, or response bodies.

## `refresh_gmail_access_token(profile) -> str`

Requires `client_id`, `client_secret`, and `refresh_token` in the normalized Gmail profile. It POSTs a bounded form-encoded `grant_type=refresh_token` request with a ten-second timeout, validates the JSON response, and returns the short-lived access token. HTTP, network, JSON, and missing-token failures raise `GmailOAuthError` with a generic actionable message.

The returned token is passed to SMTP XOAUTH2 by `src.utils.mailer`; it is not persisted or included in logs. Gmail SMTP OAuth uses the `https://mail.google.com/` scope; the Google OAuth consent and Workspace admin policy must permit the application and scope.
