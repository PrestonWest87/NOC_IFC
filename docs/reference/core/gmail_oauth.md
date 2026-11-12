# Module: `src.core.gmail_oauth`

Refreshes Google OAuth access tokens for Gmail SMTP XOAUTH2 delivery.

## Constants and errors

- `GOOGLE_OAUTH_TOKEN_URL` is Google's `https://oauth2.googleapis.com/token` endpoint.
- `GmailOAuthError` reports credential-safe token refresh failures without including client secrets, refresh tokens, or response bodies.

## `refresh_gmail_access_token(profile) -> str`

Requires `client_id`, `client_secret`, and `refresh_token` in the normalized Gmail profile. It POSTs a bounded form-encoded `grant_type=refresh_token` request with a ten-second timeout, validates the JSON response, and returns the short-lived access token. HTTP, network, JSON, and missing-token failures raise `GmailOAuthError` without including secrets or Google's response body. Google `invalid_client` points to an OAuth client ID/secret mismatch; `invalid_grant` asks the operator to reauthorize and create a new refresh token; Workspace policy and invalid-scope failures have separate guidance.

The returned token is passed to SMTP XOAUTH2 by `src.utils.mailer`; it is not persisted or included in logs. Gmail SMTP OAuth uses the `https://mail.google.com/` scope. The configured client should be a Web application OAuth client for the OAuth Playground flow; the Workspace administrator may need to trust the OAuth client and permit the Gmail scope.
