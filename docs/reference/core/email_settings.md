# Module: `src.core.email_settings`

Selects the active database-backed outbound SMTP profile shared by API and worker send paths.

## Functions

### `get_active_smtp_profile(config, overrides=None) -> dict`

Returns a normalized profile dictionary. The existing `smtp` profile includes its optional username/password; the Gmail profile includes account address, OAuth client ID, client secret, refresh token, sender, and shared recipient. A missing/blank provider defaults to the legacy `smtp` profile. Gmail uses `smtp.gmail.com:587` with STARTTLS and defaults its From address to the account. Optional `overrides` apply pending validated administrator settings when checking an unsaved configuration update.

OAuth credentials are consumed only by token refresh and SMTP XOAUTH2. Settings APIs return only configured flags, never client secrets or refresh tokens.

### `smtp_profile_is_ready(profile) -> bool`

Returns false for disabled/incomplete profiles. A Gmail profile also requires a username and all three OAuth fields; a generic SMTP relay may use unauthenticated delivery if its server permits it.

## Callers and boundaries

- `src.utils.mailer.send_alert_email()` uses this selector for every ordinary outbound message.
- `src.utils.risk_alert.send_alert()` delegates to the shared mailer, so risk-change notices follow the selected profile.
- `src.core.operational_email` snapshots the selected provider and From address in each delivery-history row.
- `src.services.save_global_config()` uses optional overrides to validate the active profile when failed-login email alerts are enabled.

The profile choice is global and evaluated when a message is sent. Switching it affects future email; already completed delivery records retain the provider and From address used for that attempt.
