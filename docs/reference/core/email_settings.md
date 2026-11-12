# Module: `src.core.email_settings`

Selects the active database-backed outbound SMTP profile shared by API and worker send paths.

## Functions

### `get_active_smtp_profile(config, overrides=None) -> dict`

Returns a normalized profile dictionary with `provider`, `enabled`, `server`, `port`, `username`, `password`, `sender`, and `recipient` keys. A missing/blank provider defaults to the legacy `smtp` profile. The Gmail profile fixes its endpoint to `smtp.gmail.com:587`, uses the saved Gmail account and app password, defaults its From address to that account, and shares the existing `smtp_recipient` fallback. Optional `overrides` apply pending validated administrator settings when checking an unsaved configuration update.

The helper removes whitespace from Gmail app passwords copied in Google's grouped display format. It does not expose credentials to API responses; callers use the returned password only for SMTP authentication.

### `smtp_profile_is_ready(profile) -> bool`

Returns false for disabled/incomplete profiles. A Gmail profile also requires a username and app password; a generic SMTP relay may use unauthenticated delivery if its server permits it.

## Callers and boundaries

- `src.utils.mailer.send_alert_email()` uses this selector for every ordinary outbound message.
- `src.utils.risk_alert.send_alert()` delegates to the shared mailer, so risk-change notices follow the selected profile.
- `src.core.operational_email` snapshots the selected provider and From address in each delivery-history row.
- `src.services.save_global_config()` uses optional overrides to validate the active profile when failed-login email alerts are enabled.

The profile choice is global and evaluated when a message is sent. Switching it affects future email; already completed delivery records retain the provider and From address used for that attempt.
