# Component: `OperationalIntegrationSettings`

**Source:** `web/src/components/OperationalIntegrationSettings.tsx`

Renders editable environment-overridable alert destinations and Elastic connection settings inside Settings > Application Settings. The parent only mounts it for users with `Action: Manage Application Settings`; server-side checks require the Settings page, Application Settings tab, and same action.

The component queries `GET /application-settings/integrations` and writes through `PUT /application-settings/integrations`. It labels each setting's effective source, supports resetting all values to environment fallbacks, and treats blank optional destinations as disabled overrides. Elastic API-key reads return only a configured flag; the UI supports write-only replace, clear, or reset-to-environment behavior.
