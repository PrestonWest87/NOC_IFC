# Component: `EmailContactsSettingsTab`

**Source:** `web/src/components/EmailContactsSettingsTab.tsx`
**Settings tab:** `email-contacts`
**Permission:** `Tab: Settings -> Email Contacts` for reads; administrator role for writes.

The tab contains two ordered tables:

- **Fiber:** Name, Company, Email, Phone (optional).
- **ONPAGE:** Department, Email.

React Query reads `GET /settings/email-contacts`. Administrators can add, edit, remove, and replace each list independently through `PUT /admin/email-contacts/fiber` or `PUT /admin/email-contacts/onpage`. Successful saves update only the edited section, so unsaved changes in the other section remain in the form. Server validation trims/bounds fields, requires one valid email address per row, validates optional phones, and caps each list at 250 rows. The backend audits replacement counts without storing contact values in audit details.
