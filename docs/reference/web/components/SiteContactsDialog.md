# `SiteContactsDialog.tsx`

Administrator-only modal editor for reference contacts associated with one monitored site. It is opened from the Contacts column in **Settings → Facilities → Manual Adjustments**.

## Props

| Prop | Type | Description |
|---|---|---|
| `siteId` | `number` | Monitored-location primary key used by the contact API. |
| `siteName` | `string` | Site label displayed in the dialog title. |
| `onClose` | `() => void` | Closes the modal and restores focus to the invoking control. |

## Data flow

- Queries `GET /admin/location/{siteId}/contacts` with React Query.
- Replaces the ordered contact list through `PUT /admin/location/{siteId}/contacts`.
- Contact `name`, `phone`, and `email` are optional. Empty rows are omitted on save; the empty list clears a site's contacts.
- Frontend validation mirrors the API's field bounds and syntax rules: a single email address up to 254 characters, international-style phone syntax with 7–15 digits and an optional extension, and bounded single-line text. The API remains authoritative and returns field validation errors for invalid input.
- The dialog is labelled with `role="dialog"`, `aria-modal`, a heading reference, Escape/backdrop close controls, field error descriptions, and polite save status messages.
- It tells administrators that details appear as reference text in automatic ONPAGE email bodies and that IFC does not send to the saved email addresses.
