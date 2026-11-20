# Component: `NetworkOrdersCircuitsTab`

**Source:** `web/src/components/NetworkOrdersCircuitsTab.tsx`
**Settings tab:** `network-orders`
**Permission:** `Tab: Settings -> Network Orders & Circuits` for reads; administrator role for writes.

The ordered editable table stores A location, Z location, Circuit/Network Order ID, Company, and a searchable checkbox multi-select of associated circuit IDs with removable selected chips. Links are reciprocal; Operational Email adds only the immediate associations of explicitly selected circuits and does not traverse links from auto-included circuits. React Query reads `GET /settings/network-orders`; administrators save the table through `PUT /admin/network-orders` or upload CSV through `POST /admin/network-orders/import`. CSV uses the A location, Z location, Circuit/Network Order ID, and Company headers; an optional Associated Circuit/Network Order IDs column uses semicolon-separated IDs. Merge/update by Circuit/Network Order ID is the default and preserves associations if that column is omitted; replace-all is also supported. Rows are editable/removable, and new rows can be appended. The backend trims and bounds fields, validates references, caps the list at 250 records, preserves submitted order, and writes an audit count without row values.
