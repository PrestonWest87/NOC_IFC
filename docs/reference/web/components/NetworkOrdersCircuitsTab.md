# Component: `NetworkOrdersCircuitsTab`

**Source:** `web/src/components/NetworkOrdersCircuitsTab.tsx`
**Settings tab:** `network-orders`
**Permission:** `Tab: Settings -> Network Orders & Circuits` for reads; administrator role for writes.

The ordered editable table stores A location, Z location, Circuit/Network Order ID, and Company. React Query reads `GET /settings/network-orders`; administrators save the table through `PUT /admin/network-orders` or upload CSV through `POST /admin/network-orders/import`. CSV uses the A location, Z location, Circuit/Network Order ID, and Company headers; merge/update by Circuit/Network Order ID is the default, with an explicit replace-all mode. Rows are editable/removable, and new rows can be appended. The backend trims and bounds each required text field, caps the list at 250 records, preserves submitted order, and writes an audit count without row values.
