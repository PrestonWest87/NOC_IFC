# Component: `UsersRolesTab`

**Source:** `web/src/components/UsersRolesTab.tsx`

Provides the searchable/filterable account directory, role editor, invitation/display-account flows, session/password administration, and recovery-review queues in Settings > Users & Roles.

The component checks its capabilities independently: `Action: Manage Users`, `Action: Manage Roles`, `Action: Review Account Recovery Requests`, and `Action: Approve Recovery Email Changes`. Queries are enabled only for the corresponding granted actions. Individual invitations require email; display accounts may omit it. The directory shows account type, recovery-email state, active state, last sign-in, and last activity. Individual accounts without an approved recovery address receive a recovery prompt; display accounts use administrator-assisted recovery.

Role grants are loaded from `/permissions/catalog` and site types from `/user-admin/site-types`. Previously assigned site types no longer in the catalog remain visible as legacy grants so an administrator can remove them; saving a role can retain them or remove them, but cannot add a new unknown site type. The backend also rejects permission escalation even if a client submits grants outside the editor's visible choices. Mutations use accessible status/error messages and refresh affected queries.
