# Module: `web/src/utils/api.ts`

Exports a singleton Axios client configured for the browser API.

## Axios Instance

```ts
axios.create({ baseURL: "/api/v1" })
```

The relative base URL allows Vite’s development proxy and production nginx `/api/` proxy to use the same frontend code.

## Request Interceptor

Reads `noc_token` from `sessionStorage`. When present, it adds:

```http
Authorization: Bearer <session-token>
```

The current frontend does not append the token as a query parameter. The backend retains query-token compatibility for older clients.

## Response Interceptor

Successful responses pass through unchanged. A `401` response:

1. Removes `noc_token` and `noc_user` from `sessionStorage`.
2. Dispatches the browser event `noc:unauthorized`.
3. Sets `window.location.hash` to `#/login`.
4. Rejects the original Axios error so the caller can handle it.

Other response errors are rethrown without local session cleanup.
