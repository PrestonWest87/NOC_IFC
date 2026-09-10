# LoginPage.tsx

Authentication page — renders a login form with username/password fields and error handling.

---

## `LoginPage` (named export)

### Purpose
Renders the NOC Fusion Center login form, handles credential submission, and navigates to the dashboard on success.

### Props
None (uses `useAuth` for authentication context).

### Returns
A full-viewport centered form with:
- Title "NOC Fusion Center" and subtitle "Intelligence Fusion Gateway"
- Error message banner (conditionally rendered)
- Username input field (default: "admin")
- Password input field (default: "admin123")
- "Sign In" submit button with loading state

### Flow

#### State Management
| State | Type | Default | Description |
|-------|------|---------|-------------|
| `username` | `string` | `"admin"` | Username input value |
| `password` | `string` | `"admin123"` | Password input value |
| `error` | `string` | `""` | Error message on failed login |
| `loading` | `boolean` | `false` | Loading indicator during authentication |

#### `handleSubmit(e)`
1. Prevents default form submission.
2. Clears any previous error.
3. Sets `loading` to true.
4. Calls `login(username, password)` from `AuthContext`.
5. On success, sets `window.location.hash` to `#/`.
6. On failure, sets error message to "Invalid credentials".
7. Sets `loading` to false in the `finally` block.

### Dependencies
- `useState` from `react`
- `useAuth` from `../utils/AuthContext`
