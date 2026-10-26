"""Authentication, permission dependencies, and restore-aware request gating.

The middleware resolves session tokens and counts protected API work for the
restore coordinator. Route dependencies enforce the canonical page, tab, action,
and administrator grants; permission failures are structured 403s, not logout
signals.
"""

from fastapi import Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from src import services as svc
from src.core.permissions import ACTION_KEYS, PAGE_KEYS, TAB_KEYS
from src.core import restore_control


def token_from_request(request: Request) -> str:
    """Resolve a session token from Bearer auth, the backup download cookie, or legacy query parameters.

    Bearer authorization takes precedence. The scoped cookie is accepted only
    for backup-download paths; query-token support remains for older clients.
    """
    authorization = request.headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    path = request.url.path
    if path.startswith("/api/v1/admin/backups/") and path.endswith("/download"):
        download_token = request.cookies.get("noc_backup_download", "")
        if download_token:
            return download_token
    return request.query_params.get("token") or request.query_params.get("session_token") or ""


def get_current_user(request: Request, token: str = Query("")):
    """Return the user already authenticated by middleware or resolve the fallback token.

    The fallback supports direct dependency use outside the normal middleware
    path. Missing, revoked, or inactive sessions produce the standard 401 body.
    """
    user = getattr(request.state, "user", None)
    if user:
        return user
    user = svc.get_user_by_token(token)
    if not user:
        raise HTTPException(
            status_code=401,
            detail={"code": "unauthenticated", "message": "Not authenticated"},
        )
    return user


def permission_denied(permission: str, scope: str = "action") -> HTTPException:
    """Build the structured 403 response while preserving the caller's session."""
    if scope == "role":
        message = "Administrator role required"
    elif scope == "page":
        message = f"Missing page permission: {permission}"
    elif scope == "tab":
        message = f"Missing tab permission: {permission}"
    else:
        message = f"Missing permission: {permission}"
    return HTTPException(
        status_code=403,
        detail={
            "code": "permission_denied",
            "scope": scope,
            "permission": permission,
            "message": message,
        },
    )


def require_admin(user=Depends(get_current_user)):
    """Require one of the built-in administrator role names and return that user."""
    if not is_admin(user):
        raise permission_denied("Administrator", "role")
    return user


def is_admin(user) -> bool:
    """Apply the backend administrator override for `admin` and `administrator`."""
    return str(user.role or "").lower() in {"admin", "administrator"}


def has_page_permission(user, page: str) -> bool:
    """Check a page grant, including the built-in administrator override."""
    return is_admin(user) or page in (user.allowed_pages or [])


def has_action_permission(user, action: str) -> bool:
    """Check an action or tab grant stored in the role's shared grant array."""
    return is_admin(user) or action in (user.allowed_actions or [])


def has_site_type_permission(user, site_type: str) -> bool:
    """Check whether a user may access a site type; administrators receive all types."""
    if is_admin(user):
        return True
    return site_type in (user.allowed_site_types or [])


def require_page(page: str):
    """Create a route dependency for one catalogued page grant."""
    def checker(user=Depends(get_current_user)):
        """Validate this request's page key and return its authenticated user."""
        if page not in PAGE_KEYS:
            raise RuntimeError(f"Unknown page permission: {page}")
        if not has_page_permission(user, page):
            raise permission_denied(page, "page")
        return user
    return checker


def require_any_page(pages: list[str]):
    """Create a dependency that accepts any listed page grant and rejects unknown keys at setup."""
    unknown = set(pages) - set(PAGE_KEYS)
    if unknown:
        raise RuntimeError(f"Unknown page permissions: {', '.join(sorted(unknown))}")

    def checker(user=Depends(get_current_user)):
        """Require at least one page from the prevalidated alternatives."""
        if not is_admin(user) and not any(page in (user.allowed_pages or []) for page in pages):
            raise permission_denied(" or ".join(pages), "page")
        return user
    return checker


def require_action(action: str):
    """Create a route dependency for one canonical action or tab grant."""
    def checker(user=Depends(get_current_user)):
        """Validate this request's action/tab key and return its authenticated user."""
        if action not in ACTION_KEYS and action not in TAB_KEYS:
            raise RuntimeError(f"Unknown action permission: {action}")
        if not has_action_permission(user, action):
            raise permission_denied(action)
        return user
    return checker


def require_any_action(actions: list[str]):
    """Create a dependency that accepts any listed action/tab grant."""
    unknown = set(actions) - (set(ACTION_KEYS) | set(TAB_KEYS))
    if unknown:
        raise RuntimeError(f"Unknown action permissions: {', '.join(sorted(unknown))}")

    def checker(user=Depends(get_current_user)):
        """Require at least one prevalidated action/tab alternative."""
        if not is_admin(user) and not any(action in (user.allowed_actions or []) for action in actions):
            raise permission_denied(" or ".join(actions), "tab")
        return user
    return checker


async def authentication_middleware(request: Request, call_next):
    """Apply restore gating, API activity accounting, and session authentication.

    Public login/registration, password-reset, recovery-email verification,
    health/readiness, and restore-status routes are explicit exceptions;
    recovery-email change submission remains authenticated. Protected requests
    are registered before dispatch and released in `finally`, allowing restore
    to drain in-flight handlers without invalidating permission-denied sessions.
    """
    path = request.url.path.rstrip("/")
    restore_status = path == "/api/v1/restore-status"
    restore_start = (
        path.startswith("/api/v1/admin/backups/staged/") and path.endswith("/restore")
    )
    maintenance_exempt = path == "/health" or restore_status or restore_start
    if restore_control.maintenance_requested() and not maintenance_exempt:
        if path == "/ready":
            message = "database restore in progress"
        else:
            message = "A full database restore is in progress. Retry after maintenance completes."
        return JSONResponse(
            status_code=503,
            content={"detail": {"code": "restore_in_progress", "message": message}},
            headers={"Retry-After": "5"},
        )

    track_request = (
        request.method != "OPTIONS"
        and path.startswith("/api/v1")
        and not maintenance_exempt
        and path != "/ready"
    )
    if track_request and not restore_control.begin_api_request():
        return JSONResponse(
            status_code=503,
            content={
                "detail": {
                    "code": "restore_in_progress",
                    "message": "A full database restore is in progress. Retry after maintenance completes.",
                }
            },
            headers={"Retry-After": "5"},
        )

    public = path in {
        "/api/v1/auth/login", "/api/v1/auth/register", "/api/v1/auth/register/validate",
        "/api/v1/auth/request-password-reset", "/api/v1/auth/reset-password",
        "/api/v1/auth/verify-recovery-email",
        "/health", "/ready",
    }
    try:
        if request.method == "OPTIONS" or public or restore_status or not path.startswith("/api/v1"):
            return await call_next(request)

        auth_token = token_from_request(request)
        user = svc.get_user_by_token(auth_token)
        if not user:
            return JSONResponse(
                status_code=401,
                content={"detail": {"code": "unauthenticated", "message": "Not authenticated"}},
            )
        request.state.user = user
        request.state.auth_token = auth_token
        return await call_next(request)
    finally:
        if track_request:
            restore_control.end_api_request()
