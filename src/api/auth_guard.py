from fastapi import Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from src import services as svc
from src.core.permissions import ACTION_KEYS, PAGE_KEYS, TAB_KEYS


def token_from_request(request: Request) -> str:
    """Read bearer auth while retaining query-token compatibility for old clients."""
    authorization = request.headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return request.query_params.get("token") or request.query_params.get("session_token") or ""


def get_current_user(request: Request, token: str = Query("")):
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
    if not is_admin(user):
        raise permission_denied("Administrator", "role")
    return user


def is_admin(user) -> bool:
    return str(user.role or "").lower() in {"admin", "administrator"}


def has_page_permission(user, page: str) -> bool:
    return is_admin(user) or page in (user.allowed_pages or [])


def has_action_permission(user, action: str) -> bool:
    return is_admin(user) or action in (user.allowed_actions or [])


def has_site_type_permission(user, site_type: str) -> bool:
    if is_admin(user):
        return True
    return site_type in (user.allowed_site_types or [])


def require_page(page: str):
    def checker(user=Depends(get_current_user)):
        if page not in PAGE_KEYS:
            raise RuntimeError(f"Unknown page permission: {page}")
        if not has_page_permission(user, page):
            raise permission_denied(page, "page")
        return user
    return checker


def require_any_page(pages: list[str]):
    unknown = set(pages) - set(PAGE_KEYS)
    if unknown:
        raise RuntimeError(f"Unknown page permissions: {', '.join(sorted(unknown))}")

    def checker(user=Depends(get_current_user)):
        if not is_admin(user) and not any(page in (user.allowed_pages or []) for page in pages):
            raise permission_denied(" or ".join(pages), "page")
        return user
    return checker


def require_action(action: str):
    def checker(user=Depends(get_current_user)):
        if action not in ACTION_KEYS and action not in TAB_KEYS:
            raise RuntimeError(f"Unknown action permission: {action}")
        if not has_action_permission(user, action):
            raise permission_denied(action)
        return user
    return checker


def require_any_action(actions: list[str]):
    unknown = set(actions) - (set(ACTION_KEYS) | set(TAB_KEYS))
    if unknown:
        raise RuntimeError(f"Unknown action permissions: {', '.join(sorted(unknown))}")

    def checker(user=Depends(get_current_user)):
        if not is_admin(user) and not any(action in (user.allowed_actions or []) for action in actions):
            raise permission_denied(" or ".join(actions), "tab")
        return user
    return checker


async def authentication_middleware(request: Request, call_next):
    path = request.url.path.rstrip("/")
    public = path in {
        "/api/v1/auth/login", "/api/v1/auth/register", "/api/v1/auth/register/validate",
        "/api/v1/auth/request-password-reset", "/api/v1/auth/reset-password",
        "/api/v1/auth/verify-recovery-email",
        "/health", "/ready",
    }
    if request.method == "OPTIONS" or public or not path.startswith("/api/v1"):
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
