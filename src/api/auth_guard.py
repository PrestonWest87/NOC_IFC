from fastapi import Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from src import services as svc


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
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def require_admin(user=Depends(get_current_user)):
    if str(user.role or "").lower() not in {"admin", "administrator"}:
        raise HTTPException(status_code=403, detail="Administrator permission required")
    return user


async def authentication_middleware(request: Request, call_next):
    path = request.url.path.rstrip("/")
    public = path in {"/api/v1/auth/login", "/health", "/ready"}
    if request.method == "OPTIONS" or public or not path.startswith("/api/v1"):
        return await call_next(request)

    user = svc.get_user_by_token(token_from_request(request))
    if not user:
        return JSONResponse(status_code=401, content={"detail": "Not authenticated"})
    request.state.user = user
    return await call_next(request)
