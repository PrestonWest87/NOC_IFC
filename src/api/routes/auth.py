import logging
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from src import services as svc
from src.api.auth_guard import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


def _public_user(user):
    if not user:
        return user
    return {
        key: value for key, value in user.items()
        if key not in {"password_hash", "session_token"}
    }


class LoginRequest(BaseModel):
    username: str
    password: str


class ProfileUpdate(BaseModel):
    full_name: str = ""
    job_title: str = ""
    contact_info: str = ""
    default_shift: str = ""
    old_password: str = ""
    new_password: str = ""


class RegistrationRequest(BaseModel):
    token: str
    password: str
    full_name: str = ""
    job_title: str = ""
    contact_info: str = ""
    default_shift: str = "No Shift"
    theme: str = "standard"


@router.post("/login")
def login(req: LoginRequest):
    logger.info("POST /login username=%s", req.username)
    user, token = svc.authenticate_user(req.username, req.password)
    if not user:
        logger.warning("POST /login failed for username=%s", req.username)
        raise HTTPException(401, "Invalid credentials")
    logger.info("POST /login success username=%s role=%s", req.username, user.get('role'))
    return {"user": _public_user(user), "token": token}


@router.get("/register/validate")
def validate_registration(token: str = Query("")):
    invite = svc.get_registration_invite(token)
    if not invite:
        raise HTTPException(status_code=400, detail="This registration link is invalid, expired, or already used.")
    return invite


@router.post("/register")
def register(req: RegistrationRequest):
    try:
        user, token = svc.complete_registration(
            req.token, req.password, req.full_name, req.job_title,
            req.contact_info, req.default_shift, req.theme,
        )
        return {"user": _public_user(user), "token": token}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/me")
def me(user=Depends(get_current_user)):
    logger.debug("GET /me: user=%s role=%s", user.get('username'), user.get('role'))
    return _public_user(user)


@router.post("/logout")
def logout(user=Depends(get_current_user)):
    logger.info("POST /logout username=%s", user.username)
    svc.logout_user(user.username)
    return {"status": "ok"}


@router.post("/update-profile")
def update_profile(body: ProfileUpdate, user=Depends(get_current_user)):
    username = user.username
    logger.info("POST /update-profile username=%s", username)
    ok, msg = svc.update_user_profile(
        username, body.full_name, body.job_title, body.contact_info,
        body.old_password, body.new_password, body.default_shift
    )
    if not ok:
        logger.warning("POST /update-profile failed: %s", msg)
        raise HTTPException(400, msg)
    logger.info("POST /update-profile success for %s", username)
    return {"status": "ok", "message": msg}


@router.post("/update-theme")
def update_theme(data: dict, user=Depends(get_current_user)):
    try:
        svc.set_user_theme(user.username, str(data.get("theme", "")))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "ok"}
