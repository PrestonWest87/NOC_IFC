from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from src import services as svc

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


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


@router.post("/login")
def login(req: LoginRequest):
    user, token = svc.authenticate_user(req.username, req.password)
    if not user:
        raise HTTPException(401, "Invalid credentials")
    return {"user": user, "token": token}


@router.get("/me")
def me(token: str = ""):
    user = svc.get_user_by_token(token)
    if not user:
        raise HTTPException(401, "Invalid session")
    return user


@router.post("/logout")
def logout(username: str):
    svc.logout_user(username)
    return {"status": "ok"}


@router.post("/update-profile")
def update_profile(username: str, body: ProfileUpdate):
    ok, msg = svc.update_user_profile(
        username, body.full_name, body.job_title, body.contact_info,
        body.old_password, body.new_password, body.default_shift
    )
    if not ok:
        raise HTTPException(400, msg)
    return {"status": "ok", "message": msg}
