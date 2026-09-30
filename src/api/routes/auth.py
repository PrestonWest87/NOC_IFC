import json
import logging
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
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


def _send_failed_login_alert(alert):
    from src.utils.mailer import send_alert_email

    attempts = alert["attempts"]
    recipient_count = len([
        value for value in alert["recipients"].replace(";", ",").split(",")
        if value.strip()
    ])
    logger.info(
        "Attempting failed-login alert delivery attempts=%d threshold=%d window_minutes=%d recipients=%d",
        len(attempts), alert["threshold"], alert["window_minutes"], recipient_count,
    )
    lines = [
        "NOC Fusion Center security alert",
        f"{len(attempts)} failed login attempts occurred within the previous {alert['window_minutes']} minute(s).",
        f"Alert threshold: {alert['threshold']} attempts.",
        f"Detected at: {alert['triggered_at']} (UTC)",
        "",
        "Attempted usernames (as submitted):",
    ]
    for attempt in attempts:
        ip = f" from {attempt['source_ip']}" if attempt.get("source_ip") else ""
        lines.append(
            f"- {attempt['attempted_at']} — {json.dumps(attempt['username'], ensure_ascii=False)}{ip}"
        )
    lines.extend(["", "Passwords are not collected or included in this alert."])

    try:
        success, message = send_alert_email(
            subject="Multiple failed login attempts detected",
            body="\n".join(lines),
            recipient_override=alert["recipients"],
            is_html=False,
        )
    except Exception:
        logger.exception("Failed-login alert background task raised unexpectedly.")
        return

    if success:
        logger.info(
            "Failed-login alert email delivered attempts=%d recipients=%d",
            len(attempts), recipient_count,
        )
    else:
        logger.error(
            "Failed-login alert email delivery failed attempts=%d recipients=%d reason=%s",
            len(attempts), recipient_count, message,
        )


@router.post("/login")
def login(req: LoginRequest, request: Request, background_tasks: BackgroundTasks):
    logger.info("POST /login")
    user, token = svc.authenticate_user(req.username, req.password)
    if not user:
        logger.warning("POST /login failed")
        try:
            source_ip = request.client.host if request.client else None
            alert = svc.record_failed_login_attempt(req.username, source_ip)
            if alert:
                background_tasks.add_task(_send_failed_login_alert, alert)
                logger.info(
                    "Failed-login alert task queued attempts=%d threshold=%d window_minutes=%d",
                    len(alert["attempts"]), alert["threshold"], alert["window_minutes"],
                )
        except Exception:
            logger.exception("Unable to record failed login attempt for security alerting.")
        # Raising HTTPException bypasses the endpoint response's background tasks.
        # Return the same 401 payload as a response so the queued alert is executed.
        return JSONResponse(
            status_code=401,
            content={"detail": "Invalid credentials"},
            background=background_tasks,
        )
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
def logout(request: Request, user=Depends(get_current_user)):
    logger.info("POST /logout username=%s", user.username)
    svc.logout_user(user.username, getattr(request.state, "auth_token", ""))
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
