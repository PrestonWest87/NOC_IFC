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


class PasswordResetRequest(BaseModel):
    identifier: str


class PasswordResetCompletion(BaseModel):
    token: str
    new_password: str


class RecoveryEmailRequest(BaseModel):
    email: str


def _send_account_recovery_notice(subject, body, recipients):
    from src.utils.mailer import send_alert_email

    success, message = send_alert_email(
        subject=subject,
        body=body,
        recipient_override=", ".join(recipients),
        is_html=False,
    )
    if not success:
        logger.error("Account recovery notification delivery failed recipient_count=%d reason=%s", len(recipients), message)


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
            content={"detail": {"code": "invalid_credentials", "message": "Invalid credentials"}},
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


@router.post("/request-password-reset")
def request_password_reset(
    body: PasswordResetRequest,
    request: Request,
    background_tasks: BackgroundTasks,
):
    source_ip = request.client.host if request.client else None
    result = svc.submit_password_reset_request(body.identifier, source_ip)
    recipients = result.get("notify", [])
    if recipients:
        body_text = (
            "A password-reset request is awaiting review in Users & Roles. "
            f"Request reference: {result['request_id']}. Sign in to approve or deny it."
        )
        background_tasks.add_task(
            _send_account_recovery_notice,
            "NOC Fusion Center password-reset request",
            body_text,
            recipients,
        )
    return {
        "status": "accepted",
        "message": (
            "If this account can use recovery, its request has been submitted for administrator review. "
            "Accounts without an approved recovery email require administrator-assisted recovery."
        ),
    }


@router.post("/reset-password")
def complete_password_reset(body: PasswordResetCompletion):
    try:
        completed = svc.complete_password_reset(body.token, body.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not completed:
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_reset_token", "message": "This password-reset link is invalid or expired."},
        )
    return {"status": "ok", "message": "Password reset successfully. Sign in with your new password."}


@router.get("/verify-recovery-email")
def verify_recovery_email(token: str = Query("")):
    if not svc.verify_recovery_email(token):
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_email_verification", "message": "This verification link is invalid or expired."},
        )
    return {"status": "verified", "message": "Your recovery email has been approved and verified."}


@router.post("/request-recovery-email")
def request_recovery_email(
    body: RecoveryEmailRequest,
    background_tasks: BackgroundTasks,
    user=Depends(get_current_user),
):
    try:
        request_id = svc.submit_email_change_request(user.id, body.email)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    recipients = svc.get_recovery_reviewer_emails(
        "Action: Approve Recovery Email Changes", exclude_user_id=user.id
    )
    if recipients:
        background_tasks.add_task(
            _send_account_recovery_notice,
            "NOC Fusion Center recovery-email change request",
            f"A recovery-email change request is awaiting review in Users & Roles. Request reference: {request_id}.",
            recipients,
        )
        message = "Your recovery-email request was submitted. A user administrator must approve it before it can be used for account recovery."
    else:
        logger.warning("Recovery-email request has no other verified reviewer request_id=%s", request_id)
        if str(user.role or "").casefold() in {"admin", "administrator"}:
            message = (
                "Your request was recorded, but no other verified recovery-email reviewer is configured. "
                "For initial administrator setup, configure DEFAULT_ADMIN_EMAIL and restart the API/worker, "
                "or add another verified user administrator to review it."
            )
        else:
            message = (
                "Your request was recorded, but no verified recovery-email reviewer is configured. "
                "A user administrator must have a verified recovery email before this request can be approved."
            )
    return {
        "status": "pending_approval",
        "message": message,
    }


@router.post("/resend-recovery-email-verification")
def resend_recovery_email_verification(
    background_tasks: BackgroundTasks,
    user=Depends(get_current_user),
):
    try:
        verification = svc.resend_recovery_email_verification(user.id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    from src.core.config import settings
    config = svc.get_cached_config() or {}
    public_app_url = str(config.get("public_app_url") or settings.public_app_url).rstrip("/")
    verify_url = f"{public_app_url}/#/verify-email?token={verification['token']}"
    background_tasks.add_task(
        _send_account_recovery_notice,
        "Verify your NOC Fusion Center recovery email",
        f"Use this link to verify your recovery email address:\n\n{verify_url}",
        [verification["email"]],
    )
    return {"status": "sent", "message": "A new verification link was sent to the pending recovery email."}


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
