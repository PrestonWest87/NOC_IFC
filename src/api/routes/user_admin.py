import logging
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException
from pydantic import BaseModel, Field

from src import services as svc
from src.api.auth_guard import get_current_user, is_admin, require_action, require_page
from src.core.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(
    prefix="/api/v1/user-admin",
    tags=["user-admin"],
    dependencies=[
        Depends(require_page("Settings & Admin")),
        Depends(require_action("Tab: Settings -> Users & Roles")),
    ],
)


class DisplayAccountRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=12, max_length=256)
    role: str = Field(min_length=1, max_length=64)
    full_name: str = Field(default="", max_length=200)


class IndividualInviteRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    email: str = Field(min_length=3, max_length=254)
    role: str = Field(min_length=1, max_length=64)
    full_name: str = Field(default="", max_length=200)
    ttl_hours: int = Field(default=72, ge=1, le=336)


class RoleRequest(BaseModel):
    role: str = Field(min_length=1, max_length=64)


class StatusRequest(BaseModel):
    is_active: bool


class UserIdentityRequest(BaseModel):
    full_name: str = Field(default="", max_length=200)
    job_title: str = Field(default="", max_length=200)
    contact_info: str = Field(default="", max_length=500)


class AccountTypeRequest(BaseModel):
    account_type: Literal["individual", "display"]


class DecisionRequest(BaseModel):
    approve: bool
    reason: str = Field(default="", max_length=1000)


class AdministratorResetRequest(BaseModel):
    new_password: str = Field(min_length=12, max_length=256)


class RoleDefinitionRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    allowed_pages: list[str] = Field(default_factory=list)
    allowed_actions: list[str] = Field(default_factory=list)
    allowed_site_types: list[str] = Field(default_factory=list)


def _send_email(subject: str, body: str, recipient: str, is_html: bool = False):
    from src.utils.mailer import send_alert_email

    success, message = send_alert_email(
        subject, body, recipient_override=recipient, is_html=is_html
    )
    if not success:
        logger.error("User-admin email delivery failed recipient_count=1 reason=%s", message)


def _app_url():
    config = svc.get_cached_config() or {}
    return str(config.get("public_app_url") or settings.public_app_url).rstrip("/")


def _ensure_assignable_role(role: str, user):
    if role.casefold() in {"admin", "administrator"} and not is_admin(user):
        raise HTTPException(
            status_code=403,
            detail={
                "code": "permission_denied",
                "scope": "role",
                "permission": "Administrator",
                "message": "Only an administrator can assign the administrator role.",
            },
        )
    if not is_admin(user):
        with svc.SessionLocal() as db:
            role_row = db.query(svc.Role).filter(svc.Role.name == role).first()
            elevated = {
                "Action: Manage Users", "Action: Manage Roles",
                "Action: Review Account Recovery Requests",
                "Action: Approve Recovery Email Changes",
            }
            if role_row and elevated.intersection(role_row.allowed_actions or []):
                raise HTTPException(
                    status_code=403,
                    detail={
                        "code": "permission_denied", "scope": "action",
                        "permission": "Action: Manage Roles",
                        "message": "Only an administrator can assign a user-management or recovery-review role.",
                    },
                )


def _ensure_manageable_target(target, actor):
    if is_admin(actor):
        return
    elevated = {
        "Action: Manage Users", "Action: Manage Roles",
        "Action: Review Account Recovery Requests", "Action: Approve Recovery Email Changes",
    }
    target_actions = svc.get_role_permissions(target.role).get("allowed_actions", [])
    if str(target.role or "").casefold() in {"admin", "administrator"} or elevated.intersection(target_actions):
        raise HTTPException(status_code=403, detail={
            "code": "permission_denied", "scope": "role", "permission": "Administrator",
            "message": "Only an administrator can manage an administrator or user-administrator account.",
        })


def _validate_role_delegation(data: RoleDefinitionRequest, actor):
    if is_admin(actor):
        return
    if not set(data.allowed_pages).issubset(set(actor.allowed_pages or [])):
        raise HTTPException(status_code=403, detail={
            "code": "permission_denied", "permission": "Action: Manage Roles",
            "message": "You cannot grant pages that your own role does not have.",
        })
    if not set(data.allowed_actions).issubset(set(actor.allowed_actions or [])):
        raise HTTPException(status_code=403, detail={
            "code": "permission_denied", "permission": "Action: Manage Roles",
            "message": "You cannot grant actions or tabs that your own role does not have.",
        })
    if not set(data.allowed_site_types).issubset(set(actor.allowed_site_types or [])):
        raise HTTPException(status_code=403, detail={
            "code": "permission_denied", "permission": "Action: Manage Roles",
            "message": "You cannot grant site types that your own role does not have.",
        })


@router.get("/users", dependencies=[Depends(require_action("Action: Manage Users"))])
def list_users():
    return svc.get_user_directory()


@router.get("/roles", dependencies=[Depends(require_action("Action: Manage Users"))])
def list_assignable_roles(user=Depends(get_current_user)):
    roles = svc.get_all_roles()
    if is_admin(user):
        return roles
    elevated = {
        "Action: Manage Users", "Action: Manage Roles",
        "Action: Review Account Recovery Requests", "Action: Approve Recovery Email Changes",
    }
    return [
        role for role in roles
        if str(role.name).casefold() not in {"admin", "administrator"}
        and not elevated.intersection(role.allowed_actions or [])
    ]


@router.get("/role-definitions", dependencies=[Depends(require_action("Action: Manage Roles"))])
def list_role_definitions(user=Depends(get_current_user)):
    roles = svc.get_all_roles()
    if is_admin(user):
        return roles
    return [role for role in roles if str(role.name).casefold() not in {"admin", "administrator"}]


@router.get("/site-types", dependencies=[Depends(require_action("Action: Manage Roles"))])
def list_role_site_types():
    return svc.get_all_site_types()


@router.post("/display-accounts", dependencies=[Depends(require_action("Action: Manage Users"))])
def create_display_account(data: DisplayAccountRequest, user=Depends(get_current_user)):
    _ensure_assignable_role(data.role, user)
    try:
        user_id = svc.create_display_account(
            data.username, data.password, data.role, data.full_name, created_by=user.id
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "created", "user_id": user_id, "account_type": "display"}


@router.post("/invitations", dependencies=[Depends(require_action("Action: Manage Users"))])
def invite_individual(
    data: IndividualInviteRequest,
    background_tasks: BackgroundTasks,
    user=Depends(get_current_user),
):
    _ensure_assignable_role(data.role, user)
    try:
        raw_token, expires_at = svc.create_registration_invite(
            username=data.username,
            email=data.email,
            role=data.role,
            created_by=user.username,
            ttl_hours=data.ttl_hours,
        )
        invite = svc.get_registration_invite(raw_token)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    registration_url = f"{_app_url()}/#/register?token={raw_token}"
    body = (
        "You have been invited to the NOC Fusion Center.\n\n"
        f"Username: {data.username}\n"
        f"Registration link: {registration_url}\n\n"
        f"This invitation expires at {expires_at.isoformat()} UTC."
    )
    background_tasks.add_task(
        _send_email, "NOC Fusion Center account invitation", body, invite["email"], False
    )
    return {
        "status": "invited",
        "delivery_status": "queued",
        "username": data.username,
        "email": invite["email"],
        "role": data.role,
        "expires_at": expires_at.isoformat(),
        "registration_url": registration_url,
    }


@router.get("/invitations", dependencies=[Depends(require_action("Action: Manage Users"))])
def list_invitations():
    return svc.get_pending_registration_invites()


@router.post("/invitations/{invite_id}/resend", dependencies=[Depends(require_action("Action: Manage Users"))])
def resend_invitation(invite_id: int, background_tasks: BackgroundTasks, user=Depends(get_current_user)):
    invite = next((item for item in svc.get_pending_registration_invites() if item["id"] == invite_id), None)
    if not invite:
        raise HTTPException(status_code=404, detail="Pending invitation not found.")
    _ensure_assignable_role(invite["role"], user)
    try:
        raw_token, expires_at = svc.create_registration_invite(
            username=invite["username"], email=invite["email"], role=invite["role"],
            created_by=user.username,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    registration_url = f"{_app_url()}/#/register?token={raw_token}"
    background_tasks.add_task(
        _send_email, "NOC Fusion Center account invitation",
        f"Your account invitation has been resent.\nRegistration link: {registration_url}\nExpires: {expires_at.isoformat()} UTC",
        invite["email"], False,
    )
    return {"status": "resent", "registration_url": registration_url, "expires_at": expires_at.isoformat()}


@router.delete("/invitations/{invite_id}", dependencies=[Depends(require_action("Action: Manage Users"))])
def revoke_invitation(invite_id: int, user=Depends(get_current_user)):
    if not svc.revoke_registration_invite(invite_id, actor_user_id=user.id):
        raise HTTPException(status_code=404, detail="Pending invitation not found.")
    return {"status": "revoked"}


@router.put("/users/{username}/role", dependencies=[Depends(require_action("Action: Manage Users"))])
def change_user_role(username: str, data: RoleRequest, actor=Depends(get_current_user)):
    _ensure_assignable_role(data.role, actor)
    with svc.SessionLocal() as db:
        target = db.query(svc.User).filter_by(username=username).first()
        if not target:
            raise HTTPException(status_code=404, detail="User not found.")
        _ensure_manageable_target(target, actor)
    try:
        if not svc.update_user_role(username, data.role, actor_user_id=actor.id):
            raise HTTPException(status_code=404, detail="User not found.")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "updated"}


@router.patch("/users/{username}/status", dependencies=[Depends(require_action("Action: Manage Users"))])
def set_user_status(username: str, data: StatusRequest, actor=Depends(get_current_user)):
    with svc.SessionLocal() as db:
        target = db.query(svc.User).filter_by(username=username).first()
        if not target:
            raise HTTPException(status_code=404, detail="User not found.")
        _ensure_manageable_target(target, actor)
    if not svc.set_user_active(username, data.is_active, actor_user_id=actor.id):
        raise HTTPException(status_code=404, detail="User not found.")
    return {"status": "updated", "is_active": data.is_active}


@router.put("/users/{username}/profile", dependencies=[Depends(require_action("Action: Manage Users"))])
def update_user_identity(username: str, data: UserIdentityRequest, actor=Depends(get_current_user)):
    with svc.SessionLocal() as db:
        target = db.query(svc.User).filter_by(username=username).first()
        if not target:
            raise HTTPException(status_code=404, detail="User not found.")
        _ensure_manageable_target(target, actor)
    if not svc.update_user_identity(
        username, data.full_name, data.job_title, data.contact_info, actor_user_id=actor.id
    ):
        raise HTTPException(status_code=404, detail="User not found.")
    return {"status": "updated"}


@router.patch("/users/{username}/account-type", dependencies=[Depends(require_action("Action: Manage Users"))])
def set_account_type(username: str, data: AccountTypeRequest, actor=Depends(get_current_user)):
    with svc.SessionLocal() as db:
        target = db.query(svc.User).filter_by(username=username).first()
        if not target:
            raise HTTPException(status_code=404, detail="User not found.")
        _ensure_manageable_target(target, actor)
    if not svc.set_user_account_type(username, data.account_type, actor_user_id=actor.id):
        raise HTTPException(status_code=404, detail="User not found.")
    return {"status": "updated", "account_type": data.account_type}


@router.post("/users/{username}/revoke-sessions", dependencies=[Depends(require_action("Action: Manage Users"))])
def revoke_sessions(username: str, actor=Depends(get_current_user)):
    with svc.SessionLocal() as db:
        target = db.query(svc.User).filter_by(username=username).first()
        if not target:
            raise HTTPException(status_code=404, detail="User not found.")
        _ensure_manageable_target(target, actor)
    if not svc.revoke_user_sessions(username, actor_user_id=actor.id):
        raise HTTPException(status_code=404, detail="User not found.")
    return {"status": "revoked"}


@router.post("/users/{username}/administrator-reset", dependencies=[Depends(require_action("Action: Manage Users"))])
def administrator_reset(username: str, data: AdministratorResetRequest, actor=Depends(get_current_user)):
    with svc.SessionLocal() as db:
        target = db.query(svc.User).filter_by(username=username).first()
        if not target:
            raise HTTPException(status_code=404, detail="User not found.")
        if target.account_type != "display" and not is_admin(actor):
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "permission_denied",
                    "scope": "action",
                    "permission": "Action: Review Account Recovery Requests",
                    "message": "Individual accounts must use administrator-reviewed recovery unless a root administrator performs an assisted reset.",
                },
            )
        if target.email and target.email_verified_at and target.account_type != "display" and not is_admin(actor):
            raise HTTPException(
                status_code=409,
                detail="Accounts with an approved recovery email must use the reviewed password-reset flow.",
            )
        _ensure_manageable_target(target, actor)
    try:
        if not svc.force_reset_pwd(username, data.new_password, actor_user_id=actor.id):
            raise HTTPException(status_code=404, detail="User not found.")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "reset", "sessions_revoked": True}


@router.get("/recovery-requests", dependencies=[Depends(require_action("Action: Review Account Recovery Requests"))])
def list_recovery_requests():
    return svc.list_password_reset_requests()


@router.post("/recovery-requests/{request_id}/decision", dependencies=[Depends(require_action("Action: Review Account Recovery Requests"))])
def decide_recovery_request(
    request_id: int,
    data: DecisionRequest,
    background_tasks: BackgroundTasks,
    reviewer=Depends(get_current_user),
):
    try:
        result = svc.review_password_reset_request(
            request_id, reviewer.id, data.approve, data.reason
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if result["status"] == "approved":
        reset_url = f"{_app_url()}/#/reset-password?token={result['token']}"
        body = (
            "Your password-reset request was approved. Use the following single-use link "
            f"within {svc.PASSWORD_RESET_TOKEN_TTL_MINUTES} minutes:\n\n{reset_url}"
        )
        background_tasks.add_task(
            _send_email, "NOC Fusion Center password reset", body, result["email"], False
        )
        return {"status": "approved", "username": result["username"]}
    if result.get("email"):
        background_tasks.add_task(
            _send_email,
            "NOC Fusion Center recovery request update",
            f"Your password-reset request was not approved. Reason: {data.reason or 'Contact a user administrator.'}",
            result["email"],
            False,
        )
    return {"status": "denied"}


@router.get("/email-change-requests", dependencies=[Depends(require_action("Action: Approve Recovery Email Changes"))])
def list_recovery_email_requests():
    return svc.list_email_change_requests()


@router.post("/email-change-requests/{request_id}/decision", dependencies=[Depends(require_action("Action: Approve Recovery Email Changes"))])
def decide_recovery_email_request(
    request_id: int,
    data: DecisionRequest,
    background_tasks: BackgroundTasks,
    reviewer=Depends(get_current_user),
):
    try:
        result = svc.review_email_change_request(
            request_id, reviewer.id, data.approve, data.reason
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if result["status"] == "pending_verification":
        verify_url = f"{_app_url()}/#/verify-email?token={result['token']}"
        body = f"Your recovery-email change was approved. Verify this email address using this link:\n\n{verify_url}"
        background_tasks.add_task(
            _send_email, "Verify your NOC Fusion Center recovery email", body, result["email"], False
        )
    elif result.get("email"):
        background_tasks.add_task(
            _send_email,
            "NOC Fusion Center recovery-email request update",
            f"Your recovery-email request was not approved. Reason: {data.reason or 'Contact a user administrator.'}",
            result["email"],
            False,
        )
    return {"status": result["status"], "username": result["username"]}


@router.post("/roles", dependencies=[Depends(require_action("Action: Manage Roles"))])
def create_role(data: RoleDefinitionRequest, actor=Depends(get_current_user)):
    _validate_role_delegation(data, actor)
    try:
        created = svc.create_role(
            data.name, data.allowed_pages, data.allowed_actions, data.allowed_site_types
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not created:
        raise HTTPException(status_code=409, detail="Role already exists.")
    return {"status": "created"}


@router.put("/roles/{name}", dependencies=[Depends(require_action("Action: Manage Roles"))])
def update_role(name: str, data: RoleDefinitionRequest, actor=Depends(get_current_user)):
    if name.casefold() in {"admin", "administrator"}:
        raise HTTPException(status_code=400, detail="The built-in administrator role cannot be edited.")
    if name != data.name:
        raise HTTPException(status_code=400, detail="Role names cannot be changed here.")
    _validate_role_delegation(data, actor)
    try:
        updated = svc.update_role(name, data.allowed_pages, data.allowed_actions, data.allowed_site_types)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not updated:
        raise HTTPException(status_code=404, detail="Role not found.")
    return {"status": "updated"}
