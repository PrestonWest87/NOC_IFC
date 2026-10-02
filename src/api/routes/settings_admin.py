import logging
import os
import tempfile
import json
from fastapi import APIRouter, Query, Body, HTTPException, UploadFile, File, Depends, BackgroundTasks, Request, Response
from fastapi.responses import FileResponse
from typing import Any

from src import services as svc
from src.api.auth_guard import require_admin
from src.core.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/admin", tags=["admin"], dependencies=[Depends(require_admin)])


def _send_invitation_email(recipient: str, username: str, role: str, link: str, expires_at: str):
    from src.utils.mailer import send_alert_email

    success, message = send_alert_email(
        "NOC Fusion Center account invitation",
        f"You have been invited to the NOC Fusion Center.\nUsername: {username}\nRole: {role}\n"
        f"Registration link: {link}\nExpires: {expires_at} UTC",
        recipient_override=recipient,
        is_html=False,
    )
    if not success:
        logger.error("Registration invitation email failed recipient_count=1 reason=%s", message)


@router.get("/lists")
def admin_lists():
    logger.debug("GET /admin/lists")
    kws, feeds, users_data = svc.get_admin_lists()
    safe_users = [
        {"id": item.get("id"), "username": item.get("username"), "role": item.get("role"), "full_name": item.get("full_name")}
        for item in users_data
    ]
    return {"keywords": kws, "feeds": feeds, "users": safe_users}


@router.post("/keywords/bulk")
def add_keywords(raw_text: str = ""):
    logger.info("POST /admin/keywords/bulk text_length=%d", len(raw_text) if raw_text else 0)
    svc.add_bulk_keywords(raw_text)
    return {"status": "ok"}


@router.post("/feeds/bulk")
def add_feeds(raw_text: str = ""):
    logger.info("POST /admin/feeds/bulk text_length=%d", len(raw_text) if raw_text else 0)
    svc.add_bulk_feeds(raw_text)
    return {"status": "ok"}


@router.patch("/keywords/{keyword_id}")
def patch_keyword(keyword_id: int, data: dict[str, Any] = Body({})):
    weight = data.get("weight")
    if weight is None or not isinstance(weight, int) or weight < 1 or weight > 100:
        raise HTTPException(400, "weight must be an integer between 1 and 100")
    logger.info("PATCH /admin/keywords/%d weight=%d", keyword_id, weight)
    try:
        updated = svc.update_keyword_weight(keyword_id, weight)
        return {"status": "ok", "keyword": updated}
    except ValueError as e:
        raise HTTPException(404, str(e))


@router.delete("/keywords/{keyword_id}")
def delete_keyword(keyword_id: int):
    logger.info("DELETE /admin/keywords/%d", keyword_id)
    svc.delete_record("Keyword", keyword_id)
    return {"status": "ok"}


@router.delete("/feeds/{feed_id}")
def delete_feed(feed_id: int):
    logger.info("DELETE /admin/feeds/%d", feed_id)
    svc.delete_record("FeedSource", feed_id)
    return {"status": "ok"}


@router.get("/ml-counts")
def ml_counts():
    logger.debug("GET /admin/ml-counts")
    pos, neg, total = svc.get_ml_counts()
    return {"positive": pos, "negative": neg, "total": total}


@router.post("/config")
def save_config(data: dict[str, Any] = Body({})):
    logger.info("POST /admin/config keys=%s", list(data.keys()))
    try:
        svc.save_global_config(data, allow_system_fields=False)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "ok"}


@router.post("/assets/software")
def upload_software_assets(csv_body: str = Body(..., embed=True)):
    logger.info("POST /admin/assets/software body_length=%d", len(csv_body) if csv_body else 0)
    success, msg = svc.import_software_assets_csv(csv_body)
    logger.info("POST /admin/assets/software result: success=%s msg=%s", success, msg)
    return {"status": "ok" if success else "error", "message": msg}


@router.post("/assets/hardware")
def upload_hardware_assets(csv_body: str = Body(..., embed=True)):
    logger.info("POST /admin/assets/hardware body_length=%d", len(csv_body) if csv_body else 0)
    success, msg = svc.import_hardware_assets_csv(csv_body)
    logger.info("POST /admin/assets/hardware result: success=%s msg=%s", success, msg)
    return {"status": "ok" if success else "error", "message": msg}


@router.get("/roles")
def roles():
    logger.debug("GET /admin/roles")
    return svc.get_all_roles()


@router.post("/roles")
def create_role(data: dict[str, Any] = Body({})):
    logger.info("POST /admin/roles name=%s", data.get("name"))
    try:
        created = svc.create_role(
            name=data.get("name", ""),
            allowed_pages=data.get("allowed_pages", []),
            allowed_actions=data.get("allowed_actions", []),
            allowed_site_types=data.get("allowed_site_types"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not created:
        raise HTTPException(status_code=409, detail="Role already exists.")
    return {"status": "ok"}


@router.put("/roles/{name}")
def update_role(
    name: str,
    data: dict[str, Any] = Body({}),
):
    logger.info("PUT /admin/roles/%s", name)
    if name.casefold() in {"admin", "administrator"}:
        raise HTTPException(status_code=400, detail="The built-in administrator role cannot be edited.")
    try:
        updated = svc.update_role(
            name,
            data.get("allowed_pages", []),
            data.get("allowed_actions", []),
            data.get("allowed_site_types"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not updated:
        raise HTTPException(status_code=404, detail="Role not found.")
    return {"status": "ok"}


@router.post("/users")
def create_user(data: dict[str, Any] = Body({}), user=Depends(require_admin)):
    logger.info("POST /admin/users username=%s role=%s", data.get("username"), data.get("role"))
    try:
        user_id = svc.create_display_account(
            username=data.get("username", ""),
            password=data.get("password", ""),
            role=data.get("role", "viewer"),
            full_name=data.get("full_name", ""),
            created_by=user.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "ok", "user_id": user_id, "account_type": "display"}


@router.post("/registration-invites")
def create_registration_invite(background_tasks: BackgroundTasks, data: dict[str, Any] = Body({}), user=Depends(require_admin)):
    try:
        raw_token, expires_at = svc.create_registration_invite(
            username=str(data.get("username", "")),
            email=str(data.get("email", "")),
            role=str(data.get("role", "analyst")),
            created_by=user.username,
            ttl_hours=int(data.get("ttl_hours", settings.registration_invite_ttl_hours)),
        )
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    with svc.SessionLocal() as db:
        config = db.query(svc.SystemConfig).first()
        public_app_url = (config.public_app_url if config else None) or settings.public_app_url
    registration_url = f"{public_app_url.rstrip('/')}/#/register?token={raw_token}"
    background_tasks.add_task(
        _send_invitation_email,
        str(data.get("email", "")).strip(),
        str(data.get("username", "")).strip(),
        str(data.get("role", "analyst")).strip(),
        registration_url,
        expires_at.isoformat(),
    )
    return {
        "username": str(data.get("username", "")).strip(),
        "email": str(data.get("email", "")).strip(),
        "role": str(data.get("role", "analyst")).strip(),
        "expires_at": expires_at.isoformat(),
        "registration_url": registration_url,
    }


@router.put("/users/{username}/role")
def update_user_role(username: str, data: dict[str, Any] = Body({}), user=Depends(require_admin)):
    logger.info("PUT /admin/users/%s/role new_role=%s", username, data.get("role"))
    try:
        updated = svc.update_user_role(username, data.get("role", ""), actor_user_id=user.id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not updated:
        raise HTTPException(status_code=404, detail="User not found.")
    return {"status": "ok"}


@router.post("/users/{username}/reset-password")
def reset_password(username: str, data: dict[str, Any] = Body({}), user=Depends(require_admin)):
    logger.info("POST /admin/users/%s/reset-password", username)
    try:
        updated = svc.force_reset_pwd(username, data.get("new_password", ""), actor_user_id=user.id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not updated:
        raise HTTPException(status_code=404, detail="User not found.")
    return {"status": "ok"}


@router.get("/location")
def get_locations():
    logger.debug("GET /admin/location")
    return svc.get_cached_locations()


@router.post("/location/import")
def import_locations(data: list[dict] = Body([]), mode: str = Query("add")):
    if mode not in ("add", "upsert", "replace"):
        raise HTTPException(400, "mode must be 'add', 'upsert', or 'replace'")
    logger.info("POST /admin/location/import mode=%s count=%d", mode, len(data))
    count = svc.import_locations(data, mode=mode)
    svc.get_cached_locations.clear()
    return {"status": "ok", "mode": mode, "count": count}


@router.put("/location")
def update_locations(data: list[dict] = Body([])):
    logger.info("PUT /admin/location count=%d", len(data))
    svc.update_locations(data)
    svc.get_cached_locations.clear()
    return {"status": "ok"}


@router.get("/backup")
def backup():
    logger.info("GET /admin/backup")
    return svc.get_backup_data()


@router.get("/backups/status")
def full_backup_status():
    from src.core import backup_manager

    return {
        "encryption_configured": backup_manager.encryption_configured(),
        "max_bytes": settings.backup_max_bytes,
        "scheduled_policy": "Sunday at 00:00 America/Chicago; retain the latest three scheduled backups.",
    }


@router.get("/backups")
def list_full_backups():
    from src.core.backup_manager import list_backups

    return {"backups": list_backups()}


@router.post("/backups")
def create_full_backup(user=Depends(require_admin)):
    from src.core.backup_manager import BackupError, create_backup

    try:
        return create_backup(kind="manual", created_by=user.username)
    except BackupError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.get("/backups/{backup_id}/download")
def download_full_backup(backup_id: str, request: Request):
    from src.core.backup_manager import BackupError, get_backup_path

    try:
        path = get_backup_path(backup_id)
    except BackupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return FileResponse(
        path,
        filename=path.name,
        media_type="application/octet-stream",
        headers={
            "Cache-Control": "no-store",
            "Set-Cookie": (
                f"noc_backup_download=; Path=/api/v1/admin/backups/{backup_id}/download; "
                "Max-Age=0; HttpOnly; SameSite=Strict"
                + ("; Secure" if request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https" else "")
            ),
        },
    )


@router.post("/backups/{backup_id}/download-link")
def create_full_backup_download_link(backup_id: str, request: Request, response: Response):
    from src.core.backup_manager import BackupError, get_backup_path
    from src.api.auth_guard import token_from_request

    try:
        get_backup_path(backup_id)
    except BackupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    token = token_from_request(request)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    is_secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    response.set_cookie(
        key="noc_backup_download",
        value=token,
        max_age=60,
        path=f"/api/v1/admin/backups/{backup_id}/download",
        secure=is_secure,
        httponly=True,
        samesite="strict",
    )
    return {"url": f"/api/v1/admin/backups/{backup_id}/download"}


@router.delete("/backups/{backup_id}")
def delete_full_backup(backup_id: str):
    from src.core.backup_manager import BackupError, delete_backup

    try:
        delete_backup(backup_id)
    except BackupError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "deleted"}


@router.get("/backups/staged")
def list_staged_full_backups():
    from src.core.backup_manager import list_staged_backups

    return {"backups": list_staged_backups()}


@router.post("/backups/staged")
def stage_full_backup(file: UploadFile = File(...)):
    from src.core.backup_manager import BackupError, stage_uploaded_backup

    try:
        return stage_uploaded_backup(file.file)
    except BackupError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        file.file.close()


@router.delete("/backups/staged/{stage_id}")
def delete_staged_full_backup(stage_id: str):
    from src.core.backup_manager import BackupError, delete_staged_backup

    try:
        delete_staged_backup(stage_id)
    except BackupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"status": "deleted"}


@router.post("/backups/staged/{stage_id}/restore", status_code=202)
async def restore_from_staged_backup(stage_id: str, user=Depends(require_admin)):
    from src.core import restore_control
    from src.core.backup_manager import BackupError
    from src.core.ui_restore import launch_staged_restore, prepare_staged_restore

    restore_id = None
    try:
        restore_id = prepare_staged_restore(stage_id, user.username)
        from src.api.main import manager

        await manager.close_all(code=1012, reason="Database restore in progress")
        launch_staged_restore(restore_id)
    except BackupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except restore_control.RestoreInProgressError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except Exception as exc:
        if restore_id:
            try:
                restore_control.finish_restore(restore_id, "error", "Unable to start the restore service.")
            except Exception:
                logger.exception("Unable to release restore maintenance mode")
        logger.exception("Unable to start a UI-initiated restore")
        raise HTTPException(status_code=500, detail="Unable to start the restore service.") from exc
    return {"status": "started", "restore_id": restore_id}


@router.post("/restore")
def restore(data: dict[str, Any] = Body({})):
    logger.info("POST /admin/restore keys=%s", list(data.keys()))
    svc.restore_backup_data(data)
    return {"status": "ok"}


@router.get("/export-all")
def export_all():
    logger.info("GET /admin/export-all")
    return svc.export_all_tables()


@router.post("/import-all")
def import_all(data: dict[str, Any] = Body({})):
    logger.info("POST /admin/import-all merge=%s", data.get("_merge", False))
    merge = data.pop("_merge", False)
    counts = svc.import_all_tables(data, merge=merge)
    logger.info("POST /admin/import-all counts=%s", counts)
    return {"status": "ok", "counts": counts}


@router.post("/upload-db")
async def upload_db(file: UploadFile = File(...)):
    logger.info("POST /admin/upload-db filename=%s", file.filename)
    if not file.filename or not file.filename.endswith(".db"):
        raise HTTPException(400, "Uploaded file must have a .db extension")
    tmp_path = None
    try:
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        tmp_path = tmp.name
        content = await file.read()
        tmp.write(content)
        tmp.close()
        logger.debug("upload-db: saved temp file to %s", tmp_path)
        counts = svc.restore_from_db_upload(tmp_path)
        logger.info("POST /admin/upload-db success counts=%s", counts)
        return {"status": "ok", "counts": counts}
    except Exception as e:
        logger.error("POST /admin/upload-db failed: %s", e)
        raise HTTPException(500, f"Database restore failed: {e}")
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
            logger.debug("upload-db: cleaned up temp file %s", tmp_path)


@router.delete("/record")
def delete_record(model_name: str = "", record_id: int = 0):
    logger.info("DELETE /admin/record model=%s id=%d", model_name, record_id)
    svc.delete_record(model_name, record_id)
    return {"status": "ok"}


@router.post("/nuke")
def nuke(tables: list[str] = Body([])):
    logger.warning("POST /admin/nuke tables=%s", tables)
    svc.nuke_tables(tables)
    return {"status": "ok"}


@router.post("/nuke/crime")
def nuke_crime():
    logger.warning("POST /admin/nuke/crime")
    svc.nuke_crime_data()
    return {"status": "ok"}


@router.post("/nuke/weather")
def nuke_weather():
    logger.warning("POST /admin/nuke/weather")
    svc.nuke_weather_data()
    return {"status": "ok"}


@router.post("/maintenance")
def maintenance():
    logger.info("POST /admin/maintenance")
    from src.scheduler import run_database_maintenance
    run_database_maintenance()
    return {"status": "ok"}


@router.post("/ml-retrain")
def ml_retrain():
    logger.info("POST /admin/ml-retrain")
    from src.train_model import train
    from src.services.logic import force_reload_scorer
    try:
        train()
        force_reload_scorer()
        logger.info("POST /admin/ml-retrain success")
        return {"status": "ok", "message": "Model retrained and scorer reloaded."}
    except Exception as e:
        logger.error("POST /admin/ml-retrain failed: %s", e)
        return {"status": "error", "message": str(e)}
