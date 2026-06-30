import logging
import os
import tempfile
import json
from fastapi import APIRouter, Query, Body, HTTPException, UploadFile, File
from typing import Any

from src import services as svc

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


@router.get("/lists")
def admin_lists():
    logger.debug("GET /admin/lists")
    kws, feeds, users_data = svc.get_admin_lists()
    return {"keywords": kws, "feeds": feeds, "users": users_data}


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


@router.get("/ml-counts")
def ml_counts():
    logger.debug("GET /admin/ml-counts")
    pos, neg, total = svc.get_ml_counts()
    return {"positive": pos, "negative": neg, "total": total}


@router.post("/config")
def save_config(data: dict[str, Any] = Body({})):
    logger.info("POST /admin/config keys=%s", list(data.keys()))
    svc.save_global_config(data)
    return {"status": "ok"}


@router.get("/roles")
def roles():
    logger.debug("GET /admin/roles")
    return svc.get_all_roles()


@router.post("/roles")
def create_role(data: dict[str, Any] = Body({})):
    logger.info("POST /admin/roles name=%s", data.get("name"))
    svc.create_role(
        name=data.get("name", ""),
        allowed_pages=data.get("allowed_pages", []),
        allowed_actions=data.get("allowed_actions", []),
        allowed_site_types=data.get("allowed_site_types"),
    )
    return {"status": "ok"}


@router.put("/roles/{name}")
def update_role(
    name: str,
    data: dict[str, Any] = Body({}),
):
    logger.info("PUT /admin/roles/%s", name)
    svc.update_role(
        name,
        data.get("allowed_pages", []),
        data.get("allowed_actions", []),
        data.get("allowed_site_types"),
    )
    return {"status": "ok"}


@router.post("/users")
def create_user(data: dict[str, Any] = Body({})):
    logger.info("POST /admin/users username=%s role=%s", data.get("username"), data.get("role"))
    svc.create_user(
        username=data.get("username", ""),
        password=data.get("password", ""),
        role=data.get("role", "analyst"),
        full_name=data.get("full_name", ""),
    )
    return {"status": "ok"}


@router.put("/users/{username}/role")
def update_user_role(username: str, data: dict[str, Any] = Body({})):
    logger.info("PUT /admin/users/%s/role new_role=%s", username, data.get("role"))
    svc.update_user_role(username, data.get("role", ""))
    return {"status": "ok"}


@router.post("/users/{username}/reset-password")
def reset_password(username: str, data: dict[str, Any] = Body({})):
    logger.info("POST /admin/users/%s/reset-password", username)
    svc.force_reset_pwd(username, data.get("new_password", ""))
    return {"status": "ok"}


@router.get("/location")
def get_locations():
    logger.debug("GET /admin/location")
    return svc.get_cached_locations()


@router.post("/location/import")
def import_locations(data: list[dict] = Body([])):
    logger.info("POST /admin/location/import count=%d", len(data))
    svc.import_locations(data)
    svc.get_cached_locations.clear()
    return {"status": "ok"}


@router.put("/location")
def update_locations(data: list[dict] = Body([])):
    logger.info("PUT /admin/location count=%d", len(data))
    import pandas as pd
    svc.update_locations(pd.DataFrame(data))
    svc.get_cached_locations.clear()
    return {"status": "ok"}


@router.get("/backup")
def backup():
    logger.info("GET /admin/backup")
    return svc.get_backup_data()


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
