from fastapi import APIRouter, Query, Body, HTTPException
from typing import Any

from src import services as svc

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


@router.get("/lists")
def admin_lists():
    kws, feeds, users_data = svc.get_admin_lists()
    return {"keywords": kws, "feeds": feeds, "users": users_data}


@router.post("/keywords/bulk")
def add_keywords(raw_text: str = ""):
    svc.add_bulk_keywords(raw_text)
    return {"status": "ok"}


@router.post("/feeds/bulk")
def add_feeds(raw_text: str = ""):
    svc.add_bulk_feeds(raw_text)
    return {"status": "ok"}


@router.get("/ml-counts")
def ml_counts():
    pos, neg, total = svc.get_ml_counts()
    return {"positive": pos, "negative": neg, "total": total}


@router.post("/config")
def save_config(data: dict[str, Any] = Body({})):
    svc.save_global_config(data)
    return {"status": "ok"}


@router.get("/roles")
def roles():
    return svc.get_all_roles()


@router.post("/roles")
def create_role(data: dict[str, Any] = Body({})):
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
    svc.update_role(
        name,
        data.get("allowed_pages", []),
        data.get("allowed_actions", []),
        data.get("allowed_site_types"),
    )
    return {"status": "ok"}


@router.post("/users")
def create_user(data: dict[str, Any] = Body({})):
    svc.create_user(
        username=data.get("username", ""),
        password=data.get("password", ""),
        role=data.get("role", "analyst"),
        full_name=data.get("full_name", ""),
    )
    return {"status": "ok"}


@router.put("/users/{username}/role")
def update_user_role(username: str, data: dict[str, Any] = Body({})):
    svc.update_user_role(username, data.get("role", ""))
    return {"status": "ok"}


@router.post("/users/{username}/reset-password")
def reset_password(username: str, data: dict[str, Any] = Body({})):
    svc.force_reset_pwd(username, data.get("new_password", ""))
    return {"status": "ok"}


@router.get("/location")
def get_locations():
    return svc.get_cached_locations()


@router.post("/location/import")
def import_locations(data: list[dict] = Body([])):
    svc.import_locations(data)
    svc.get_cached_locations.clear()
    return {"status": "ok"}


@router.put("/location")
def update_locations(data: list[dict] = Body([])):
    import pandas as pd
    svc.update_locations(pd.DataFrame(data))
    svc.get_cached_locations.clear()
    return {"status": "ok"}


@router.get("/backup")
def backup():
    return svc.get_backup_data()


@router.post("/restore")
def restore(data: dict[str, Any] = Body({})):
    svc.restore_backup_data(data)
    return {"status": "ok"}


@router.delete("/record")
def delete_record(model_name: str = "", record_id: int = 0):
    svc.delete_record(model_name, record_id)
    return {"status": "ok"}


@router.post("/nuke")
def nuke(tables: list[str] = Body([])):
    svc.nuke_tables(tables)
    return {"status": "ok"}


@router.post("/nuke/crime")
def nuke_crime():
    svc.nuke_crime_data()
    return {"status": "ok"}


@router.post("/nuke/weather")
def nuke_weather():
    svc.nuke_weather_data()
    return {"status": "ok"}


@router.post("/maintenance")
def maintenance():
    from src.scheduler import run_database_maintenance
    run_database_maintenance()
    return {"status": "ok"}


@router.post("/ml-retrain")
def ml_retrain():
    from src.train_model import train
    try:
        train()
        return {"status": "ok", "message": "Model retrained successfully."}
    except Exception as e:
        return {"status": "error", "message": str(e)}
