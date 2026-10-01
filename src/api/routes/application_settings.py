import logging
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from src import services as svc
from src.api.auth_guard import get_current_user, require_action, require_page

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/application-settings", tags=["application-settings"])
APP_SETTINGS_TAB = "Tab: Settings -> Application Settings"


class RiskScoringUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scoring_mode: Literal["auto", "manual", "hybrid"] | None = None
    baseline_override_cyber: float | None = Field(default=None, ge=0, le=5)
    baseline_override_phys: float | None = Field(default=None, ge=0, le=5)
    cyber_criticality_override: int | None = Field(default=None, ge=0, le=5)
    cyber_lethality_override: int | None = Field(default=None, ge=0, le=5)
    physical_criticality_override: int | None = Field(default=None, ge=0, le=5)
    physical_lethality_override: int | None = Field(default=None, ge=0, le=5)
    internal_criticality_override: int | None = Field(default=None, ge=0, le=5)
    internal_lethality_override: int | None = Field(default=None, ge=0, le=5)
    global_risk_offset: int | None = Field(default=None, ge=-3, le=3)
    internal_risk_offset: int | None = Field(default=None, ge=-3, le=3)
    sys_countermeasures: int | None = Field(default=None, ge=1, le=5)
    net_countermeasures: int | None = Field(default=None, ge=1, le=5)


class ApplicationValuesUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    public_app_url: str | None = Field(default=None, max_length=500)
    tech_stack: str | None = Field(default=None, max_length=1000)
    monitored_asns: str | None = Field(default=None, max_length=1000)
    failed_login_alert_enabled: bool | None = None
    failed_login_alert_recipients: str | None = Field(default=None, max_length=5000)
    failed_login_alert_threshold: int | None = Field(default=None, ge=2, le=100)
    failed_login_alert_window_minutes: int | None = Field(default=None, ge=1, le=60)


class SchedulerUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schedule: dict


@router.get("", dependencies=[Depends(require_page("Settings & Admin")), Depends(require_action(APP_SETTINGS_TAB))])
def get_application_settings(user=Depends(get_current_user)):
    from src.models.schema import SystemConfig
    from src.core.db import SessionLocal

    with SessionLocal() as db:
        config = db.query(SystemConfig).first()
        if not config:
            return {"public_app_url": "", "tech_stack": "", "monitored_asns": ""}
        return {
            "public_app_url": config.public_app_url or "",
            "tech_stack": config.tech_stack or "",
            "monitored_asns": config.monitored_asns or "",
            "failed_login_alert_enabled": bool(config.failed_login_alert_enabled),
            "failed_login_alert_recipients": config.failed_login_alert_recipients or "" if str(user.role or "").casefold() in {"admin", "administrator"} or "Action: Manage Application Settings" in (user.allowed_actions or []) else "",
            "failed_login_alert_threshold": config.failed_login_alert_threshold,
            "failed_login_alert_window_minutes": config.failed_login_alert_window_minutes,
        }


@router.put("", dependencies=[
    Depends(require_page("Settings & Admin")),
    Depends(require_action(APP_SETTINGS_TAB)),
    Depends(require_action("Action: Manage Application Settings")),
])
def update_application_settings(body: ApplicationValuesUpdate, user=Depends(get_current_user)):
    values = body.model_dump(exclude_unset=True, exclude_none=True)
    if not values:
        raise HTTPException(status_code=400, detail="Provide at least one application setting.")
    try:
        svc.save_global_config(values, allow_system_fields=False)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    logger.info("Application settings updated by user_id=%s keys=%s", user.id, sorted(values))
    return {"status": "updated"}


@router.get("/risk-scoring", dependencies=[
    Depends(require_page("Settings & Admin")), Depends(require_action(APP_SETTINGS_TAB)),
])
def get_risk_scoring_settings():
    from src.models.schema import SystemConfig
    from src.core.db import SessionLocal

    with SessionLocal() as db:
        config = db.query(SystemConfig).first()
        if not config:
            return {}
        fields = (
            "scoring_mode", "baseline_override_cyber", "baseline_override_phys",
            "cyber_criticality_override", "cyber_lethality_override",
            "physical_criticality_override", "physical_lethality_override",
            "internal_criticality_override", "internal_lethality_override",
            "global_risk_offset", "internal_risk_offset", "sys_countermeasures", "net_countermeasures",
        )
        return {field: getattr(config, field) for field in fields}


@router.put("/risk-scoring", dependencies=[
    Depends(require_page("Settings & Admin")),
    Depends(require_action(APP_SETTINGS_TAB)),
    Depends(require_action("Action: Adjust Risk Scoring Overrides")),
])
def update_risk_scoring_settings(body: RiskScoringUpdate, user=Depends(get_current_user)):
    values = body.model_dump(exclude_unset=True, exclude_none=True)
    if not values:
        raise HTTPException(status_code=400, detail="Provide at least one risk-scoring setting.")
    try:
        svc.save_global_config(values, allow_system_fields=False)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    logger.info("Risk scoring overrides updated by user_id=%s keys=%s", user.id, sorted(values))
    return {"status": "updated"}


@router.get("/scheduler", dependencies=[
    Depends(require_page("Settings & Admin")), Depends(require_action(APP_SETTINGS_TAB)),
])
def get_scheduler_settings():
    return svc.get_scheduler_settings()


@router.patch("/scheduler/jobs/{job_key}", dependencies=[
    Depends(require_page("Settings & Admin")),
    Depends(require_action(APP_SETTINGS_TAB)),
    Depends(require_action("Action: Manage Scheduler Settings")),
])
def update_scheduler_job(job_key: str, body: SchedulerUpdate, user=Depends(get_current_user)):
    try:
        result = svc.save_scheduler_setting(job_key, body.schedule, user.username, user.id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "saved", **result}


@router.get("/ml-counts", dependencies=[
    Depends(require_page("Settings & Admin")),
    Depends(require_action("Tab: Settings -> ML Training")),
])
def get_ml_counts():
    positive, negative, total = svc.get_ml_counts()
    return {"positive": positive, "negative": negative, "total": total}


@router.post("/ml-retrain", dependencies=[
    Depends(require_page("Settings & Admin")),
    Depends(require_action("Tab: Settings -> ML Training")),
    Depends(require_action("Action: Train ML Model")),
])
def retrain_ml_model():
    from src.train_model import train
    from src.services.logic import force_reload_scorer

    try:
        train()
        force_reload_scorer()
        return {"status": "ok", "message": "Model retrained and scorer reloaded."}
    except Exception as exc:
        logger.exception("Manual model retraining failed")
        raise HTTPException(status_code=500, detail="Model retraining failed.") from exc
