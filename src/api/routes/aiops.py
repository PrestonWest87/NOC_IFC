import logging
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session

from src.core.db import get_db
from src.services.aiops_engine import EnterpriseAIOpsEngine
from src import services as svc
from src.api.auth_guard import (
    get_current_user, has_action_permission, permission_denied, require_action,
    require_page,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/aiops", tags=["aiops"], dependencies=[Depends(require_page("AIOps RCA"))])


@router.get("/dashboard", dependencies=[Depends(require_action("Tab: AIOps RCA -> Active Board"))])
def get_dashboard(user=Depends(get_current_user)):
    logger.debug("GET /aiops/dashboard")
    alerts, events, grid = svc.get_aiops_dashboard_data()
    locations = svc.get_cached_locations()
    payload = svc.filter_aiops_payload_for_user(
        {"alerts": alerts, "events": events, "grid": grid}, user, locations=locations
    )
    logger.debug("GET /aiops/dashboard: alerts=%d events=%d", len(alerts), len(events))
    return payload


@router.get("/sitrep", dependencies=[
    Depends(require_action("Tab: AIOps RCA -> Global Correlation")),
    Depends(require_action("Action: Generate Reports")),
])
def get_sitrep(user=Depends(get_current_user), db: Session = Depends(get_db)):
    logger.debug("GET /aiops/sitrep")
    if not svc.user_has_all_site_type_access(user):
        raise HTTPException(status_code=403, detail={
            "code": "site_scope_denied", "message": "This global sitrep requires access to all site types."
        })
    config = db.query(svc.SystemConfig).first()
    config_dict = {
        "is_active": config.is_active if config else False,
        "llm_endpoint": config.llm_endpoint if config else "",
        "llm_api_key": config.llm_api_key if config else "",
        "llm_model_name": config.llm_model_name if config else "",
    }
    report = svc.generate_global_sitrep(config_dict)
    return {"report": report}


@router.get("/sites", dependencies=[Depends(require_action("Tab: AIOps RCA -> Active Board"))])
def get_sites(user=Depends(get_current_user), db: Session = Depends(get_db)):
    logger.debug("GET /aiops/sites")
    from src.models.schema import MonitoredLocation
    sites = db.query(MonitoredLocation).all()
    allowed_types = set(user.allowed_site_types or [])
    if str(user.role or "").casefold() not in {"admin", "administrator"}:
        sites = [site for site in sites if site.loc_type in allowed_types]
    logger.debug("GET /aiops/sites: found %d sites", len(sites))
    return [
        {
            "id": s.id, "name": s.name, "lat": s.lat, "lon": s.lon,
            "type": s.loc_type, "district": s.district, "priority": s.priority,
            "under_maintenance": s.under_maintenance,
        }
        for s in sites
    ]


def _require_acknowledge(user=Depends(get_current_user)):
    if not has_action_permission(user, "Action: Acknowledge RCA Alerts"):
        raise permission_denied("Action: Acknowledge RCA Alerts")
    return user

@router.patch("/sites/{site_id}/acknowledge", dependencies=[Depends(require_action("Tab: AIOps RCA -> Active Board"))])
def acknowledge_site(site_id: int, user=Depends(_require_acknowledge), db: Session = Depends(get_db)):
    logger.info("PATCH /aiops/sites/%d/acknowledge by %s", site_id, user.username)
    from src.models.schema import MonitoredLocation, SolarWindsAlert
    site = db.query(MonitoredLocation).filter(MonitoredLocation.id == site_id).first()
    if not site:
        raise HTTPException(status_code=404, detail="Site not found")
    if not svc.user_can_access_site(user, site.name):
        raise HTTPException(status_code=403, detail={
            "code": "site_scope_denied", "message": "This site is outside your permitted site types."
        })
    alerts = db.query(SolarWindsAlert).filter(
        SolarWindsAlert.is_correlated == False,
        SolarWindsAlert.status != "Resolved",
        SolarWindsAlert.mapped_location == site.name,
    ).all()
    svc.acknowledge_cluster([a.id for a in alerts], username=user.username)
    logger.info("PATCH /aiops/sites/%d/acknowledge: acknowledged %d alerts by %s", site_id, len(alerts), user.username)
    return {"status": "acknowledged"}
