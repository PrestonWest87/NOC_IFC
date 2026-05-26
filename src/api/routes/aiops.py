from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from src.core.db import get_db
from src.services.aiops_engine import EnterpriseAIOpsEngine
from src import services as svc

router = APIRouter(prefix="/api/v1/aiops", tags=["aiops"])


@router.get("/dashboard")
def get_dashboard():
    alerts, events, grid = svc.get_aiops_dashboard_data()
    return {"alerts": alerts, "events": events, "grid": grid}


@router.get("/sitrep")
def get_sitrep(db: Session = Depends(get_db)):
    config = db.query(svc.SystemConfig).first()
    config_dict = {
        "is_active": config.is_active if config else False,
        "llm_endpoint": config.llm_endpoint if config else "",
        "llm_api_key": config.llm_api_key if config else "",
        "llm_model_name": config.llm_model_name if config else "",
    }
    report = svc.generate_global_sitrep(config_dict)
    return {"report": report}


@router.get("/sites")
def get_sites(db: Session = Depends(get_db)):
    from src.models.schema import MonitoredLocation
    sites = db.query(MonitoredLocation).all()
    return [
        {
            "id": s.id, "name": s.name, "lat": s.lat, "lon": s.lon,
            "type": s.loc_type, "district": s.district, "priority": s.priority,
            "under_maintenance": s.under_maintenance,
        }
        for s in sites
    ]


@router.patch("/sites/{site_id}/acknowledge")
def acknowledge_site(site_id: int, db: Session = Depends(get_db)):
    from src.models.schema import SolarWindsAlert
    alerts = db.query(SolarWindsAlert).filter(
        SolarWindsAlert.is_correlated == False,
        SolarWindsAlert.status != "Resolved",
    ).all()
    svc.acknowledge_cluster([a.id for a in alerts])
    return {"status": "acknowledged"}
