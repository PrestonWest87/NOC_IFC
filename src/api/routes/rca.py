import logging
from fastapi import APIRouter, Query, Body
from typing import Any

from src import services as svc
from src.services.aiops_engine import EnterpriseAIOpsEngine

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/rca", tags=["rca"])


@router.get("/dashboard")
def rca_dashboard():
    alerts, events, grid = svc.get_aiops_dashboard_data()
    locs = svc.get_cached_locations()
    return {"alerts": alerts, "events": events, "grid": grid, "locations": locs}


@router.post("/analyze")
def analyze():
    alerts, events, grid = svc.get_aiops_dashboard_data()
    engine = EnterpriseAIOpsEngine()
    clustered = engine.analyze_and_cluster(alerts)
    fleet = engine.identify_fleet_outages()
    rca = engine.calculate_root_cause()
    chronic = engine.generate_chronic_insights()
    return {
        "clustered": clustered,
        "fleet_outages": fleet,
        "root_cause": rca,
        "chronic_insights": chronic,
        "events": events,
    }


@router.post("/acknowledge")
def acknowledge(alert_ids: list[int] = Body([])):
    svc.acknowledge_cluster(alert_ids)
    return {"status": "ok"}


@router.post("/dispatch")
def dispatch(alert_ids: list[int] = Body([]), is_dispatched: bool = True):
    svc.set_cluster_dispatch(alert_ids, is_dispatched)
    return {"status": "ok"}


@router.post("/site-maintenance")
def site_maintenance(site_name: str = "", is_maint: bool = False, etr: str = None, reason: str = ""):
    from datetime import datetime
    etr_date = datetime.fromisoformat(etr) if etr else None
    svc.set_site_maintenance(site_name, is_maint, etr_date, reason)
    return {"status": "ok"}


@router.post("/generate-ticket")
def generate_ticket(site: str = "", priority: str = "P3", patient_zero: str = "", root_cause: str = ""):
    return {"ticket": svc.generate_rca_ticket_text(site, {}, priority, patient_zero, root_cause)}


@router.get("/sitrep")
def sitrep():
    from src.models.schema import SystemConfig
    from src.core.db import SessionLocal
    with SessionLocal() as db:
        config = db.query(SystemConfig).first()
    config_dict = {
        "is_active": config.is_active if config else False,
        "llm_endpoint": config.llm_endpoint if config else "",
        "llm_api_key": config.llm_api_key if config else "",
        "llm_model_name": config.llm_model_name if config else "",
    }
    return {"report": svc.generate_global_sitrep(config_dict)}


@router.post("/sitrep")
def sitrep_action(data: dict[str, Any] = Body({})):
    action = data.get("action", "")
    logger.info("POST /sitrep action=%s", action)

    if action == "refresh_briefing":
        result = svc.trigger_rolling_summary()
        return result

    if action == "scoring_rationale":
        intel = data.get("intel", {})
        result = svc.trigger_scoring_rationale(intel)
        return result

    if action == "security_audit":
        from src.utils.llm import cross_reference_cves
        from src.core.db import SessionLocal
        from src.models.schema import CveItem
        with SessionLocal() as session:
            cves = session.query(CveItem).order_by(CveItem.date_added.desc()).limit(50).all()
            audit = cross_reference_cves(cves, session)
        return {"status": "ok", "report": audit}

    logger.warning("POST /sitrep unknown action=%s", action)
    return {"status": "error", "message": f"Unknown action: {action}"}


@router.post("/clear-events")
def clear_events():
    svc.clear_timeline_events()
    return {"status": "ok"}


@router.post("/nuke-alerts")
def nuke_alerts():
    svc.nuke_active_alerts()
    return {"status": "ok"}


@router.post("/resolve-alert")
def resolve_alert(alert_id: int = 0, node_name: str = ""):
    svc.resolve_alert(alert_id, node_name)
    return {"status": "ok"}
