import logging
from fastapi import APIRouter, Depends, Query, Body, HTTPException
from typing import Any

from src import services as svc
from src.services.aiops_engine import EnterpriseAIOpsEngine

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/rca", tags=["rca"])


def require_action(action: str):
    def checker(token: str = Query("")):
        user = svc.get_user_by_token(token)
        if not user:
            raise HTTPException(401, "Not authenticated")
        if action not in (user.allowed_actions or []):
            raise HTTPException(403, f"Missing permission: {action}")
        return user
    return checker


@router.get("/dashboard")
def rca_dashboard():
    logger.debug("GET /rca/dashboard")
    alerts, events, grid = svc.get_aiops_dashboard_data()
    locs = svc.get_cached_locations()
    logger.debug("GET /rca/dashboard: alerts=%d events=%d locations=%d", len(alerts), len(events), len(locs))
    return {"alerts": alerts, "events": events, "grid": grid, "locations": locs}


@router.post("/analyze")
def analyze():
    logger.info("POST /rca/analyze: starting root cause analysis")
    from src.models.schema import CloudOutage, RegionalHazard, BgpAnomaly
    from src.core.db import SessionLocal
    alerts, events, grid = svc.get_aiops_dashboard_data()
    logger.debug("POST /rca/analyze: aiops data alerts=%d events=%d", len(alerts), len(events))
    engine = EnterpriseAIOpsEngine()
    clustered = engine.analyze_and_cluster(alerts)
    logger.debug("POST /rca/analyze: clustered into %d sites", len(clustered))

    fleet = engine.identify_fleet_outages(clustered)
    logger.debug("POST /rca/analyze: fleet_outages=%d", len(fleet))

    with SessionLocal() as db:
        active_clouds = db.query(CloudOutage).filter_by(is_resolved=False).all()
        active_weather = db.query(RegionalHazard).all()
        active_bgp = db.query(BgpAnomaly).filter_by(is_resolved=False).all()
    logger.debug("POST /rca/analyze: active_clouds=%d active_weather=%d active_bgp=%d",
                  len(active_clouds), len(active_weather), len(active_bgp))

    root_cause = {}
    for site, data in clustered.items():
        result = engine.calculate_root_cause(
            site, data, active_weather, active_clouds, active_bgp, fleet
        )
        root_cause[site] = result

    chronic = engine.generate_chronic_insights()
    logger.info("POST /rca/analyze: complete root_cause_sites=%d", len(root_cause))
    return {
        "clustered": clustered,
        "fleet_outages": fleet,
        "root_cause": root_cause,
        "chronic_insights": chronic,
        "events": events,
    }


@router.post("/acknowledge")
def acknowledge(alert_ids: list[int] = Body([])):
    logger.info("POST /rca/acknowledge alert_ids=%s", alert_ids)
    svc.acknowledge_cluster(alert_ids)
    from src.api.main import manager
    background_tasks.add_task(manager.broadcast_json, {"type": "RCA_UPDATE"})
    return {"status": "ok"}


@router.post("/dispatch")
def dispatch(data: dict = Body(...), _=Depends(require_action("Action: Dispatch RCA Tickets"))):
    logger.info("POST /rca/dispatch alert_ids=%s is_dispatched=%s",
                 data.get("alert_ids"), data.get("is_dispatched"))
    svc.set_cluster_dispatch(data.get("alert_ids", []), data.get("is_dispatched", True))
    from src.api.main import manager
    background_tasks.add_task(manager.broadcast_json, {"type": "RCA_UPDATE"})
    return {"status": "ok"}


@router.post("/site-maintenance")
def site_maintenance(data: dict = Body(...), user=Depends(require_action("Action: Manage Site Maintenance"))):
    from datetime import datetime
    site_name = data.get("site_name", "")
    is_maint = data.get("is_maint", False)
    etr = data.get("etr")
    reason = data.get("reason", "")
    logger.info("POST /rca/site-maintenance site=%s is_maint=%s etr=%s reason=%s modifier=%s",
                 site_name, is_maint, etr, reason, user.username)
    etr_date = datetime.fromisoformat(etr) if etr else None
    svc.set_site_maintenance(site_name, is_maint, etr_date, reason, modified_by=user.username)

    from src.api.main import manager
    background_tasks.add_task(manager.broadcast_json, {"type": "RCA_UPDATE"})
    return {"status": "ok"}


@router.post("/generate-ticket")
def generate_ticket(site: str = "", priority: str = "P3", patient_zero: str = "", root_cause: str = ""):
    logger.debug("POST /rca/generate-ticket site=%s priority=%s", site, priority)
    return {"ticket": svc.generate_rca_ticket_text(site, {}, priority, patient_zero, root_cause)}


@router.get("/sitrep")
def sitrep():
    logger.debug("GET /rca/sitrep")
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
    logger.info("POST /rca/sitrep action=%s", action)

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

    logger.warning("POST /rca/sitrep unknown action=%s", action)
    return {"status": "error", "message": f"Unknown action: {action}"}


@router.post("/clear-events")
def clear_events():
    logger.info("POST /rca/clear-events")
    svc.clear_timeline_events()
    return {"status": "ok"}


@router.post("/nuke-alerts")
def nuke_alerts():
    logger.warning("POST /rca/nuke-alerts")
    svc.nuke_active_alerts()
    return {"status": "ok"}


@router.post("/resolve-alert")
def resolve_alert(alert_id: int = 0, node_name: str = ""):
    logger.info("POST /rca/resolve-alert alert_id=%d node_name=%s", alert_id, node_name)
    svc.resolve_alert(alert_id, node_name)
    return {"status": "ok"}
