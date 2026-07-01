import logging
# Ensure BackgroundTasks is imported
from fastapi import APIRouter, Depends, Query, Body, HTTPException, BackgroundTasks
from typing import Any

from src import services as svc
from src.services.aiops_engine import EnterpriseAIOpsEngine

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/rca", tags=["rca"])

# --- NEW: Store investigating sites in backend memory so they survive refreshes ---
INVESTIGATING_SITES = set()

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
    
    # Send the investigating states down to all users
    return {
        "alerts": alerts, 
        "events": events, 
        "grid": grid, 
        "locations": locs,
        "investigating_sites": list(INVESTIGATING_SITES)
    }

# --- NEW: Dedicated endpoint to lock/unlock investigations globally ---
@router.post("/investigate")
def set_investigate(background_tasks: BackgroundTasks, data: dict = Body(...), _=Depends(require_action("Action: Dispatch RCA Tickets"))):
    site = data.get("site", "")
    is_investigating = data.get("is_investigating", False)
    
    if is_investigating:
        INVESTIGATING_SITES.add(site)
    else:
        INVESTIGATING_SITES.discard(site)
        
    logger.info(f"POST /rca/investigate site={site} is_investigating={is_investigating}")
    
    # Broadcast to all users to refresh their screens
    from src.api.main import manager
    background_tasks.add_task(manager.broadcast_json, {"type": "RCA_UPDATE"})
    return {"status": "ok"}


@router.post("/analyze")
def analyze():
    # Your existing analyze logic remains untouched
    logger.info("POST /rca/analyze: starting root cause analysis")
    from src.models.schema import CloudOutage, RegionalHazard, BgpAnomaly
    from src.core.db import SessionLocal
    alerts, events, grid = svc.get_aiops_dashboard_data()
    engine = EnterpriseAIOpsEngine()
    clustered = engine.analyze_and_cluster(alerts)
    fleet = engine.identify_fleet_outages(clustered)

    with SessionLocal() as db:
        active_clouds = db.query(CloudOutage).filter_by(is_resolved=False).all()
        active_weather = db.query(RegionalHazard).all()
        active_bgp = db.query(BgpAnomaly).filter_by(is_resolved=False).all()

    root_cause = {}
    for site, data in clustered.items():
        result = engine.calculate_root_cause(
            site, data, active_weather, active_clouds, active_bgp, fleet
        )
        root_cause[site] = result

    chronic = engine.generate_chronic_insights()
    return {
        "clustered": clustered,
        "fleet_outages": fleet,
        "root_cause": root_cause,
        "chronic_insights": chronic,
        "events": events,
    }


# UPDATE: Add BackgroundTasks to force live-sync on Acknowledgements
@router.post("/acknowledge")
def acknowledge(background_tasks: BackgroundTasks, alert_ids: list[int] = Body([])):
    logger.info("POST /rca/acknowledge alert_ids=%s", alert_ids)
    svc.acknowledge_cluster(alert_ids)
    
    from src.api.main import manager
    background_tasks.add_task(manager.broadcast_json, {"type": "RCA_UPDATE"})
    return {"status": "ok"}


# UPDATE: Add BackgroundTasks to force live-sync on Dispatches
@router.post("/dispatch")
def dispatch(background_tasks: BackgroundTasks, data: dict = Body(...), _=Depends(require_action("Action: Dispatch RCA Tickets"))):
    logger.info("POST /rca/dispatch alert_ids=%s is_dispatched=%s", data.get("alert_ids"), data.get("is_dispatched"))
    svc.set_cluster_dispatch(data.get("alert_ids", []), data.get("is_dispatched", True))
    
    from src.api.main import manager
    background_tasks.add_task(manager.broadcast_json, {"type": "RCA_UPDATE"})
    return {"status": "ok"}


# UPDATE: Add BackgroundTasks to force live-sync on Maintenance 
@router.post("/site-maintenance")
def site_maintenance(background_tasks: BackgroundTasks, data: dict = Body(...), user=Depends(require_action("Action: Manage Site Maintenance"))):
    from datetime import datetime
    site_name = data.get("site_name", "")
    is_maint = data.get("is_maint", False)
    etr = data.get("etr")
    reason = data.get("reason", "")
    
    etr_date = datetime.fromisoformat(etr) if etr else None
    svc.set_site_maintenance(site_name, is_maint, etr_date, reason, modified_by=user.username)
    
    from src.api.main import manager
    background_tasks.add_task(manager.broadcast_json, {"type": "RCA_UPDATE"})
    return {"status": "ok"}


@router.post("/generate-ticket")
def generate_ticket(data: dict = Body(...)):
    site = data.get("site", "")
    priority = data.get("priority", "P3")
    patient_zero = data.get("patient_zero", "")
    root_cause = data.get("root_cause", "")
    cluster = data.get("cluster", {})
    return {"ticket": svc.generate_rca_ticket_text(site, cluster, priority, patient_zero, root_cause)}


@router.post("/send-ticket")
def send_ticket(background_tasks: BackgroundTasks, data: dict = Body(...), _=Depends(require_action("Action: Dispatch RCA Tickets"))):
    from src.utils.mailer import send_alert_email
    site = data.get("site", "")
    ticket_text = data.get("ticket_text", "")
    recipient = data.get("recipient", "remedyforceworkflow@aecc.com, noc@aecc.com")
    alert_ids = data.get("alert_ids", [])
    priority = data.get("priority", "P3")
    district = data.get("district", "Unknown")
    sla = data.get("sla", "N/A (Manual Dispatch)")

    base_body = f"Priority: {priority}\nDistrict: {district.title()}\nTarget SLA: {sla}\n\n{ticket_text}"
    ticket_body = f"Automated Comms Outage\n*** MANUAL TICKET ***\n\n{base_body}"
    success, msg = send_alert_email(
        subject=f"TICKET: {priority} Incident at {site}",
        body=ticket_body,
        recipient_override=recipient,
        is_html=False
    )
    if alert_ids:
        svc.set_cluster_dispatch(alert_ids, True)
    from src.api.main import manager
    background_tasks.add_task(manager.broadcast_json, {"type": "RCA_UPDATE"})
    return {"status": "ok" if success else "error", "message": msg}


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
    if action == "refresh_briefing":
        return svc.trigger_rolling_summary()
    if action == "scoring_rationale":
        return svc.trigger_scoring_rationale(data.get("intel", {}))
    if action == "security_audit":
        from src.utils.llm import cross_reference_cves
        from src.core.db import SessionLocal
        from src.models.schema import CveItem
        with SessionLocal() as session:
            cves = session.query(CveItem).order_by(CveItem.date_added.desc()).limit(50).all()
            audit = cross_reference_cves(cves, session)
        return {"status": "ok", "report": audit}
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
