import logging
# Ensure BackgroundTasks is imported
from fastapi import APIRouter, Depends, Query, Body, HTTPException, BackgroundTasks
from typing import Any

from src import services as svc
from src.services.aiops_engine import EnterpriseAIOpsEngine
from src.api.auth_guard import (
    get_current_user, has_action_permission, permission_denied, require_page,
    require_action as require_authorized_action,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/rca", tags=["rca"], dependencies=[Depends(require_page("AIOps RCA"))])

# --- NEW: Store investigating sites in backend memory so they survive refreshes ---
INVESTIGATING_SITES = set()

def require_action(action: str):
    return require_authorized_action(action)


@router.get("/dashboard", dependencies=[Depends(require_action("Tab: AIOps RCA -> Active Board"))])
def rca_dashboard(user=Depends(get_current_user)):
    logger.debug("GET /rca/dashboard")
    alerts, events, grid = svc.get_aiops_dashboard_data()
    locs = svc.get_cached_locations()
    payload = svc.filter_aiops_payload_for_user(
        {"alerts": alerts, "events": events, "grid": grid}, user, locations=locs
    )
    allowed_sites = svc.get_allowed_site_names_for_user(user)
    
    # Send the investigating states down to all users
    return {
        "alerts": payload["alerts"],
        "events": payload["events"],
        "grid": payload["grid"],
        "locations": [
            location for location in locs
            if str(user.role or "").casefold() in {"admin", "administrator"}
            or location.get("name") in allowed_sites
        ],
        "investigating_sites": [site for site in INVESTIGATING_SITES if site in allowed_sites]
            if str(user.role or "").casefold() not in {"admin", "administrator"}
            else list(INVESTIGATING_SITES),
    }

# --- NEW: Dedicated endpoint to lock/unlock investigations globally ---
@router.post("/investigate", dependencies=[Depends(require_action("Tab: AIOps RCA -> Active Board"))])
def set_investigate(background_tasks: BackgroundTasks, data: dict = Body(...), user=Depends(require_action("Action: Dispatch RCA Tickets"))):
    site = data.get("site", "")
    is_investigating = data.get("is_investigating", False)
    if not svc.user_can_access_site(user, site):
        raise HTTPException(status_code=403, detail={
            "code": "site_scope_denied", "message": "This site is outside your permitted site types."
        })
    
    if is_investigating:
        INVESTIGATING_SITES.add(site)
    else:
        INVESTIGATING_SITES.discard(site)
        
    logger.info(f"POST /rca/investigate site={site} is_investigating={is_investigating}")
    
    # Broadcast to all users to refresh their screens
    from src.api.main import manager
    background_tasks.add_task(manager.broadcast_json, {"type": "RCA_UPDATE"})
    return {"status": "ok"}


@router.post("/needs-dispatch", dependencies=[Depends(require_action("Tab: AIOps RCA -> Active Board"))])
def set_needs_dispatch(
    background_tasks: BackgroundTasks,
    data: dict = Body(...),
    user=Depends(require_action("Action: Dispatch RCA Tickets")),
):
    site = str(data.get("site", ""))
    needs_dispatch = data.get("needs_dispatch")
    if not isinstance(needs_dispatch, bool):
        raise HTTPException(status_code=422, detail="needs_dispatch must be a boolean.")
    if not svc.user_can_access_site(user, site):
        raise HTTPException(status_code=403, detail={
            "code": "site_scope_denied", "message": "This site is outside your permitted site types."
        })
    try:
        updated_alerts = svc.set_site_needs_dispatch(site, needs_dispatch, modified_by=user.username)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if updated_alerts is None:
        raise HTTPException(status_code=404, detail="Site not found.")

    from src.api.main import manager
    background_tasks.add_task(manager.broadcast_json, {"type": "RCA_UPDATE"})
    return {"status": "ok", "updated_alerts": updated_alerts}


@router.post("/analyze", dependencies=[Depends(require_action("Tab: AIOps RCA -> Active Board")), Depends(require_action("Action: Run RCA Analysis"))])
def analyze(user=Depends(get_current_user)):
    logger.info("POST /rca/analyze: starting root cause analysis")
    from src.models.schema import CloudOutage, RegionalHazard, BgpAnomaly
    from src.core.db import SessionLocal
    alerts, events, grid = svc.get_aiops_dashboard_data()
    payload = svc.filter_aiops_payload_for_user(
        {"alerts": alerts, "events": events, "grid": grid}, user
    )
    alerts, events, grid = payload["alerts"], payload["events"], payload["grid"]
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

    chronic = engine.generate_chronic_insights() if svc.user_has_all_site_type_access(user) else []
    return {
        "clustered": clustered,
        "fleet_outages": fleet,
        "root_cause": root_cause,
        "chronic_insights": chronic,
        "events": events,
    }


# UPDATE: Add BackgroundTasks to force live-sync on Acknowledgements
@router.post("/acknowledge", dependencies=[Depends(require_action("Tab: AIOps RCA -> Active Board"))])
def acknowledge(background_tasks: BackgroundTasks, alert_ids: list[int] = Body([]), user=Depends(require_action("Action: Acknowledge RCA Alerts"))):
    logger.info("POST /rca/acknowledge alert_ids=%s", alert_ids)
    try:
        svc.ensure_user_can_access_alerts(user, alert_ids)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail={"code": "site_scope_denied", "message": str(exc)}) from exc
    svc.acknowledge_cluster(alert_ids, username=user.username)
    
    from src.api.main import manager
    background_tasks.add_task(manager.broadcast_json, {"type": "RCA_UPDATE"})
    return {"status": "ok"}


# UPDATE: Add BackgroundTasks to force live-sync on Dispatches
@router.post("/dispatch", dependencies=[Depends(require_action("Tab: AIOps RCA -> Active Board"))])
def dispatch(background_tasks: BackgroundTasks, data: dict = Body(...), user=Depends(require_action("Action: Dispatch RCA Tickets"))):
    logger.info("POST /rca/dispatch alert_ids=%s is_dispatched=%s", data.get("alert_ids"), data.get("is_dispatched"))
    alert_ids = data.get("alert_ids", [])
    try:
        svc.ensure_user_can_access_alerts(user, alert_ids)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail={"code": "site_scope_denied", "message": str(exc)}) from exc
    svc.set_cluster_dispatch(alert_ids, data.get("is_dispatched", True), dispatched_by=user.username)
    
    from src.api.main import manager
    background_tasks.add_task(manager.broadcast_json, {"type": "RCA_UPDATE"})
    return {"status": "ok"}


# UPDATE: Add BackgroundTasks to force live-sync on Maintenance 
@router.post("/site-maintenance", dependencies=[Depends(require_action("Tab: AIOps RCA -> Active Board"))])
def site_maintenance(background_tasks: BackgroundTasks, data: dict = Body(...), user=Depends(require_action("Action: Manage Site Maintenance"))):
    from datetime import datetime
    site_name = data.get("site_name", "")
    is_maint = data.get("is_maint", False)
    etr = data.get("etr")
    reason = data.get("reason", "")
    if not svc.user_can_access_site(user, site_name):
        raise HTTPException(status_code=403, detail={
            "code": "site_scope_denied", "message": "This site is outside your permitted site types."
        })
    
    etr_date = datetime.fromisoformat(etr) if etr else None
    svc.set_site_maintenance(site_name, is_maint, etr_date, reason, modified_by=user.username)
    
    from src.api.main import manager
    background_tasks.add_task(manager.broadcast_json, {"type": "RCA_UPDATE"})
    return {"status": "ok"}


@router.post("/generate-ticket", dependencies=[Depends(require_action("Tab: AIOps RCA -> Active Board")), Depends(require_action("Action: Dispatch RCA Tickets"))])
def generate_ticket(data: dict = Body(...), user=Depends(get_current_user)):
    site = data.get("site", "")
    if not svc.user_can_access_site(user, site):
        raise HTTPException(status_code=403, detail={
            "code": "site_scope_denied", "message": "This site is outside your permitted site types."
        })
    priority = data.get("priority", "P3")
    patient_zero = data.get("patient_zero", "")
    root_cause = data.get("root_cause", "")
    cluster = data.get("cluster", {})
    return {"ticket": svc.generate_rca_ticket_text(site, cluster, priority, patient_zero, root_cause)}


@router.post("/send-ticket", dependencies=[Depends(require_action("Tab: AIOps RCA -> Active Board"))])
def send_ticket(background_tasks: BackgroundTasks, data: dict = Body(...), user=Depends(require_action("Action: Dispatch RCA Tickets"))):
    from src.utils.mailer import send_alert_email
    site = data.get("site", "")
    ticket_text = data.get("ticket_text", "")
    recipient = data.get("recipient", "remedyforceworkflow@aecc.com, noc@aecc.com")
    alert_ids = data.get("alert_ids", [])
    priority = data.get("priority", "P3")
    district = data.get("district", "Unknown")
    sla = data.get("sla", "N/A (Manual Dispatch)")
    if not svc.user_can_access_site(user, site):
        raise HTTPException(status_code=403, detail={
            "code": "site_scope_denied", "message": "This site is outside your permitted site types."
        })
    try:
        svc.ensure_user_can_access_alerts(user, alert_ids)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail={"code": "site_scope_denied", "message": str(exc)}) from exc

    ticket_body = f"*** MANUAL TICKET ***\nTarget SLA: {sla}\n\n{ticket_text}"
    success, msg = send_alert_email(
        subject=f"TICKET: {priority} Incident at {site}",
        body=ticket_body,
        recipient_override=recipient,
        is_html=False
    )
    if alert_ids:
        svc.set_cluster_dispatch(alert_ids, True, dispatched_by=user.username)
    from src.api.main import manager
    background_tasks.add_task(manager.broadcast_json, {"type": "RCA_UPDATE"})
    return {"status": "ok" if success else "error", "message": msg}


@router.get("/sitrep", dependencies=[Depends(require_action("Tab: AIOps RCA -> Global Correlation")), Depends(require_action("Action: Generate Reports"))])
def sitrep(user=Depends(get_current_user)):
    if not svc.user_has_all_site_type_access(user):
        raise HTTPException(status_code=403, detail={
            "code": "site_scope_denied", "message": "This global sitrep requires access to all site types."
        })
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


@router.post("/sitrep", dependencies=[Depends(require_action("Tab: AIOps RCA -> Global Correlation"))])
def sitrep_action(data: dict[str, Any] = Body({}), user=Depends(get_current_user)):
    action = data.get("action", "")
    required_action = {
        "refresh_briefing": "Action: Generate Reports",
        "scoring_rationale": "Action: Trigger AI Functions",
        "security_audit": "Action: Run RCA Analysis",
    }.get(action)
    if not required_action:
        return {"status": "error", "message": f"Unknown action: {action}"}
    if not has_action_permission(user, required_action):
        raise permission_denied(required_action)
    if action in {"scoring_rationale", "security_audit"} and not svc.user_has_all_site_type_access(user):
        raise HTTPException(status_code=403, detail={
            "code": "site_scope_denied", "message": "This operation requires access to all site types."
        })
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

@router.post("/clear-events", dependencies=[Depends(require_action("Tab: Settings -> Danger Zone")), Depends(require_action("Action: Clear AIOps Data"))])
def clear_events():
    svc.clear_timeline_events()
    return {"status": "ok"}

@router.post("/nuke-alerts", dependencies=[Depends(require_action("Tab: Settings -> Danger Zone")), Depends(require_action("Action: Clear AIOps Data"))])
def nuke_alerts():
    svc.nuke_active_alerts()
    return {"status": "ok"}

@router.post("/resolve-alert", dependencies=[Depends(require_action("Tab: AIOps RCA -> Active Board")), Depends(require_action("Action: Acknowledge RCA Alerts"))])
def resolve_alert(alert_id: int = 0, node_name: str = "", user=Depends(get_current_user)):
    try:
        svc.ensure_user_can_access_alerts(user, [alert_id])
    except ValueError as exc:
        raise HTTPException(status_code=403, detail={"code": "site_scope_denied", "message": str(exc)}) from exc
    svc.resolve_alert(alert_id, node_name)
    return {"status": "ok"}
