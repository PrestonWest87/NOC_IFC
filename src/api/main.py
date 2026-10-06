import asyncio
import json
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Body
from sqlalchemy import text
from fastapi.middleware.cors import CORSMiddleware

from src.core.db import engine, init_db
from src.core.config import setup_logging
from src.core.config import settings as app_settings
from src.core import restore_control
from src import services as svc
from src.api.ws_manager import ConnectionManager
from src.api.auth_guard import (
    authentication_middleware, has_action_permission, has_page_permission,
)
from src.api.routes import (
    aiops, threat, settings, reporting, auth, dashboard, regional, hunting, rca,
    logbook, settings_admin, llm, email, keyword_analysis, permissions, user_admin,
    application_settings,
)

setup_logging()
logger = logging.getLogger(__name__)

manager = ConnectionManager()


def _has_aiops_websocket_access(user):
    return (
        has_page_permission(user, "AIOps RCA")
        and has_action_permission(user, "Tab: AIOps RCA -> Active Board")
    )


async def broadcaster():
    from src import services as svc
    cycle = 0
    while True:
        if not restore_control.begin_api_background_writer():
            await asyncio.sleep(0.5)
            continue
        try:
            if manager.count == 0:
                await asyncio.sleep(10)
                continue
            alerts, events, grid = await asyncio.to_thread(svc.get_aiops_dashboard_data)
            locations = await asyncio.to_thread(svc.get_cached_locations)
            non_admin_scopes = sorted({
                tuple(sorted(svc.get_allowed_site_names_for_user(user, locations=locations)))
                for user in tuple(manager.connection_users.values())
                if user
                and _has_aiops_websocket_access(user)
                and str(getattr(user, "role", "") or "").casefold() not in {"admin", "administrator"}
            })
            scoped_events = {}
            if non_admin_scopes:
                event_lists = await asyncio.gather(*(
                    asyncio.to_thread(svc.get_aiops_timeline_events, site_names)
                    for site_names in non_admin_scopes
                ))
                scoped_events = dict(zip(non_admin_scopes, event_lists))
            payload = {
                "type": "dashboard_update",
                "alerts": alerts,
                "events": events,
                "grid": grid,
                "alert_count": len(alerts),
            }

            def filter_for_user(message, user):
                if not user or not _has_aiops_websocket_access(user):
                    return None
                is_admin = str(getattr(user, "role", "") or "").casefold() in {"admin", "administrator"}
                if not is_admin:
                    scope = tuple(sorted(svc.get_allowed_site_names_for_user(user, locations=locations)))
                    message = {**message, "events": scoped_events.get(scope, [])}
                return svc.filter_aiops_payload_for_user(message, user, locations=locations)

            await manager.broadcast_json(payload, transform=filter_for_user)
            cycle += 1
            if cycle % 12 == 0:
                logger.debug("Broadcaster: cycle=%d alerts=%d events=%d clients=%d",
                              cycle, len(alerts), len(events), manager.count)
        except Exception as e:
            logger.error("Broadcaster error: %s", e)
        finally:
            restore_control.end_api_background_writer()
        await asyncio.sleep(10)

@asynccontextmanager
async def lifespan(app: FastAPI):
    if restore_control.maintenance_requested():
        logger.warning("Starting API in restore maintenance mode; waiting for restore recovery.")
    else:
        init_db()
    task = asyncio.create_task(broadcaster())
    if restore_control.maintenance_requested():
        from src.core.ui_restore import resume_pending_restore

        resume_pending_restore()
    logger.info("FastAPI server started with WebSocket broadcaster.")
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

app = FastAPI(title="NOC Fusion Enterprise API", version="2.0.0", lifespan=lifespan)
app.middleware("http")(authentication_middleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in app_settings.cors_origins.split(",") if origin.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(aiops.router)
app.include_router(threat.router)
app.include_router(settings.router)
app.include_router(reporting.router)
app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(regional.router)
app.include_router(hunting.router)
app.include_router(rca.router)
app.include_router(logbook.router)
app.include_router(settings_admin.router)
app.include_router(llm.router)
app.include_router(email.router)
app.include_router(keyword_analysis.router)
app.include_router(permissions.router)
app.include_router(user_admin.router)
app.include_router(application_settings.router)

@app.get("/health")
def health():
    return {"status": "ok", "ws_clients": manager.count}


@app.get("/ready")
def ready():
    """Readiness probe: the process is serving only after the database responds."""
    if restore_control.maintenance_requested():
        raise HTTPException(status_code=503, detail="database restore in progress")
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:
        logger.warning("Readiness check failed: %s", exc)
        raise HTTPException(status_code=503, detail="database unavailable")
    return {"status": "ready"}


@app.post("/api/v1/restore-status")
def restore_status(data: dict = Body(...)):
    """Expose progress through an unguessable, short-lived restore ID capability."""
    status = restore_control.restore_status(str(data.get("restore_id", "")))
    if status is None:
        raise HTTPException(status_code=404, detail="Restore status not found.")
    return status

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    if restore_control.maintenance_requested():
        await websocket.close(code=1012, reason="Database restore in progress")
        return
    token = websocket.query_params.get("token", "")
    user = await asyncio.to_thread(svc.get_user_by_token, token)
    if not user:
        await websocket.close(code=1008, reason="Authentication required")
        return
    if not _has_aiops_websocket_access(user):
        await websocket.close(code=1008, reason="AIOps Active Board permission required")
        return
    await manager.connect(websocket, user)
    try:
        while True:
            if restore_control.maintenance_requested():
                await websocket.close(code=1012, reason="Database restore in progress")
                break
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30)
            except asyncio.TimeoutError:
                refreshed_user = await asyncio.to_thread(svc.get_user_by_token, token)
                if not refreshed_user or not _has_aiops_websocket_access(refreshed_user):
                    await websocket.close(code=1008, reason="AIOps permission revoked")
                    break
                manager.update_user(websocket, refreshed_user)
                continue
            if len(data.encode("utf-8")) > app_settings.websocket_max_message_bytes:
                await websocket.close(code=1009, reason="Message too large")
                break
            user = await asyncio.to_thread(svc.get_user_by_token, token)
            if not user or not _has_aiops_websocket_access(user):
                await websocket.close(code=1008, reason="AIOps permission revoked")
                break
            manager.update_user(websocket, user)
            logger.debug("Received WS message from user=%s", user.username)
            
            # ECHO UI MESSAGES TO ALL CONNECTED CLIENTS
            try:
                parsed_data = json.loads(data)
                if not isinstance(parsed_data, dict):
                    continue
                msg_type = parsed_data.get("type", "")
                required_action = {
                    "INVESTIGATING_UPDATE": "Action: Dispatch RCA Tickets",
                    "RCA_UPDATE": "Action: Dispatch RCA Tickets",
                }.get(msg_type)
                if not required_action or not has_action_permission(user, required_action):
                    await websocket.send_json({
                        "type": "error",
                        "code": "permission_denied",
                        "permission": required_action,
                        "message": "You do not have permission to send this command.",
                    })
                    continue
                if len(parsed_data) > 10:
                    continue

                if msg_type == "INVESTIGATING_UPDATE":
                    site = str(parsed_data.get("site", ""))
                    if not svc.user_can_access_site(user, site):
                        await websocket.send_json({
                            "type": "error",
                            "code": "site_scope_denied",
                            "message": "This site is outside your permitted site types.",
                        })
                        continue
                
                # If a client sends an investigating lock or a manual resync request, broadcast it!
                if msg_type in ["INVESTIGATING_UPDATE", "RCA_UPDATE"]:
                    def filter_command(message, recipient):
                        if not recipient or not _has_aiops_websocket_access(recipient):
                            return None
                        if message.get("type") == "INVESTIGATING_UPDATE":
                            site = str(message.get("site", ""))
                            if not svc.user_can_access_site(recipient, site):
                                return None
                        return message

                    await manager.broadcast_json(parsed_data, transform=filter_command)
                    
            except json.JSONDecodeError:
                pass
            except Exception as ex:
                logger.error("Error echoing WS message: %s", ex)
                
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error("WebSocket error: %s", e)
    finally:
        manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.api.main:app", host="0.0.0.0", port=8101, reload=True)
