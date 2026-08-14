import asyncio
import json
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from sqlalchemy import text
from fastapi.middleware.cors import CORSMiddleware

from src.core.db import engine, init_db
from src.core.config import setup_logging
from src.core.config import settings as app_settings
from src import services as svc
from src.api.ws_manager import ConnectionManager
from src.api.auth_guard import authentication_middleware
from src.api.routes import aiops, threat, settings, reporting, auth, dashboard, regional, hunting, rca, logbook, settings_admin, llm, email, keyword_analysis

setup_logging()
logger = logging.getLogger(__name__)

manager = ConnectionManager()

async def broadcaster():
    from src import services as svc
    cycle = 0
    while True:
        try:
            if manager.count == 0:
                await asyncio.sleep(10)
                continue
            alerts, events, grid = await asyncio.to_thread(svc.get_aiops_dashboard_data)
            payload = {
                "type": "dashboard_update",
                "alerts": alerts,
                "events": events,
                "grid": grid,
                "alert_count": len(alerts),
            }
            await manager.broadcast_json(payload)
            cycle += 1
            if cycle % 12 == 0:
                logger.debug("Broadcaster: cycle=%d alerts=%d events=%d clients=%d",
                              cycle, len(alerts), len(events), manager.count)
        except Exception as e:
            logger.error("Broadcaster error: %s", e)
        await asyncio.sleep(10)

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    task = asyncio.create_task(broadcaster())
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

@app.get("/health")
def health():
    return {"status": "ok", "ws_clients": manager.count}


@app.get("/ready")
def ready():
    """Readiness probe: the process is serving only after the database responds."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:
        logger.warning("Readiness check failed: %s", exc)
        raise HTTPException(status_code=503, detail="database unavailable")
    return {"status": "ready"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    token = websocket.query_params.get("token", "")
    user = await asyncio.to_thread(svc.get_user_by_token, token)
    if not user:
        await websocket.close(code=1008, reason="Authentication required")
        return
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if len(data.encode("utf-8")) > app_settings.websocket_max_message_bytes:
                await websocket.close(code=1009, reason="Message too large")
                break
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
                if not required_action or required_action not in (user.allowed_actions or []):
                    await websocket.send_json({"type": "error", "message": "Not authorized"})
                    continue
                if len(parsed_data) > 10:
                    continue
                
                # If a client sends an investigating lock or a manual resync request, broadcast it!
                if msg_type in ["INVESTIGATING_UPDATE", "RCA_UPDATE"]:
                    await manager.broadcast_json(parsed_data)
                    
            except json.JSONDecodeError:
                pass
            except Exception as ex:
                logger.error("Error echoing WS message: %s", ex)
                
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error("WebSocket error: %s", e)
        manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.api.main:app", host="0.0.0.0", port=8101, reload=True)
