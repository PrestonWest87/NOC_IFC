import asyncio
import json
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from src.core.db import init_db
from src.core.config import setup_logging
from src.api.ws_manager import ConnectionManager
from src.api.routes import aiops, threat, settings, reporting, auth, dashboard, regional, hunting, rca, logbook, settings_admin, llm, email

setup_logging()
logger = logging.getLogger(__name__)

manager = ConnectionManager()

async def broadcaster():
    from src import services as svc
    cycle = 0
    while True:
        try:
            alerts, events, grid = svc.get_aiops_dashboard_data()
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
        await asyncio.sleep(5)

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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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

@app.get("/health")
def health():
    return {"status": "ok", "ws_clients": manager.count}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            logger.debug("Received WS message: %s", data)
            
            # ECHO UI MESSAGES TO ALL CONNECTED CLIENTS
            try:
                parsed_data = json.loads(data)
                msg_type = parsed_data.get("type", "")
                
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
