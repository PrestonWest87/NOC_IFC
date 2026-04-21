from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import json

# Import your database session and sanitized services
from src.database import SessionLocal
import src.services as svc 

app = FastAPI(
    title="NOC Intelligence Fusion Center API", 
    version="2.0.0",
    description="Decoupled API Gateway for Net-mapper"
)

# ---------------------------------------------------------
# MIDDLEWARE & SECURITY
# ---------------------------------------------------------
# CORS allows your React frontend (running on a different port) to talk to this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict this to your specific UI domain/IP
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------
# DATABASE DEPENDENCY
# ---------------------------------------------------------
def get_db():
    """Safely yields a database session for each API request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ---------------------------------------------------------
# 1. METRICS ENDPOINT
# ---------------------------------------------------------
@app.get("/api/v1/dashboard/metrics", tags=["Dashboard"])
def get_top_metrics():
    """Returns the top-row KPI numbers for the dashboard."""
    try:
        # Utilizing the cached metrics from services.py
        metrics = svc.get_dashboard_metrics()
        return {"status": "success", "data": metrics}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ---------------------------------------------------------
# 2. INTELLIGENCE ENDPOINT
# ---------------------------------------------------------
@app.get("/api/v1/dashboard/intel", tags=["Intelligence"])
def get_executive_intel(hours_back: int = 24, max_distance: float = 1.0):
    """Generates and serves the unified threat posture and AI summaries."""
    try:
        # 1. Gather active NWS alert counts (from the cache)
        spc, ar_warn, oos_warn = svc.get_cached_geojson()
        ar_count = len(ar_warn.get("features", [])) if ar_warn else 0
        oos_count = len(oos_warn.get("features", [])) if oos_warn else 0
        active_nws_count = ar_count + oos_count
        
        # 2. Gather recent perimeter crimes
        crime_data = svc.get_recent_crimes(
            max_distance=max_distance, 
            grid_only=True, 
            hours_back=hours_back
        )
        
        # 3. Calculate the Unified Grid Intel
        intel = svc.get_executive_grid_intel(active_nws_count, crime_data)
        return {"status": "success", "data": intel}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ---------------------------------------------------------
# 3. GEOSPATIAL MAP ENDPOINTS
# ---------------------------------------------------------
@app.get("/api/v1/map/layers", tags=["Geospatial"])
def get_map_layers():
    """
    Ships the massive, pre-fetched raw GeoJSON geometries directly 
    to the client's browser for instant GPU rendering via Deck.gl.
    """
    try:
        spc, ar, oos = svc.get_cached_geojson()
        return {
            "status": "success",
            "layers": {
                "spc_outlooks": spc or {},
                "nws_arkansas": ar or {},
                "nws_regional": oos or {}
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/map/facilities", tags=["Geospatial"])
def get_facilities():
    """Returns the list of monitored locations/sites to plot on the map."""
    try:
        locations = svc.get_cached_locations()
        return {"status": "success", "data": locations}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ---------------------------------------------------------
# 4. MANUAL TRIGGERS (Optional/Admin)
# ---------------------------------------------------------
@app.post("/api/v1/admin/force-crime-fetch", tags=["Admin"])
def force_crime_fetch(background_tasks: BackgroundTasks):
    """Triggers the crime worker asynchronously so the API doesn't hang."""
    background_tasks.add_task(svc.force_fetch_crime_data)
    return {"status": "success", "message": "Crime data fetch initiated in the background."}