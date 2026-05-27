import pandas as pd
from fastapi import APIRouter, Query, Body
from typing import Any

from src import services as svc

router = APIRouter(prefix="/api/v1/regional", tags=["regional"])


@router.get("/locations")
def locations():
    return svc.get_cached_locations()


@router.get("/geojson")
def geojson():
    spc_d1, spc_d2, spc_d3, ar, oos, usgs_ar, usgs_oos = svc.get_cached_geojson()
    return {
        "spc_day1": spc_d1, "spc_day2": spc_d2, "spc_day3": spc_d3,
        "nws_ar": ar, "nws_oos": oos,
        "usgs_ar": usgs_ar, "usgs_oos": usgs_oos,
    }


@router.get("/infrastructure-analytics")
def infrastructure_analytics():
    locs = svc.get_cached_locations()
    return {"total_sites": len(locs), "at_risk_sites": 0, "highest_risk": "None"}


@router.post("/compile-map")
def compile_map(data: dict[str, Any] = Body({})):
    toggles = data.get("toggles", {})
    spc = data.get("spc_data")
    ar = data.get("ar_data")
    oos = data.get("oos_data")
    usgs_ar = data.get("usgs_ar_data")
    usgs_oos = data.get("usgs_oos_data")
    selected = tuple(data.get("selected_events", []))
    raw_map_df = data.get("map_df", [])

    if raw_map_df:
        map_df = pd.DataFrame(raw_map_df)
    else:
        map_df = pd.DataFrame()

    cache = svc._precompute_geo_matrix(spc, ar, oos, usgs_ar, usgs_oos, selected, map_df)

    toggled_affected_sites_dict = {}
    for site in cache["master_affected_sites"]:
        hazard = site["Hazard"]
        is_visible = False
        if "SPC:" in hazard and toggles.get("spc", True): is_visible = True
        elif "Wildfire Risk:" in hazard and toggles.get("fire_risk", False): is_visible = True
        elif "Active Wildfire:" in hazard and toggles.get("active_wildfires", False): is_visible = True
        elif "EQ (" in hazard and toggles.get("earthquakes", True): is_visible = True
        elif "[OOS]" in hazard and toggles.get("oos", True): is_visible = True
        elif "[AR]" in hazard:
            if site["Severity"] == "Warning" and toggles.get("warn", True): is_visible = True
            elif site["Severity"] == "Watch/Advisory" and toggles.get("watch", True): is_visible = True
        if is_visible:
            name = site["Monitored Site"]
            if name not in toggled_affected_sites_dict:
                toggled_affected_sites_dict[name] = {
                    "Monitored Site": name, "District": site["District"],
                    "Facility Type": site["Type"], "Priority": site["Priority"], "Hazards": set()
                }
            toggled_affected_sites_dict[name]["Hazards"].add(hazard)

    toggled_affected_sites = []
    for v in toggled_affected_sites_dict.values():
        v["Intersecting Hazards"] = ", ".join(list(v["Hazards"]))
        v.pop("Hazards")
        toggled_affected_sites.append(v)

    return [[], {}, cache["map_diagnostics"], toggled_affected_sites, cache["master_affected_sites"]]


@router.get("/weather-prefs")
def weather_prefs(username: str = ""):
    return svc.get_user_weather_prefs(username)


@router.post("/weather-prefs")
def set_weather_prefs(username: str = "", alerts: list[str] = Body([])):
    svc.set_user_weather_prefs(username, alerts)
    return {"status": "ok"}


@router.get("/forecast")
def forecast(lat: float = Query(34.8), lon: float = Query(-92.2)):
    return svc.get_nws_forecast(lat, lon)


@router.get("/weather-alerts-log")
def weather_alerts_log():
    _, _, _, ar, oos, usgs_ar, usgs_oos = svc.get_cached_geojson()
    return svc.get_weather_alerts_log(ar, oos, [], usgs_ar, usgs_oos)


@router.get("/site-types")
def site_types():
    return svc.get_all_site_types()


@router.post("/sync-hazards")
def sync_hazards():
    from src.workers.infra_worker import fetch_regional_hazards
    try:
        fetch_regional_hazards()
        svc.get_cached_geojson.clear()
        return {"status": "ok", "message": "Regional hazards synced."}
    except Exception as e:
        return {"status": "error", "message": str(e)}
