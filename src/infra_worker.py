import requests
import uuid
import gc
import math
from datetime import datetime, timedelta
from src.database import SessionLocal, RegionalHazard, GeoJsonCache, MonitoredLocation

def log_print(msg):
    print(f"[{datetime.utcnow().strftime('%H:%M:%S')}] [INFRA] {msg}")

def save_geojson_to_db(session, feed_name, data):
    """Upserts the raw JSON geometry into the database."""
    cache_entry = session.query(GeoJsonCache).filter_by(feed_name=feed_name).first()
    if cache_entry:
        cache_entry.data = data
        cache_entry.updated_at = datetime.utcnow()
    else:
        session.add(GeoJsonCache(feed_name=feed_name, data=data))

def fetch_spc_outlooks():
    """Fetches SPC Day 1, 2, and 3 Convective Outlooks and caches the JSON to the DB."""
    SPC_URLS = {
        "spc_day1": "https://www.spc.noaa.gov/products/outlook/day1otlk_cat.nolyr.geojson",
        "spc_day2": "https://www.spc.noaa.gov/products/outlook/day2otlk_cat.nolyr.geojson",
        "spc_day3": "https://www.spc.noaa.gov/products/outlook/day3otlk_cat.nolyr.geojson"
    }
    
    with SessionLocal() as session:
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (NOC_Fusion_Center)'}
            for feed_name, url in SPC_URLS.items():
                response = requests.get(url, headers=headers, timeout=15)
                
                if response.status_code == 200:
                    save_geojson_to_db(session, feed_name, response.json())
                    log_print(f"[OK] Downloaded and cached {feed_name} GeoJSON to DB.")
                else:
                    log_print(f"[ERROR] Failed to fetch {feed_name}. HTTP {response.status_code}")
                    
            session.commit()
        except Exception as e:
            session.rollback()
            log_print(f"[ERROR] SPC Fetch Error: {e}")

def fetch_nws_alerts_for_region(area_str, feed_name):
    """Fetches active NWS alerts, caches JSON to DB, and logs metadata."""
    with SessionLocal() as session:
        try:
            url = f"https://api.weather.gov/alerts/active?area={area_str}"
            headers = {'User-Agent': 'Mozilla/5.0 (NOC_Fusion_Center)'}
            response = requests.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                
                # 1. Save raw geometry for the UI to draw
                save_geojson_to_db(session, feed_name, data)
                
                # 2. Parse features for the AIOps RCA engine
                features = data.get('features', [])
                added, updated = 0, 0
                
                for f in features:
                    props = f.get('properties', {})
                    hazard_id = props.get('id', str(uuid.uuid4()))
                    existing_hazard = session.query(RegionalHazard).filter_by(hazard_id=hazard_id).first()
                    
                    if existing_hazard:
                        existing_hazard.updated_at = datetime.utcnow()
                        updated += 1
                    else:
                        session.add(RegionalHazard(
                            hazard_id=hazard_id,
                            hazard_type=props.get('event', 'Unknown'),
                            severity=props.get('severity', 'Unknown'),
                            title=props.get('headline', 'Weather Alert'),
                            description=props.get('description', ''),
                            location=props.get('areaDesc', 'Regional'),
                            updated_at=datetime.utcnow()
                        ))
                        added += 1
                
                session.commit()
                log_print(f"[OK] NWS ({area_str}) Sync complete. Added {added}, updated {updated}.")
            else:
                log_print(f"[ERROR] NWS API returned HTTP {response.status_code} for {area_str}")
                
        except Exception as e:
            session.rollback()
            log_print(f"[ERROR] NWS Fetch Error for {area_str}: {e}")

USGS_BOUNDS = {
    "ar": {"minlat": 33.0, "maxlat": 36.5, "minlon": -94.5, "maxlon": -89.6},
    "oos": {"minlat": 33.0, "maxlat": 37.5, "minlon": -95.5, "maxlon": -89.0}
}

def fetch_usgs_earthquakes(area_key, feed_name):
    """Fetches USGS earthquake data for Arkansas region."""
    bounds = USGS_BOUNDS.get(area_key, USGS_BOUNDS["ar"])
    start_time = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%d")
    
    url = (
        f"https://earthquake.usgs.gov/fdsnws/event/1/query?"
        f"format=geojson&starttime={start_time}&minmagnitude=2.0"
        f"&minlatitude={bounds['minlat']}&maxlatitude={bounds['maxlat']}"
        f"&minlongitude={bounds['minlon']}&maxlongitude={bounds['maxlon']}"
    )
    
    with SessionLocal() as session:
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (NOC_Fusion_Center)'}
            response = requests.get(url, headers=headers, timeout=20)
            
            if response.status_code == 200:
                data = response.json()
                save_geojson_to_db(session, feed_name, data)
                session.commit()
                count = len(data.get('features', []))
                log_print(f"[OK] USGS ({area_key}) Fetched {count} earthquakes.")
            else:
                log_print(f"[ERROR] USGS API returned HTTP {response.status_code} for {area_key}")
                
        except Exception as e:
            session.rollback()
            log_print(f"[ERROR] USGS Fetch Error for {area_key}: {e}")

def haversine_distance(lat1, lon1, lat2, lon2):
    """Calculate distance in miles between two lat/lon points."""
    R = 3959  # Earth radius in miles
    lat1_r, lat2_r = math.radians(lat1), math.radians(lat2)
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat/2)**2 + math.cos(lat1_r) * math.cos(lat2_r) * math.sin(dlon/2)**2
    c = 2 * math.asin(math.sqrt(a))
    return R * c

def check_earthquake_proximity(equake_data, distance_miles=50):
    """Check if earthquakes are within specified distance of any monitored site."""
    from src.risk_alert import send_alert, get_alert_recipients, build_eq_alert_email_body
    
    if not equake_data or 'features' not in equake_data:
        return
    
    with SessionLocal() as session:
        sites = session.query(MonitoredLocation).filter(
            MonitoredLocation.lat.isnot(None),
            MonitoredLocation.lon.isnot(None)
        ).all()
        
        new_alerts = []
        for f in equake_data['features']:
            props = f.get('properties', {})
            mag = props.get('mag', 0)
            if mag < 2.5:
                continue
            
            coords = f.get('geometry', {}).get('coordinates', [0, 0, 0])
            eq_lon, eq_lat = coords[0], coords[1]
            place = props.get('place', 'Unknown')
            time_ms = props.get('time', 0)
            time_str = datetime.fromtimestamp(time_ms/1000).strftime('%Y-%m-%d %H:%M') if time_ms else 'Unknown'
            depth = coords[2]
            
            for site in sites:
                if not site.lat or not site.lon:
                    continue
                dist = haversine_distance(eq_lat, eq_lon, site.lat, site.lon)
                if dist <= distance_miles:
                    new_alerts.append({
                        'site': site.name,
                        'site_type': site.loc_type,
                        'distance': round(dist, 1),
                        'mag': mag,
                        'place': place,
                        'depth': depth,
                        'time': time_str,
                        'lat': eq_lat,
                        'lon': eq_lon
                    })
        
        if new_alerts:
            recipients = get_alert_recipients()
            if recipients:
                body = build_eq_alert_email_body(new_alerts)
                send_alert(recipients, f"NOC Alert: Earthquake Proximity Warning", body)
                log_print(f"[ALERT] Earthquake alert sent for {len(new_alerts)} site proximities")

def fetch_regional_hazards():
    """Main wrapper for infrastructure telemetry."""
    fetch_spc_outlooks()
    fetch_nws_alerts_for_region("AR", "nws_ar")
    fetch_nws_alerts_for_region("OK,MS,MO", "nws_oos")
    fetch_usgs_earthquakes("ar", "usgs_ar")
    fetch_usgs_earthquakes("oos", "usgs_oos")
    
    with SessionLocal() as db:
        usgs_ar = db.query(GeoJsonCache).filter_by(feed_name="usgs_ar").first()
        usgs_oos = db.query(GeoJsonCache).filter_by(feed_name="usgs_oos").first()
        if usgs_ar and usgs_ar.data:
            check_earthquake_proximity(usgs_ar.data, 50)
        if usgs_oos and usgs_oos.data:
            check_earthquake_proximity(usgs_oos.data, 50)
    
    gc.collect()

if __name__ == "__main__":
    fetch_regional_hazards()
