import requests
import uuid
import gc
from datetime import datetime
from src.database import SessionLocal, RegionalHazard, GeoJsonCache

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

SPC_URLS = {
    "spc_day1": "https://www.spc.noaa.gov/products/outlook/day1otlk_cat.nolyr.geojson",
    "spc_day2": "https://www.spc.noaa.gov/products/outlook/day2otlk_cat.nolyr.geojson",
    "spc_day3": "https://www.spc.noaa.gov/products/outlook/day3otlk_cat.nolyr.geojson"
}

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
                    log_print(f"✅ Downloaded and cached {feed_name} GeoJSON to DB.")
                else:
                    log_print(f"❌ Failed to fetch {feed_name}. HTTP {response.status_code}")
                    
            session.commit()
        except Exception as e:
            session.rollback()
            log_print(f"❌ SPC Fetch Error: {e}")

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
                log_print(f"✅ NWS ({area_str}) Sync complete. Added {added}, updated {updated}.")
            else:
                log_print(f"❌ NWS API returned HTTP {response.status_code} for {area_str}")
                
        except Exception as e:
            session.rollback()
            log_print(f"❌ NWS Fetch Error for {area_str}: {e}")

def fetch_regional_hazards():
    """Main wrapper for infrastructure telemetry."""
    fetch_spc_outlooks()
    fetch_nws_alerts_for_region("AR", "nws_ar")
    # Extended to seamlessly grab OOS warnings for adjacent states
    fetch_nws_alerts_for_region("OK,MS,MO", "nws_oos") 
    gc.collect()

if __name__ == "__main__":
    fetch_regional_hazards()
