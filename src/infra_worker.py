import requests
import uuid
import gc
from datetime import datetime
from shapely.geometry import shape, Point
from src.database import SessionLocal, RegionalHazard, MonitoredLocation

def log_print(msg):
    print(f"[{datetime.utcnow().strftime('%H:%M:%S')}] [INFRA] {msg}")

def fetch_spc_outlooks():
    """Fetches SPC Day 1 Convective Outlook and maps risk to custom locations."""
    with SessionLocal() as session:
        try:
            url = "https://www.spc.noaa.gov/products/outlook/day1otlk_cat.lyr.geojson"
            headers = {'User-Agent': 'Mozilla/5.0 (NOC_Fusion_Center)'}
            response = requests.get(url, headers=headers, timeout=15)
            
            if response.status_code != 200:
                log_print(f"❌ Failed to fetch SPC. HTTP {response.status_code}")
                return

            features = response.json().get('features', [])
            log_print(f"✅ Downloaded SPC GeoJSON. Found {len(features)} risk polygons.")
            
            risk_levels = {"HIGH": 6, "MDT": 5, "ENH": 4, "SLGT": 3, "MRGL": 2, "TSTM": 1, "None": 0}
            locations = session.query(MonitoredLocation).all()
            
            if not locations:
                log_print("⚠️ No tracked locations found in DB. Skipping geospatial math.")
                return

            # Pre-compile the polygons for speed
            risk_polygons = []
            for feature in features:
                geom = feature.get('geometry')
                label = feature.get('properties', {}).get('LABEL', 'None')
                if geom and label in risk_levels:
                    risk_polygons.append((label, risk_levels[label], shape(geom)))

            # Check every location against the polygons
            updated_count = 0
            for loc in locations:
                point = Point(loc.lon, loc.lat) # Shapely uses (lon, lat)
                max_risk_name, max_risk_val = "None", 0
                
                for label, r_val, poly in risk_polygons:
                    if point.within(poly) and r_val > max_risk_val:
                        max_risk_val, max_risk_name = r_val, label
                
                if loc.current_spc_risk != max_risk_name:
                    loc.current_spc_risk = max_risk_name
                    updated_count += 1
                loc.last_updated = datetime.utcnow()
                
            session.commit()
            log_print(f"✅ SPC Geospatial math complete. {updated_count} locations updated risk status.")

        except Exception as e:
            session.rollback()
            log_print(f"❌ SPC Fetch Error: {e}")

def fetch_nws_warnings():
    """Fetches active NWS alerts for the operational region (AR, OK, MS, MO)."""
    with SessionLocal() as session:
        try:
            url = "https://api.weather.gov/alerts/active?area=AR,OK,MS,MO"
            headers = {'User-Agent': 'Mozilla/5.0 (NOC_Fusion_Center)'}
            response = requests.get(url, headers=headers, timeout=15)
            
            if response.status_code != 200: 
                return
                
            features = response.json().get('features', [])
            added, updated = 0, 0
            
            for f in features:
                props = f.get('properties', {})
                hazard_id = props.get('id', str(uuid.uuid4()))
                existing_hazard = session.query(RegionalHazard).filter_by(hazard_id=hazard_id).first()
                
                if existing_hazard:
                    existing_hazard.updated_at = datetime.utcnow()
                    updated += 1
                else:
                    haz = RegionalHazard(
                        hazard_id=hazard_id,
                        hazard_type=props.get('event', 'Unknown'),
                        severity=props.get('severity', 'Unknown'),
                        title=props.get('headline', 'Weather Alert'),
                        description=props.get('description', ''),
                        location=props.get('areaDesc', 'Regional'),
                        updated_at=datetime.utcnow()
                    )
                    session.add(haz)
                    added += 1
                
            session.commit()
            log_print(f"✅ NWS Sync complete. Added {added}, updated {updated} alerts.")
        except Exception as e:
            session.rollback()
            log_print(f"❌ NWS Fetch Error: {e}")

def fetch_regional_hazards():
    """Main wrapper for infrastructure telemetry."""
    fetch_nws_warnings()
    fetch_spc_outlooks()
    gc.collect()

if __name__ == "__main__":
    fetch_regional_hazards()
