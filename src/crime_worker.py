import os
import sys
import requests
import math
import random
import time
from datetime import datetime, timedelta

# --- PATH FIX: Ensure Python can find the 'src' module ---
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.database import SessionLocal, CrimeIncident

# Simple memory cache to prevent spamming the geocoder with the same addresses
GEO_CACHE = {}

def calculate_distance(lat1, lon1, lat2, lon2):
    R = 3958.8
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
    c = 2 * math.asin(math.sqrt(a))
    return R * c

def geocode_address(address, hq_lat, hq_lon):
    """Converts a street address to Lat/Lon using OpenStreetMap."""
    if address in GEO_CACHE:
        return GEO_CACHE[address]

    clean_address = address.split("/")[0].strip() # Strip intersections to basic streets if needed
    
    try:
        url = "https://nominatim.openstreetmap.org/search"
        params = {
            "q": f"{clean_address}, Little Rock, AR",
            "format": "json",
            "limit": 1
        }
        headers = {"User-Agent": "NOC_IFC_Worker/1.0"}
        
        resp = requests.get(url, params=params, headers=headers, timeout=5)
        if resp.status_code == 200 and resp.json():
            data = resp.json()[0]
            lat, lon = float(data["lat"]), float(data["lon"])
            GEO_CACHE[address] = (lat, lon)
            time.sleep(1) # Respect OSM rate limits
            return lat, lon
    except Exception:
        pass

    # Fallback: If address can't be geocoded, apply a slight random scatter around HQ
    # so the incident still appears on the 1-mile radius map.
    lat = hq_lat + random.uniform(-0.015, 0.015)
    lon = hq_lon + random.uniform(-0.015, 0.015)
    GEO_CACHE[address] = (lat, lon)
    return lat, lon

def fetch_live_crimes():
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🚨 CRIME WORKER: Polling LR Dispatches...")
    
    # The hidden JSON endpoint discovered via the HAR file
    api_url = "https://web.littlerock.state.ar.us/pub/Home/CadEvents"
    
    try:
        # The site expects a POST request to deliver the payload
        response = requests.post(api_url, timeout=15)
        response.raise_for_status()
        data = response.json()
        
        hq_lat, hq_lon = 34.6836, -92.3350
        seven_days_ago = datetime.now() - timedelta(hours=168)
        
        with SessionLocal() as db:
            added_count = 0
            
            for entry in data:
                try:
                    desc = entry.get("typeDescription", "UNKNOWN").upper()
                    location = entry.get("location", "UNKNOWN")
                    raw_date = entry.get("dispatchDate", "")
                    
                    if not raw_date: continue
                    incident_date = datetime.strptime(raw_date, "%m/%d/%Y %H:%M:%S")
                    if incident_date < seven_days_ago: continue
                    
                    # Geocode the raw address
                    incident_lat, incident_lon = geocode_address(location, hq_lat, hq_lon)
                    distance = calculate_distance(hq_lat, hq_lon, incident_lat, incident_lon)
                    
                    # Filter to roughly 1.5 miles to account for geocoding drift
                    if distance > 1.5: continue
                    
                    # Generate a unique ID since the new API doesn't provide one
                    inc_id = f"LR_{incident_date.strftime('%Y%m%d%H%M%S')}_{abs(hash(location)) % 10000}"
                    
                    severity = "Low"
                    if any(k in desc for k in ["ARSON", "EXPLOSIVE", "TERROR", "SABOTAGE", "SHOOTING"]): category, severity = "Critical Infrastructure Threat", "Critical"
                    elif any(k in desc for k in ["THEFT", "BURGLARY", "ROBBERY", "BREAKING"]): category, severity = "Asset/Copper Theft Risk", "High"
                    elif any(k in desc for k in ["ASSAULT", "BATTERY", "HOMICIDE", "WEAPON"]): category, severity = "Violent Proximity Threat", "High"
                    elif any(k in desc for k in ["VANDALISM", "TRESPASS", "PROWLER", "DISTURBANCE", "SUSPICIOUS"]): category, severity = "Perimeter Breach/Vandalism", "Medium"
                    else: category, severity = "General Police Activity", "Low"
                    
                    existing_incident = db.query(CrimeIncident).filter_by(id=inc_id).first()
                    if not existing_incident:
                        new_inc = CrimeIncident(
                            id=inc_id,
                            category=category,
                            raw_title=desc.title(),
                            timestamp=incident_date,
                            distance_miles=round(distance, 2),
                            severity=severity,
                            lat=incident_lat,
                            lon=incident_lon
                        )
                        db.add(new_inc)
                        added_count += 1
                        
                except Exception as e:
                    continue
            
            db.commit()
            db.query(CrimeIncident).filter(CrimeIncident.timestamp < seven_days_ago).delete()
            db.commit()
            
            print(f"[{datetime.now().strftime('%H:%M:%S')}] ✅ CRIME WORKER: {added_count} new local dispatches mapped to DB.")

    except Exception as e:
        print(f"🚨 CRIME WORKER FAILED: {e}")

if __name__ == "__main__":
    from src.database import init_db
    init_db()
    fetch_live_crimes()
