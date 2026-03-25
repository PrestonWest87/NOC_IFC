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

GEO_CACHE = {}

def calculate_distance(lat1, lon1, lat2, lon2):
    """Accurate Great-Circle Haversine Distance."""
    R = 3958.8
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
    c = 2 * math.asin(math.sqrt(a))
    return R * c

def geocode_address_arcgis(address, hq_lat, hq_lon):
    """Converts a street address to Lat/Lon using ArcGIS World Geocoding."""
    if address in GEO_CACHE:
        return GEO_CACHE[address]

    # ArcGIS is very smart, but replacing "/" with "&" ensures it recognizes intersections perfectly
    clean_address = address.replace("/", " & ").replace(" BLK ", " ").replace(" BLOCK ", " ").strip()
    clean_address = " ".join(clean_address.split())
    
    url = "https://geocode.arcgis.com/arcgis/rest/services/World/GeocodeServer/findAddressCandidates"
    params = {
        "SingleLine": f"{clean_address}, Little Rock, Arkansas",
        "f": "json",
        "maxLocations": 1
    }
    
    try:
        resp = requests.get(url, params=params, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if "candidates" in data and len(data["candidates"]) > 0:
                candidate = data["candidates"][0]
                lat = candidate["location"]["y"]
                lon = candidate["location"]["x"]
                
                # ArcGIS provides a confidence score! Anything under 90 usually means 
                # it matched the street or zip, but not the exact point.
                score = candidate.get("score", 0)
                is_approx = score < 90 
                
                GEO_CACHE[address] = (lat, lon, is_approx)
                return lat, lon, is_approx
                
    except Exception as e:
        pass

    # FALLBACK: The Donut of Uncertainty
    # If the address is complete garbage (e.g. "UNKNOWN"), drop it in a 0.6 to 1.2 mile ring.
    radius_deg = random.uniform(0.009, 0.018) 
    angle = random.uniform(0, 2 * math.pi)
    lat = hq_lat + radius_deg * math.cos(angle)
    lon = hq_lon + radius_deg * math.sin(angle)
    
    GEO_CACHE[address] = (lat, lon, True)
    return lat, lon, True


def fetch_live_crimes():
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🚨 CRIME WORKER: Polling LR Dispatches (ArcGIS Engine)...")
    
    api_url = "https://web.littlerock.state.ar.us/pub/Home/CadEvents"
    
    try:
        response = requests.post(api_url, timeout=15)
        response.raise_for_status()
        data = response.json()
        
        hq_lat, hq_lon = 34.6755, -92.3235
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
                    
                    # Use the new ArcGIS geocoder
                    incident_lat, incident_lon, is_approx = geocode_address_arcgis(location, hq_lat, hq_lon)
                    distance = calculate_distance(hq_lat, hq_lon, incident_lat, incident_lon)
                                        
                    inc_id = f"LR_{incident_date.strftime('%Y%m%d%H%M%S')}_{abs(hash(location)) % 10000}"
                    
                    severity = "Low"
                    if any(k in desc for k in ["ARSON", "EXPLOSIVE", "TERROR", "SABOTAGE", "SHOOTING"]): category, severity = "Critical Infrastructure Threat", "Critical"
                    elif any(k in desc for k in ["THEFT", "BURGLARY", "ROBBERY", "BREAKING"]): category, severity = "Asset/Copper Theft Risk", "High"
                    elif any(k in desc for k in ["ASSAULT", "BATTERY", "HOMICIDE", "WEAPON"]): category, severity = "Violent Proximity Threat", "High"
                    elif any(k in desc for k in ["VANDALISM", "TRESPASS", "PROWLER", "DISTURBANCE", "SUSPICIOUS"]): category, severity = "Perimeter Breach/Vandalism", "Medium"
                    else: category, severity = "General Police Activity", "Low"
                    
                    display_title = f"{desc.title()}"
                    if is_approx: display_title += " (Approx Loc)"
                    
                    existing_incident = db.query(CrimeIncident).filter_by(id=inc_id).first()
                    if not existing_incident:
                        new_inc = CrimeIncident(
                            id=inc_id,
                            category=category,
                            raw_title=display_title,
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
