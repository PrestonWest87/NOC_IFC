import os
import sys
import requests
import math
import random
import time
import feedparser
from datetime import datetime, timedelta

# --- PATH FIX: Ensure Python can find the 'src' module ---
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.database import SessionLocal, CrimeIncident, JmsCrimeIncident
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

def geocode_address_arcgis(address, hq_lat, hq_lon, region="Little Rock, AR"):
    """Converts a street address to Lat/Lon using ArcGIS World Geocoding (Region Aware)."""
    if address in GEO_CACHE: return GEO_CACHE[address]

    clean_address = address.replace("/", " and ").replace(" BLK ", " ").replace(" BLOCK ", " ").strip()
    clean_address = " ".join(clean_address.split())
    
    url = "https://geocode.arcgis.com/arcgis/rest/services/World/GeocodeServer/findAddressCandidates"
    params = {"SingleLine": f"{clean_address}, {region}", "f": "json", "maxLocations": 1}
    
    try:
        resp = requests.get(url, params=params, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if "candidates" in data and len(data["candidates"]) > 0:
                candidate = data["candidates"][0]
                lat, lon = candidate["location"]["y"], candidate["location"]["x"]
                
                score = candidate.get("score", 0)
                is_approx = score < 75 
                
                GEO_CACHE[address] = (lat, lon, is_approx)
                return lat, lon, is_approx
    except Exception: pass

    # FALLBACK: Donut of Uncertainty
    radius_deg = random.uniform(0.009, 0.018) 
    angle = random.uniform(0, 2 * math.pi)
    lat = hq_lat + radius_deg * math.cos(angle)
    lon = hq_lon + radius_deg * math.sin(angle)
    GEO_CACHE[address] = (lat, lon, True)
    return lat, lon, True


def fetch_live_crimes():
    """Fetches Little Rock AR Dispatch JSON"""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🚨 CRIME WORKER: Polling LR Dispatches...")
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
                    
                    # Target Little Rock specifically
                    incident_lat, incident_lon, is_approx = geocode_address_arcgis(location, hq_lat, hq_lon, "Little Rock, AR")
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
                        db.add(CrimeIncident(
                            id=inc_id, category=category, raw_title=display_title,
                            timestamp=incident_date, distance_miles=round(distance, 2),
                            severity=severity, lat=incident_lat, lon=incident_lon
                        ))
                        added_count += 1
                except Exception: continue
            
            db.commit()
            # Clean up old records while we are here
            db.query(CrimeIncident).filter(CrimeIncident.timestamp < seven_days_ago).delete()
            db.commit()
            print(f"[{datetime.now().strftime('%H:%M:%S')}] ✅ CRIME WORKER: {added_count} new LR dispatches mapped.")

    except Exception as e:
        print(f"🚨 LR CRIME WORKER FAILED: {e}")

def fetch_jackson_crimes():
    """Fetches Jackson County MS RSS Data"""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🚨 CRIME WORKER: Polling Jackson MS RSS...")
    
    try:
        feed = feedparser.parse("https://www.co.jackson.ms.us/RSSFeed.aspx?ModID=1&CID=Crime-Reports-11")
        
        # Jackson County MS approximate central coordinates for fallback
        hq_lat, hq_lon = 30.4126, -88.5833 
        seven_days_ago = datetime.now() - timedelta(hours=168)
        
        with SessionLocal() as db:
            added_count = 0
            
            for entry in feed.entries:
                try:
                    raw_title = entry.get("title", "UNKNOWN")
                    desc = entry.get("summary", "")
                    
                    # Handle RSS pub dates safely
                    if hasattr(entry, "published_parsed") and entry.published_parsed:
                        incident_date = datetime(*entry.published_parsed[:6])
                    else:
                        incident_date = datetime.now()
                        
                    if incident_date < seven_days_ago: continue
                    
                    # Police RSS Feeds usually format as "Incident - Address"
                    location = raw_title
                    desc_str = raw_title
                    if "-" in raw_title:
                        parts = raw_title.split("-", 1)
                        desc_str = parts[0].strip()
                        location = parts[1].strip()

                    # Target Jackson County specifically
                    incident_lat, incident_lon, is_approx = geocode_address_arcgis(location, hq_lat, hq_lon, "Jackson County, MS")
                    distance = calculate_distance(hq_lat, hq_lon, incident_lat, incident_lon)
                    
                    inc_id = f"JMS_{incident_date.strftime('%Y%m%d%H%M%S')}_{abs(hash(raw_title)) % 10000}"
                    
                    # Severity parsing
                    severity = "Low"
                    upper_text = (desc_str + " " + desc).upper()
                    if any(k in upper_text for k in ["ARSON", "EXPLOSIVE", "TERROR", "SABOTAGE", "SHOOTING", "MURDER"]): category, severity = "Critical Infrastructure Threat", "Critical"
                    elif any(k in upper_text for k in ["THEFT", "BURGLARY", "ROBBERY", "BREAKING"]): category, severity = "Asset/Copper Theft Risk", "High"
                    elif any(k in upper_text for k in ["ASSAULT", "BATTERY", "HOMICIDE", "WEAPON", "STABBING"]): category, severity = "Violent Proximity Threat", "High"
                    elif any(k in upper_text for k in ["VANDALISM", "TRESPASS", "PROWLER", "DISTURBANCE", "SUSPICIOUS"]): category, severity = "Perimeter Breach/Vandalism", "Medium"
                    else: category, severity = "General Police Activity", "Low"
                    
                    display_title = f"{desc_str.title()}"
                    if is_approx: display_title += " (Approx Loc)"
                    
                    existing_incident = db.query(CrimeIncident).filter_by(id=inc_id).first()
                    if not existing_incident:
                        db.add(CrimeIncident(
                            id=inc_id, category=category, raw_title=display_title,
                            timestamp=incident_date, distance_miles=round(distance, 2),
                            severity=severity, lat=incident_lat, lon=incident_lon
                        ))
                        added_count += 1
                except Exception: continue
                
            db.commit()
            print(f"[{datetime.now().strftime('%H:%M:%S')}] ✅ CRIME WORKER: {added_count} new Jackson County dispatches mapped.")

    except Exception as e:
        print(f"🚨 JACKSON CRIME WORKER FAILED: {e}")

if __name__ == "__main__":
    from src.database import init_db
    init_db()
    fetch_live_crimes()
    fetch_jackson_crimes()
