import os
import json
import requests
import math
from datetime import datetime, timedelta

CRIME_CACHE_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "crime_cache.json")

def calculate_distance(lat1, lon1, lat2, lon2):
    """Haversine formula to calculate the distance in miles between two coordinates."""
    R = 3958.8 # Earth radius in miles
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
    c = 2 * math.asin(math.sqrt(a))
    return R * c

def fetch_live_crimes():
    """Fetches live crime data via City of Little Rock Open Data API (Socrata)."""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🚨 CRIME WORKER: Polling LRPD Socrata API...")
    os.makedirs(os.path.dirname(CRIME_CACHE_FILE), exist_ok=True)
    
    # City of Little Rock - Violent & Property Crimes API
    api_url = "https://data.littlerock.gov/resource/8mii-3cm3.json?$order=incident_date DESC&$limit=150"
    
    try:
        response = requests.get(api_url, timeout=15)
        response.raise_for_status()
        data = response.json()
        
        # 1 Cooperative Way, Little Rock, AR
        hq_lat, hq_lon = 34.6836, -92.3350
        crimes = []
        
        for entry in data:
            try:
                raw_date = entry.get("incident_date", "")
                if not raw_date: continue
                
                # Socrata date format: "2024-10-16T20:07:00.000"
                incident_date = datetime.strptime(raw_date.split(".")[0], "%Y-%m-%dT%H:%M:%S")
                
                incident_lat = float(entry.get("latitude", hq_lat))
                incident_lon = float(entry.get("longitude", hq_lon))
                
                # Geofence: Only include crimes within 15 miles of HQ
                if calculate_distance(hq_lat, hq_lon, incident_lat, incident_lon) > 15.0:
                    continue
                
                desc = entry.get("offense_description", "UNKNOWN OFFENSE").upper()
                weapon = entry.get("weapon_type", "NONE")
                
                # BES Grid-Threat Categorization
                severity = "Low"
                if any(k in desc for k in ["THEFT", "BURGLARY", "ROBBERY", "LARCENY"]):
                    category = "Theft / Possible Asset Loss"
                    severity = "High"
                elif any(k in desc for k in ["VANDALISM", "ARREST", "TRESPASS"]):
                    category = "Perimeter Vandalism / Trespassing"
                    severity = "Medium"
                elif any(k in desc for k in ["ASSAULT", "BATTERY", "HOMICIDE"]) or "FIREARM" in weapon.upper():
                    category = "Violent Incident near Asset"
                    severity = "High"
                else:
                    category = "General Incident"
                
                crimes.append({
                    "id": entry.get("incident_number", "UNKNOWN"),
                    "category": category,
                    "raw_title": f"{desc.title()} (Weapon: {weapon.title()})",
                    "timestamp": incident_date.strftime("%Y-%m-%d %H:%M:%S"),
                    "lat": incident_lat,
                    "lon": incident_lon,
                    "severity": severity,
                    "link": "https://data.littlerock.gov/Safe-City/LR-Crime-by-Zip/8mii-3cm3"
                })
            except Exception as e:
                continue

        with open(CRIME_CACHE_FILE, "w") as f:
            json.dump(crimes, f, indent=4)
            
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ✅ CRIME WORKER: {len(crimes)} incidents logged within 15 miles of HQ.")
    except Exception as e:
        print(f"🚨 CRIME WORKER FAILED: {e}")

if __name__ == "__main__":
    fetch_live_crimes()
