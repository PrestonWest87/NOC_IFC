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
    """Fetches live crime data within a strict 1-mile radius of HQ."""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🚨 CRIME WORKER: Polling LRPD for perimeter threats (1 Mile)...")
    os.makedirs(os.path.dirname(CRIME_CACHE_FILE), exist_ok=True)
    
    base_url = "https://data.littlerock.gov/resource/bz82-34ep.json"
    
    try:
        # Fetch 500 recent incidents
        query_url = f"{base_url}?$order=incident_date DESC&$limit=500"
        response = requests.get(query_url, timeout=15)
        response.raise_for_status()
        data = response.json()
        
        # 1 Cooperative Way, Little Rock, AR
        hq_lat, hq_lon = 34.6836, -92.3350
        crimes = []
        forty_eight_hours_ago = datetime.now() - timedelta(hours=48)
        
        for entry in data:
            try:
                raw_date = entry.get("incident_date", "")
                if not raw_date: continue
                
                incident_date = datetime.strptime(raw_date.split(".")[0], "%Y-%m-%dT%H:%M:%S")
                if incident_date < forty_eight_hours_ago: continue
                
                incident_lat = entry.get("latitude")
                incident_lon = entry.get("longitude")
                if not incident_lat or not incident_lon: continue
                incident_lat, incident_lon = float(incident_lat), float(incident_lon)
                
                # GEOFENCE: Strict 1-Mile Perimeter
                distance = calculate_distance(hq_lat, hq_lon, incident_lat, incident_lon)
                if distance > 1.0:
                    continue
                
                desc = entry.get("offense_description", "UNKNOWN").upper()
                weapon = entry.get("weapon_type", "NONE").upper()
                
                # UTILITY-FOCUSED RISK WEIGHTING
                severity = "Low"
                if any(k in desc for k in ["THEFT", "BURGLARY", "ROBBERY", "LARCENY"]):
                    category = "Asset/Copper Theft Risk"
                    severity = "High"
                elif any(k in desc for k in ["VANDALISM", "TRESPASS", "DAMAGE"]):
                    category = "Perimeter Breach/Vandalism"
                    severity = "High" # Elevated for utility proximity
                elif any(k in desc for k in ["ASSAULT", "BATTERY", "HOMICIDE"]) or "FIREARM" in weapon:
                    category = "Violent Proximity Threat"
                    severity = "High"
                else:
                    category = "General Police Activity"
                    severity = "Medium"
                
                crimes.append({
                    "id": entry.get("incident_number", "UNKNOWN"),
                    "category": category,
                    "raw_title": f"{desc.title()} (Weapon: {weapon.title()})",
                    "timestamp": incident_date.strftime("%Y-%m-%d %H:%M:%S"),
                    "distance_miles": round(distance, 2),
                    "severity": severity
                })
            except Exception as e:
                continue

        crimes.sort(key=lambda x: x["timestamp"], reverse=True)
        with open(CRIME_CACHE_FILE, "w") as f:
            json.dump(crimes, f, indent=4)
            
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ✅ CRIME WORKER: {len(crimes)} perimeter incidents logged (1 Mile).")
    except Exception as e:
        print(f"🚨 CRIME WORKER FAILED: {e}")

if __name__ == "__main__":
    fetch_live_crimes()
