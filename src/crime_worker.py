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
    
    # Base dataset for Little Rock Police Department Statistics
    base_url = "https://data.littlerock.gov/resource/bz82-34ep.json"
    
    try:
        # 1. Fetch a single row to dynamically sniff the schema (bulletproof against 400 errors)
        sample_resp = requests.get(f"{base_url}?$limit=1", timeout=15)
        sample_resp.raise_for_status()
        sample_data = sample_resp.json()
        
        if not sample_data:
            print("🚨 CRIME WORKER: Empty response from Socrata.")
            return
            
        keys = sample_data[0].keys()
        
        # Determine exact column names from the live schema
        date_col = "incident_date" if "incident_date" in keys else next((k for k in keys if "date" in k), "incident_date")
        desc_col = "offense_description" if "offense_description" in keys else next((k for k in keys if "desc" in k or "offense" in k), "offense_description")
        weap_col = "weapon_type" if "weapon_type" in keys else next((k for k in keys if "weapon" in k), "weapon_type")
        
        # 2. Fetch the latest 500 records ordered dynamically
        query_url = f"{base_url}?$order={date_col} DESC&$limit=500"
        response = requests.get(query_url, timeout=15)
        response.raise_for_status()
        data = response.json()
        
        # 1 Cooperative Way, Little Rock, AR
        hq_lat, hq_lon = 34.6836, -92.3350
        crimes = []
        
        # 48-Hour boundary (using local time to match LRPD timestamps)
        forty_eight_hours_ago = datetime.now() - timedelta(hours=48)
        
        for entry in data:
            try:
                raw_date = entry.get(date_col, "")
                if not raw_date: continue
                
                # Parse Socrata date format: "2024-10-16T20:07:00.000"
                incident_date = datetime.strptime(raw_date.split(".")[0], "%Y-%m-%dT%H:%M:%S")
                
                # Drop incidents older than 48 hours
                if incident_date < forty_eight_hours_ago:
                    continue
                
                # Dynamic lat/lon extraction (Socrata sometimes nests this in a location_1 object)
                incident_lat = entry.get("latitude")
                incident_lon = entry.get("longitude")
                
                if not incident_lat or not incident_lon:
                    loc_obj = entry.get("location_1", {})
                    if isinstance(loc_obj, dict):
                        incident_lat = loc_obj.get("latitude")
                        incident_lon = loc_obj.get("longitude")
                        
                if not incident_lat or not incident_lon: continue
                
                incident_lat, incident_lon = float(incident_lat), float(incident_lon)
                
                # Geofence: Only include crimes strictly within 15 miles of HQ
                if calculate_distance(hq_lat, hq_lon, incident_lat, incident_lon) > 15.0:
                    continue
                
                desc = entry.get(desc_col, "UNKNOWN OFFENSE").upper()
                weapon = entry.get(weap_col, "NONE").upper()
                
                # BES Grid-Threat Categorization
                severity = "Low"
                if any(k in desc for k in ["THEFT", "BURGLARY", "ROBBERY", "LARCENY"]):
                    category = "Theft / Possible Asset Loss"
                    severity = "High"
                elif any(k in desc for k in ["VANDALISM", "ARREST", "TRESPASS"]):
                    category = "Perimeter Vandalism / Trespassing"
                    severity = "Medium"
                elif any(k in desc for k in ["ASSAULT", "BATTERY", "HOMICIDE", "RAPE"]) or "FIREARM" in weapon:
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
                    "link": "https://data.littlerock.gov/Safe-City/Little-Rock-Police-Department-Statistics-2017-to-Y/bz82-34ep"
                })
            except Exception as e:
                continue

        # Sort the array newest to oldest just to be perfectly clean
        crimes.sort(key=lambda x: x["timestamp"], reverse=True)

        with open(CRIME_CACHE_FILE, "w") as f:
            json.dump(crimes, f, indent=4)
            
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ✅ CRIME WORKER: {len(crimes)} incidents logged within 15 miles of HQ in last 48 hours.")
    except Exception as e:
        print(f"🚨 CRIME WORKER FAILED: {e}")

if __name__ == "__main__":
    fetch_live_crimes()
