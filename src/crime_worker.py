import os
import requests
import math
from datetime import datetime, timedelta

# Import your database session and the new model
from src.database import SessionLocal, CrimeIncident

def calculate_distance(lat1, lon1, lat2, lon2):
    R = 3958.8
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
    c = 2 * math.asin(math.sqrt(a))
    return R * c

def fetch_live_crimes():
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🚨 CRIME WORKER: Polling LRPD & Syncing to Database...")
    base_url = "https://data.littlerock.gov/resource/bz82-34ep.json"
    
    try:
        sample_resp = requests.get(f"{base_url}?$limit=1", timeout=15)
        sample_resp.raise_for_status()
        keys = sample_resp.json()[0].keys()
        
        date_col = "incident_date" if "incident_date" in keys else next((k for k in keys if "date" in k), "incident_date")
        desc_col = "offense_description" if "offense_description" in keys else next((k for k in keys if "desc" in k or "offense" in k), "offense_description")
        weap_col = "weapon_type" if "weapon_type" in keys else next((k for k in keys if "weapon" in k), "weapon_type")
        
        query_url = f"{base_url}?$order={date_col} DESC&$limit=500"
        response = requests.get(query_url, timeout=15)
        response.raise_for_status()
        data = response.json()
        
        hq_lat, hq_lon = 34.6836, -92.3350
        forty_eight_hours_ago = datetime.now() - timedelta(hours=48)
        
        with SessionLocal() as db:
            added_count = 0
            
            for entry in data:
                try:
                    raw_date = entry.get(date_col, "")
                    if not raw_date: continue
                    
                    incident_date = datetime.strptime(raw_date.split(".")[0], "%Y-%m-%dT%H:%M:%S")
                    if incident_date < forty_eight_hours_ago: continue
                    
                    incident_lat = entry.get("latitude")
                    incident_lon = entry.get("longitude")
                    if not incident_lat or not incident_lon:
                        loc_obj = entry.get("location_1", {})
                        if isinstance(loc_obj, dict):
                            incident_lat, incident_lon = loc_obj.get("latitude"), loc_obj.get("longitude")
                            
                    if not incident_lat or not incident_lon: continue
                    incident_lat, incident_lon = float(incident_lat), float(incident_lon)
                    
                    distance = calculate_distance(hq_lat, hq_lon, incident_lat, incident_lon)
                    if distance > 1.0: continue
                    
                    desc = entry.get(desc_col, "UNKNOWN OFFENSE").upper()
                    weapon = entry.get(weap_col, "NONE").upper()
                    inc_id = entry.get("incident_number", "UNKNOWN")
                    
                    severity = "Low"
                    if any(k in desc for k in ["ARSON", "EXPLOSIVE", "TERROR", "SABOTAGE"]): category, severity = "Critical Infrastructure Threat", "Critical"
                    elif any(k in desc for k in ["THEFT", "BURGLARY", "ROBBERY", "LARCENY"]): category, severity = "Asset/Copper Theft Risk", "High"
                    elif any(k in desc for k in ["ASSAULT", "BATTERY", "HOMICIDE"]) or "FIREARM" in weapon: category, severity = "Violent Proximity Threat", "High"
                    elif any(k in desc for k in ["VANDALISM", "TRESPASS", "DAMAGE", "PROWLER"]): category, severity = "Perimeter Breach/Vandalism", "Medium"
                    else: category, severity = "General Police Activity", "Low"
                    
                    # --- DATABASE UPSERT LOGIC ---
                    existing_incident = db.query(CrimeIncident).filter_by(id=inc_id).first()
                    if not existing_incident:
                        new_inc = CrimeIncident(
                            id=inc_id,
                            category=category,
                            raw_title=f"{desc.title()} (Weapon: {weapon.title()})",
                            timestamp=incident_date,
                            distance_miles=round(distance, 2),
                            severity=severity,
                            lat=incident_lat,
                            lon=incident_lon
                        )
                        db.add(new_inc)
                        added_count += 1
                        
                except Exception: continue
            
            # Commit the new records
            db.commit()
            
            # Purge any records older than 48 hours to keep the DB perfectly clean
            db.query(CrimeIncident).filter(CrimeIncident.timestamp < forty_eight_hours_ago).delete()
            db.commit()
            
            print(f"[{datetime.now().strftime('%H:%M:%S')}] ✅ CRIME WORKER: {added_count} new incidents saved to DB.")

    except Exception as e:
        print(f"🚨 CRIME WORKER FAILED: {e}")

if __name__ == "__main__":
    # If run directly, it will create the tables if they don't exist yet
    from src.database import init_db
    init_db()
    fetch_live_crimes()
