import os
import sys
import requests
import math
import random
import time
import hashlib
import warnings
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo  # <-- Added for timezone correction

# Suppress insecure request warnings for gov sites
from urllib3.exceptions import InsecureRequestWarning
warnings.simplefilter('ignore', InsecureRequestWarning)

# --- PATH FIX: Ensure Python can find the 'src' module ---
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.database import SessionLocal, CrimeIncident

GEO_CACHE = {}

def log(msg, level="INFO"):
    """Helper to standardize logging output with timestamps."""
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [CRIME_{level}] {msg}")

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
    """Converts a street address to Lat/Lon using ArcGIS World Geocoding."""
    if address in GEO_CACHE: 
        return GEO_CACHE[address]

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
    except Exception as e: 
        log(f"Geocode Request Exception for '{address}': {e}", "ERROR")

    # FALLBACK: Donut of Uncertainty
    radius_deg = random.uniform(0.009, 0.018) 
    angle = random.uniform(0, 2 * math.pi)
    lat = hq_lat + radius_deg * math.cos(angle)
    lon = hq_lon + radius_deg * math.sin(angle)
    GEO_CACHE[address] = (lat, lon, True)
    return lat, lon, True


def fetch_live_crimes():
    """Fetches Little Rock AR Dispatch Data with resilient fallback parsing."""
    log("Polling LR Dispatches...", "INFO")
    api_url = "https://web.littlerock.state.ar.us/pub/Home/CadEvents"
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)',
        'Accept': 'application/json, text/javascript, text/html, */*; q=0.01',
        'X-Requested-With': 'XMLHttpRequest'
    }

    data = []
    try:
        log(f"Attempting POST request to {api_url}", "DEBUG")
        response = requests.post(api_url, headers=headers, timeout=15, verify=False)
        response.raise_for_status()
        data = response.json()
    except Exception as post_e:
        log(f"POST request failed ({post_e}). Attempting GET request...", "WARN")
        try:
            response = requests.get(api_url, headers=headers, timeout=15, verify=False)
            response.raise_for_status()
            data = response.json()
        except Exception as get_e:
            log(f"JSON API completely failed ({get_e}). Attempting HTML scraping fallback...", "WARN")
            try:
                import pandas as pd
                html_url = "https://web.littlerock.state.ar.us/pub"
                html_resp = requests.get(html_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=15, verify=False)
                html_resp.raise_for_status()
                tables = pd.read_html(html_resp.text)
                if tables:
                    df = tables[0]
                    for _, row in df.iterrows():
                        data.append({
                            "CallType": str(row.get('Call Type', '')),
                            "Location": str(row.get('Location', '')),
                            "DispatchTime": str(row.get('Dispatch Time', ''))
                        })
                else:
                    raise ValueError("No tables found in HTML.")
            except Exception as html_e:
                log(f"HTML fallback failed: {html_e}. Cannot update crime data.", "ERROR")
                return

    # UNBOX DataTables format
    if isinstance(data, dict):
        unboxed = False
        if "data" in data and isinstance(data["data"], list):
            data = data["data"]
            unboxed = True
        elif "Data" in data and isinstance(data["Data"], list):
            data = data["Data"]
            unboxed = True
        else:
            for v in data.values():
                if isinstance(v, list):
                    data = v
                    unboxed = True
                    break
        if not unboxed:
            log("API returned a dictionary but could not find a data list inside it.", "ERROR")
            return

    if not isinstance(data, list):
        log(f"Expected a list of incidents, but got: type {type(data)}", "ERROR")
        return

    log(f"Successfully retrieved {len(data)} raw CAD entries.", "INFO")

    hq_lat, hq_lon = 34.6755, -92.3235
    
    # <-- UPDATED: Now uses UTC to match DB standards -->
    seven_days_ago = datetime.utcnow() - timedelta(hours=168)

    with SessionLocal() as db:
        batch = []
        batch_size = 100
        seen_ids = set()
        added_count = 0
        skip_count_old = 0
        skip_count_missing = 0
        skip_count_errors = 0

        for entry in data:
            if not isinstance(entry, dict): continue
            try:
                desc = entry.get("typeDescription") or entry.get("CallType") or entry.get("TypeDescription") or entry.get("Call Type") or "UNKNOWN"
                desc = str(desc).upper()

                location = entry.get("location") or entry.get("Location") or "UNKNOWN"
                location = str(location)

                raw_date = entry.get("dispatchDate") or entry.get("DispatchTime") or entry.get("DispatchDate") or entry.get("dispatchTime") or entry.get("Dispatch Time") or ""
                raw_date = str(raw_date).strip()

                if not raw_date or raw_date.upper() in ["NAN", "NONE"]: 
                    skip_count_missing += 1
                    continue
                    
                incident_date = None
                for fmt in ["%m/%d/%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M", "%Y-%m-%dT%H:%M:%S"]:
                    try:
                        incident_date = datetime.strptime(raw_date, fmt)
                        break
                    except ValueError:
                        pass
                
                if not incident_date:
                    log(f"Could not parse date format: '{raw_date}' in entry: {entry}", "ERROR")
                    skip_count_errors += 1
                    continue

                # <-- NEW: TIMEZONE CORRECTION -->
                # The CAD system provides America/Chicago (Central) time. 
                # We make the naive object aware, then convert it to UTC for the database.
                incident_date = incident_date.replace(tzinfo=ZoneInfo("America/Chicago")).astimezone(ZoneInfo("UTC")).replace(tzinfo=None)

                if incident_date < seven_days_ago: 
                    skip_count_old += 1
                    continue

                incident_lat, incident_lon, is_approx = geocode_address_arcgis(location, hq_lat, hq_lon)
                distance = calculate_distance(hq_lat, hq_lon, incident_lat, incident_lon)

                loc_hash = hashlib.md5(location.encode('utf-8')).hexdigest()[:6]
                inc_id = f"LR_{incident_date.strftime('%Y%m%d%H%M%S')}_{loc_hash}"

                if inc_id in seen_ids: 
                    continue
                seen_ids.add(inc_id)

                severity = "Low"
                if any(k in desc for k in ["ARSON", "EXPLOSIVE", "TERROR", "SABOTAGE", "SHOOTING"]): category, severity = "Critical Infrastructure Threat", "Critical"
                elif any(k in desc for k in ["THEFT", "BURGLARY", "ROBBERY", "BREAKING"]): category, severity = "Asset/Copper Theft Risk", "High"
                elif any(k in desc for k in ["ASSAULT", "BATTERY", "HOMICIDE", "WEAPON", "SHOTS"]): category, severity = "Violent Proximity Threat", "High"
                elif any(k in desc for k in ["VANDALISM", "TRESPASS", "PROWLER", "DISTURBANCE", "SUSPICIOUS"]): category, severity = "Perimeter Breach/Vandalism", "Medium"
                else: category, severity = "General Police Activity", "Low"

                display_title = f"{desc.title()}"
                if is_approx: display_title += " (Approx Loc)"

                batch.append(CrimeIncident(
                    id=inc_id, category=category, raw_title=display_title,
                    timestamp=incident_date, distance_miles=round(distance, 2),
                    severity=severity, lat=incident_lat, lon=incident_lon
                ))

                if len(batch) >= batch_size:
                    for item in batch:
                        existing = db.query(CrimeIncident).filter_by(id=item.id).first()
                        if not existing:
                            db.add(item)
                            added_count += 1
                    db.commit()
                    batch = []

            except Exception as loop_e: 
                log(f"Failed to process entry: {loop_e} | RAW: {entry}", "ERROR")
                skip_count_errors += 1
                continue

        # Commit remaining items
        if batch:
            for item in batch:
                existing = db.query(CrimeIncident).filter_by(id=item.id).first()
                if not existing:
                    db.add(item)
                    added_count += 1
            db.commit()

        # Garbage Collection for DB
        deleted_stale = db.query(CrimeIncident).filter(CrimeIncident.timestamp < seven_days_ago).delete()
        db.commit()
        
        log(f"Metrics: {added_count} new | {deleted_stale} purged | {skip_count_old} old | {skip_count_missing} no date | {skip_count_errors} errors.", "INFO")

        if added_count > 0:
            log("Triggering Perimeter Crime SMS Alerts dispatch...", "INFO")
            from src.services import dispatch_perimeter_crime_alerts
            dispatch_perimeter_crime_alerts()

if __name__ == "__main__":
    from src.database import init_db
    init_db()
    fetch_live_crimes()
