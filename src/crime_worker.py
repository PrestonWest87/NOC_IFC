import os
import json
import feedparser
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

CRIME_CACHE_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "crime_cache.json")

def fetch_live_crimes():
    """Fetches live 48-hour crime data via SpotCrime RSS centered on 1 Cooperative Way, Little Rock, AR."""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🚨 CRIME WORKER: Polling live SpotCrime RSS...")
    os.makedirs(os.path.dirname(CRIME_CACHE_FILE), exist_ok=True)
    
    # Coordinates for 1 Cooperative Way, Little Rock, AR
    lat, lon = "34.6836", "-92.3350"
    rss_url = f"https://spotcrime.com/crimes.rss?lat={lat}&lon={lon}"
    
    try:
        feed = feedparser.parse(rss_url)
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(hours=48)
        
        crimes = []
        
        for entry in feed.entries:
            try:
                # Parse RSS pubDate
                pub_date = parsedate_to_datetime(entry.published)
                if pub_date < cutoff:
                    continue # Skip older than 48 hours
                    
                title = entry.title.upper()
                
                # Categorize based on grid-threat relevance
                severity = "Low"
                if any(k in title for k in ["THEFT", "BURGLARY", "ROBBERY"]):
                    category = "Theft / Possible Asset Loss"
                    severity = "High"
                elif any(k in title for k in ["VANDALISM", "ARREST"]):
                    category = "Perimeter Vandalism / Trespassing"
                    severity = "Medium"
                elif any(k in title for k in ["SHOOTING", "ASSAULT", "WEAPON"]):
                    category = "Violent Incident near Asset"
                    severity = "High"
                else:
                    category = "General Incident"
                
                # Spotcrime stores lat/lon in the geo:lat / geo:long tags if available, or link
                lat_str = entry.get('geo_lat', lat)
                lon_str = entry.get('geo_long', lon)
                
                crimes.append({
                    "id": entry.get('guid', entry.link),
                    "category": category,
                    "raw_title": entry.title,
                    "timestamp": pub_date.strftime("%Y-%m-%d %H:%M:%S %Z"),
                    "lat": float(lat_str),
                    "lon": float(lon_str),
                    "severity": severity,
                    "link": entry.link
                })
            except Exception as e:
                continue

        with open(CRIME_CACHE_FILE, "w") as f:
            json.dump(crimes, f, indent=4)
            
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ✅ CRIME WORKER: {len(crimes)} incidents logged in last 48 hours near HQ.")
    except Exception as e:
        print(f"🚨 CRIME WORKER FAILED: {e}")

if __name__ == "__main__":
    fetch_live_crimes()
