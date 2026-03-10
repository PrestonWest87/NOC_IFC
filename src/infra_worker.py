import requests
from datetime import datetime, timedelta
from database import SessionLocal, RegionalHazard

def fetch_regional_hazards():
    print("🌪️ [INFRA WORKER] Fetching regional hazards...")
    session = SessionLocal()
    
    # NEW: Keep a temporary list of IDs seen in this specific run 
    # to prevent cross-state duplicates from crashing the commit.
    seen_in_cycle = set()
    
    states = ["AR"]
    added_count = 0
    
    try:
        for state in states:
            url = f"https://api.weather.gov/alerts/active?area={state}"
            headers = {"User-Agent": "NOC-Fusion-Center/1.0"}
            
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code != 200:
                continue
                
            data = response.json()
            features = data.get('features', [])
            
            for feature in features:
                props = feature.get('properties', {})
                hazard_id = props.get('id')
                
                # If we already grabbed this alert from a neighboring state, skip it
                if not hazard_id or hazard_id in seen_in_cycle:
                    continue
                    
                exists = session.query(RegionalHazard).filter_by(hazard_id=hazard_id).first()
                if not exists:
                    sent_str = props.get('sent', '')
                    try:
                        updated_at = datetime.strptime(sent_str[:19], '%Y-%m-%dT%H:%M:%S')
                    except ValueError:
                        updated_at = datetime.utcnow()
                        
                    new_hazard = RegionalHazard(
                        hazard_id=hazard_id,
                        hazard_type="Weather/Grid",
                        severity=props.get('severity', 'Unknown'),
                        title=props.get('event', 'Alert'),
                        description=props.get('headline', '') or props.get('description', ''),
                        location=props.get('areaDesc', state),
                        updated_at=updated_at
                    )
                    session.add(new_hazard)
                    seen_in_cycle.add(hazard_id) # Log it in the short-term memory
                    added_count += 1
                    
        # Self-cleaning: Purge alerts older than 48 hours
        cutoff = datetime.utcnow() - timedelta(days=2)
        purged = session.query(RegionalHazard).filter(RegionalHazard.updated_at < cutoff).delete()
        
        session.commit()
        print(f"✅ [INFRA WORKER] Added {added_count} new hazards. Purged {purged} expired alerts.")
        
    except Exception as e:
        print(f"❌ [INFRA WORKER] Failed to fetch hazard data: {e}")
        session.rollback()
    finally:
        session.close()

if __name__ == "__main__":
    fetch_regional_hazards()