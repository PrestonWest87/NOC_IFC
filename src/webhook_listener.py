import re
import json
import uvicorn
from fastapi import FastAPI, Request, HTTPException, Depends, BackgroundTasks
from datetime import datetime
from sqlalchemy.orm import Session
from src.database import SessionLocal, init_db, SolarWindsAlert, MonitoredLocation, NodeAlias, TimelineEvent
from rapidfuzz import process, fuzz

init_db()
app = FastAPI(title="NOC Fusion Enterprise Gateway")

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

# --- HEURISTIC CLASSIFIERS (Maintained from your code) ---
def classify_device(text_corpus: str, node_type_hint: str = None) -> str:
    # If SolarWinds sent an explicit Node Type, use it!
    if node_type_hint and node_type_hint.lower() != "unknown":
        return node_type_hint

    text_corpus = text_corpus.lower()
    fingerprints = {
        'Firewall': ['fw', 'firewall', 'asa', 'palo', 'fortigate', 'meraki mx'],
        'Router': ['rtr', 'router', 'asr', 'isr', 'gateway', 'sd-wan'],
        'Switch': ['sw', 'switch', 'nexus', 'catalyst', 'idf', 'mdf'],
        'Power/UPS': ['ups', 'pdu', 'ats', 'battery', 'generator']
    }
    for device, keywords in fingerprints.items():
        if any(kw in text_corpus for kw in keywords): return device
    return "Network Node"

def smart_extract(payload: dict):
    """
    Upgraded extraction to prioritize the specific SolarWinds 
    JSON structure while maintaining fuzzy fallbacks.
    """
    # 1. Direct Mapping from your SolarWinds JSON structure
    # Use .get() with exact keys from your provided payload
    extracted = {
        "node_name": payload.get("DisplayName", "Unknown"),
        "ip_address": payload.get("IP Address", "Unknown"),
        "severity": payload.get("severity", "Unknown"),
        "event_type": payload.get("Alert Name", payload.get("check", "Unknown")),
        "status": payload.get("Status Description", "Unknown"),
        "is_resolution": False,
        "device_type": payload.get("Node Type", "Unknown"),
        "event_category": "General Degradation",
        "site_group": payload.get("Site", "Unknown")
    }

    # 2. Resolution Detection
    res_indicators = ['resolved', 'up', 'ok', 'clear', 'operational', 'recovered']
    status_lower = str(extracted["status"]).lower()
    if any(word in status_lower for word in res_indicators):
        extracted["is_resolution"] = True
        extracted["status"] = "Resolved"

    # 3. Fuzzy Fallbacks (Only if direct mapping failed)
    if extracted["node_name"] == "Unknown":
        # Fallback to your regex/fuzzy logic if DisplayName is missing
        corpus = json.dumps(payload).lower()
        ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', corpus)
        if ip_match: extracted["ip_address"] = ip_match.group(0)

    # 4. Refined Device Classification
    # Passes the 'Node Type' from your JSON as a hint
    extracted["device_type"] = classify_device(
        f"{extracted['node_name']} {extracted['event_type']}", 
        node_type_hint=extracted["device_type"]
    )

    return extracted

def resolve_location_mapping(node_name: str, sw_site_hint: str, db: Session):
    """
    Prioritizes the 'Site' custom property from SolarWinds.
    """
    # If SolarWinds explicitly tells us the Site, use it immediately
    if sw_site_hint and sw_site_hint != "Unknown":
        return sw_site_hint

    # Otherwise, fallback to your Fuzzy Logic mapper
    clean_node = str(node_name).upper().split('.')[0] # Remove FQDN
    existing = db.query(NodeAlias).filter(NodeAlias.node_pattern == clean_node).first()
    if existing: return existing.mapped_location_name

    sites = [loc.name for loc in db.query(MonitoredLocation).all()]
    if not sites: return "Unknown"

    best_match = process.extractOne(clean_node, sites, scorer=fuzz.partial_ratio)
    if best_match and best_match[1] > 70:
        db.add(NodeAlias(node_pattern=clean_node, mapped_location_name=best_match[0], confidence_score=best_match[1]))
        db.commit()
        return best_match[0]
    
    return "Unknown"
  
  
def resolve_location_mapping(node_name: str, sw_site_hint: str, db: Session):
    """
    Prioritizes the 'Site' custom property from SolarWinds for the map.
    """
    # 1. Primary: Use the explicit Site name from SolarWinds
    if sw_site_hint and sw_site_hint != "Unknown":
        # Ensure the site exists in our monitored_locations so it shows up on the map
        # If it doesn't exist, we'll still map it, but the map won't have coords yet.
        return sw_site_hint

    # 2. Secondary: Fallback to Fuzzy Logic for the node name
    clean_node = str(node_name).upper().split('.')[0] 
    existing = db.query(NodeAlias).filter(NodeAlias.node_pattern == clean_node).first()
    if existing: 
        return existing.mapped_location_name

    return "Unknown"

@app.post("/webhook/solarwinds")
async def receive_alert(request: Request, db: Session = Depends(get_db)):
    try:
        raw_payload = await request.json()
        parsed = smart_extract(raw_payload)
        
        # Resolve where this belongs (Priority: Site Property -> Fuzzy Match)
        mapped_site = resolve_location_mapping(parsed["node_name"], parsed["site_group"], db)

        # Handle Resolution
        if parsed["is_resolution"]:
            active = db.query(SolarWindsAlert).filter(
                SolarWindsAlert.node_name == parsed["node_name"],
                SolarWindsAlert.status != 'Resolved'
            ).all()
            for a in active:
                a.status = 'Resolved'
                a.resolved_at = datetime.utcnow()
            
            db.add(TimelineEvent(source="Webhook", event_type="Resolution", message=f"🟢 {parsed['node_name']} recovered at {mapped_site}"))
            db.commit()
            return {"status": "success", "action": "resolved"}

        # Create New Alert
        new_alert = SolarWindsAlert(
            event_type=parsed["event_type"],
            severity=parsed["severity"],
            node_name=parsed["node_name"],
            ip_address=parsed["ip_address"],
            status=parsed["status"],
            details=parsed.get("description", "No description provided"),
            raw_payload=raw_payload, # Critical: Stores the full JSON for the AIOps engine
            mapped_location=mapped_site,
            device_type=parsed["device_type"],
            is_correlated=False # Ensures it shows up for the AIOps engine
        )
        db.add(new_alert)
        db.add(TimelineEvent(source="Webhook", event_type="Alert", message=f"🔴 Alert: {parsed['node_name']} ({parsed['device_type']}) at {mapped_site}"))
        
        db.commit()
        return {"status": "success", "action": "alert-created"}
        
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8100)