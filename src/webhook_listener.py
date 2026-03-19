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

# --- HEURISTIC CLASSIFIERS ---
def classify_device(text_corpus: str, node_type_hint: str = None) -> str:
    if node_type_hint and node_type_hint.lower() not in ["unknown", "", "none"]:
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
    Safely navigates deeply nested SolarWinds JSON payloads with cascading fallbacks.
    """
    # Isolate the nested dictionaries safely
    nd = payload.get("Node_Details") or {}
    pm = payload.get("Performance_Metrics") or {}
    cp = payload.get("Custom_Properties_Universal") or {}

    # 1. Cascading Extraction (Safely falls back if a field is empty)
    extracted = {
        "node_name": nd.get("NodeName") or nd.get("SysName") or payload.get("entity_caption") or "Unknown",
        "ip_address": nd.get("IP_Address") or "Unknown",
        "severity": payload.get("severity") or cp.get("Alert_Level") or "Unknown",
        "event_type": payload.get("check") or payload.get("class") or payload.get("description") or "Unknown",
        "status": nd.get("StatusDescription") or payload.get("description") or "Unknown",
        "is_resolution": False,
        "device_type": nd.get("MachineType") or cp.get("Node_Type") or payload.get("entity_type") or "Unknown",
        "event_category": "General Degradation",
        "site_group": cp.get("Site") or cp.get("City") or "Unknown"
    }

    # 2. Resolution Detection
    res_indicators = ['resolved', 'up', 'ok', 'clear', 'operational', 'recovered']
    status_lower = str(extracted["status"]).lower() + " " + str(payload.get("description", "")).lower()
    if any(word in status_lower for word in res_indicators):
        extracted["is_resolution"] = True
        extracted["status"] = "Resolved"

    # 3. Fuzzy Fallbacks (Only if IP is completely missing)
    if extracted["ip_address"] == "Unknown":
        corpus = json.dumps(payload).lower()
        ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', corpus)
        if ip_match: extracted["ip_address"] = ip_match.group(0)

    # 4. Refined Device Classification
    extracted["device_type"] = classify_device(
        f"{extracted['node_name']} {extracted['event_type']}", 
        node_type_hint=extracted["device_type"]
    )

    return extracted

def resolve_location_mapping(node_name: str, sw_site_hint: str, db: Session):
    """
    Prioritizes the 'Site' custom property from SolarWinds for the map.
    """
    # 1. Primary: Use the explicit Site name from SolarWinds
    if sw_site_hint and sw_site_hint.lower() not in ["unknown", "", "none"]:
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

        print("\n" + "="*50)
        print(f"?? INCOMING SOLARWINDS PAYLOAD:\n{json.dumps(raw_payload, indent=4)}")
        print("="*50 + "\n")
         

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
            
            db.add(TimelineEvent(source="Webhook", event_type="Resolution", message=f"?? {parsed['node_name']} recovered at {mapped_site}"))
            db.commit()
            return {"status": "success", "action": "resolved"}

        # Create New Alert
        new_alert = SolarWindsAlert(
            event_type=parsed["event_type"],
            severity=parsed["severity"],
            node_name=parsed["node_name"],
            ip_address=parsed["ip_address"],
            status=parsed["status"],
            details=raw_payload.get("description", "No description provided"),
            raw_payload=raw_payload, # Critical: Stores the full nested JSON for the AIOps engine
            mapped_location=mapped_site,
            device_type=parsed["device_type"],
            is_correlated=False
        )
        db.add(new_alert)
        db.add(TimelineEvent(source="Webhook", event_type="Alert", message=f"?? Alert: {parsed['node_name']} ({parsed['device_type']}) at {mapped_site}"))
        
        db.commit()
        return {"status": "success", "action": "alert-created"}
        
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8100)
