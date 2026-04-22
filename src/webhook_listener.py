import re
import json
import uvicorn
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from datetime import datetime

from src.database import SessionLocal, init_db, SolarWindsAlert, TimelineEvent

init_db()
app = FastAPI(title="NOC Fusion Enterprise Gateway")

def log(msg):
    print(f"[{datetime.utcnow().strftime('%H:%M:%S')}] [WEBHOOK] {msg}")

def classify_device(text_corpus: str, node_type_hint: str = None) -> str:
    if node_type_hint and node_type_hint.lower() not in ["unknown", "", "none"]:
        return node_type_hint

    text_corpus = text_corpus.lower()
    fingerprints = {
        'TRANSPORT_CORE': ['fw', 'firewall', 'asa', 'palo', 'fortigate', 'meraki', 'rtr', 'router', 'asr', 'isr', 'gateway', 'sd-wan'],
        'NETWORK_ACCESS': ['sw', 'switch', 'nexus', 'catalyst', 'idf', 'mdf', 'ap', 'wireless', 'wlc'],
        'POWER_ENV': ['ups', 'pdu', 'ats', 'battery', 'generator', 'hvac', 'ac unit'],
        'COMPUTE_STORAGE': ['vm', 'host', 'server', 'storage', 'san', 'nas', 'esxi'],
        'SCADA_OT': ['rtu', 'plc', 'meter', 'substation', 'plant', 'relay', 'sel-']
    }
    
    for device_class, keywords in fingerprints.items():
        if any(kw in text_corpus for kw in keywords): 
            return device_class
    return "Network Node"

def smart_extract(payload: dict):
    nd = payload.get("Node_Details") or {}
    pm = payload.get("Performance_Metrics") or {}
    cp = payload.get("Custom_Properties_Universal") or {}

    extracted = {
        "node_name": nd.get("NodeName") or nd.get("SysName") or payload.get("entity_caption") or "Unknown",
        "ip_address": nd.get("IP_Address") or "Unknown",
        "severity": payload.get("severity") or cp.get("Alert_Level") or "Unknown",
        "event_type": payload.get("check") or payload.get("class") or payload.get("description") or "Unknown",
        "status": nd.get("StatusDescription") or payload.get("description") or "Unknown",
        "is_resolution": False,
        "device_type": nd.get("MachineType") or cp.get("Node_Type") or payload.get("entity_type") or "Unknown",
        "event_category": "General Degradation",
        "site_group": cp.get("Site") or cp.get("City") or "Unknown",
        "primary_comms": cp.get("Primary_Comms") or "Unknown", # NEW: Extracted for Fleet Correlation
        "secondary_comms": cp.get("Secondary_Comms") or "Unknown" # NEW: Extracted for redundancy checks
    }

    res_indicators = ['resolved', 'up', 'ok', 'clear', 'operational', 'recovered']
    status_lower = str(extracted["status"]).lower() + " " + str(payload.get("description", "")).lower()
    if any(word in status_lower for word in res_indicators):
        extracted["is_resolution"] = True
        extracted["status"] = "Resolved"

    # PRESERVED: Your original Regex fallback for missing IPs
    if extracted["ip_address"] == "Unknown":
        corpus = json.dumps(payload).lower()
        ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', corpus)
        if ip_match: extracted["ip_address"] = ip_match.group(0)

    # PRESERVED: Your original classifier logic
    extracted["device_type"] = classify_device(
        f"{extracted['node_name']} {extracted['event_type']} {extracted['device_type']}", 
        node_type_hint=extracted["device_type"]
    )
    return extracted
    
def process_payload_background(raw_payload: dict):
    with SessionLocal() as db:
        try:
            parsed = smart_extract(raw_payload)
            mapped_site = parsed["site_group"] # Direct mapping from payload

            if parsed["is_resolution"]:
                active = db.query(SolarWindsAlert).filter(
                    SolarWindsAlert.node_name == parsed["node_name"],
                    SolarWindsAlert.status != 'Resolved'
                ).all()
                for a in active:
                    a.status, a.resolved_at = 'Resolved', datetime.utcnow()
                
                db.add(TimelineEvent(source="Webhook", event_type="Resolution", message=f" {parsed['node_name']} recovered at {mapped_site}"))
                db.commit()
                log(f"[OK] Resolved Active Alert for {parsed['node_name']}")
                return

            new_alert = SolarWindsAlert(
                event_type=parsed["event_type"], severity=parsed["severity"],
                node_name=parsed["node_name"], ip_address=parsed["ip_address"],
                status=parsed["status"], details=raw_payload.get("description", "No description provided"),
                raw_payload=raw_payload, mapped_location=mapped_site,
                device_type=parsed["device_type"], is_correlated=False
            )
            db.add(new_alert)
            db.add(TimelineEvent(source="Webhook", event_type="Alert", message=f"[CRITICAL] Alert: {parsed['node_name']} ({parsed['device_type']}) at {mapped_site}"))
            
            db.commit()
            log(f"[ALERT] Processed New Alert: {parsed['node_name']} at {mapped_site}")
        except Exception as e:
            db.rollback()
            log(f"[ERROR] Background Processing Error: {e}")

@app.post("/webhook/solarwinds")
async def receive_alert(request: Request, background_tasks: BackgroundTasks):
    try:
        raw_payload = await request.json()
        background_tasks.add_task(process_payload_background, raw_payload)
        return {"status": "accepted", "message": "Payload queued for AI processing."}
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")
    except Exception as e:
        log(f"[ERROR] Gateway Rejection Error: {e}")
        raise HTTPException(status_code=500, detail="Internal Gateway Error")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8100)
