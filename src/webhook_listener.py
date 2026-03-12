import re
import json
from fastapi import FastAPI, Request, HTTPException, Depends
from datetime import datetime
from sqlalchemy.orm import Session
from src.database import SessionLocal, init_db, SolarWindsAlert, MonitoredLocation, NodeAlias, TimelineEvent
import uvicorn
from rapidfuzz import process, fuzz

init_db()
app = FastAPI(title="NOC Fusion Webhook Gateway")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def flatten_dict(d, parent_key='', sep='_'):
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        elif isinstance(v, list):
            items.append((new_key, str(v)))
        else:
            items.append((new_key, v))
    return dict(items)

def classify_device(text_corpus: str) -> str:
    text_corpus = text_corpus.lower()
    fingerprints = {
        'Firewall': ['fw', 'firewall', 'asa', 'palo', 'panw', 'fortigate', 'sophos', 'meraki mx'],
        'Router': ['rtr', 'router', 'asr', 'isr', 'csr', 'gateway', 'bgp', 'wan'],
        'Switch': ['sw', 'switch', 'nexus', 'catalyst', 'idf', 'mdf', 'vlan'],
        'Access Point': ['ap', 'access point', 'wap', 'wireless', 'wifi', '802.11'],
        'Virtual Machine': ['vm', 'esx', 'esxi', 'vcenter', 'hyper-v', 'instance', 'guest'],
        'Server': ['server', 'host', 'dc', 'domain controller', 'win', 'linux', 'ubuntu', 'baremetal'],
        'Camera/CCTV': ['cam', 'camera', 'cctv', 'axis', 'hikvision', 'avigilon', 'nvr', 'dvr'],
        'Access Control': ['reader', 'badge', 'door', 'access control', 'lenel', 'hid'],
        'Fire/Life Safety': ['fire alarm', 'panel', 'fap', 'smoke', 'strobe'],
        'SCADA/OT': ['scada', 'plc', 'rtu', 'hmi', 'modbus', 'dnp3', 'pump', 'valve', 'meter', 'rtu'],
        'Power/Env': ['ups', 'pdu', 'hvac', 'crac', 'temp', 'humidity', 'battery']
    }
    
    for device, keywords in fingerprints.items():
        if any(re.search(r'\b' + re.escape(kw) + r'\b', text_corpus) for kw in keywords):
            return device
    return "Network Node (Unknown)"

def classify_event_category(text_corpus: str) -> str:
    text_corpus = text_corpus.lower()
    categories = {
        'Hard Down': ['down', 'offline', 'unreachable', 'timeout', 'fatal', 'no response'],
        'Network Congestion': ['transmit', 'receive', 'bandwidth', 'utilization', 'bps', 'congestion', 'drops'],
        'Routing/Link': ['bgp', 'ospf', 'adjacency', 'flap', 'interface', 'link state', 'packet loss', 'latency', 'jitter'],
        'Compute Resource Exhaustion': ['cpu', 'memory', 'ram', 'disk', 'storage', 'inode', 'swap', 'leak'],
        'Hardware Fault': ['power supply', 'psu', 'fan', 'temperature', 'chassis', 'module', 'transceiver'],
        'Application/Service': ['process', 'service', 'crash', 'restart', 'database', 'sql', 'iis', 'apache']
    }
    
    for cat, keywords in categories.items():
        if any(kw in text_corpus for kw in keywords):
            return cat
    return "General Degradation"

def smart_extract(payload):
    flat = flatten_dict(payload)
    extracted = {
        "node_name": "Unknown",
        "ip_address": "Unknown",
        "severity": "Unknown",
        "event_type": "Unknown",
        "status": "Unknown",
        "is_resolution": False,
        "device_type": "Unknown",
        "event_category": "Unknown"
    }
    
    # Dump the absolute raw JSON to a string so we never miss nested keywords
    corpus = json.dumps(payload).lower()
    
    # 1. IP Extraction
    ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', corpus)
    if ip_match: extracted["ip_address"] = ip_match.group(0)
                
    # 2. Status / Resolution Sniffing
    sev_words = ['critical', 'high', 'medium', 'low', 'warning', 'fatal', 'down', 'offline']
    res_words = ['resolved', 'up', 'ok', 'clear', 'operational', 'recovered', 'restored']
    
    for k, v in flat.items():
        if isinstance(v, str):
            val_lower = v.lower()
            if val_lower in sev_words and extracted["severity"] == "Unknown":
                extracted["severity"] = v.capitalize()
                extracted["status"] = v.capitalize()
            elif val_lower in res_words:
                extracted["is_resolution"] = True
                extracted["status"] = "Resolved"
                extracted["severity"] = "Info"
            
    # 3. Fuzzy Key Matching for specific metrics
    def fuzzy_get(target_concepts):
        best_k, best_score = None, 0
        for k in flat.keys():
            score = max([fuzz.partial_ratio(k.lower(), c) for c in target_concepts])
            if score > 75 and score > best_score:
                best_score = score; best_k = k
        if best_k: return str(flat[best_k])
        return "Unknown"

    if extracted["node_name"] == "Unknown": extracted["node_name"] = fuzzy_get(['node', 'device', 'host', 'system', 'server'])
    if extracted["event_type"] == "Unknown": extracted["event_type"] = fuzzy_get(['event', 'alert', 'type', 'issue', 'description'])
    if extracted["severity"] == "Unknown" and not extracted["is_resolution"]: extracted["severity"] = fuzzy_get(['severity', 'level'])
    if extracted["status"] == "Unknown" and not extracted["is_resolution"]: extracted["status"] = fuzzy_get(['status', 'state'])
    
    # 4. Advanced Heuristics Classification
    # We feed the raw JSON corpus into the heuristic fingerprints
    analysis_string = f"{extracted['node_name']} {extracted['event_type']} {corpus}"
    extracted["device_type"] = classify_device(analysis_string)
    
    if not extracted["is_resolution"]:
        extracted["event_category"] = classify_event_category(analysis_string)
        
    return extracted

def resolve_location_mapping(node_name: str, db: Session):
    if not node_name or node_name == "Unknown": return "Unknown"
    clean_node = str(node_name).upper().replace("-RTR", "").replace("-SW", "").replace("-FW", "")
    
    existing_alias = db.query(NodeAlias).filter(NodeAlias.node_pattern == clean_node).first()
    if existing_alias: return existing_alias.mapped_location_name

    sites = [loc.name for loc in db.query(MonitoredLocation).all()]
    if not sites: 
        db.add(NodeAlias(node_pattern=clean_node, mapped_location_name="Unknown", confidence_score=0.0, is_verified=False))
        try: db.commit()
        except: db.rollback()
        return "Unknown"

    best_match = process.extractOne(clean_node, sites, scorer=fuzz.partial_ratio)
    if best_match:
        matched_site, confidence = best_match[0], best_match[1]
        if confidence > 60.0:
            db.add(NodeAlias(node_pattern=clean_node, mapped_location_name=matched_site, confidence_score=confidence, is_verified=False))
            try: db.commit()
            except: db.rollback()
            return matched_site
        else:
            db.add(NodeAlias(node_pattern=clean_node, mapped_location_name="Unknown", confidence_score=confidence, is_verified=False))
            try: db.commit()
            except: db.rollback()
            return "Unknown"
            
    return "Unknown"

@app.post("/webhook/solarwinds")
async def receive_alert(request: Request, db: Session = Depends(get_db)):
    try:
        raw_payload = await request.json()
        parsed = smart_extract(raw_payload)
        mapped_site = resolve_location_mapping(parsed["node_name"], db)

        if parsed["is_resolution"]:
            active_alerts = db.query(SolarWindsAlert).filter(
                SolarWindsAlert.node_name == parsed["node_name"],
                SolarWindsAlert.status != 'Resolved'
            ).all()
            
            if active_alerts:
                for a in active_alerts:
                    a.status = 'Resolved'
                    a.resolved_at = datetime.utcnow()
                db.add(TimelineEvent(source="Webhook", event_type="Resolution", message=f"🟢 {parsed['node_name']} ({parsed['device_type']}) recovered."))
            else:
                db.add(TimelineEvent(source="Webhook", event_type="Info", message=f"🔵 Received CLEAR for {parsed['node_name']}, but no active alert was found."))
            
            db.commit()
            return {"status": "success", "action": "auto-resolved"}

        new_alert = SolarWindsAlert(
            event_type=parsed["event_type"], severity=parsed["severity"], node_name=parsed["node_name"],
            ip_address=parsed["ip_address"], status=parsed["status"], details=str(raw_payload)[:1000],
            raw_payload=raw_payload, mapped_location=mapped_site, received_at=datetime.utcnow(),
            device_type=parsed["device_type"], event_category=parsed["event_category"]
        )
        db.add(new_alert)
        db.add(TimelineEvent(source="Webhook", event_type="Alert", message=f"🔴 {parsed['node_name']} | {parsed['device_type']} | {parsed['event_category']}"))
        db.commit()
        
        return {"status": "success", "action": "alert-created"}
        
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8100)