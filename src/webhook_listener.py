import re
import json
import logging
import hashlib
import hmac
import time
from collections import OrderedDict
import uvicorn
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from datetime import datetime

from src.core.db import SessionLocal, init_db
from src.models.schema import SolarWindsAlert, TimelineEvent
from src.core.config import settings

logger = logging.getLogger(__name__)

init_db()
app = FastAPI(title="NOC Fusion Enterprise Gateway")


@app.get("/health")
def health():
    return {"status": "ok"}
_seen_nonces: OrderedDict[str, float] = OrderedDict()


def _verify_webhook(request: Request, body: bytes) -> None:
    """Verify an opt-in SolarWinds HMAC signature and reject replayed requests."""
    secret = settings.webhook_hmac_secret
    if not secret:
        if not settings.allow_unsigned_webhooks:
            raise HTTPException(status_code=503, detail="Webhook signing is not configured")
        return
    signature = request.headers.get(settings.webhook_signature_header)
    if not signature:
        raise HTTPException(status_code=401, detail="Missing webhook signature")

    timestamp = request.headers.get(settings.webhook_timestamp_header)
    signed_values = [body]
    if timestamp:
        try:
            timestamp_value = float(timestamp)
        except ValueError as exc:
            raise HTTPException(status_code=401, detail="Invalid webhook timestamp") from exc
        if abs(time.time() - timestamp_value) > settings.webhook_replay_window_seconds:
            raise HTTPException(status_code=401, detail="Expired webhook timestamp")
        signed_values.insert(0, f"{timestamp}.".encode() + body)
    elif settings.webhook_replay_window_seconds > 0:
        raise HTTPException(status_code=401, detail="Missing webhook timestamp")

    supplied = signature.removeprefix("sha256=").strip()
    if not any(hmac.compare_digest(hmac.new(secret.encode(), value, hashlib.sha256).hexdigest(), supplied)
               for value in signed_values):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    if timestamp:
        now = time.time()
        for nonce, seen_at in list(_seen_nonces.items()):
            if now - seen_at > settings.webhook_replay_window_seconds:
                _seen_nonces.pop(nonce, None)
        nonce = f"{timestamp}:{supplied}"
        if nonce in _seen_nonces:
            raise HTTPException(status_code=409, detail="Replayed webhook request")
        _seen_nonces[nonce] = now
        while len(_seen_nonces) > 10000:
            _seen_nonces.popitem(last=False)

def log(msg):
    logger.info("[WEBHOOK] %s", msg)

def classify_device(text_corpus: str, node_type_hint: str = None) -> str:
    if node_type_hint and node_type_hint.lower() not in ["unknown", "", "none"]:
        return node_type_hint

    text_corpus = text_corpus.lower()
    fingerprints = {
        'PRIMARY_INTERNET': ['vsat', 'cellular', 'sd-wan', 'modem', 'radio', 'isp', 'internet'],
        'COMMS_EQUIPMENT': ['fw', 'firewall', 'asa', 'palo', 'fortigate', 'meraki', 'rtr', 'router', 'asr', 'isr', 'gateway', 'sw', 'switch', 'nexus', 'catalyst', 'idf', 'mdf', 'ap', 'wireless', 'wlc'],
        'POWER_SUPPLIES': ['ups', 'pdu', 'ats', 'battery', 'generator', 'hvac', 'ac unit', 'dc power', 'dc controller'],
        'COMPUTE': ['vm', 'host', 'server', 'storage', 'san', 'nas', 'esxi'],
        'SCADA': ['rtu', 'plc', 'meter', 'substation', 'plant', 'relay', 'sel-']
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
        "severity": payload.get("severity") or cp.get("Severity") or "Unknown",
        "alert_level": payload.get("Alert_Level") or cp.get("Alert_Level") or "Unknown",
        "event_type": payload.get("AlertName") or payload.get("check") or payload.get("class") or payload.get("description") or "Unknown",
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
    if any(re.search(r'\b' + re.escape(word) + r'\b', status_lower) for word in res_indicators):
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
    log(f"[PROCESSING] Starting background processing of webhook payload")
    with SessionLocal() as db:
        try:
            parsed = smart_extract(raw_payload)
            mapped_site = parsed["site_group"]
            log(f"[EXTRACT] node={parsed['node_name']} type={parsed['device_type']} site={mapped_site} severity={parsed['severity']} alert_level={parsed['alert_level']} event_type={parsed['event_type']} is_resolution={parsed['is_resolution']}")

            raw_payload["Normalized_Alert_Level"] = parsed["alert_level"]

            if parsed["is_resolution"]:
                active = db.query(SolarWindsAlert).filter(
                    SolarWindsAlert.node_name == parsed["node_name"],
                    SolarWindsAlert.status != 'Resolved'
                ).all()
                log(f"[RESOLUTION] Found {len(active)} active alerts for {parsed['node_name']}")
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
            logger.exception("webhook background processing error")

@app.post("/webhook/solarwinds")
async def receive_alert(request: Request, background_tasks: BackgroundTasks):
    try:
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > settings.webhook_max_body_bytes:
            raise HTTPException(status_code=413, detail="Webhook payload too large")
        body = await request.body()
        if len(body) > settings.webhook_max_body_bytes:
            raise HTTPException(status_code=413, detail="Webhook payload too large")
        _verify_webhook(request, body)
        raw_payload = json.loads(body)
        if not isinstance(raw_payload, dict) or not raw_payload:
            raise HTTPException(status_code=422, detail="Webhook payload must be a non-empty JSON object")
        if len(raw_payload) > 100:
            raise HTTPException(status_code=422, detail="Webhook payload has too many fields")
        log(f"[RECEIVED] Webhook payload received keys={list(raw_payload.keys())}")
        background_tasks.add_task(process_payload_background, raw_payload)
        return {"status": "accepted", "message": "Payload queued for AI processing."}
    except json.JSONDecodeError:
        log("[ERROR] Invalid JSON payload")
        raise HTTPException(status_code=400, detail="Invalid JSON payload")
    except Exception as e:
        if isinstance(e, HTTPException):
            raise
        log(f"[ERROR] Gateway Rejection Error: {e}")
        logger.exception("webhook gateway error")
        raise HTTPException(status_code=500, detail="Internal Gateway Error")

if __name__ == "__main__":
    from src.core.config import setup_logging
    setup_logging()
    uvicorn.run(app, host="0.0.0.0", port=8100)
