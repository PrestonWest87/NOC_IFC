import requests
import time
from datetime import datetime
from src.database import SessionLocal, RegionalOutage, BgpAnomaly, SystemConfig

def log_print(msg):
    print(f"[{datetime.utcnow().strftime('%H:%M:%S')}] [TELEMETRY] {msg}")

# Rough coordinate centers for major AR counties to render ODIN data geospatially
AR_COUNTY_COORDS = {
    "PULASKI": (34.76, -92.28), "SALINE": (34.64, -92.68), "GARLAND": (34.58, -93.18),
    "BENTON": (36.33, -94.25), "WASHINGTON": (35.97, -94.18), "FAULKNER": (35.15, -92.37),
    "CRAIGHEAD": (35.83, -90.70), "SEBASTIAN": (35.18, -94.27), "LONOKE": (34.75, -91.87)
}

def fetch_ornl_odin_power():
    """Pulls live county-level power outages in Arkansas via ODIN API."""
    session = SessionLocal()
    try:
        url = "https://ornl.opendatasoft.com/api/explore/v2.1/catalog/datasets/odin-real-time-outages-county/records?limit=100&refine=state%3AArkansas"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json().get("results", [])
            
            # Clear old ODIN data
            session.query(RegionalOutage).filter(RegionalOutage.provider == "ORNL ODIN").delete()
            
            for record in data:
                county = str(record.get("county", "")).upper()
                out_count = record.get("customers_out", 0)
                
                # Only log significant outages (e.g., > 100 people without power)
                if out_count > 100:
                    coords = AR_COUNTY_COORDS.get(county, (34.8, -92.2)) # Default to central AR
                    
                    # Calculate a dynamic radius based on how many people are offline
                    est_radius = 10.0 + (out_count / 1000) 
                    
                    new_outage = RegionalOutage(
                        outage_type="Power",
                        provider="ORNL ODIN",
                        description=f"{out_count} customers without power in {county} County.",
                        affected_area=f"{county} County, AR",
                        lat=coords[0],
                        lon=coords[1],
                        radius_km=est_radius,
                        is_resolved=False
                    )
                    session.add(new_outage)
            session.commit()
            log_print("✅ ODIN Power Grid sync complete.")
    except Exception as e:
        session.rollback()
        log_print(f"❌ ODIN fetch failed: {e}")
    finally:
        session.close()

def fetch_bgp_anomalies():
    """Checks for BGP route leaks or drops for configured ASNs via RIPE Stat."""
    session = SessionLocal()
    try:
        config = session.query(SystemConfig).first()
        if not config or not config.monitored_asns:
            return
            
        asns = [asn.strip() for asn in config.monitored_asns.split(",")]
        
        for asn in asns:
            # Strip the 'AS' prefix if present for the API call
            clean_asn = asn.replace("AS", "").replace("as", "")
            
            # Using RIPE Network Coordination Centre API
            url = f"https://stat.ripe.net/data/routing-status/data.json?resource={clean_asn}"
            resp = requests.get(url, timeout=10)
            
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                visibility = data.get("visibility", {}).get("v4", {})
                
                # If IPv4 routing visibility drops below a threshold, flag it
                risk_score = visibility.get("risk", 0)
                if risk_score > 0.5: # Arbitrary threshold for routing instability
                    exists = session.query(BgpAnomaly).filter_by(asn=asn, is_resolved=False).first()
                    if not exists:
                        anomaly = BgpAnomaly(
                            asn=asn,
                            event_type="BGP Visibility Drop",
                            description=f"Routing visibility for {asn} has degraded. Risk score: {risk_score}",
                            is_resolved=False
                        )
                        session.add(anomaly)
                        
        session.commit()
        log_print("✅ RIPE BGP Telemetry sync complete.")
    except Exception as e:
        session.rollback()
        log_print(f"❌ BGP fetch failed: {e}")
    finally:
        session.close()

def fetch_ioda_isp_outages():
    """Pulls live ISP outage alerts for Arkansas and Monitored ASNs via the IODA API."""
    session = SessionLocal()
    try:
        now_epoch = int(time.time())
        past_epoch = now_epoch - (12 * 3600) # Fetch alerts from the last 12 hours
        
        base_url = "https://api.ioda.inetintel.cc.gatech.edu/v2/outages/alerts"
        
        # Clear old IODA ISP data to prevent ghost alerts
        session.query(RegionalOutage).filter(RegionalOutage.provider == "IODA").delete()
        
        total_alerts = 0
        
        # 1. Fetch Arkansas Regional ISP Outages (ISO-3166-2: US-AR)
        resp_ar = requests.get(f"{base_url}?entityType=region&entityCode=US-AR&from={past_epoch}&until={now_epoch}", timeout=10)
        if resp_ar.status_code == 200:
            ar_alerts = resp_ar.json().get("data", [])
            for alert in ar_alerts:
                total_alerts += 1
                datasource = alert.get("datasource", "Unknown source")
                session.add(RegionalOutage(
                    outage_type="ISP",
                    provider="IODA",
                    description=f"IODA detected ISP degradation via {datasource} in Arkansas.",
                    affected_area="Arkansas, US",
                    lat=34.8, 
                    lon=-92.2,
                    radius_km=200.0, # Cover the state of AR so any node inside gets flagged
                    is_resolved=False
                ))

        # 2. Fetch specific monitored ASN outages
        config = session.query(SystemConfig).first()
        if config and config.monitored_asns:
            asns = [asn.strip().replace("AS", "").replace("as", "") for asn in config.monitored_asns.split(",")]
            for asn in asns:
                resp_asn = requests.get(f"{base_url}?entityType=asn&entityCode={asn}&from={past_epoch}&until={now_epoch}", timeout=10)
                if resp_asn.status_code == 200:
                    asn_alerts = resp_asn.json().get("data", [])
                    for alert in asn_alerts:
                        total_alerts += 1
                        datasource = alert.get("datasource", "Unknown source")
                        session.add(RegionalOutage(
                            outage_type="ISP",
                            provider="IODA",
                            description=f"IODA detected global routing drops via {datasource} for ASN {asn}.",
                            affected_area=f"Global ASN {asn}",
                            lat=34.8, # Drop a marker on the AR map to warn the NOC
                            lon=-92.2,
                            radius_km=300.0, 
                            is_resolved=False
                        ))
                        
        session.commit()
        log_print(f"✅ IODA ISP sync complete. Found {total_alerts} active alerts.")
    except Exception as e:
        session.rollback()
        log_print(f"❌ IODA ISP fetch failed: {e}")
    finally:
        session.close()

def run_telemetry_sync():
    # No longer passing a global session down the chain.
    # Functions independently manage their own connections.
    fetch_ornl_odin_power()
    fetch_bgp_anomalies()
    fetch_ioda_isp_outages() 
    log_print("✅ Multi-Domain Telemetry Sync Complete.")

if __name__ == "__main__":
    run_telemetry_sync()