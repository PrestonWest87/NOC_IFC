"""Seed deterministic SolarWinds-style AIOps test data.

Run inside the API/webhook image with:
    python scripts/seed_aiops_test_data.py --apply

The records are marked with the ``AIOTEST-`` prefix so they can be removed
without touching real alerts or monitored locations.
"""

from __future__ import annotations

import argparse
import random
from datetime import datetime, timezone

from src.core.db import SessionLocal
from src.models.schema import MonitoredLocation, SolarWindsAlert
from src.webhook_listener import process_payload_background


NODE_TYPES = [
    ("Switch", "P5"),
    ("UPS", "P2-High"),
    ("Physical Machine", "P2-High"),
    ("Router", "P1-High"),
    ("Firealram", "P2-High"),
    ("PACS", "P2-High"),
    ("VM Host", "P2-High"),
    ("Meter Point 8650", "P4"),
    ("Meter Point 7403", "P4"),
    ("Member Equipment", "P4"),
    ("RTU", "P1-Low"),
    ("PDU", "P4"),
    ("IP Phone", "P4"),
    ("VSAT Modem", "P6"),
    ("lanolinx-switch", "P4"),
    ("Firewall", "P2-High"),
    ("Service Provider", ""),
    ("VM Server", "P2-High"),
    ("IP Camera", "P6"),
    ("Door Controller", "P6"),
    ("Access Point", "P4"),
    ("GarrettCom-6KL", "P4"),
    ("Plant Equipment", "P2-High"),
    ("Storage", "P2-High"),
    ("Fabric Interconnect", "P2-High"),
    ("Wireless Controller", "P1-Low"),
    ("Radio", "P4"),
    ("Sub Equipment", "P4"),
    ("Intercom", "P6"),
    ("DC Power Supply", "P4"),
    ("CAT Bank Meter", "P4"),
    ("Data Center PDU", "P2-High"),
    ("NTP Server", "P2-High"),
    ("Data Center A/C", "P2-High"),
    ("Generator", "P1-Low"),
    ("Storage Switch", "P2-High"),
    ("I/O", "P1-High"),
    ("ZPE", "P1-Low"),
    ("NTEST RTU", "P1-Low"),
    ("Access Control Panel", "P2-High"),
]

ARKANSAS_CITIES = [
    "Little Rock", "Fort Smith", "Fayetteville", "Springdale", "Jonesboro",
    "Conway", "Rogers", "Pine Bluff", "Bentonville", "Hot Springs",
    "Benton", "Russellville", "Texarkana", "Sherwood", "Jacksonville",
    "Paragould", "Cabot", "Searcy", "Van Buren", "El Dorado",
]


def build_payload(site: str, city: str, index: int, node_type: str, alert_level: str, lat: float, lon: float) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    ip = f"10.77.{index // 250 + 1}.{index % 250 + 1}"
    severity = "Critical" if alert_level.startswith("P1") else "High" if alert_level.startswith("P2") else "Warning"
    return {
        "description": f"AIOTEST simulated {node_type} outage at {site}",
        "severity": severity,
        "source": f"AIOTEST-SWIS-{index:03d}",
        "alias": f"AIOTEST-{index:03d}",
        "check": "Node Down",
        "manager": "SolarWinds-Test",
        "manager_id": f"https://solarwinds.invalid/alerts/AIOTEST-{index:03d}",
        "class": "Node Down",
        "timestamp": now,
        "entity_caption": f"AIOTEST-{index:03d}-{node_type}",
        "entity_type": "Node",
        "Node_Details": {
            "NodeID": str(77000 + index),
            "IP_Address": ip,
            "NodeName": f"AIOTEST-{index:03d}-{node_type.replace(' ', '-')}",
            "SysName": f"AIOTEST-{index:03d}",
            "Vendor": "AIOTEST",
            "MachineType": node_type,
            "StatusDescription": "Down",
            "DetailsURL": f"https://solarwinds.invalid/nodes/{77000 + index}",
            "IOSImage": "AIOTEST-IMAGE",
            "IOSVersion": "AIOTEST-1.0",
            "LastBoot": now,
        },
        "Performance_Metrics": {
            "AvgResponseTime": "9999",
            "MinResponseTime": "9999",
            "MaxResponseTime": "9999",
            "PercentLoss": "100",
            "CPULoad": "92",
            "PercentMemoryUsed": "88",
            "PercentMemoryAvailable": "12",
            "CustomPollerLastPoll": now,
        },
        "Custom_Properties_Universal": {
            "Address": f"{100 + index} Test Operations Way, {city}, AR",
            "Alert_Level": alert_level,
            "CarrierName": "AIOTEST Carrier",
            "CircuitID": f"AIOTEST-CIRCUIT-{index:03d}",
            "City": city,
            "Co_Op": "AIOTEST Cooperative",
            "Comments_Node": "Synthetic test record; do not dispatch.",
            "Comments_Entity": "Synthetic test record; do not dispatch.",
            "Comms_Enclosure": "AIOTEST Cabinet",
            "ContactGroup": "AIOTEST NOC",
            "Contacts": "AIOTEST Test Contact",
            "Department": "AIOTEST Operations",
            "District": "AIOTEST Central",
            "Interface_Type": "Ethernet",
            "Jurisdiction": "Arkansas",
            "LocationType": "Field Office",
            "Media": "AIOTEST",
            "Monitor_Status": "True",
            "Node_Type": node_type,
            "P_Comm_Provider": "AIOTEST Carrier",
            "S_Comm_Provider": "AIOTEST Backup",
            "Port_Channel": "AIOTEST-PORT",
            "Port_Channel_Members": "AIOTEST-MEMBERS",
            "Power_Market": "AIOTEST Market",
            "Primary_Comms": "AIOTEST Carrier",
            "Secondary_Comms": "AIOTEST Backup",
            "Priority": alert_level,
            "PseudoTies": "False",
            "SDWAN": "False",
            "Site": site,
            "Tunnel_Type": "AIOTEST",
        },
    }


def main(apply: bool) -> None:
    rng = random.Random(20260814)
    sites = []
    for index, city in enumerate(ARKANSAS_CITIES, 1):
        sites.append({
            "name": f"AIOTEST Site {index:02d}",
            "city": city,
            "lat": round(rng.uniform(33.004, 36.499), 6),
            "lon": round(rng.uniform(-94.617, -89.644), 6),
        })

    if not apply:
        print(f"Would create {len(sites)} sites and {len(NODE_TYPES)} alerts. Re-run with --apply.")
        return

    with SessionLocal() as db:
        old_site_names = {site["name"] for site in sites}
        db.query(SolarWindsAlert).filter(SolarWindsAlert.node_name.like("AIOTEST-%")).delete(synchronize_session=False)
        db.query(MonitoredLocation).filter(MonitoredLocation.name.in_(old_site_names)).delete(synchronize_session=False)
        for site in sites:
            db.add(MonitoredLocation(
                name=site["name"], lat=site["lat"], lon=site["lon"],
                loc_type="Field Office", district="AIOTEST Central", priority="P3-Moderate",
            ))
        db.commit()

    for index, (node_type, alert_level) in enumerate(NODE_TYPES, 1):
        site = sites[(index - 1) % len(sites)]
        process_payload_background(build_payload(site["name"], site["city"], index, node_type, alert_level, site["lat"], site["lon"]))

    print(f"Seeded {len(sites)} Arkansas sites and {len(NODE_TYPES)} normalized SolarWinds test alerts.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="Write synthetic records to the database")
    main(parser.parse_args().apply)
