import ipaddress
import math
from datetime import datetime, timedelta
from src.database import SessionLocal, MonitoredLocation, SolarWindsAlert

class EnterpriseAIOpsEngine:
    # THE INFRASTRUCTURE ONTOLOGY
    ONTOLOGY = {
        "TRANSPORT_CORE": ["Router", "DWDM", "Firewall", "Service Provider", "VSAT Modem", "Radio", "SD-WAN"],
        "NETWORK_ACCESS": ["Switch", "Lanolinx-switch", "Fabric Interconnect", "Wireless Controller", "Access Point", "GarrettCom-6KL"],
        "COMPUTE_STORAGE": ["VM Host", "VM Server", "Physical Machine", "Storage", "Storage Switch", "NTP Server"],
        "POWER_ENV": ["UPS", "Generator", "DC Power Supply", "Data Center PDU", "Data Center A/C", "PDU", "HVAC"],
        "SCADA_OT": ["RTU", "NTEST RTU", "Sub Equipment", "Plant Equipment", "Meter Point 7403", "Meter Point 8650", "CAT Bank Meter", "I/O", "Member Equipment"],
        "FACILITIES_IOT": ["Access Control Panel", "Door Controller", "PACS", "Firealram", "IP Camera", "IP Phone", "Intercom"]
    }

    # ENTERPRISE DOMINANCE TIERS (Lower Number = Higher Authority)
    # Tier 1 failure implies all downstream Tiers are isolated.
    TIER_RANKING = {
        "POWER_ENV": 1,
        "TRANSPORT_CORE": 2,
        "NETWORK_ACCESS": 3,
        "COMPUTE_STORAGE": 4,
        "SCADA_OT": 5,
        "FACILITIES_IOT": 5,
        "UNKNOWN_DOMAIN": 6
    }

    def __init__(self, db_session):
        self.session = db_session

    def _get_domain(self, node_type):
        for domain, types in self.ONTOLOGY.items():
            if any(t.lower() in str(node_type).lower() for t in types):
                return domain
        return "UNKNOWN_DOMAIN"

    def _determine_patient_zero(self, alerts):
        """
        TOPOLOGICAL DOMINANCE ALGORITHM:
        Prioritizes Root Cause based on infrastructure tier rather than timestamp.
        """
        if not alerts: return None, []

        scored_alerts = []
        for alert in alerts:
            p = alert.raw_payload if isinstance(alert.raw_payload, dict) else {}
            cp = p.get('Custom_Properties_Universal') or {}
            node_type = cp.get('Node_Type') or alert.device_type or 'Unknown'
            domain = self._get_domain(node_type)
            
            # Base Tier Score (Tier 1 = 10000, Tier 5 = 2000)
            tier = self.TIER_RANKING.get(domain, 6)
            tier_score = (7 - tier) * 2000 

            # Severity Multiplier
            status = str(alert.status).lower()
            sev_score = 1000 if 'down' in status or 'offline' in status else 500

            # Time is only a tie-breaker (max 100 pts)
            # This ensures a Router alerting 2 minutes late still beats a Meter alerting now.
            final_score = tier_score + sev_score

            scored_alerts.append({
                "alert": alert, "score": final_score, 
                "domain": domain, "node_type": node_type, "tier": tier
            })

        scored_alerts.sort(key=lambda x: x['score'], reverse=True)
        return scored_alerts[0]['alert'], scored_alerts

    def identify_fleet_outages(self, incidents, threshold=5):
        """
        Detects "VSAT Storms" or Carrier outages across multiple sites.
        """
        provider_map = {}
        for site, data in incidents.items():
            comms = data['site_metadata'].get('primary_coms', 'Unknown')
            if comms not in provider_map: provider_map[comms] = []
            
            # Only count sites where the Transport Tier is the failure
            if any(sa['domain'] == "TRANSPORT_CORE" for sa in data['dependency_chain']):
                provider_map[comms].append(site)

        fleet_events = []
        for provider, sites in provider_map.items():
            if len(sites) >= threshold and provider != "Unknown":
                fleet_events.append({
                    "provider": provider,
                    "affected_sites": sites,
                    "event_type": "Regional Provider Outage",
                    "severity": "CRITICAL"
                })
        return fleet_events

    def calculate_root_cause(self, site_name, data, active_weather=[], active_cloud=[], active_bgp=[], fleet_events=[]):
        meta = data['site_metadata']
        p0 = data['patient_zero']
        p0_sa = next((sa for sa in data['dependency_chain'] if sa['alert'] == p0), None)
        p0_domain = p0_sa['domain'] if p0_sa else "UNKNOWN"
        
        evidence_log = []
        score = 0
        
        # 1. Check for Fleet-Wide Event
        for event in fleet_events:
            if site_name in event['affected_sites']:
                evidence_log.append(f"FLEET CORRELATION: Site is part of a massive {event['provider']} outage affecting {len(event['affected_sites'])} sites.")
                return f"Regional {event['provider']} Outage", 100, "P1 - CRITICAL", evidence_log, "Multi-Site Cascade", p0.node_name, "N/A"

        # 2. Topological Determinations
        if p0_domain == "POWER_ENV":
            cause = "Complete Site Power Failure"
            score = 95
            evidence_log.append(f"Structural Cause: {p0.node_name} (Tier 1 Power) failed, isolating all downstream equipment.")
        
        elif p0_domain == "TRANSPORT_CORE":
            cause = f"Site Isolation - {meta.get('primary_coms', 'Unknown')} Circuit Down"
            score = 90
            evidence_log.append(f"Structural Cause: {p0.node_name} (Tier 2 Core) failed. Communication path severed.")

        elif p0_domain == "SCADA_OT":
            cause = "Localized SCADA/Field Equipment Failure"
            score = 40
            evidence_log.append("Structural Cause: Field device alarming while Core Transport remains stable.")

        else:
            cause = f"Degradation originating at {p0.node_name}"
            score = 50

        priority = "P1 - CRITICAL" if score >= 80 else "P2 - HIGH" if score >= 50 else "P3 - MODERATE"
        return cause, score, priority, evidence_log, "Internal Topology", p0.node_name, "Simultaneous"

    def analyze_and_cluster(self, active_alerts):
        incidents = {}
        for alert in active_alerts:
            p = alert.raw_payload if isinstance(alert.raw_payload, dict) else {}
            cp = p.get('Custom_Properties_Universal') or {}
            site_name = cp.get('Site') or alert.mapped_location or 'Unknown'
            
            if site_name not in incidents:
                incidents[site_name] = {
                    'alerts': [], 'site_metadata': {
                        'primary_coms': cp.get('Primary_Comms') or 'Unknown',
                        'district': cp.get('District') or 'Unknown'
                    },
                    'domains_affected': set(), 'dependency_chain': []
                }
            incidents[site_name]['alerts'].append(alert)

        for site, cluster in incidents.items():
            pz_alert, scored_chain = self._determine_patient_zero(cluster['alerts'])
            cluster['patient_zero'] = pz_alert
            cluster['dependency_chain'] = scored_chain
            for sa in scored_chain: cluster['domains_affected'].add(sa['domain'])
                
        return incidents
