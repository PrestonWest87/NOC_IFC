import ipaddress
import math
import re
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import List, Dict, Any, Tuple, Optional
import pandas as pd
from src.database import SessionLocal, MonitoredLocation, SolarWindsAlert

# Pre-compile regex for performance during major cascade events
ALERT_LEVEL_REGEX = re.compile(r'\d+')

@dataclass
class RootCauseResult:
    cause: str = "Under Investigation"
    score: int = 0
    priority: str = "P3 - MODERATE (SLA: 4 Hours)"
    evidence_log: List[str] = field(default_factory=list)
    blast_radius: str = "Unknown"
    patient_zero_node: str = "Unknown"
    cascade_time: str = "N/A"

class EnterpriseAIOpsEngine:
    # UNIFIED ONTOLOGY: Sorted and categorized to prevent substring collisions
    ONTOLOGY = {
        "PRIMARY_INTERNET": [
            "vsat modem", "cellular", "radio", "sd-wan", "modem", "isp", "service provider", "vsat"
        ],
        "FIBER_MONITORING": [
            "ntest rtu"
        ],
        "COMMS_EQUIPMENT": [
            "router", "switch", "firewall", "lanolinx-switch", "fabric interconnect", 
            "nexus", "catalyst", "wlc", "access point", "wireless controller", 
            "dwdm", "storage switch", "garrettcom-6kl", "zpe"
        ],
        "POWER_SUPPLIES": [
            "ups", "generator", "dc power supply", "pdu", "data center pdu", 
            "battery monitor", "pds", "dc controller", "ats"
        ],
        "SCADA": [
            "rtu", "sub equipment", "plant equipment", "meter point", "meter point 7403", 
            "meter point 8650", "i/o", "member equipment", "scada", "relay", "sel-", 
            "plc", "cat bank meter"
        ],
        "COMPUTE": [
            "vm host", "vm server", "physical machine", "storage", "esxi", "san", "nas", "ntp server"
        ],
        "FACILITIES": [
            "access control panel", "door controller", "ip camera", "hvac", "ac unit", 
            "data center a/c", "firealram", "fire alarm", "intercom", "ip phone", "pacs"
        ]
    }

    # ENTERPRISE DOMINANCE TIERS (Lower Number = Higher Authority)
    TIER_RANKING = {
        "POWER_SUPPLIES": 1,
        "PRIMARY_INTERNET": 2,
        "FIBER_MONITORING": 3,
        "COMMS_EQUIPMENT": 4,
        "COMPUTE": 5,
        "SCADA": 6,
        "FACILITIES": 7,
        "UNKNOWN_DOMAIN": 8
    }

    def __init__(self, db_session):
        self.session = db_session
        self._location_cache = {} # Caches DB queries for locations
        
        # Flatten ontology and sort keys by length (longest first)
        # This PREVENTS substring collisions! 
        flat_map = {
            kw: domain for domain, keywords in self.ONTOLOGY.items() for kw in keywords
        }
        self._keyword_map = dict(sorted(flat_map.items(), key=lambda item: len(item[0]), reverse=True))

    def _get_domain(self, node_type: str, node_name: str = "", primary_comms: str = "") -> str:
        """Streamlined O(1) keyword lookup for domain classification."""
        node_str = f"{node_type} {node_name}".lower()
        
        # 1. Check strict primary internet overrides
        if "internet" in node_str or (primary_comms and primary_comms.lower() in node_str):
            if any(t in node_str for t in ["router", "switch", "firewall", "gateway"]):
                return "PRIMARY_INTERNET"

        # 2. Fast multi-keyword search against the length-sorted flattened map
        for keyword, domain in self._keyword_map.items():
            if keyword in node_str:
                return domain
                
        return "UNKNOWN_DOMAIN"

    def _determine_patient_zero(self, alerts: List[SolarWindsAlert]) -> Tuple[Optional[SolarWindsAlert], List[Dict]]:
        if not alerts: return None, []

        scored_alerts = []
        valid_times = [a.received_at for a in alerts if a.received_at]
        earliest_time = min(valid_times) if valid_times else datetime.utcnow()

        for alert in alerts:
            p = alert.raw_payload if isinstance(alert.raw_payload, dict) else {}
            cp = p.get('Custom_Properties_Universal', {})
            pm = p.get('Performance_Metrics', {})

            # Trust the webhook's device_type if it did the work, otherwise fallback
            node_type = alert.device_type if alert.device_type != "Unknown" else cp.get('Node_Type', '')
            domain = self._get_domain(node_type, alert.node_name or "", cp.get('Primary_Comms', ''))

            # Topology base score
            tier = self.TIER_RANKING.get(domain, 8)
            topo_score = (9 - tier) * 2000 

            # Severity calculation
            status = str(alert.status).lower()
            event_cat = str(alert.event_category).lower()
            loss = float(str(pm.get('PercentLoss', 0)).replace('%', '')) if pm.get('PercentLoss') else 0.0

            sev_score = 0
            if 'down' in status or loss >= 90 or 'offline' in event_cat: 
                sev_score = 1000
            elif 'critical' in status or loss > 50: 
                sev_score = 500
            elif 'warning' in status: 
                sev_score = 100

            # Time penalty (caps at 200 seconds to keep topology dominant)
            time_offset = (alert.received_at - earliest_time).total_seconds() if alert.received_at else 0
            time_penalty = min(time_offset, 200)

            scored_alerts.append({
                "alert": alert, 
                "score": topo_score + sev_score - time_penalty, 
                "domain": domain, 
                "severity": sev_score
            })

        scored_alerts.sort(key=lambda x: x['score'], reverse=True)
        return scored_alerts[0]['alert'], scored_alerts

    def identify_fleet_outages(self, incidents: Dict, threshold: int = 5) -> List[Dict]:
        """Detects Carrier outages across multiple sites in a single pass."""
        provider_map = {}
        for site, data in incidents.items():
            comms = data['site_metadata'].get('primary_coms', 'Unknown')
            if comms == 'Unknown': continue
            
            # Only map if core transport is affected
            if any(sa['domain'] in ["PRIMARY_INTERNET", "COMMS_EQUIPMENT"] for sa in data['dependency_chain']):
                provider_map.setdefault(comms, []).append(site)

        return [
            {
                "provider": provider, 
                "affected_sites": sites,
                "event_type": "Regional Provider Outage", 
                "severity": "CRITICAL"
            }
            for provider, sites in provider_map.items() if len(sites) >= threshold
        ]

    def generate_chronic_insights(self):
        """
        Analyzes historical SolarWinds alerts to identify chronic degradation.
        Returns:
            f (DataFrame): Top Offending Nodes
            v (DataFrame): Infrastructure Hotspots
            r (list): AI Predictive Maintenance Forecast
        """
        cutoff = datetime.utcnow() - timedelta(days=60)
        alerts = self.session.query(SolarWindsAlert).filter(SolarWindsAlert.received_at >= cutoff).all()
        
        if not alerts:
            return None, None, None
            
        data = []
        for a in alerts:
            p = a.raw_payload if isinstance(a.raw_payload, dict) else {}
            cp = p.get('Custom_Properties_Universal') or {}
            site = cp.get('Site') or a.mapped_location or 'Unknown'
            
            # Skip resolved messages to focus strictly on degradation events
            if 'resolved' in str(a.status).lower(): continue
            
            data.append({
                'node_name': a.node_name,
                'device_type': a.device_type,
                'site': site
            })
            
        df = pd.DataFrame(data)
        if df.empty:
            return None, None, None
            
        # 1. Calculate "f": Top Offending Nodes (Flapping/Failing Equipment)
        node_counts = df['node_name'].value_counts().reset_index()
        node_counts.columns = ['Node Name', 'Total Incidents (60 Days)']
        
        node_meta = df[['node_name', 'device_type', 'site']].drop_duplicates(subset=['node_name'])
        f = pd.merge(node_counts, node_meta, left_on='Node Name', right_on='node_name').drop(columns=['node_name'])
        f.rename(columns={'device_type': 'Device Type', 'site': 'Site'}, inplace=True)
        f = f.head(15) 
        
        # 2. Calculate "v": Infrastructure Hotspots (Sites with the most issues)
        site_counts = df[df['site'] != 'Unknown']['site'].value_counts().reset_index()
        site_counts.columns = ['Site', 'Total Incidents (60 Days)']
        v = site_counts.head(10)
        
        # 3. Calculate "r": AI Predictive Maintenance Forecast
        r = []
        if not f.empty:
            top_node = f.iloc[0]['Node Name']
            top_node_count = f.iloc[0]['Total Incidents (60 Days)']
            if top_node_count > 5:
                r.append(f"[CRITICAL] **CRITICAL FLAP DETECTED:** Node `{top_node}` is exhibiting severe chronic instability with {top_node_count} logged incidents this week. Recommend immediate hardware diagnostic or circuit test.")
        
        if not v.empty:
            top_site = v.iloc[0]['Site']
            top_site_count = v.iloc[0]['Total Incidents (60 Days)']
            if top_site_count > 15:
                r.append(f"[HIGH] **REGIONAL DEGRADATION:** The `{top_site}` facility is a current infrastructure hotspot. Recommend dispatching field tech to review local power conditioning and physical transport handoffs.")
                
        if not r:
            r.append("[OK] Telemetry indicates normal operational limits. Devices are stable and no immediate predictive maintenance is required.")
            
        return f, v, r

    def _preload_locations(self, site_names: set):
        """Batch query locations to prevent N+1 database queries during cascades."""
        missing = [s for s in site_names if s not in self._location_cache]
        if missing:
            records = self.session.query(MonitoredLocation).filter(MonitoredLocation.name.in_(missing)).all()
            for r in records:
                self._location_cache[r.name] = r
            
            # Cache missing sites as None so we don't query them again
            for site in missing:
                if site not in self._location_cache:
                    self._location_cache[site] = None

    def calculate_root_cause(self, site_name: str, data: Dict, active_weather: List, active_cloud: List, active_bgp: List, fleet_events: List = None) -> Tuple:
        result = RootCauseResult()
        fleet_events = fleet_events or []
        meta = data.get('site_metadata', {})
        domains = data.get('domains_affected', set())
        
        # Secure metric averages
        avg_loss = sum(data['avg_loss']) / len(data['avg_loss']) if data['avg_loss'] else 0.0
        
        p0 = data.get('patient_zero')
        if not p0:
            # Fallback exact tuple to guarantee unpacking safety
            return ("Indeterminate Failure", 0, "P3 - MODERATE (SLA: 4 Hours)", [], "Unknown", "Unknown", "N/A")
            
        result.patient_zero_node = p0.node_name
        p0_domain = next((sa['domain'] for sa in data.get('dependency_chain', []) if sa['alert'] == p0), "UNKNOWN")
        
        # 1. Cascade Logic
        if len(domains) > 1:
            result.score += 20
            result.evidence_log.append(f"Dependency Cascade: Primary failure in [{p0_domain}] triggered isolation of {len(data['alerts']) - 1} downstream devices.")

        # 2. Fleet Correlation (O(1) lookup)
        fleet_hit = next((event for event in fleet_events if site_name in event['affected_sites']), None)
        if fleet_hit:
            result.cause = f"Regional Carrier Outage ({fleet_hit['provider']})"
            result.score += 100
            result.evidence_log.append(f"Fleet Correlation: Site caught in {fleet_hit['provider']} outage affecting {len(fleet_hit['affected_sites'])} sites.")
        
        # 3. Cloud/Upstream Correlation
        elif active_cloud:
            for alert in data['alerts']:
                payload_str = str(alert.raw_payload).lower() if alert.raw_payload else ""
                for c in active_cloud:
                    if c.provider.lower() in alert.node_name.lower() or c.provider.lower() in payload_str:
                        result.cause = f"Upstream Cloud Failure ({c.provider})"
                        result.score += 85
                        result.evidence_log.append(f"Cloud Correlation: Node relies on {c.provider}, which has a known outage.")
                        break
                if result.score >= 85: break

        # 4. BGP Routing Correlation
        elif active_bgp and ("PRIMARY_INTERNET" in domains or "COMMS_EQUIPMENT" in domains):
            primary = str(meta.get('primary_coms', ''))
            secondary = str(meta.get('secondary_coms', ''))
            for b in active_bgp:
                if b.asn in primary or b.asn in secondary:
                    result.cause = f"Carrier Routing Anomaly (BGP Event on {b.asn})"
                    result.score += 75
                    result.evidence_log.append(f"BGP Correlation: Transport provider {b.asn} is experiencing a routing anomaly.")
                    break

        # 5. Topological Heuristics
        if result.cause == "Under Investigation":
            if p0_domain == "POWER_SUPPLIES":
                result.cause = "Catastrophic Facilities/Power Failure causing complete site isolation."
                result.score += 60
                result.evidence_log.append(f"Structural Cause: Foundational Power/Environmental node ({p0.node_name}) failed.")
            elif p0_domain in ["PRIMARY_INTERNET", "COMMS_EQUIPMENT"]:
                if avg_loss >= 80 or 'down' in str(p0.status).lower():
                    result.cause = f"Site Isolation. Hard down on {meta.get('primary_coms', 'Unknown')} transport tier."
                    result.score += 50
                    result.evidence_log.append(f"Structural Cause: Core transport/comms equipment ({p0.node_name}) severed communication path.")
                else:
                    result.cause = f"Severe Transport Congestion ({avg_loss:.1f}% Packet Loss)."
            elif p0_domain in ["SCADA", "RTU"]:
                result.cause = "Isolated OT/SCADA Telemetry Failure."
                result.score += 30
                result.evidence_log.append(f"Structural Cause: Field equipment ({p0.node_name}) alarming while Core IT network is stable.")
            else:
                result.cause = f"Generalized Infrastructure Degradation originating at {p0.node_name}."

        # 6. Geospatial / Weather Context
        site_record = self._location_cache.get(site_name)
        if site_record:
            if site_record.under_maintenance and site_record.maintenance_etr:
                if datetime.utcnow().date() > site_record.maintenance_etr.date():
                    site_record.under_maintenance = False
                    site_record.maintenance_etr = None
                    site_record.maintenance_reason = None
                    self.session.commit()
                    result.evidence_log.append("Maintenance Override: Expired maintenance window was automatically cleared.")

            if site_record.lat and site_record.lon:
                for h in active_weather:
                    # Bounding Box pre-filter (fast) before Haversine (slow)
                    if hasattr(h, 'lat') and hasattr(h, 'lon'):
                        lat_diff = abs(site_record.lat - h.lat)
                        lon_diff = abs(site_record.lon - h.lon)
                        if lat_diff > 2.0 or lon_diff > 2.0: # Approx 138 miles, skip math if too far
                            continue
                            
                        # Haversine Math
                        R = 3958.8 
                        lat1, lon1, lat2, lon2 = map(math.radians, [site_record.lat, site_record.lon, h.lat, h.lon])
                        a = math.sin((lat2 - lat1)/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1)/2)**2
                        distance_miles = R * (2 * math.asin(math.sqrt(a)))
                        hazard_radius = getattr(h, 'radius_km', 24.1) * 0.621371 
                        
                        if distance_miles <= hazard_radius:
                            result.score += 55
                            result.evidence_log.append(f"Geospatial Correlation: Site is {distance_miles:.1f} miles from {h.hazard_type} epicenter.")
                            if p0_domain in ["POWER_SUPPLIES", "PRIMARY_INTERNET"]: 
                                result.cause = f"Direct Kinetic Impact: Severe Weather ({h.hazard_type}) caused infrastructure failure."
                            break

        # 7. SLA and Policy Overrides
        max_level = data.get('max_alert_level', 3)
        if max_level == 1:
            result.score += 50
            result.evidence_log.append("Policy Override: Native Alert Level 1 detected.")

        sla_map = {
            1: ("P1 - CRITICAL", "15 Minutes"),
            2: ("P2 - HIGH", "1 Hour"),
            3: ("P3 - MODERATE", "4 Hours"),
            4: ("P4 - LOW", "24 Hours"),
            5: ("P5 - PLANNING", "Best Effort")
        }
        
        base_priority, sla_time = sla_map.get(max_level, ("P3 - MODERATE", "4 Hours"))
        result.priority = f"{base_priority} (SLA: {sla_time})"
        result.score = min(result.score, 100)

        # 8. Cascade Timing
        latest = data.get('latest_alert')
        if latest and p0 and latest.received_at and p0.received_at:
            cascade_sec = int((latest.received_at - p0.received_at).total_seconds())
            result.cascade_time = f"{cascade_sec}s" if cascade_sec > 0 else "Simultaneous"

        # 9. Subnet Blast Radius Integration
        if hasattr(self, '_analyze_subnets'):
            result.blast_radius = self._analyze_subnets(data.get('ips', []))

        # --- PRODUCTION SAFETY OVERRIDE ---
        # Packs the dataclass state back into the strict 7-item tuple format required by 
        # external files (like telemetry_worker.py) to prevent sequence unpacking errors.
        return (
            result.cause, 
            result.score, 
            result.priority, 
            result.evidence_log, 
            result.blast_radius, 
            result.patient_zero_node, 
            result.cascade_time
        )

    def analyze_and_cluster(self, active_alerts: List[SolarWindsAlert]) -> Dict:
        incidents = {}
        
        # Extract unique site names and pre-load them in a single DB query
        site_names = {
            (a.raw_payload or {}).get('Custom_Properties_Universal', {}).get('Site') or a.mapped_location or 'Unknown'
            for a in active_alerts
        }
        self._preload_locations(site_names)

        for alert in active_alerts:
            p = alert.raw_payload if isinstance(alert.raw_payload, dict) else {}
            cp = p.get('Custom_Properties_Universal', {})
            pm = p.get('Performance_Metrics', {})
            site_name = cp.get('Site') or alert.mapped_location or 'Unknown'
            
            # Initialize Cluster
            if site_name not in incidents:
                incidents[site_name] = {
                    'alerts': [], 
                    'site_metadata': {
                        'primary_coms': cp.get('Primary_Comms', 'Unknown'),
                        'secondary_coms': cp.get('Secondary_Comms', 'Unknown'),
                        'district': cp.get('District', 'Unknown')
                    },
                    'domains_affected': set(), 
                    'dependency_chain': [],
                    'avg_loss': [],
                    'avg_cpu': [],
                    'ips': [],
                    'max_alert_level': 99,
                    'latest_alert': alert
                }
            
            cluster = incidents[site_name]
            cluster['alerts'].append(alert)
            
            # Keep track of most recent alert
            if alert.received_at and cluster['latest_alert'].received_at:
                if alert.received_at > cluster['latest_alert'].received_at:
                    cluster['latest_alert'] = alert
            
            # Safe Performance Extraction
            loss_val = pm.get('PercentLoss', 0)
            if loss_val:
                try: cluster['avg_loss'].append(float(str(loss_val).replace('%', '')))
                except ValueError: pass
                
            cpu_val = pm.get('CPULoad', 0)
            if cpu_val:
                try: cluster['avg_cpu'].append(float(str(cpu_val).replace('%', '')))
                except ValueError: pass
            
            if alert.ip_address and alert.ip_address != "Unknown":
                cluster['ips'].append(alert.ip_address)
                
            # Extract Alert Level using pre-compiled regex
            al = p.get('Normalized_Alert_Level') or cp.get('Alert_Level') or p.get('severity')
            if al:
                match = ALERT_LEVEL_REGEX.search(str(al))
                if match:
                    cluster['max_alert_level'] = min(cluster['max_alert_level'], int(match.group()))

        # Post-Processing: Assign Patient Zero and Topo Domains
        for site, cluster in incidents.items():
            if cluster['max_alert_level'] == 99: 
                cluster['max_alert_level'] = 3  # Normalize default

            pz_alert, scored_chain = self._determine_patient_zero(cluster['alerts'])
            cluster['patient_zero'] = pz_alert
            cluster['dependency_chain'] = scored_chain
            cluster['domains_affected'] = {sa['domain'] for sa in scored_chain}
                
        return incidents
