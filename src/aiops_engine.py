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
        if not alerts: return None, []

        scored_alerts = []
        valid_times = [a.received_at for a in alerts if a.received_at]
        earliest_time = min(valid_times) if valid_times else datetime.utcnow()

        for alert in alerts:
            p = alert.raw_payload if isinstance(alert.raw_payload, dict) else {}
            cp = p.get('Custom_Properties_Universal') or {}
            nd = p.get('Node_Details') or {}
            pm = p.get('Performance_Metrics') or {}

            node_type = nd.get('MachineType') or cp.get('Node_Type') or alert.device_type or 'Unknown'
            domain = self._get_domain(node_type)

            # NEW: Structural Dominance Tiering
            tier = self.TIER_RANKING.get(domain, 6)
            topo_score = (7 - tier) * 2000 

            # Severity Score
            status = str(alert.status).lower()
            event_cat = str(alert.event_category).lower()
            loss = float(str(pm.get('PercentLoss', 0)).replace('%', '')) if pm else 0

            sev_score = 0
            if 'down' in status or loss == 100 or 'offline' in event_cat: sev_score = 1000
            elif 'critical' in status or loss > 50: sev_score = 500
            elif 'warning' in status: sev_score = 100

            # PRESERVED: Time offset as a micro-tiebreaker within the SAME tier
            time_offset = (alert.received_at - earliest_time).total_seconds() if alert.received_at else 0
            time_penalty = min(time_offset, 200)

            final_score = topo_score + sev_score - time_penalty

            scored_alerts.append({
                "alert": alert, "score": final_score, 
                "domain": domain, "node_type": node_type, "severity": sev_score
            })

        scored_alerts.sort(key=lambda x: x['score'], reverse=True)
        return scored_alerts[0]['alert'], scored_alerts

    def identify_fleet_outages(self, incidents, threshold=5):
        """NEW: Detects Carrier outages across multiple sites."""
        provider_map = {}
        for site, data in incidents.items():
            comms = data['site_metadata'].get('primary_coms', 'Unknown')
            if comms not in provider_map: provider_map[comms] = []
            if any(sa['domain'] == "TRANSPORT_CORE" for sa in data['dependency_chain']):
                provider_map[comms].append(site)

        fleet_events = []
        for provider, sites in provider_map.items():
            if len(sites) >= threshold and provider != "Unknown":
                fleet_events.append({
                    "provider": provider, "affected_sites": sites,
                    "event_type": "Regional Provider Outage", "severity": "CRITICAL"
                })
        return fleet_events

    def calculate_root_cause(self, site_name, data, active_weather, active_cloud, active_bgp, fleet_events=[]):
        meta = data.get('site_metadata', {})
        domains = data.get('domains_affected', set())
        
        # --- SAFE METRIC EXTRACTION TO PREVENT KEYERRORS ---
        avg_loss_list = data.get('avg_loss', [])
        avg_cpu_list = data.get('avg_cpu', [])
        
        avg_loss = sum(avg_loss_list) / len(avg_loss_list) if avg_loss_list else 0
        avg_cpu = sum(avg_cpu_list) / len(avg_cpu_list) if avg_cpu_list else 0
        
        score = 0
        evidence_log = []
        
        # Safely call _analyze_subnets if it exists in your class
        if hasattr(self, '_analyze_subnets'):
            blast_radius = self._analyze_subnets(data.get('ips', []))
        else:
            blast_radius = "Unknown"
            
        p0 = data.get('patient_zero')
        if not p0:
            return "Indeterminate Failure", score, "P3 - MODERATE", evidence_log, blast_radius, "Unknown", "N/A"
            
        p0_domain = next((sa['domain'] for sa in data.get('dependency_chain', []) if sa['alert'] == p0), "UNKNOWN")
        
        # PRESERVED: Cascade logging
        if len(domains) > 1:
            score += 20
            downstream_count = len(data.get('alerts', [])) - 1
            evidence_log.append(f"Dependency Cascade: Primary failure in [{p0_domain}] triggered isolation of {downstream_count} downstream devices.")
            
        cause = "Under Investigation"
        
        # --- NEW 1. FLEET / VSAT CORRELATION ---
        fleet_hit = False
        for event in fleet_events:
            if site_name in event['affected_sites']:
                cause = f"Regional Carrier Outage ({event['provider']})"
                score += 100
                evidence_log.append(f"Fleet Correlation: Site is caught in a massive {event['provider']} outage affecting {len(event['affected_sites'])} total sites.")
                fleet_hit = True
                break

        # --- PRESERVED 2. CLOUD / UPSTREAM CORRELATION ---
        cloud_hit = False
        if active_cloud and not fleet_hit:
            for alert in data.get('alerts', []):
                payload_str = str(alert.raw_payload).lower() if alert.raw_payload else ""
                for c in active_cloud:
                    if c.provider.lower() in alert.node_name.lower() or c.provider.lower() in payload_str:
                        cause = f"Upstream Cloud Dependency Failure ({c.provider})"
                        score += 85
                        evidence_log.append(f"Cloud Correlation: Node relies on {c.provider}, which is currently experiencing a known outage.")
                        cloud_hit = True
                        break
                if cloud_hit: break

        # --- PRESERVED 3. BGP / ROUTING CORRELATION ---
        bgp_hit = False
        if active_bgp and not cloud_hit and not fleet_hit:
            if "TRANSPORT_CORE" in domains or "Service Provider" in str(domains):
                for b in active_bgp:
                    if b.asn in str(meta.get('primary_coms', '')) or b.asn in str(meta.get('secondary_coms', '')):
                        cause = f"Carrier Routing Anomaly (BGP Event on {b.asn})"
                        score += 75
                        evidence_log.append(f"BGP Correlation: Transport provider {b.asn} is actively experiencing a global routing anomaly.")
                        bgp_hit = True
                        break

        # --- NEW & IMPROVED 4. HARDWARE / TOPOLOGICAL HEURISTICS ---
        if not cloud_hit and not bgp_hit and not fleet_hit:
            if p0_domain == "POWER_ENV":
                cause = "Catastrophic Facilities/Power Failure causing complete site isolation."
                score += 60
                evidence_log.append(f"Structural Cause: Foundational Power/Environmental node ({p0.node_name}) failed.")
            elif p0_domain == "TRANSPORT_CORE":
                if avg_loss >= 80 or 'down' in str(p0.status).lower():
                    cause = f"Site Isolation. Hard down on {meta.get('primary_coms', 'Unknown')} transport tier."
                    score += 50
                    evidence_log.append(f"Structural Cause: Core transport equipment ({p0.node_name}) severed communication path.")
                else:
                    cause = f"Severe Transport Congestion ({avg_loss}% Packet Loss)."
            elif p0_domain == "SCADA_OT":
                cause = "Isolated OT/SCADA Telemetry Failure."
                score += 30
                evidence_log.append(f"Structural Cause: Field equipment ({p0.node_name}) alarming while Core IT network remains structurally stable.")
            else:
                cause = f"Generalized Infrastructure Degradation originating at {p0.node_name}."

        # --- PRESERVED 5. GEOSPATIAL WEATHER / GRID CORRELATION ---
        from src.database import MonitoredLocation, SessionLocal
        with SessionLocal() as db:
            site_record = db.query(MonitoredLocation).filter(MonitoredLocation.name == site_name).first()
            if site_record and site_record.lat and site_record.lon:
                for h in active_weather:
                    if not getattr(h, 'lat', None) or not getattr(h, 'lon', None):
                        if meta.get('district', '').lower() in str(h.location).lower() or site_name.lower() in str(h.location).lower():
                            score += 40
                            evidence_log.append(f"Regional Correlation: Site intersects active {h.hazard_type} warning zone.")
                            if p0_domain in ["POWER_ENV", "TRANSPORT_CORE"]: cause = f"Severe Weather ({h.hazard_type}) induced failure of Utility/Carrier."
                            break
                    else:
                        R = 3958.8 
                        lat1, lon1, lat2, lon2 = map(math.radians, [site_record.lat, site_record.lon, h.lat, h.lon])
                        dlat, dlon = lat2 - lat1, lon2 - lon1
                        a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
                        distance_miles = R * (2 * math.asin(math.sqrt(a)))
                        hazard_radius = getattr(h, 'radius_km', 24.1) * 0.621371 
                        
                        if distance_miles <= hazard_radius:
                            score += 55
                            evidence_log.append(f"Geospatial Correlation: Site is exactly {round(distance_miles, 1)} miles from active {h.hazard_type} epicenter.")
                            if p0_domain in ["POWER_ENV", "TRANSPORT_CORE"]: cause = f"Direct Kinetic Impact: Severe Weather ({h.hazard_type}) caused physical infrastructure failure."
                            break

        if data.get('max_alert_level', 3) == 1:
            score += 50
            evidence_log.append("Policy Override: Native Alert Level 1 detected.")

        priority = "P1 - CRITICAL" if score >= 80 else "P2 - HIGH" if score >= 50 else "P3 - MODERATE"
        
        # Safely calculate cascade seconds using latest_alert
        latest = data.get('latest_alert')
        if latest and getattr(latest, 'received_at', None) and getattr(p0, 'received_at', None):
            cascade_sec = int((latest.received_at - p0.received_at).total_seconds())
        else:
            cascade_sec = 0
            
        cascade_str = f"{cascade_sec}s" if cascade_sec > 0 else "Simultaneous"
        
        return cause, min(score, 100), priority, evidence_log, blast_radius, p0.node_name, cascade_str

    def analyze_and_cluster(self, active_alerts):
        incidents = {}
        for alert in active_alerts:
            p = alert.raw_payload if isinstance(alert.raw_payload, dict) else {}
            cp = p.get('Custom_Properties_Universal') or {}
            pm = p.get('Performance_Metrics') or {}
            site_name = cp.get('Site') or alert.mapped_location or 'Unknown'
            
            if site_name not in incidents:
                incidents[site_name] = {
                    'alerts': [], 
                    'site_metadata': {
                        'primary_coms': cp.get('Primary_Comms') or 'Unknown',
                        'secondary_coms': cp.get('Secondary_Comms') or 'Unknown',
                        'district': cp.get('District') or 'Unknown'
                    },
                    'domains_affected': set(), 
                    'dependency_chain': [],
                    # NEW: Explicitly initialize arrays to prevent KeyErrors
                    'avg_loss': [],
                    'avg_cpu': [],
                    'ips': [],
                    'max_alert_level': 3,
                    'latest_alert': alert # Start with first alert found
                }
            
            incidents[site_name]['alerts'].append(alert)
            
            # Keep track of the most recent alert for the cascade timer
            if getattr(alert, 'received_at', None) and getattr(incidents[site_name]['latest_alert'], 'received_at', None):
                if alert.received_at > incidents[site_name]['latest_alert'].received_at:
                    incidents[site_name]['latest_alert'] = alert
            
            # Extract CPU and Packet Loss safely
            try: incidents[site_name]['avg_loss'].append(float(str(pm.get('PercentLoss', 0)).replace('%', '')))
            except (ValueError, TypeError): pass
            
            try: incidents[site_name]['avg_cpu'].append(float(str(pm.get('CPULoad', 0)).replace('%', '')))
            except (ValueError, TypeError): pass
            
            # Extract IP safely
            if alert.ip_address and alert.ip_address != "Unknown":
                incidents[site_name]['ips'].append(alert.ip_address)
                
            # Extract Alert Level safely
            al = cp.get('Alert_Level') or p.get('severity')
            if al:
                try: incidents[site_name]['max_alert_level'] = min(incidents[site_name]['max_alert_level'], int(al))
                except (ValueError, TypeError): pass

        for site, cluster in incidents.items():
            pz_alert, scored_chain = self._determine_patient_zero(cluster['alerts'])
            cluster['patient_zero'] = pz_alert
            cluster['dependency_chain'] = scored_chain
            for sa in scored_chain: cluster['domains_affected'].add(sa['domain'])
                
        return incidents
