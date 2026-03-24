import ipaddress
import math
from datetime import datetime
from email.message import EmailMessage
import smtplib

class EnterpriseAIOpsEngine:
    # THE INFRASTRUCTURE ONTOLOGY
    ONTOLOGY = {
        "TRANSPORT_CORE": ["Router", "DWDM", "Firewall", "Service Provider", "VSAT Modem", "Radio"],
        "NETWORK_ACCESS": ["Switch", "Lanolinx-switch", "Fabric Interconnect", "Wireless Controller", "Access Point", "GarrettCom-6KL"],
        "COMPUTE_STORAGE": ["VM Host", "VM Server", "Physical Machine", "Storage", "Storage Switch", "NTP Server"],
        "POWER_ENV": ["UPS", "Generator", "DC Power Supply", "Data Center PDU", "Data Center A/C", "PDU", "HVAC"],
        "SCADA_OT": ["RTU", "NTEST RTU", "Sub Equipment", "Plant Equipment", "Meter Point 7403", "Meter Point 8650", "CAT Bank Meter", "I/O", "Member Equipment"],
        "FACILITIES_IOT": ["Access Control Panel", "Door Controller", "PACS", "Firealram", "IP Camera", "IP Phone", "Intercom"]
    }

    # TOPOLOGICAL DEPENDENCY WEIGHTS (Higher = More Foundational)
    # E.g., If Power dies, everything dies. If WAN dies, LAN and endpoints die.
    DOMAIN_WEIGHTS = {
        "POWER_ENV": 100,
        "TRANSPORT_CORE": 80,
        "NETWORK_ACCESS": 60,
        "COMPUTE_STORAGE": 40,
        "SCADA_OT": 20,
        "FACILITIES_IOT": 20,
        "UNKNOWN_DOMAIN": 10
    }

    def __init__(self, db_session):
        self.session = db_session

    def _get_domain(self, node_type):
        for domain, types in self.ONTOLOGY.items():
            if any(t.lower() in str(node_type).lower() for t in types):
                return domain
        return "UNKNOWN_DOMAIN"
        
    def _analyze_subnets(self, ip_list):
        if not ip_list: return "Unknown Topology"
        subnets = {ipaddress.IPv4Network(f"{ip}/24", strict=False) for ip in ip_list if ip.version == 4}
        if len(subnets) == 1: return f"Isolated to Single Subnet ({list(subnets)[0]})"
        return f"Cross-Subnet Cascade ({len(subnets)} distinct VLANs affected)"

    def _determine_patient_zero(self, alerts):
        """
        The Supreme Patient Zero Algorithm:
        Scores nodes based on Topological Hierarchy + Severity + Time Offset.
        Bypasses the "polling cycle" timestamp trap.
        """
        if not alerts: return None, []
        if len(alerts) == 1: return alerts[0], [{"alert": alerts[0], "domain": self._get_domain(alerts[0].device_type)}]

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

            # 1. Topological Score (A core router inherently outranks a server)
            topo_score = self.DOMAIN_WEIGHTS.get(domain, 10) * 1000

            # 2. Severity Score (A Hard Down outranks High CPU)
            status = str(alert.status).lower()
            event_cat = str(alert.event_category).lower()
            loss = float(str(pm.get('PercentLoss', 0)).replace('%', '')) if pm else 0

            sev_score = 0
            if 'down' in status or loss == 100 or 'offline' in event_cat: sev_score = 500
            elif 'critical' in status or loss > 50: sev_score = 300
            elif 'warning' in status: sev_score = 100

            # 3. Time Offset Penalty (Only used as a tie-breaker within the same domain)
            time_offset = (alert.received_at - earliest_time).total_seconds() if alert.received_at else 0
            time_penalty = min(time_offset, 200) # Cap penalty so a router that alerts 3 mins late still outranks a server

            final_score = topo_score + sev_score - time_penalty

            scored_alerts.append({
                "alert": alert, "score": final_score, 
                "domain": domain, "node_type": node_type, "severity": sev_score
            })

        # Sort highest score first
        scored_alerts.sort(key=lambda x: x['score'], reverse=True)
        return scored_alerts[0]['alert'], scored_alerts

    def analyze_and_cluster(self, active_alerts):
        incidents = {}
        for alert in active_alerts:
            p = alert.raw_payload if isinstance(alert.raw_payload, dict) else {}
            cp = p.get('Custom_Properties_Universal') or {}
            pm = p.get('Performance_Metrics') or {}
            
            site_name = cp.get('Site') or alert.mapped_location or 'Unknown'
            
            if site_name not in incidents:
                incidents[site_name] = {
                    'alerts': [], 'ips': [],
                    'site_metadata': {
                        'address': cp.get('Address') or 'N/A', 'district': cp.get('District') or 'N/A',
                        'jurisdiction': cp.get('Jurisdiction') or 'N/A', 'market': cp.get('Power_Market') or 'N/A',
                        'primary_coms': cp.get('Primary_Comms') or 'Unknown', 'secondary_coms': cp.get('Secondary_Comms') or 'Unknown'
                    },
                    'max_alert_level': 4, 'avg_cpu': [], 'avg_loss': [],
                    'domains_affected': set(), 'device_breakdown': {},
                    'patient_zero': None, 'latest_alert': alert, 'dependency_chain': []
                }
            
            cluster = incidents[site_name]
            cluster['alerts'].append(alert)
            
            if alert.received_at > cluster['latest_alert'].received_at:
                cluster['latest_alert'] = alert
            
            # Telemetry Extraction
            try: cluster['avg_cpu'].append(float(str(pm.get('CPULoad', 0)).replace('%', '')))
            except: pass
            try: cluster['avg_loss'].append(float(str(pm.get('PercentLoss', 0)).replace('%', '')))
            except: pass
            try: cluster['max_alert_level'] = min(cluster['max_alert_level'], int(cp.get('Alert_Level', 4)))
            except: pass
            try:
                if alert.ip_address and alert.ip_address != "Unknown": 
                    cluster['ips'].append(ipaddress.ip_address(alert.ip_address))
            except: pass

        # Post-Process Clusters to determine Supreme Patient Zero and Dependencies
        for site, cluster in incidents.items():
            pz_alert, scored_chain = self._determine_patient_zero(cluster['alerts'])
            cluster['patient_zero'] = pz_alert
            cluster['dependency_chain'] = scored_chain
            
            for sa in scored_chain:
                cluster['domains_affected'].add(sa['domain'])
                cluster['device_breakdown'][sa['node_type']] = cluster['device_breakdown'].get(sa['node_type'], 0) + 1
                
        return incidents

    def calculate_root_cause(self, site_name, data, active_weather, active_cloud, active_bgp):
        meta = data['site_metadata']
        domains = data['domains_affected']
        avg_loss = sum(data['avg_loss']) / len(data['avg_loss']) if data['avg_loss'] else 0
        avg_cpu = sum(data['avg_cpu']) / len(data['avg_cpu']) if data['avg_cpu'] else 0
        
        score = 0
        evidence_log = []
        
        blast_radius = self._analyze_subnets(data['ips'])
        p0 = data['patient_zero']
        p0_domain = next((sa['domain'] for sa in data['dependency_chain'] if sa['alert'] == p0), "UNKNOWN")
        
        # Determine Cascade scale
        if len(domains) > 1:
            score += 20
            downstream_count = len(data['alerts']) - 1
            evidence_log.append(f"Dependency Cascade: Primary failure in [{p0_domain}] triggered cascading isolation of {downstream_count} downstream devices across {len(domains)} infrastructure layers.")
            
        cause = "Under Investigation"
        
        # --- 1. CLOUD / UPSTREAM CORRELATION ---
        cloud_hit = False
        if active_cloud:
            for alert in data['alerts']:
                payload_str = str(alert.raw_payload).lower() if alert.raw_payload else ""
                for c in active_cloud:
                    if c.provider.lower() in alert.node_name.lower() or c.provider.lower() in payload_str:
                        cause = f"Upstream Cloud Dependency Failure ({c.provider})"
                        score += 85
                        evidence_log.append(f"Cloud Correlation: Node relies on {c.provider}, which is currently experiencing a known outage.")
                        cloud_hit = True
                        break
                if cloud_hit: break

        # --- 2. BGP / ROUTING CORRELATION ---
        bgp_hit = False
        if active_bgp and not cloud_hit:
            if "TRANSPORT_CORE" in domains or "Service Provider" in str(domains):
                for b in active_bgp:
                    if b.asn in str(meta['primary_coms']) or b.asn in str(meta['secondary_coms']):
                        cause = f"Carrier Routing Anomaly (BGP Event on {b.asn})"
                        score += 75
                        evidence_log.append(f"BGP Correlation: Transport provider {b.asn} is actively experiencing a global routing anomaly.")
                        bgp_hit = True
                        break

        # --- 3. HARDWARE / DOMAIN HEURISTICS ---
        if not cloud_hit and not bgp_hit:
            if p0_domain == "POWER_ENV":
                cause = "Catastrophic Facilities/Power Failure causing complete site isolation."
                score += 60
                evidence_log.append(f"Primary Trigger: Foundational Power/Environmental node ({p0.node_name}) failed.")
                
            elif p0_domain == "TRANSPORT_CORE" and avg_loss >= 80:
                cause = f"Wide Area Network (WAN) Isolation. Hard down on {meta['primary_coms']} transport tier."
                score += 50
                evidence_log.append(f"Primary Trigger: Core transport equipment ({p0.node_name}) dropped with critical packet loss.")
                
            elif p0_domain == "SCADA_OT":
                cause = "Isolated OT/SCADA Telemetry Failure."
                score += 30
                evidence_log.append(f"Primary Trigger: Field equipment ({p0.node_name}) alarming while Core IT network remains structurally stable.")
                
            elif p0_domain == "COMPUTE_STORAGE" and avg_cpu > 90:
                cause = "Data Center Compute/Storage Resource Exhaustion."
                score += 30
                evidence_log.append(f"Primary Trigger: Compute tier reporting critical CPU/Resource utilization ({avg_cpu}% avg).")
                
            elif p0_domain == "NETWORK_ACCESS" and "Isolated to Single" in blast_radius:
                cause = "Localized Access Layer Failure (Switch/Closet fault)."
                score += 20
                evidence_log.append(f"Primary Trigger: Access network fault on {p0.node_name} restricted to a single broadcast domain.")
                
            else:
                cause = f"Generalized Infrastructure Degradation originating at {p0.node_name}."

        # --- 4. GEOSPATIAL WEATHER / GRID CORRELATION ---
        from src.database import MonitoredLocation, SessionLocal
        with SessionLocal() as db:
            site_record = db.query(MonitoredLocation).filter(MonitoredLocation.name == site_name).first()
            if site_record and site_record.lat and site_record.lon:
                for h in active_weather:
                    if not getattr(h, 'lat', None) or not getattr(h, 'lon', None):
                        if meta['district'].lower() in str(h.location).lower() or site_name.lower() in str(h.location).lower():
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

        if data['max_alert_level'] == 1:
            score += 50
            evidence_log.append("Policy Override: Native Alert Level 1 detected.")

        priority = "P1 - CRITICAL" if score >= 80 else "P2 - HIGH" if score >= 50 else "P3 - MODERATE"
        cascade_sec = int((data['latest_alert'].received_at - p0.received_at).total_seconds())
        cascade_str = f"{cascade_sec}s" if cascade_sec > 0 else "Simultaneous"
        
        return cause, min(score, 100), priority, evidence_log, blast_radius, p0.node_name, cascade_str

    # [Note: Keep your existing generate_chronic_insights function here unchanged]
    def generate_chronic_insights(self, days_back=30):
        import pandas as pd
        from datetime import datetime, timedelta
        
        cutoff = datetime.utcnow() - timedelta(days=days_back)
        historical_alerts = self.session.query(type(self).alert_model).filter(
            type(self).alert_model.received_at >= cutoff
        ).all() if hasattr(type(self), 'alert_model') else []
        
        if not historical_alerts:
            from src.database import SolarWindsAlert
            historical_alerts = self.session.query(SolarWindsAlert).filter(SolarWindsAlert.received_at >= cutoff).all()

        if not historical_alerts: return None, None, None

        data = []
        for a in historical_alerts:
            p = a.raw_payload if isinstance(a.raw_payload, dict) else {}
            cp = p.get('Custom_Properties_Universal') or {}
            nd = p.get('Node_Details') or {}
            duration = (a.resolved_at - a.received_at).total_seconds() / 60 if a.resolved_at else None
            
            data.append({
                "Node": a.node_name, "Site": cp.get('Site') or a.mapped_location,
                "Device_Type": nd.get('MachineType') or cp.get('Node_Type') or 'Unknown',
                "Primary_Coms": cp.get('Primary_Comms') or 'Unknown',
                "Secondary_Coms": cp.get('Secondary_Comms') or 'Unknown',
                "Event": a.event_category or p.get('check') or p.get('class') or 'Unknown',
                "Duration_Mins": duration, "Received": a.received_at,
                "Resolved": a.is_correlated or a.status == 'Resolved'
            })
            
        df = pd.DataFrame(data)
        blips = df[(df['Duration_Mins'] > 0) & (df['Duration_Mins'] < 5.0)]
        cellular_flaps = blips[blips['Secondary_Coms'].str.contains('Cellular|LTE', case=False, na=False)]
        flap_summary = cellular_flaps.groupby('Site').size().reset_index(name='Micro_Blips (<5m)')
        flap_summary = flap_summary[flap_summary['Micro_Blips (<5m)'] > 2].sort_values('Micro_Blips (<5m)', ascending=False)
        
        vsat_data = df[df['Primary_Coms'].str.contains('VSAT', case=False, na=False) | df['Device_Type'].str.contains('VSAT', case=False, na=False)]
        vsat_summary = vsat_data.groupby('Site').size().reset_index(name='Total_Outage_Events')
        vsat_summary['Vulnerability_Score'] = (vsat_summary['Total_Outage_Events'] * 8.5).clip(upper=100)
        vsat_summary = vsat_summary.sort_values('Vulnerability_Score', ascending=False)

        reboots = df[df['Event'].str.contains('reboot|crash|unexpected', case=False, na=False)]
        reboot_summary = reboots.groupby(['Site', 'Node']).size().reset_index(name='Reboot_Count')
        reboot_summary = reboot_summary[reboot_summary['Reboot_Count'] > 1].sort_values('Reboot_Count', ascending=False)

        return flap_summary, vsat_summary, reboot_summary
