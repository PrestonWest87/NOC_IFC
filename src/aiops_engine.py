import ipaddress
from datetime import datetime
from email.message import EmailMessage
import smtplib

class EnterpriseAIOpsEngine:
    # THE INFRASTRUCTURE ONTOLOGY
    ONTOLOGY = {
        "TRANSPORT_CORE": ["Router", "DWDM", "Firewall", "Service Provider", "VSAT Modem", "Radio"],
        "NETWORK_ACCESS": ["Switch", "Lanolinx-switch", "Fabric Interconnect", "Wireless Controller", "Access Point", "GarrettCom-6KL"],
        "COMPUTE_STORAGE": ["VM Host", "VM Server", "Physical Machine", "Storage", "Storage Switch", "NTP Server"],
        "POWER_ENV": ["UPS", "Generator", "DC Power Supply", "Data Center PDU", "Data Center A/C", "PDU"],
        "SCADA_OT": ["RTU", "NTEST RTU", "Sub Equipment", "Plant Equipment", "Meter Point 7403", "Meter Point 8650", "CAT Bank Meter", "I/O", "Member Equipment"],
        "FACILITIES_IOT": ["Access Control Panel", "Door Controller", "PACS", "Firealram", "IP Camera", "IP Phone", "Intercom"]
    }

    def __init__(self, db_session):
        self.session = db_session

    def _get_domain(self, node_type):
        for domain, types in self.ONTOLOGY.items():
            if any(t.lower() == str(node_type).lower() or t.lower() in str(node_type).lower() for t in types):
                return domain
        return "UNKNOWN_DOMAIN"
      
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

        if not historical_alerts:
            return None, None, None

        data = []
        for a in historical_alerts:
            p = a.raw_payload if isinstance(a.raw_payload, dict) else {}
            # Safe traversal of the nested JSON
            cp = p.get('Custom_Properties_Universal') or {}
            nd = p.get('Node_Details') or {}
            
            duration = (a.resolved_at - a.received_at).total_seconds() / 60 if a.resolved_at else None
            
            data.append({
                "Node": a.node_name,
                "Site": cp.get('Site') or a.mapped_location,
                "Device_Type": nd.get('MachineType') or cp.get('Node_Type') or 'Unknown',
                "Primary_Coms": cp.get('Primary_Comms') or 'Unknown',
                "Secondary_Coms": cp.get('Secondary_Comms') or 'Unknown',
                "Event": a.event_category or p.get('check') or p.get('class') or 'Unknown',
                "Duration_Mins": duration,
                "Received": a.received_at,
                "Resolved": a.is_correlated or a.status == 'Resolved'
            })
            
        df = pd.DataFrame(data)
        
        blips = df[(df['Duration_Mins'] > 0) & (df['Duration_Mins'] < 5.0)]
        cellular_flaps = blips[blips['Secondary_Coms'].str.contains('Cellular|LTE', case=False, na=False)]
        flap_summary = cellular_flaps.groupby('Site').size().reset_index(name='Micro_Blips (<5m)')
        flap_summary = flap_summary[flap_summary['Micro_Blips (<5m)'] > 2].sort_values('Micro_Blips (<5m)', ascending=False)
        
        vsat_data = df[df['Primary_Coms'].str.contains('VSAT', case=False, na=False) | 
                       df['Device_Type'].str.contains('VSAT', case=False, na=False)]
        vsat_summary = vsat_data.groupby('Site').size().reset_index(name='Total_Outage_Events')
        vsat_summary['Vulnerability_Score'] = (vsat_summary['Total_Outage_Events'] * 8.5).clip(upper=100)
        vsat_summary = vsat_summary.sort_values('Vulnerability_Score', ascending=False)

        reboots = df[df['Event'].str.contains('reboot|crash|unexpected', case=False, na=False)]
        reboot_summary = reboots.groupby(['Site', 'Node']).size().reset_index(name='Reboot_Count')
        reboot_summary = reboot_summary[reboot_summary['Reboot_Count'] > 1].sort_values('Reboot_Count', ascending=False)

        return flap_summary, vsat_summary, reboot_summary

    def analyze_and_cluster(self, active_alerts):
        incidents = {}
        for alert in active_alerts:
            p = alert.raw_payload if isinstance(alert.raw_payload, dict) else {}
            
            # Extract nested dictionaries safely
            cp = p.get('Custom_Properties_Universal') or {}
            pm = p.get('Performance_Metrics') or {}
            nd = p.get('Node_Details') or {}
            
            site_name = cp.get('Site') or alert.mapped_location or 'Unknown'
            
            if site_name not in incidents:
                incidents[site_name] = {
                    'alerts': [],
                    'ips': [],
                    'site_metadata': {
                        'address': cp.get('Address') or 'N/A',
                        'district': cp.get('District') or 'N/A',
                        'jurisdiction': cp.get('Jurisdiction') or 'N/A',
                        'market': cp.get('Power_Market') or 'N/A',
                        'primary_coms': cp.get('Primary_Comms') or 'Unknown',
                        'secondary_coms': cp.get('Secondary_Comms') or 'Unknown'
                    },
                    'max_alert_level': 4,
                    'avg_cpu': [],
                    'avg_loss': [],
                    'domains_affected': set(),
                    'device_breakdown': {},
                    'patient_zero': alert,
                    'latest_alert': alert
                }
            
            cluster = incidents[site_name]
            cluster['alerts'].append(alert)
            
            node_type = nd.get('MachineType') or cp.get('Node_Type') or alert.device_type or 'Unknown'
            domain = self._get_domain(node_type)
            cluster['domains_affected'].add(domain)
            cluster['device_breakdown'][node_type] = cluster['device_breakdown'].get(node_type, 0) + 1
            
            if alert.received_at < cluster['patient_zero'].received_at:
                cluster['patient_zero'] = alert
            if alert.received_at > cluster['latest_alert'].received_at:
                cluster['latest_alert'] = alert
            
            # Telemetry Extraction from the nested Performance_Metrics block
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
                
        return incidents

    def _analyze_subnets(self, ip_list):
        if not ip_list: return "Unknown Topology"
        subnets = {ipaddress.IPv4Network(f"{ip}/24", strict=False) for ip in ip_list if ip.version == 4}
        if len(subnets) == 1: return f"Isolated to Single Subnet ({list(subnets)[0]})"
        return f"Cross-Subnet Cascade ({len(subnets)} distinct VLANs affected)"

    def calculate_root_cause(self, site_name, data, active_weather, active_cloud, active_bgp):
        import math
        
        meta = data['site_metadata']
        domains = data['domains_affected']
        avg_loss = sum(data['avg_loss']) / len(data['avg_loss']) if data['avg_loss'] else 0
        avg_cpu = sum(data['avg_cpu']) / len(data['avg_cpu']) if data['avg_cpu'] else 0
        
        score = 0
        evidence_log = []
        
        blast_radius = self._analyze_subnets(data['ips'])
        if len(domains) > 1:
            score += 20
            evidence_log.append(f"Cross-Domain Cascade: Failure spans {len(domains)} different infrastructure layers.")
            
        cause = "Under Investigation"
        
        # --- 1. CLOUD / UPSTREAM CORRELATION ---
        cloud_hit = False
        if active_cloud:
            for alert in data['alerts']:
                payload_str = str(alert.raw_payload).lower() if alert.raw_payload else ""
                for c in active_cloud:
                    # If the node name, details, or payload mentions the degraded cloud provider
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

        # --- 3. HARDWARE / DOMAIN HEURISTICS (If no external cloud/bgp causes) ---
        if not cloud_hit and not bgp_hit:
            if "POWER_ENV" in domains and len(domains) > 1:
                cause = "Catastrophic Facilities/Power Failure causing cascade to IT/OT infrastructure."
                score += 60
                evidence_log.append("Primary Trigger: Critical Power/Environmental (UPS/Generator/AC) node alarms detected.")
                
            elif "TRANSPORT_CORE" in domains and avg_loss >= 80:
                cause = f"Wide Area Network (WAN) Isolation. Hard down on {meta['primary_coms']} transport tier."
                score += 50
                evidence_log.append(f"Primary Trigger: Core routing/DWDM equipment dropped with >80% packet loss.")
                
            elif "SCADA_OT" in domains and "TRANSPORT_CORE" not in domains:
                cause = "Isolated OT/SCADA Telemetry Failure (Substation/Plant Equipment degraded)."
                score += 30
                evidence_log.append("Primary Trigger: Field equipment (RTU/Meters) alarming while Core IT network remains stable.")
                
            elif "COMPUTE_STORAGE" in domains and avg_cpu > 90:
                cause = "Data Center Compute/Storage Resource Exhaustion."
                score += 30
                evidence_log.append(f"Primary Trigger: Compute tier reporting critical CPU/Resource utilization ({avg_cpu}% avg).")
                
            elif "NETWORK_ACCESS" in domains and "Isolated to Single" in blast_radius:
                cause = "Localized Access Layer Failure (Switch/Closet fault)."
                score += 20
                evidence_log.append("Primary Trigger: Access network fault restricted to a single broadcast domain.")
                
            else:
                cause = "Generalized Infrastructure Degradation (Multiple unclassified vectors)."

        # --- 4. GEOSPATIAL WEATHER / GRID CORRELATION ---
        # Fetch the exact lat/lon for the site from the database to do real math
        from src.database import MonitoredLocation, SessionLocal
        with SessionLocal() as db:
            site_record = db.query(MonitoredLocation).filter(MonitoredLocation.name == site_name).first()
            
            if site_record and site_record.lat and site_record.lon:
                for h in active_weather:
                    # If the hazard doesn't have coordinates, fall back to string matching the district/county
                    if not getattr(h, 'lat', None) or not getattr(h, 'lon', None):
                        if meta['district'].lower() in str(h.location).lower() or site_name.lower() in str(h.location).lower():
                            score += 40
                            evidence_log.append(f"Regional Correlation: Site intersects active {h.hazard_type} warning zone.")
                            if "POWER_ENV" in domains or "TRANSPORT_CORE" in domains:
                                cause = f"Severe Weather ({h.hazard_type}) induced failure of Utility/Carrier."
                            break
                    else:
                        # Real Geospatial Math (Haversine Distance)
                        R = 3958.8 # Radius of earth in miles
                        lat1, lon1, lat2, lon2 = map(math.radians, [site_record.lat, site_record.lon, h.lat, h.lon])
                        dlat, dlon = lat2 - lat1, lon2 - lon1
                        a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
                        distance_miles = R * (2 * math.asin(math.sqrt(a)))
                        
                        # Assume an average weather cell radius of 15 miles if not specified
                        hazard_radius = getattr(h, 'radius_km', 24.1) * 0.621371 
                        
                        if distance_miles <= hazard_radius:
                            score += 55
                            evidence_log.append(f"Geospatial Correlation: Site is exactly {round(distance_miles, 1)} miles from active {h.hazard_type} epicenter.")
                            if "POWER_ENV" in domains or "TRANSPORT_CORE" in domains:
                                cause = f"Direct Kinetic Impact: Severe Weather ({h.hazard_type}) caused physical infrastructure failure."
                            break

        if data['max_alert_level'] == 1:
            score += 50
            evidence_log.append("Policy Override: Native Alert Level 1 detected.")

        priority = "P1 - CRITICAL" if score >= 80 else "P2 - HIGH" if score >= 50 else "P3 - MODERATE"
        
        p0 = data['patient_zero']
        cascade_sec = int((data['latest_alert'].received_at - p0.received_at).total_seconds())
        cascade_str = f"{cascade_sec}s" if cascade_sec > 0 else "Simultaneous"
        
        return cause, min(score, 100), priority, evidence_log, blast_radius, p0.node_name, cascade_str

    def generate_itsm_payload(self, site_name, data, cause, confidence, priority, evidence, blast_radius, p0, cascade_str):
        m = data['site_metadata']
        
        inventory_block = ""
        for domain in sorted(list(data['domains_affected'])):
            nodes_in_domain = []
            for a in data['alerts']:
                p = a.raw_payload if isinstance(a.raw_payload, dict) else {}
                cp = p.get('Custom_Properties_Universal') or {}
                nd = p.get('Node_Details') or {}
                node_type = nd.get('MachineType') or cp.get('Node_Type') or a.device_type or 'Unknown'
                if self._get_domain(node_type) == domain:
                    nodes_in_domain.append((a, node_type, p.get('Performance_Metrics') or {}))
                    
            if nodes_in_domain:
                inventory_block += f"  [{domain}]\n"
                
                seen_nodes = set()
                for a, node_type, pm in sorted(nodes_in_domain, key=lambda x: x[0].received_at):
                    if a.node_name in seen_nodes:
                        continue
                    seen_nodes.add(a.node_name)
                    
                    flag = "[PATIENT ZERO] " if a.node_name == p0 else "   - "
                    inventory_block += f"  {flag}{a.node_name} | {node_type} | Loss: {pm.get('PercentLoss', '0%')}\n"
                inventory_block += "\n"

        evidence_str = "\n".join([f"  [+] {e}" for e in evidence])

        return f"""INCIDENT DISPATCH: {site_name}
===================================================
PRIORITY LEVEL   : {priority}
BLAST RADIUS     : {blast_radius}
CASCADE DURATION : {cascade_str}
SITE ADDRESS     : {m['address']}
PRIMARY COMMS    : {m['primary_coms']} / SEC: {m['secondary_coms']}
DOMAINS AFFECTED : {', '.join(data['domains_affected'])}
===================================================

AI FORENSIC ANALYSIS
---------------------------------------------------
SUSPECTED ROOT CAUSE: 
{cause}
(Correlation Confidence: {confidence}%)

CORRELATION EVIDENCE:
{evidence_str if evidence_str else "  [-] No external factors detected."}

AFFECTED INFRASTRUCTURE INVENTORY (BY DOMAIN)
---------------------------------------------------
{inventory_block.strip()}
===================================================
Generated by NOC Fusion Enterprise AIOps Engine
"""

    def send_to_ticketing_system(self, config, subject, body):
        if not config.smtp_enabled or not config.smtp_server: return False, "SMTP is not configured in Settings."
        try:
            msg = EmailMessage()
            msg.set_content(body)
            msg['Subject'] = subject
            msg['From'], msg['To'] = config.smtp_sender, config.smtp_recipient
            server = smtplib.SMTP(config.smtp_server, config.smtp_port)
            server.starttls()
            server.login(config.smtp_username, config.smtp_password)
            server.send_message(msg)
            server.quit()
            return True, "Ticket successfully dispatched."
        except Exception as e: return False, str(e)
