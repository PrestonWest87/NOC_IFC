import ipaddress
from datetime import datetime
from email.message import EmailMessage
import smtplib

class EnterpriseAIOpsEngine:
    # THE INFRASTRUCTURE ONTOLOGY
    # Maps specific device types into functional domains to calculate blast radius and causality.
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
        """Maps a SolarWinds node type to its Ontological Domain."""
        for domain, types in self.ONTOLOGY.items():
            # Using exact matches and substring fallbacks to handle case variations
            if any(t.lower() == str(node_type).lower() or t.lower() in str(node_type).lower() for t in types):
                return domain
        return "UNKNOWN_DOMAIN"
      
    def generate_chronic_insights(self, days_back=30):
        """Analyzes historical data to find recurring blips, VSAT rain fade, and correlated reboots."""
        import pandas as pd
        from datetime import datetime, timedelta
        
        cutoff = datetime.utcnow() - timedelta(days=days_back)
        
        # 1. Fetch historical alerts
        historical_alerts = self.session.query(type(self).alert_model).filter(
            type(self).alert_model.received_at >= cutoff
        ).all() if hasattr(type(self), 'alert_model') else []
        
        # Fallback if model isn't explicitly bound to the class
        if not historical_alerts:
            from src.database import SolarWindsAlert
            historical_alerts = self.session.query(SolarWindsAlert).filter(SolarWindsAlert.received_at >= cutoff).all()

        if not historical_alerts:
            return None, None, None

        # 2. Build the DataFrame
        data = []
        for a in historical_alerts:
            p = a.raw_payload if isinstance(a.raw_payload, dict) else {}
            duration = (a.resolved_at - a.received_at).total_seconds() / 60 if a.resolved_at else None
            
            data.append({
                "Node": a.node_name,
                "Site": p.get('Site', a.mapped_location),
                "Device_Type": p.get('Node Type', 'Unknown'),
                "Primary_Coms": p.get('Primary Coms', 'Unknown'),
                "Secondary_Coms": p.get('Secondary Coms', 'Unknown'),
                "Event": a.event_category or p.get('Alert Name', 'Unknown'),
                "Duration_Mins": duration,
                "Received": a.received_at,
                "Resolved": a.is_correlated or a.status == 'Resolved'
            })
            
        df = pd.DataFrame(data)
        
        # --- INSIGHT 1: Micro-Blips & Cellular Flaps ---
        blips = df[(df['Duration_Mins'] > 0) & (df['Duration_Mins'] < 5.0)]
        cellular_flaps = blips[blips['Secondary_Coms'].str.contains('Cellular|LTE', case=False, na=False)]
        flap_summary = cellular_flaps.groupby('Site').size().reset_index(name='Micro_Blips (<5m)')
        flap_summary = flap_summary[flap_summary['Micro_Blips (<5m)'] > 2].sort_values('Micro_Blips (<5m)', ascending=False)
        
        # --- INSIGHT 2: VSAT Weather Vulnerability ---
        vsat_data = df[df['Primary_Coms'].str.contains('VSAT', case=False, na=False) | 
                       df['Device_Type'].str.contains('VSAT', case=False, na=False)]
        vsat_summary = vsat_data.groupby('Site').size().reset_index(name='Total_Outage_Events')
        vsat_summary['Vulnerability_Score'] = (vsat_summary['Total_Outage_Events'] * 8.5).clip(upper=100)
        vsat_summary = vsat_summary.sort_values('Vulnerability_Score', ascending=False)

        # --- INSIGHT 3: Correlated Hardware Reboots ---
        reboots = df[df['Event'].str.contains('reboot|crash|unexpected', case=False, na=False)]
        reboot_summary = reboots.groupby(['Site', 'Node']).size().reset_index(name='Reboot_Count')
        reboot_summary = reboot_summary[reboot_summary['Reboot_Count'] > 1].sort_values('Reboot_Count', ascending=False)

        return flap_summary, vsat_summary, reboot_summary

    def analyze_and_cluster(self, active_alerts):
        """Phase 1: Temporal and Ontological Clustering"""
        incidents = {}
        for alert in active_alerts:
            p = alert.raw_payload if isinstance(alert.raw_payload, dict) else {}
            site_name = p.get('Site', alert.mapped_location)
            
            if site_name not in incidents:
                incidents[site_name] = {
                    'alerts': [],
                    'ips': [],
                    'site_metadata': {
                        'address': p.get('Address', 'N/A'),
                        'district': p.get('District', 'N/A'),
                        'jurisdiction': p.get('Jurisdiction', 'N/A'),
                        'market': p.get('Power Market', 'N/A'),
                        'primary_coms': p.get('Primary Coms', 'Unknown'),
                        'secondary_coms': p.get('Secondary Coms', 'Unknown')
                    },
                    'max_alert_level': 4,
                    'avg_cpu': [],
                    'avg_loss': [],
                    'domains_affected': set(), # Tracks the cross-domain blast radius
                    'device_breakdown': {},
                    'patient_zero': alert,
                    'latest_alert': alert
                }
            
            cluster = incidents[site_name]
            cluster['alerts'].append(alert)
            
            # Ontological Mapping
            node_type = p.get('Node Type', alert.device_type or 'Unknown')
            domain = self._get_domain(node_type)
            cluster['domains_affected'].add(domain)
            cluster['device_breakdown'][node_type] = cluster['device_breakdown'].get(node_type, 0) + 1
            
            # Temporal Tracking
            if alert.received_at < cluster['patient_zero'].received_at:
                cluster['patient_zero'] = alert
            if alert.received_at > cluster['latest_alert'].received_at:
                cluster['latest_alert'] = alert
            
            # Telemetry Extraction (Safe casting)
            try: cluster['avg_cpu'].append(float(str(p.get('CPU Load', 0)).replace('%', '')))
            except: pass
            try: cluster['avg_loss'].append(float(str(p.get('Percent Loss', 0)).replace('%', '')))
            except: pass
            try: cluster['max_alert_level'] = min(cluster['max_alert_level'], int(p.get('Alert Level', 4)))
            except: pass
            try:
                if alert.ip_address: cluster['ips'].append(ipaddress.ip_address(alert.ip_address))
            except: pass
                
        return incidents

    def _analyze_subnets(self, ip_list):
        if not ip_list: return "Unknown Topology"
        subnets = {ipaddress.IPv4Network(f"{ip}/24", strict=False) for ip in ip_list if ip.version == 4}
        if len(subnets) == 1: return f"Isolated to Single Subnet ({list(subnets)[0]})"
        return f"Cross-Subnet Cascade ({len(subnets)} distinct VLANs affected)"

    def calculate_root_cause(self, site_name, data, active_weather, active_cloud, active_bgp):
        """Phase 2: The Multi-Domain Causation Matrix"""
        meta = data['site_metadata']
        domains = data['domains_affected']
        avg_loss = sum(data['avg_loss']) / len(data['avg_loss']) if data['avg_loss'] else 0
        avg_cpu = sum(data['avg_cpu']) / len(data['avg_cpu']) if data['avg_cpu'] else 0
        
        score = 0
        evidence_log = []
        
        # 1. Topological & Domain Math
        blast_radius = self._analyze_subnets(data['ips'])
        if len(domains) > 1:
            score += 20
            evidence_log.append(f"Cross-Domain Cascade: Failure spans {len(domains)} different infrastructure layers.")
            
        # 2. Causation Rules Engine (The AI Logic)
        cause = "Under Investigation"
        
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

        # 3. Geospatial / External Overlays
        weather_hit = next((h for h in active_weather if meta['district'].lower() in h.location.lower() or site_name.lower() in h.location.lower()), None)
        if weather_hit:
            score += 40
            evidence_log.append(f"Geospatial Correlation: Site intersects active {weather_hit.hazard_type} warning.")
            if "POWER_ENV" in domains or "TRANSPORT_CORE" in domains:
                cause = f"Severe Weather ({weather_hit.hazard_type}) induced failure of Utility/Carrier."

        # 4. ITIL Priority Calculation
        if data['max_alert_level'] == 1:
            score += 50
            evidence_log.append("Policy Override: Native Alert Level 1 detected.")

        priority = "P1 - CRITICAL" if score >= 80 else "P2 - HIGH" if score >= 50 else "P3 - MODERATE"
        
        # Temporal cascade timing
        p0 = data['patient_zero']
        cascade_sec = int((data['latest_alert'].received_at - p0.received_at).total_seconds())
        cascade_str = f"{cascade_sec}s" if cascade_sec > 0 else "Simultaneous"
        
        return cause, min(score, 100), priority, evidence_log, blast_radius, p0.node_name, cascade_str

    def generate_itsm_payload(self, site_name, data, cause, confidence, priority, evidence, blast_radius, p0, cascade_str):
        """Phase 3: The Structured Forensic Ticket"""
        m = data['site_metadata']
        
        # Group inventory by Ontological Domain dynamically based on what was ACTUALLY affected
        inventory_block = ""
        for domain in sorted(list(data['domains_affected'])):
            nodes_in_domain = [a for a in data['alerts'] if self._get_domain(a.raw_payload.get('Node Type', '')) == domain]
            if nodes_in_domain:
                inventory_block += f"  [{domain}]\n"
                
                seen_nodes = set()
                for a in sorted(nodes_in_domain, key=lambda x: x.received_at):
                    # Deduplication check
                    if a.node_name in seen_nodes:
                        continue
                    seen_nodes.add(a.node_name)
                    
                    p = a.raw_payload if isinstance(a.raw_payload, dict) else {}
                    # Removed the emoji from Patient Zero flag
                    flag = "[PATIENT ZERO] " if a.node_name == p0 else "   - "
                    inventory_block += f"  {flag}{a.node_name} | {p.get('Node Type', 'Unknown')} | Loss: {p.get('Percent Loss', '0%')}\n"
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