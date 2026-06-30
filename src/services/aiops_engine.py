import ipaddress
import json
import logging
import math
import re
from datetime import datetime, timedelta
from src.core.db import SessionLocal
from src.models.schema import MonitoredLocation, SolarWindsAlert

logger = logging.getLogger(__name__)

class EnterpriseAIOpsEngine:
    ONTOLOGY = {
        "PRIMARY_INTERNET": ["VSAT", "Cellular", "Radio", "SD-WAN", "Modem"],
        "COMMS_EQUIPMENT": ["Router", "Switch", "Firewall", "Lanolinx-switch", "Fabric Interconnect"],
        "POWER_SUPPLIES": ["UPS", "Generator", "DC Power Supply", "PDU", "PDS", "DC Controller"],
        "RTU": ["RTU", "NTEST RTU"],
        "SCADA": ["Sub Equipment", "Plant Equipment", "Meter Point", "I/O", "Member Equipment", "SCADA"],
        "COMPUTE": ["VM Host", "VM Server", "Physical Machine", "Storage"],
        "FACILITIES": ["Access Control Panel", "Door Controller", "IP Camera", "HVAC"]
    }

    TIER_RANKING = {
        "POWER_SUPPLIES": 1,
        "PRIMARY_INTERNET": 2,
        "COMMS_EQUIPMENT": 3,
        "COMPUTE": 4,
        "RTU": 5,
        "SCADA": 6,
        "FACILITIES": 7,
        "UNKNOWN_DOMAIN": 8
    }

    def __init__(self, session_factory=None):
        self.session_factory = session_factory or SessionLocal
        logger.info("EnterpriseAIOpsEngine initialized")

    def _get_domain(self, node_type, node_name="", primary_comms=""):
        node_str = f"{node_type} {node_name}".lower()
        logger.debug("_get_domain: node_type=%s node_name=%s primary_comms=%s", node_type, node_name, primary_comms)

        if any(t in node_str for t in ["vsat", "cell", "cellular", "sd-wan", "isp", "modem"]):
            logger.debug("_get_domain: classified as PRIMARY_INTERNET")
            return "PRIMARY_INTERNET"

        if any(t in node_str for t in ["ups", "pds", "pdu", "dc controller", "generator", "dc power"]):
            return "POWER_SUPPLIES"

        if any(t in node_str for t in ["router", "switch", "firewall"]):
            if "internet" in node_str or (primary_comms and primary_comms.lower() in node_str):
                return "PRIMARY_INTERNET"
            return "COMMS_EQUIPMENT"

        if "rtu" in node_str:
            return "RTU"

        if any(t in node_str for t in ["scada", "meter", "i/o", "plant equipment", "sub equipment"]):
            return "SCADA"

        for domain, types in self.ONTOLOGY.items():
            if any(t.lower() in str(node_type).lower() for t in types):
                logger.debug("_get_domain: matched ontology domain=%s", domain)
                return domain

        logger.debug("_get_domain: no match, returning UNKNOWN_DOMAIN")
        return "UNKNOWN_DOMAIN"

    def _determine_patient_zero(self, alerts):
        if not alerts:
            logger.debug("_determine_patient_zero: no alerts provided")
            return None, []

        logger.debug("_determine_patient_zero: scoring %d alerts", len(alerts))
        scored_alerts = []
        valid_times = [a.received_at for a in alerts if a.received_at]
        earliest_time = min(valid_times) if valid_times else datetime.utcnow()

        for alert in alerts:
            p = alert.raw_payload if isinstance(alert.raw_payload, dict) else {}
            cp = p.get('Custom_Properties_Universal') or {}
            nd = p.get('Node_Details') or {}
            pm = p.get('Performance_Metrics') or {}

            node_type = nd.get('MachineType') or cp.get('Node_Type') or alert.device_type or 'Unknown'
            node_name = alert.node_name or ""
            primary_comms = cp.get('Primary_Comms') or ""

            domain = self._get_domain(node_type, node_name, primary_comms)

            tier = self.TIER_RANKING.get(domain, 8)
            topo_score = (9 - tier) * 2000

            status = str(alert.status).lower()
            event_cat = str(alert.event_category).lower()
            loss = float(str(pm.get('PercentLoss', 0)).replace('%', '')) if pm else 0

            sev_score = 0
            if 'down' in status or loss == 100 or 'offline' in event_cat: sev_score = 1000
            elif 'critical' in status or loss > 50: sev_score = 500
            elif 'warning' in status: sev_score = 100

            time_offset = (alert.received_at - earliest_time).total_seconds() if alert.received_at else 0
            time_penalty = min(time_offset, 200)

            final_score = topo_score + sev_score - time_penalty

            scored_alerts.append({
                "alert": alert, "score": final_score,
                "domain": domain, "node_type": node_type, "severity": sev_score
            })

        scored_alerts.sort(key=lambda x: x['score'], reverse=True)
        logger.debug("_determine_patient_zero: winner=%s score=%.1f domain=%s",
                      scored_alerts[0]['alert'].node_name if scored_alerts else 'None',
                      scored_alerts[0]['score'] if scored_alerts else 0,
                      scored_alerts[0]['domain'] if scored_alerts else 'None')
        return scored_alerts[0]['alert'], scored_alerts

    def identify_fleet_outages(self, incidents, threshold=5):
        logger.debug("identify_fleet_outages: checking %d sites with threshold=%d", len(incidents), threshold)
        provider_map = {}
        for site, data in incidents.items():
            comms = data['site_metadata'].get('primary_coms', 'Unknown')
            if comms not in provider_map: provider_map[comms] = []
            if any(sa['domain'] in ["PRIMARY_INTERNET", "COMMS_EQUIPMENT"] for sa in data['dependency_chain']):
                provider_map[comms].append(site)

        fleet_events = []
        for provider, sites in provider_map.items():
            if len(sites) >= threshold and provider != "Unknown":
                logger.info("identify_fleet_outages: FLEET EVENT provider=%s affected=%d sites", provider, len(sites))
                fleet_events.append({
                    "provider": provider, "affected_sites": sites,
                    "event_type": "Regional Provider Outage", "severity": "CRITICAL"
                })
        logger.debug("identify_fleet_outages: found %d fleet events", len(fleet_events))
        return fleet_events

    def generate_chronic_insights(self):
        import pandas as pd
        from datetime import datetime, timedelta

        logger.info("generate_chronic_insights: fetching alerts from last 60 days")
        cutoff = datetime.utcnow() - timedelta(days=60)
        with self.session_factory() as session:
            alerts = session.query(SolarWindsAlert).filter(SolarWindsAlert.received_at >= cutoff).all()
        logger.debug("generate_chronic_insights: found %d total alerts", len(alerts))

        if not alerts:
            logger.info("generate_chronic_insights: no alerts found, returning None")
            return None, None, None

        data = []
        for a in alerts:
            p = a.raw_payload if isinstance(a.raw_payload, dict) else {}
            cp = p.get('Custom_Properties_Universal') or {}
            site = cp.get('Site') or a.mapped_location or 'Unknown'

            if 'resolved' in str(a.status).lower(): continue

            data.append({
                'node_name': a.node_name,
                'device_type': a.device_type,
                'site': site
            })

        df = pd.DataFrame(data)
        if df.empty:
            return None, None, None

        node_counts = df['node_name'].value_counts().reset_index()
        node_counts.columns = ['Node Name', 'Total Incidents (60 Days)']

        node_meta = df[['node_name', 'device_type', 'site']].drop_duplicates(subset=['node_name'])
        f = pd.merge(node_counts, node_meta, left_on='Node Name', right_on='node_name').drop(columns=['node_name'])
        f.rename(columns={'device_type': 'Device Type', 'site': 'Site'}, inplace=True)
        f = f.head(15)

        site_counts = df[df['site'] != 'Unknown']['site'].value_counts().reset_index()
        site_counts.columns = ['Site', 'Total Incidents (60 Days)']
        v = site_counts.head(10)

        r = []
        if not f.empty:
            top_node = f.iloc[0]['Node Name']
            top_node_count = int(f.iloc[0]['Total Incidents (60 Days)'])
            if top_node_count > 5:
                r.append(f"[CRITICAL] **CRITICAL FLAP DETECTED:** Node `{top_node}` is exhibiting severe chronic instability with {top_node_count} logged incidents this week. Recommend immediate hardware diagnostic or circuit test.")

        if not v.empty:
            top_site = v.iloc[0]['Site']
            top_site_count = int(v.iloc[0]['Total Incidents (60 Days)'])
            if top_site_count > 15:
                r.append(f"[HIGH] **REGIONAL DEGRADATION:** The `{top_site}` facility is a current infrastructure hotspot. Recommend dispatching field tech to review local power conditioning and physical transport handoffs.")

        if not r:
            r.append("[OK] Telemetry indicates normal operational limits. Devices are stable and no immediate predictive maintenance is required.")

        f_json = json.loads(f.to_json(orient="records")) if not f.empty else []
        v_json = json.loads(v.to_json(orient="records")) if not v.empty else []

        return f_json, v_json, r

    def calculate_root_cause(self, site_name, data, active_weather, active_cloud, active_bgp, fleet_events=[]):
        logger.info("calculate_root_cause: site=%s domains=%s", site_name, data.get('domains_affected', set()))
        meta = data.get('site_metadata', {})
        domains = data.get('domains_affected', set())

        avg_loss_list = data.get('avg_loss', [])
        avg_cpu_list = data.get('avg_cpu', [])

        avg_loss = sum(avg_loss_list) / len(avg_loss_list) if avg_loss_list else 0
        avg_cpu = sum(avg_cpu_list) / len(avg_cpu_list) if avg_cpu_list else 0
        logger.debug("calculate_root_cause: avg_loss=%.1f avg_cpu=%.1f", avg_loss, avg_cpu)

        score = 0
        evidence_log = []

        if hasattr(self, '_analyze_subnets'):
            blast_radius = self._analyze_subnets(data.get('ips', []))
        else:
            blast_radius = "Unknown"

        p0 = data.get('patient_zero')
        if not p0:
            logger.warning("calculate_root_cause: no patient_zero for site=%s", site_name)
            return "Indeterminate Failure", score, "P3 - MODERATE", evidence_log, blast_radius, "Unknown", "N/A"

        p0_domain = next((sa['domain'] for sa in data.get('dependency_chain', []) if sa['alert'] == p0), "UNKNOWN")

        if len(domains) > 1:
            score += 20
            downstream_count = len(data.get('alerts', [])) - 1
            evidence_log.append(f"Dependency Cascade: Primary failure in [{p0_domain}] triggered isolation of {downstream_count} downstream devices.")

        cause = "Under Investigation"

        fleet_hit = False
        for event in fleet_events:
            if site_name in event['affected_sites']:
                cause = f"Regional Carrier Outage ({event['provider']})"
                score += 100
                evidence_log.append(f"Fleet Correlation: Site is caught in a massive {event['provider']} outage affecting {len(event['affected_sites'])} total sites.")
                fleet_hit = True
                break

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

        bgp_hit = False
        if active_bgp and not cloud_hit and not fleet_hit:
            if "PRIMARY_INTERNET" in domains or "COMMS_EQUIPMENT" in domains or "Service Provider" in str(domains):
                for b in active_bgp:
                    if b.asn in str(meta.get('primary_coms', '')) or b.asn in str(meta.get('secondary_coms', '')):
                        cause = f"Carrier Routing Anomaly (BGP Event on {b.asn})"
                        score += 75
                        evidence_log.append(f"BGP Correlation: Transport provider {b.asn} is actively experiencing a global routing anomaly.")
                        bgp_hit = True
                        break

        if not cloud_hit and not bgp_hit and not fleet_hit:
            if p0_domain == "POWER_SUPPLIES":
                cause = "Catastrophic Facilities/Power Failure causing complete site isolation."
                score += 60
                evidence_log.append(f"Structural Cause: Foundational Power/Environmental node ({p0.node_name}) failed.")
            elif p0_domain in ["PRIMARY_INTERNET", "COMMS_EQUIPMENT"]:
                if avg_loss >= 80 or 'down' in str(p0.status).lower():
                    cause = f"Site Isolation. Hard down on {meta.get('primary_coms', 'Unknown')} transport tier."
                    score += 50
                    evidence_log.append(f"Structural Cause: Core transport/comms equipment ({p0.node_name}) severed communication path.")
                else:
                    cause = f"Severe Transport Congestion ({avg_loss}% Packet Loss)."
            elif p0_domain in ["SCADA", "RTU"]:
                cause = "Isolated OT/SCADA Telemetry Failure."
                score += 30
                evidence_log.append(f"Structural Cause: Field equipment ({p0.node_name}) alarming while Core IT network remains structurally stable.")
            else:
                cause = f"Generalized Infrastructure Degradation originating at {p0.node_name}."

        with SessionLocal() as db:
            site_record = db.query(MonitoredLocation).filter(MonitoredLocation.name == site_name).first()

            if site_record:
                if site_record.under_maintenance and site_record.maintenance_etr:
                    if datetime.utcnow().date() > site_record.maintenance_etr.date():
                        site_record.under_maintenance = False
                        site_record.maintenance_etr = None
                        site_record.maintenance_reason = None
                        db.commit()
                        evidence_log.append("Maintenance Override: Expired maintenance window was automatically cleared.")

                if site_record.lat and site_record.lon:
                    for h in active_weather:
                        if not getattr(h, 'lat', None) or not getattr(h, 'lon', None):
                            if meta.get('district', '').lower() in str(h.location).lower() or site_name.lower() in str(h.location).lower():
                                score += 40
                                evidence_log.append(f"Regional Correlation: Site intersects active {h.hazard_type} warning zone.")
                                if p0_domain in ["POWER_SUPPLIES", "PRIMARY_INTERNET"]: cause = f"Severe Weather ({h.hazard_type}) induced failure of Utility/Carrier."
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
                                if p0_domain in ["POWER_SUPPLIES", "PRIMARY_INTERNET"]: cause = f"Direct Kinetic Impact: Severe Weather ({h.hazard_type}) caused physical infrastructure failure."
                                break

        if data.get('max_alert_level', 99) == 1:
            score += 50
            evidence_log.append("Policy Override: Native Alert Level 1 detected.")

        max_level = data.get('max_alert_level', 99)
        if max_level == 99:
            max_level = 3

        sla_map = {
            1: ("P1 - CRITICAL", "15 Minutes"),
            2: ("P2 - HIGH", "1 Hour"),
            3: ("P3 - MODERATE", "4 Hours"),
            4: ("P4 - LOW", "24 Hours"),
            5: ("P5 - PLANNING", "Best Effort")
        }

        base_priority, sla_time = sla_map.get(max_level, ("P3 - MODERATE", "4 Hours"))
        priority = f"{base_priority} (SLA: {sla_time})"

        latest = data.get('latest_alert')
        if latest and getattr(latest, 'received_at', None) and getattr(p0, 'received_at', None):
            cascade_sec = int((latest.received_at - p0.received_at).total_seconds())
        else:
            cascade_sec = 0

        cascade_str = f"{cascade_sec}s" if cascade_sec > 0 else "Simultaneous"

        logger.info("calculate_root_cause: site=%s cause=%s score=%d priority=%s", site_name, cause, min(score, 100), priority)
        return cause, min(score, 100), priority, evidence_log, blast_radius, p0.node_name, cascade_str

    def analyze_and_cluster(self, active_alerts):
        logger.info("analyze_and_cluster: clustering %d active alerts", len(active_alerts))
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
                    'avg_loss': [],
                    'avg_cpu': [],
                    'ips': [],
                    'max_alert_level': 99,
                    'latest_alert': alert
                }

            incidents[site_name]['alerts'].append(alert)

            if getattr(alert, 'received_at', None) and getattr(incidents[site_name]['latest_alert'], 'received_at', None):
                if alert.received_at > incidents[site_name]['latest_alert'].received_at:
                    incidents[site_name]['latest_alert'] = alert

            try: incidents[site_name]['avg_loss'].append(float(str(pm.get('PercentLoss', 0)).replace('%', '')))
            except (ValueError, TypeError): pass

            try: incidents[site_name]['avg_cpu'].append(float(str(pm.get('CPULoad', 0)).replace('%', '')))
            except (ValueError, TypeError): pass

            if alert.ip_address and alert.ip_address != "Unknown":
                incidents[site_name]['ips'].append(alert.ip_address)

            al = p.get('Normalized_Alert_Level') or cp.get('Alert_Level') or p.get('severity')
            if al:
                try:
                    match = re.search(r'\d+', str(al))
                    if match:
                        incidents[site_name]['max_alert_level'] = min(incidents[site_name]['max_alert_level'], int(match.group()))
                except (ValueError, TypeError): pass

        for site, cluster in incidents.items():
            pz_alert, scored_chain = self._determine_patient_zero(cluster['alerts'])
            cluster['patient_zero'] = pz_alert
            cluster['dependency_chain'] = scored_chain
            for sa in scored_chain: cluster['domains_affected'].add(sa['domain'])

        logger.info("analyze_and_cluster: clustered into %d incidents", len(incidents))
        return incidents
