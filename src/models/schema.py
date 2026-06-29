from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Boolean, JSON
from sqlalchemy.orm import declarative_base
from datetime import datetime

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    role = Column(String, default="analyst", index=True)
    session_token = Column(String, nullable=True, index=True)
    full_name = Column(String, nullable=True)
    job_title = Column(String, nullable=True)
    contact_info = Column(String, nullable=True)
    default_shift = Column(String, default="No Shift")


class Role(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    allowed_pages = Column(JSON)
    allowed_actions = Column(JSON, default=list)
    allowed_site_types = Column(JSON, default=list)


class SavedReport(Base):
    __tablename__ = "saved_reports"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    author = Column(String)
    content = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class FeedSource(Base):
    __tablename__ = "feed_sources"
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, unique=True, index=True)
    name = Column(String)
    is_active = Column(Boolean, default=True)


class Keyword(Base):
    __tablename__ = "keywords"
    id = Column(Integer, primary_key=True, index=True)
    word = Column(String, unique=True, index=True)
    weight = Column(Integer, default=10)


class SystemConfig(Base):
    __tablename__ = "system_config"
    id = Column(Integer, primary_key=True, index=True)
    llm_endpoint = Column(String, default="https://api.openai.com/v1")
    llm_api_key = Column(String, default="")
    llm_model_name = Column(String, default="gpt-4o-mini")
    is_active = Column(Boolean, default=False)
    tech_stack = Column(Text, default="SolarWinds, Cisco SD-WAN, Microsoft Office, Verizon, Cisco")
    monitored_asns = Column(String, default="AS701, AS7922, AS3356")
    rolling_summary = Column(Text, nullable=True)
    rolling_summary_time = Column(DateTime, nullable=True)
    smtp_server = Column(String, nullable=True)
    smtp_port = Column(Integer, default=587)
    smtp_username = Column(String, nullable=True)
    smtp_password = Column(String, nullable=True)
    smtp_sender = Column(String, nullable=True)
    smtp_recipient = Column(String, nullable=True)
    smtp_enabled = Column(Boolean, default=False)
    baseline_override_cyber = Column(Float, default=0.0)
    baseline_override_phys = Column(Float, default=0.0)
    unified_brief = Column(Text, nullable=True)
    unified_brief_time = Column(DateTime, nullable=True)
    last_global_risk = Column(String, nullable=True)
    last_internal_risk = Column(String, nullable=True)
    last_risk_alert_time = Column(DateTime, nullable=True)
    sys_countermeasures = Column(Integer, default=3)
    net_countermeasures = Column(Integer, default=3)

    scoring_mode = Column(String, default="auto")
    cyber_criticality_override = Column(Integer, default=0)
    cyber_lethality_override = Column(Integer, default=0)
    physical_criticality_override = Column(Integer, default=0)
    physical_lethality_override = Column(Integer, default=0)
    internal_criticality_override = Column(Integer, default=0)
    internal_lethality_override = Column(Integer, default=0)
    global_risk_offset = Column(Integer, default=0)
    internal_risk_offset = Column(Integer, default=0)


class ShiftLogEntry(Base):
    __tablename__ = "shift_logs"
    id = Column(Integer, primary_key=True, index=True)
    analyst = Column(String, index=True)
    author_role = Column(String, index=True)
    shift_date = Column(DateTime, default=datetime.utcnow, index=True)
    shift_period = Column(String)
    content = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_deleted = Column(Boolean, default=False, index=True)


class SoftwareAsset(Base):
    __tablename__ = "software_assets"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    last_updated = Column(DateTime, default=datetime.utcnow)


class HardwareAsset(Base):
    __tablename__ = "hardware_assets"
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, nullable=False, index=True)
    asset_name = Column(String, nullable=True, index=True)
    host_type = Column(String, nullable=True)
    ip_addresses = Column(Text, nullable=True)
    operating_system = Column(String, nullable=True)
    os_architecture = Column(String, nullable=True)
    os_family = Column(String, nullable=True)
    os_product = Column(String, nullable=True)
    os_vendor = Column(String, nullable=True)
    os_version = Column(String, nullable=True)
    instances = Column(Integer, nullable=True, default=0)
    critical_instances = Column(Integer, nullable=True, default=0)
    severe_instances = Column(Integer, nullable=True, default=0)
    moderate_instances = Column(Integer, nullable=True, default=0)
    vulnerabilities = Column(Integer, nullable=True, default=0)
    critical_vulnerabilities = Column(Integer, nullable=True, default=0)
    severe_vulnerabilities = Column(Integer, nullable=True, default=0)
    moderate_vulnerabilities = Column(Integer, nullable=True, default=0)
    exploit_count = Column(Integer, nullable=True, default=0)
    malware_count = Column(Integer, nullable=True, default=0)
    raw_risk_score = Column(Float, nullable=True, default=0.0)
    risk_score = Column(Float, nullable=True, default=0.0)
    last_updated = Column(DateTime, default=datetime.utcnow)


class InternalRiskSnapshot(Base):
    __tablename__ = "internal_risk_snapshots"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    score = Column(Float)
    risk_level = Column(String)
    total_assets = Column(Integer)
    total_osint_hits = Column(Integer)
    critical_osint_hits = Column(Integer)
    hw_data_json = Column(Text)
    sw_data_json = Column(Text)


class Article(Base):
    __tablename__ = "articles"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    link = Column(String, unique=True, index=True)
    summary = Column(Text)
    published_date = Column(DateTime, default=datetime.utcnow, index=True)
    source = Column(String, index=True)
    score = Column(Float, default=0.0, index=True)
    category = Column(String, default="General", index=True)
    keywords_found = Column(JSON)
    is_bubbled = Column(Boolean, default=False)
    story_group = Column(String, nullable=True)
    human_feedback = Column(Integer, default=0)
    ai_bluf = Column(Text, nullable=True)
    is_pinned = Column(Boolean, default=False, index=True)


class ExtractedIOC(Base):
    __tablename__ = "extracted_iocs"
    id = Column(Integer, primary_key=True, index=True)
    article_id = Column(Integer, index=True)
    indicator_type = Column(String, index=True)
    indicator_value = Column(String, index=True)
    context = Column(Text, nullable=True)
    detected_at = Column(DateTime, default=datetime.utcnow, index=True)


class CveItem(Base):
    __tablename__ = "cve_items"
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, unique=True, index=True)
    vendor = Column(String, index=True)
    product = Column(String, index=True)
    vulnerability_name = Column(String)
    date_added = Column(DateTime, index=True)
    description = Column(Text)
    required_action = Column(Text)
    due_date = Column(String)


class ElasticEvent(Base):
    __tablename__ = 'elastic_events'
    id = Column(String, primary_key=True)
    timestamp = Column(DateTime, index=True)
    index_name = Column(String)
    severity = Column(String, index=True)
    message = Column(String)
    source_ip = Column(String, nullable=True)
    event_category = Column(String, nullable=True)


class DailyBriefing(Base):
    __tablename__ = "daily_briefings"
    id = Column(Integer, primary_key=True, index=True)
    report_date = Column(DateTime, unique=True, index=True)
    content = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)


class DailyThreatScore(Base):
    __tablename__ = "daily_threat_scores"
    id = Column(Integer, primary_key=True, index=True)
    record_date = Column(DateTime, unique=True, index=True)
    cyber_points = Column(Float, default=0.0)
    physical_points = Column(Float, default=0.0)
    cyber_baseline = Column(Float, default=0.0)
    physical_baseline = Column(Float, default=0.0)


class RegionalHazard(Base):
    __tablename__ = "regional_hazards"
    id = Column(Integer, primary_key=True, index=True)
    hazard_id = Column(String, unique=True, index=True)
    hazard_type = Column(String)
    severity = Column(String)
    title = Column(String)
    description = Column(Text)
    location = Column(String)
    updated_at = Column(DateTime, index=True)


class RegionalOutage(Base):
    __tablename__ = "regional_outages"
    id = Column(Integer, primary_key=True, index=True)
    outage_type = Column(String, index=True)
    provider = Column(String)
    description = Column(Text)
    affected_area = Column(String)
    lat = Column(Float, nullable=True)
    lon = Column(Float, nullable=True)
    radius_km = Column(Float, default=10.0)
    detected_at = Column(DateTime, default=datetime.utcnow)
    is_resolved = Column(Boolean, default=False, index=True)


class CloudOutage(Base):
    __tablename__ = "cloud_outages"
    id = Column(Integer, primary_key=True, index=True)
    provider = Column(String, index=True)
    service = Column(String)
    title = Column(String)
    description = Column(Text)
    link = Column(String)
    is_resolved = Column(Boolean, default=False, index=True)
    updated_at = Column(DateTime, index=True)


class BgpAnomaly(Base):
    __tablename__ = "bgp_anomalies"
    id = Column(Integer, primary_key=True, index=True)
    asn = Column(String, index=True)
    event_type = Column(String)
    description = Column(Text)
    detected_at = Column(DateTime, default=datetime.utcnow)
    is_resolved = Column(Boolean, default=False, index=True)


class SolarWindsAlert(Base):
    __tablename__ = "solarwinds_alerts"
    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String, index=True)
    severity = Column(String)
    node_name = Column(String, index=True)
    ip_address = Column(String)
    status = Column(String, index=True)
    sw_timestamp = Column(String)
    details = Column(Text)
    node_link = Column(String)
    raw_payload = Column(JSON, nullable=True)
    mapped_location = Column(String, nullable=True, index=True)
    received_at = Column(DateTime, default=datetime.utcnow, index=True)
    resolved_at = Column(DateTime, nullable=True, index=True)
    is_dispatched = Column(Boolean, default=False, index=True)
    is_ticketed = Column(Boolean, default=False, index=True)
    is_correlated = Column(Boolean, default=False, index=True)
    ai_root_cause = Column(Text, nullable=True)
    device_type = Column(String, default="Unknown", index=True)
    event_category = Column(String, default="Unknown")


class TimelineEvent(Base):
    __tablename__ = "timeline_events"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source = Column(String, index=True)
    event_type = Column(String, index=True)
    message = Column(String)


class MonitoredLocation(Base):
    __tablename__ = "monitored_locations"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    lat = Column(Float)
    lon = Column(Float)
    loc_type = Column(String, default="General", index=True)
    district = Column(String, default="Central", index=True)
    priority = Column(Integer, default=3, index=True)
    current_spc_risk = Column(String, default="None")
    last_updated = Column(DateTime, default=datetime.utcnow)
    under_maintenance = Column(Boolean, default=False)
    maintenance_etr = Column(DateTime, nullable=True)
    maintenance_reason = Column(Text, nullable=True)
    last_auto_ticket = Column(DateTime, nullable=True)
    last_escalation_ticket = Column(DateTime, nullable=True)
    last_auto_dispatch = Column(DateTime, nullable=True)
    last_escalation_dispatch = Column(DateTime, nullable=True)
    status_modified_by = Column(String, nullable=True)
    status_modified_at = Column(DateTime, nullable=True)


class CrimeIncident(Base):
    __tablename__ = "crime_incidents"
    id = Column(String, primary_key=True, index=True)
    category = Column(String)
    raw_title = Column(String)
    timestamp = Column(DateTime, index=True)
    distance_miles = Column(Float)
    severity = Column(String)
    lat = Column(Float)
    lon = Column(Float)
    is_alert_dispatched = Column(Boolean, default=False, index=True)


class GeoJsonCache(Base):
    __tablename__ = "geojson_cache"
    feed_name = Column(String, primary_key=True, index=True)
    data = Column(JSON)
    updated_at = Column(DateTime, default=datetime.utcnow)


class NodeAlias(Base):
    __tablename__ = "node_aliases"
    id = Column(Integer, primary_key=True, index=True)
    node_pattern = Column(String, index=True)
    mapped_location_name = Column(String)
    confidence_score = Column(Float, default=0.0)
    is_verified = Column(Boolean, default=False)


class UserWeatherPreference(Base):
    __tablename__ = "user_weather_prefs"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True)
    alert_type = Column(String)
