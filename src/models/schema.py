"""SQLAlchemy mappings for operational, identity, authorization, and recovery state.

These models are the runtime schema contract; versioned migrations, including
the frozen first-revision snapshot, define how persisted databases evolve.
"""

from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Boolean, JSON, ForeignKey, Index, text
from sqlalchemy.orm import declarative_base
from datetime import datetime

Base = declarative_base()


class User(Base):
    """Account profile, role reference, recovery mailbox, and durable access history."""
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
    theme = Column(String, default="standard")
    account_type = Column(String(20), nullable=False, default="individual", index=True)
    email = Column(String(254), nullable=True)
    email_normalized = Column(String(254), nullable=True)
    email_verified_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True, index=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_login_at = Column(DateTime, nullable=True, index=True)
    last_activity_at = Column(DateTime, nullable=True, index=True)


Index("uq_users_email_normalized", User.email_normalized, unique=True)


class UserSession(Base):
    """One independently revocable login session per device/browser."""
    __tablename__ = "user_sessions"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    token = Column(String, unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class FailedLoginAttempt(Base):
    """Short-lived record of a failed login for threshold-based security alerts."""
    __tablename__ = "failed_login_attempts"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(128), nullable=False)
    source_ip = Column(String(64), nullable=True)
    attempted_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)


class RegistrationInvite(Base):
    """Email-bound individual invitation with hashed single-use token and revocation state."""
    __tablename__ = "registration_invites"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, nullable=False, index=True)
    role = Column(String, nullable=False, default="analyst")
    token_hash = Column(String, nullable=False, unique=True, index=True)
    created_by = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)
    used_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)
    email = Column(String(254), nullable=False)
    email_normalized = Column(String(254), nullable=False, index=True)
    account_type = Column(String(20), nullable=False, default="individual")


class EmailChangeRequest(Base):
    """Reviewer decision and mailbox-verification lifecycle for a recovery-email change."""
    __tablename__ = "email_change_requests"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    requested_email = Column(String(254), nullable=False)
    requested_email_normalized = Column(String(254), nullable=False, index=True)
    status = Column(String(32), nullable=False, default="pending_review", index=True)
    requested_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    reviewed_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    decision_reason = Column(Text, nullable=True)
    verification_token_hash = Column(String(64), nullable=True, unique=True, index=True)
    verification_expires_at = Column(DateTime, nullable=True)
    verified_at = Column(DateTime, nullable=True)


class PasswordResetRequest(Base):
    """Public reset request evidence and administrator decision history."""
    __tablename__ = "password_reset_requests"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    identifier_hash = Column(String(64), nullable=False, index=True)
    requester_ip = Column(String(64), nullable=True, index=True)
    status = Column(String(32), nullable=False, default="pending_review", index=True)
    requested_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    reviewed_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    decision_reason = Column(Text, nullable=True)
    reset_email_sent_at = Column(DateTime, nullable=True)


class PasswordResetToken(Base):
    """Hashed expiring reset capability issued only after reviewer approval."""
    __tablename__ = "password_reset_tokens"
    id = Column(Integer, primary_key=True, index=True)
    request_id = Column(Integer, ForeignKey("password_reset_requests.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    token_hash = Column(String(64), nullable=False, unique=True, index=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False, index=True)
    used_at = Column(DateTime, nullable=True)


class AccountAuditEvent(Base):
    """Append-only actor/subject event detail for account and recovery actions."""
    __tablename__ = "account_audit_events"
    id = Column(Integer, primary_key=True, index=True)
    actor_user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    subject_user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    event_detail = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)


class SchedulerJobConfig(Base):
    """Persisted validated schedule override and editor metadata for one registry job."""
    __tablename__ = "scheduler_job_config"
    id = Column(Integer, primary_key=True, index=True)
    job_key = Column(String(80), nullable=False, unique=True, index=True)
    schedule_type = Column(String(16), nullable=False, default="interval")
    every_value = Column(Integer, nullable=True)
    unit = Column(String(16), nullable=True)
    run_at = Column(String(5), nullable=True)
    weekday = Column(String(12), nullable=True)
    timezone = Column(String(64), nullable=False, default="America/Chicago")
    enabled = Column(Boolean, nullable=False, default=True)
    updated_by = Column(String(128), nullable=True)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class Role(Base):
    """Named page, tab/action, and site-type grants used by role resolution."""
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    allowed_pages = Column(JSON)
    allowed_actions = Column(JSON, default=list)
    allowed_site_types = Column(JSON, default=list)


class SavedReport(Base):
    """User-saved custom report available through the shared reporting library."""
    __tablename__ = "saved_reports"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    author = Column(String)
    content = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class FeedSource(Base):
    """RSS/Atom source configuration and active-ingestion flag."""
    __tablename__ = "feed_sources"
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, unique=True, index=True)
    name = Column(String)
    is_active = Column(Boolean, default=True)


class Keyword(Base):
    """Persisted article-scoring keyword and its bounded weight."""
    __tablename__ = "keywords"
    id = Column(Integer, primary_key=True, index=True)
    word = Column(String, unique=True, index=True)
    weight = Column(Integer, default=10)


class SystemConfig(Base):
    """Singleton application settings, scoring state, saved briefs, and scheduler revisions."""
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
    global_brief = Column(Text, nullable=True)
    global_brief_time = Column(DateTime, nullable=True)
    internal_brief = Column(Text, nullable=True)
    internal_brief_time = Column(DateTime, nullable=True)
    last_global_risk = Column(String, nullable=True)
    last_internal_risk = Column(String, nullable=True)
    last_risk_alert_time = Column(DateTime, nullable=True)
    sys_countermeasures = Column(Integer, default=3)
    net_countermeasures = Column(Integer, default=3)
    failed_login_alert_enabled = Column(Boolean, default=False, nullable=False)
    failed_login_alert_recipients = Column(Text, default="", nullable=False)
    failed_login_alert_threshold = Column(Integer, default=5, nullable=False)
    failed_login_alert_window_minutes = Column(Integer, default=5, nullable=False)
    failed_login_alert_last_sent = Column(DateTime, nullable=True)

    scoring_mode = Column(String, default="auto")
    cyber_criticality_override = Column(Integer, default=0)
    cyber_lethality_override = Column(Integer, default=0)
    physical_criticality_override = Column(Integer, default=0)
    physical_lethality_override = Column(Integer, default=0)
    internal_criticality_override = Column(Integer, default=0)
    internal_lethality_override = Column(Integer, default=0)
    global_risk_offset = Column(Integer, default=0)
    internal_risk_offset = Column(Integer, default=0)
    alerted_eq_ids = Column(Text, default="[]")
    alerted_wildfire_ids = Column(Text, default="[]")
    wildfire_proximity_state = Column(Text, default="{}")
    llm_context_window = Column(Integer, default=128000)
    public_app_url = Column(String, default="http://localhost:8501")
    permission_catalog_version = Column(Integer, nullable=False, default=0)
    scheduler_revision = Column(Integer, nullable=False, default=0)
    scheduler_applied_revision = Column(Integer, nullable=False, default=0)


class ShiftLogEntry(Base):
    """Shift note with author/role, time scope, and soft-delete state."""
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
    """Software inventory entry used by internal asset-risk matching."""
    __tablename__ = "software_assets"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    last_updated = Column(DateTime, default=datetime.utcnow)


class HardwareAsset(Base):
    """Hardware inventory and vulnerability summary used by internal risk analysis."""
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
    """Point-in-time internal CIS result with serialized hardware/software matches."""
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
    """Ingested/scored intelligence article, analyst feedback, enrichment, and pin state."""
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
    full_content = Column(Text, nullable=True)
    ai_bluf = Column(Text, nullable=True)
    is_pinned = Column(Boolean, default=False, index=True)
    ingested_at = Column(DateTime, default=datetime.utcnow, index=True)
    enrichment_status = Column(String, default="pending", index=True)
    enrichment_attempts = Column(Integer, default=0)
    last_enrichment_error = Column(Text, nullable=True)
    last_enriched_at = Column(DateTime, nullable=True)


class ExtractedIOC(Base):
    """Indicator and contextual match extracted from a source article."""
    __tablename__ = "extracted_iocs"
    id = Column(Integer, primary_key=True, index=True)
    article_id = Column(Integer, index=True)
    indicator_type = Column(String, index=True)
    indicator_value = Column(String, index=True)
    context = Column(Text, nullable=True)
    detected_at = Column(DateTime, default=datetime.utcnow, index=True)


class CveItem(Base):
    """CISA Known Exploited Vulnerability catalog item."""
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
    """Normalized high-severity event imported into the local Elastic cache."""
    __tablename__ = 'elastic_events'
    id = Column(String, primary_key=True)
    timestamp = Column(DateTime, index=True)
    index_name = Column(String)
    severity = Column(String, index=True)
    message = Column(String)
    source_ip = Column(String, nullable=True)
    event_category = Column(String, nullable=True)


class DailyBriefing(Base):
    """Archived Daily Fusion report keyed by its report date."""
    __tablename__ = "daily_briefings"
    id = Column(Integer, primary_key=True, index=True)
    report_date = Column(DateTime, unique=True, index=True)
    content = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)


class DailyThreatScore(Base):
    """Daily external cyber/physical score and displayed baseline values."""
    __tablename__ = "daily_threat_scores"
    id = Column(Integer, primary_key=True, index=True)
    record_date = Column(DateTime, unique=True, index=True)
    cyber_points = Column(Float, default=0.0)
    physical_points = Column(Float, default=0.0)
    cyber_baseline = Column(Float, default=0.0)
    physical_baseline = Column(Float, default=0.0)


class RegionalHazard(Base):
    """Normalized regional weather, earthquake, or wildfire hazard metadata."""
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
    """Provider-reported regional power or connectivity outage record."""
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
    """Provider status incident with active/resolved lifecycle state."""
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
    """RIPE/route-visibility anomaly with resolution state."""
    __tablename__ = "bgp_anomalies"
    id = Column(Integer, primary_key=True, index=True)
    asn = Column(String, index=True)
    event_type = Column(String)
    description = Column(Text)
    detected_at = Column(DateTime, default=datetime.utcnow)
    is_resolved = Column(Boolean, default=False, index=True)


class SolarWindsAlert(Base):
    """Normalized SolarWinds event and persisted acknowledgement/dispatch workflow."""
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
    needs_dispatch = Column(Boolean, nullable=False, default=False, server_default=text("0"))
    ai_root_cause = Column(Text, nullable=True)
    device_type = Column(String, default="Unknown", index=True)
    event_category = Column(String, default="Unknown")
    acknowledged_by = Column(String, nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)
    dispatched_by = Column(String, nullable=True)
    dispatched_at = Column(DateTime, nullable=True)
    onpage_sent_at = Column(DateTime, nullable=True)


class TimelineEvent(Base):
    """Operational timeline event with optional site scope."""
    __tablename__ = "timeline_events"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source = Column(String, index=True)
    event_type = Column(String, index=True)
    message = Column(String)
    site_name = Column(String(255), nullable=True, index=True)


class MonitoredLocation(Base):
    """Monitored facility coordinates, site type, maintenance, and escalation metadata."""
    __tablename__ = "monitored_locations"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    lat = Column(Float)
    lon = Column(Float)
    loc_type = Column(String, default="General", index=True)
    district = Column(String, default="Central", index=True)
    priority = Column(String, default="P3-Moderate", index=True)
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
    """Geocoded Little Rock CAD incident with proximity-notification state."""
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
    """Cached provider GeoJSON layer and its last-refresh timestamp."""
    __tablename__ = "geojson_cache"
    feed_name = Column(String, primary_key=True, index=True)
    data = Column(JSON)
    updated_at = Column(DateTime, default=datetime.utcnow)


class NodeAlias(Base):
    """Operator mapping from a node-name pattern to a monitored location."""
    __tablename__ = "node_aliases"
    id = Column(Integer, primary_key=True, index=True)
    node_pattern = Column(String, index=True)
    mapped_location_name = Column(String)
    confidence_score = Column(Float, default=0.0)
    is_verified = Column(Boolean, default=False)


class UserWeatherPreference(Base):
    """Per-user NWS alert-type selection for Regional Grid notifications."""
    __tablename__ = "user_weather_prefs"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True)
    alert_type = Column(String)
