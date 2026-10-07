import logging

logger = logging.getLogger(__name__)
import requests
import bcrypt
import uuid
import re
import json
import os
import hashlib
import secrets
import math
from urllib.parse import quote, urlparse
import ipaddress
from datetime import datetime, timedelta
from sqlalchemy import text, or_, func
from sqlalchemy.types import Boolean, DateTime
from zoneinfo import ZoneInfo
# Import your DB setup and models
from src.database import (
    SessionLocal, Article, FeedSource, Keyword, SystemConfig, CveItem,
    RegionalHazard, CloudOutage, User, UserSession, FailedLoginAttempt, RegistrationInvite,
    EmailChangeRequest, PasswordResetRequest, PasswordResetToken, AccountAuditEvent,
    SchedulerJobConfig, Role, SavedReport, DailyBriefing,
    ExtractedIOC, MonitoredLocation, SolarWindsAlert, TimelineEvent,
    RegionalOutage, BgpAnomaly, GeoJsonCache, DailyThreatScore, ShiftLogEntry,
    SoftwareAsset, HardwareAsset, InternalRiskSnapshot, CrimeIncident,
    ElasticEvent, UserWeatherPreference, NodeAlias
)
from src.core.permissions import (
    ACTION_KEYS, ADMIN_ACTIONS, PAGE_KEYS, TAB_KEYS,
)
from src.core.scheduler_registry import JOB_REGISTRY, default_schedule, validate_schedule

LOCAL_TZ = ZoneInfo("America/Chicago")
VALID_THEMES = {
    "standard", "noc-terminal", "high-contrast", "cyberpunk", "solarized-dark", "midnight-ocean",
    "arctic-command", "ember-watch", "forest-ops", "amethyst-grid", "slate-steel", "paper-light",
    "nordic-frost", "dracula-console", "synthwave", "desert-signal", "olive-command", "mono-ops",
    "rose-pine", "oceanic-teal", "copper-wire",
}


class TTLCache:
    """Small process-local TTL cache for repeatedly requested service data."""
    def __init__(self, ttl: int = 300, max_entries: int = 128):
        self.ttl = ttl
        self.max_entries = max_entries
        self._store: dict = {}
        self._timestamps: dict = {}

    def __call__(self, func):
        def wrapper(*args, **kwargs):
            key = str(args) + str(sorted(kwargs.items()))
            now = datetime.utcnow().timestamp()
            if key in self._store and (now - self._timestamps.get(key, 0)) < self.ttl:
                return self._store[key]
            result = func(*args, **kwargs)
            if len(self._store) >= self.max_entries:
                oldest = min(self._timestamps, key=self._timestamps.get)
                del self._store[oldest]
                del self._timestamps[oldest]
            self._store[key] = result
            self._timestamps[key] = now
            return result
        wrapper.clear = self.clear
        return wrapper

    def clear(self):
        self._store.clear()
        self._timestamps.clear()


def sanitize_text(text: str) -> str:
    """Strip supplementary Unicode planes and unwanted characters from text."""
    text = re.sub(r'[\U00010000-\U0010ffff]', '', text)
    text = text.replace('?', '').strip()
    return text


# ==========================================
# 0. CORE UTILITIES & CACHED MAPPERS
# ==========================================

class DotDict(dict):
    """Utility class to allow dot.notation access to dicts for seamless UI integration."""
    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

import re

def priority_tier(p):
    """Extract numeric tier (1-5) from a priority string like 'P1-Critical' or int."""
    if p is None: return 3
    if isinstance(p, (int, float)):
        return int(p)
    m = re.search(r'\d+', str(p))
    return int(m.group()) if m else 3

def to_dotdict(obj):
    if not obj: return None
    return DotDict({c.name: getattr(obj, c.name) for c in obj.__table__.columns})

def to_dotdict_list(objs):
    return [to_dotdict(obj) for obj in objs]

def central_now():
    """Return current time in Central timezone."""
    return datetime.now(LOCAL_TZ)

def utc_now():
    """Return current UTC time."""
    return datetime.utcnow()

def _get_attr(obj, attr, default=None):
    """Get attribute from either an ORM object or a dict."""
    if isinstance(obj, dict):
        return obj.get(attr, default)
    return getattr(obj, attr, default)

def format_central(dt):
    """Format a UTC datetime as Central time string."""
    if dt is None:
        return "Unknown"
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
        except (ValueError, TypeError):
            return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=ZoneInfo("UTC"))
    return dt.astimezone(LOCAL_TZ).strftime('%Y-%m-%d %H:%M:%S')

from sqlalchemy.exc import OperationalError

@TTLCache(ttl=300)
def get_cached_config():
    with SessionLocal() as db:
        try:
            config = db.query(SystemConfig).first()
        except OperationalError:
            db.rollback()
            config = db.execute(text("SELECT * FROM system_config LIMIT 1")).first()
            if config:
                return to_dotdict(config)
            config = SystemConfig(); db.add(config); db.commit(); db.refresh(config)
        if not config:
            config = SystemConfig(); db.add(config); db.commit(); db.refresh(config)
        return to_dotdict(config)

@TTLCache(ttl=600, max_entries=1)
def get_cached_locations():
    with SessionLocal() as db:
        return to_dotdict_list(db.query(MonitoredLocation).all())

@TTLCache(ttl=120, max_entries=1)
def get_cached_geojson():
    feed_names = ("spc_day1", "spc_day2", "spc_day3", "nws_ar", "nws_oos", "usgs_ar", "usgs_oos")
    with SessionLocal() as db:
        records = db.query(GeoJsonCache).filter(GeoJsonCache.feed_name.in_(feed_names)).all()
    feeds = {record.feed_name: record.data for record in records}
    return tuple(feeds.get(name) for name in feed_names)


@TTLCache(ttl=120, max_entries=1)
def get_cached_geojson_status():
    """Return freshness metadata without transferring the feed payload again."""
    feed_names = ("spc_day1", "spc_day2", "spc_day3", "nws_ar", "nws_oos", "usgs_ar", "usgs_oos")
    with SessionLocal() as db:
        records = db.query(GeoJsonCache).filter(GeoJsonCache.feed_name.in_(feed_names)).all()
    return {
        name: {
            "updated_at": record.updated_at.isoformat() if record.updated_at else None,
            "feature_count": len((record.data or {}).get("features", [])) if isinstance(record.data, dict) else 0,
            "status": "empty" if not record.data else (
                "stale" if not record.updated_at or datetime.utcnow() - record.updated_at > timedelta(minutes=15) else "ok"
            ),
        }
        for name in feed_names
        for record in records
        if record.feed_name == name
    }

@TTLCache(ttl=3600, max_entries=1)
def get_ar_counties_mapping():
    """Fetches and caches the official US County boundaries, filtering for Arkansas (FIPS 05)."""
    try:
        url = "https://raw.githubusercontent.com/plotly/datasets/master/geojson-counties-fips.json"
        resp = requests.get(url, timeout=10)
        data = resp.json()
        del resp
        ar_counties = {}
        for f in data.get("features", []):
            if f.get("properties", {}).get("STATE") == "05":
                name = f["properties"].get("NAME", "").lower()
                ar_counties[name] = f["geometry"]
        del data
        return ar_counties
    except Exception as e:
        logger.error("Error fetching county GeoJSON: %s", e)
        return {}

@TTLCache(ttl=3600, max_entries=1)
def get_regional_counties_mapping():
    """Fetches and caches all US county boundaries keyed by 5-digit FIPS code."""
    try:
        url = "https://raw.githubusercontent.com/plotly/datasets/master/geojson-counties-fips.json"
        resp = requests.get(url, timeout=10)
        data = resp.json()
        del resp
        counties = {}
        for f in data.get("features", []):
            props = f.get("properties", {})
            state_fips = props.get("STATE", "")
            county_fips = props.get("COUNTY", "")
            fips = state_fips + county_fips
            name = props.get("NAME", "").lower()
            counties[fips] = {
                "state_fips": state_fips,
                "geometry": f["geometry"],
                "name": name,
            }
        del data
        return counties
    except Exception as e:
        logger.error("Error fetching county GeoJSON: %s", e)
        return {}

def get_all_site_types(db=None):
    DEFAULT_SITE_TYPES = ["NOC", "SOC", "Data Center", "Field Office", "HQ", "Remote Site", "Cloud"]
    from src.database import MonitoredLocation
    if db is None:
        with SessionLocal() as session:
            db_types = [t[0] for t in session.query(MonitoredLocation.loc_type).distinct().all() if t[0]]
    else:
        db_types = [t[0] for t in db.query(MonitoredLocation.loc_type).distinct().all() if t[0]]
    seen = set()
    merged = []
    for t in DEFAULT_SITE_TYPES + db_types:
        if t not in seen:
            seen.add(t)
            merged.append(t)
    return merged

def set_cluster_dispatch(alert_ids, is_dispatched, dispatched_by="unknown"):
    with SessionLocal() as db:
        now_utc = datetime.utcnow()
        alerts = db.query(SolarWindsAlert).filter(SolarWindsAlert.id.in_(alert_ids)).all()
        updated_sites = set()
        for a in alerts:
            a.is_dispatched = is_dispatched
            a.needs_dispatch = False
            a.dispatched_by = dispatched_by
            a.dispatched_at = now_utc
            if a.mapped_location:
                updated_sites.add(a.mapped_location)
        for site in updated_sites:
            loc = db.query(MonitoredLocation).filter(MonitoredLocation.name == site).first()
            if loc:
                loc.status_modified_by = dispatched_by
                loc.status_modified_at = now_utc
        db.commit()
        return True

def set_site_needs_dispatch(site_name, needs_dispatch, modified_by="unknown"):
    from src.database import MonitoredLocation, SolarWindsAlert

    with SessionLocal() as db:
        location = db.query(MonitoredLocation).filter_by(name=site_name).first()
        if not location:
            return None

        alerts = db.query(SolarWindsAlert).filter(
            SolarWindsAlert.mapped_location == site_name,
            SolarWindsAlert.status != "Resolved",
            SolarWindsAlert.is_correlated == False,
        ).all()
        if needs_dispatch and not alerts:
            raise ValueError("Needs Dispatch requires at least one active site alert.")

        for alert in alerts:
            alert.needs_dispatch = needs_dispatch
            if needs_dispatch:
                alert.is_dispatched = False

        now_utc = datetime.utcnow()
        location.status_modified_by = modified_by
        location.status_modified_at = now_utc
        db.commit()
        return len(alerts)
      
def get_shift_logs(role_filter="All", start_date=None, end_date=None):
    with SessionLocal() as db:
        query = db.query(ShiftLogEntry).filter(ShiftLogEntry.is_deleted == False)
        
        if role_filter and role_filter != "All":
            query = query.filter(ShiftLogEntry.author_role == role_filter)
            
        if start_date:
            if start_date.tzinfo is None:
                start_date = start_date.replace(tzinfo=ZoneInfo("America/Chicago"))
            start_utc = start_date.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
            query = query.filter(ShiftLogEntry.created_at >= start_utc)
        if end_date:
            if end_date.tzinfo is None:
                end_date = end_date.replace(tzinfo=ZoneInfo("America/Chicago"))
            end_utc = end_date.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
            query = query.filter(ShiftLogEntry.created_at < end_utc + timedelta(days=1))
            
        logs = query.order_by(ShiftLogEntry.created_at.desc()).all()
        return to_dotdict_list(logs)

def save_shift_log(analyst, role, shift_period, content, custom_date=None):
    from datetime import datetime
    from zoneinfo import ZoneInfo
    with SessionLocal() as db:
        new_log = ShiftLogEntry(
            analyst=analyst, 
            author_role=role, 
            shift_period=shift_period, 
            content=content
        )
        
        # If a custom date was selected (No Shift), override the timestamp
        if custom_date:
            # Combine the selected date with the current time so it orders nicely
            local_dt = datetime.combine(custom_date, datetime.now(ZoneInfo("America/Chicago")).time()).replace(tzinfo=ZoneInfo("America/Chicago"))
            utc_dt = local_dt.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
            new_log.created_at = utc_dt
            new_log.shift_date = utc_dt
            
        db.add(new_log)
        db.commit()
        return True

def set_site_maintenance(site_name, is_maint, etr_date, reason, modified_by=None):
    from src.database import SessionLocal, MonitoredLocation
    from datetime import datetime
    with SessionLocal() as db:
        loc = db.query(MonitoredLocation).filter_by(name=site_name).first()
        if loc:
            loc.under_maintenance = is_maint
            loc.maintenance_etr = datetime.combine(etr_date, datetime.min.time()) if etr_date else None
            loc.maintenance_reason = reason
            if modified_by:
                loc.status_modified_by = modified_by
                loc.status_modified_at = datetime.utcnow()
            db.commit()
    get_cached_locations.clear()


def auto_clear_expired_maintenance():
    """Clear maintenance status after 11:59 PM Central on the ETR date. Returns list of cleared site names."""
    from src.database import SessionLocal, MonitoredLocation
    from datetime import datetime
    from zoneinfo import ZoneInfo
    ct = ZoneInfo("America/Chicago")
    now_ct = datetime.now(ct)
    now_utc = datetime.utcnow()
    cleared = []
    with SessionLocal() as db:
        sites = db.query(MonitoredLocation).filter(
            MonitoredLocation.under_maintenance == True,
            MonitoredLocation.maintenance_etr.isnot(None),
        ).all()
        for loc in sites:
            etr = loc.maintenance_etr
            etr_date = etr.date() if hasattr(etr, 'date') else etr
            if not etr_date:
                continue
            etr_end_of_day = datetime(etr_date.year, etr_date.month, etr_date.day, 23, 59, 59, tzinfo=ct)
            if now_ct > etr_end_of_day:
                loc.under_maintenance = False
                loc.maintenance_etr = None
                loc.maintenance_reason = None
                loc.status_modified_by = "System (ETR Expired)"
                loc.status_modified_at = now_utc
                cleared.append(loc.name)
        if cleared:
            db.commit()
    if cleared:
        get_cached_locations.clear()
    return cleared


@TTLCache(ttl=3600) # Cache forecasts for 1 hour to prevent rate limiting
def get_nws_forecast(lat, lon):
    """Fetches the 7-day forecast for a specific coordinate using the NWS API."""
    headers = {
        "User-Agent": "NOC_IFC_Weather_Module (noc-fusion@localhost)" # NWS requires a User-Agent
    }
    try:
        # Step 1: Get the gridpoints URL
        point_url = f"https://api.weather.gov/points/{lat},{lon}"
        point_res = requests.get(point_url, headers=headers, timeout=10)
        point_res.raise_for_status()
        
        forecast_url = point_res.json().get("properties", {}).get("forecast")
        if not forecast_url: return None
        
        # Step 2: Get the actual forecast
        forecast_res = requests.get(forecast_url, headers=headers, timeout=10)
        forecast_res.raise_for_status()
        
        periods = forecast_res.json().get("properties", {}).get("periods", [])
        return periods
    except Exception as e:
        logger.error("NWS Forecast Error for %s, %s: %s", lat, lon, e)
        return None


def get_filtered_notification_alerts(username, ar_data, oos_data, locs):
    from shapely.geometry import Point, shape
    """
    Retrieves weather alerts based on user preferences.
    - Arkansas Alerts: Returns ALL alerts matching preferences.
    - Out-of-State Alerts: Returns ONLY alerts that geographically intersect a monitored facility.
    """
    from src.database import SessionLocal, UserWeatherPreference
    
    with SessionLocal() as db:
        prefs = db.query(UserWeatherPreference).filter_by(username=username).all()
        alert_types = [p.alert_type for p in prefs]
        
    if not alert_types:
        return []
        
    valid_alerts = []
    
    # 1. Process Arkansas Data (Keep everything matching preferences)
    if ar_data and 'features' in ar_data:
        for f in ar_data['features']:
            props = f.get('properties', {})
            event = props.get('event')
            if event in alert_types:
                valid_alerts.append({
                    "Event": event,
                    "Affected Area": props.get('areaDesc', 'Unknown'),
                    "Expires": props.get('expires', 'Unknown'),
                    "Description": props.get('description', '')
                })
                
    # 2. Process OOS Data (Geofence constraint applied)
    if oos_data and 'features' in oos_data:
        for f in oos_data['features']:
            props = f.get('properties', {})
            event = props.get('event')
            if event in alert_types:
                geom = f.get('geometry')
                if not geom: continue
                try:
                    poly = shape(geom)
                    poly_bounds = poly.bounds  # (minx, miny, maxx, maxy)
                    intersects = False
                    for l in locs:
                        if not (poly_bounds[0] <= l.lon <= poly_bounds[2] and poly_bounds[1] <= l.lat <= poly_bounds[3]):
                            continue
                        pt = Point(l.lon, l.lat)
                        if poly.intersects(pt):
                            intersects = True
                            break
                            
                    if intersects:
                        valid_alerts.append({
                            "Event": event,
                            "Affected Area": props.get('areaDesc', 'Unknown'),
                            "Expires": props.get('expires', 'Unknown'),
                            "Description": props.get('description', '')
                        })
                except Exception:
                    pass
                    
    # Deduplicate alerts to prevent spam (NWS sometimes issues redundant polygons)
    seen = set()
    unique_alerts = []
    for a in valid_alerts:
        key = f"{a['Event']}_{a['Affected Area']}_{a['Expires']}"
        if key not in seen:
            seen.add(key)
            unique_alerts.append(a)
            
    return unique_alerts

# ==========================================
# 1. AUTHENTICATION & USER PROFILE
# ==========================================

def get_role_permissions(role_name, db=None):
    """Return the effective grants using one caller-owned session when available."""
    normalized_role = str(role_name or "").strip().casefold()

    def full_access(session=None):
        return {
            "allowed_pages": list(PAGE_KEYS),
            "allowed_actions": list(ADMIN_ACTIONS),
            "allowed_site_types": get_all_site_types(session),
        }

    if normalized_role in {"admin", "administrator"}:
        return full_access(db)

    def lookup(session):
        role = session.query(Role).filter(func.lower(Role.name) == normalized_role).first()
        if not role:
            return {"allowed_pages": [], "allowed_actions": [], "allowed_site_types": []}
        return {
            "allowed_pages": list(role.allowed_pages or []),
            "allowed_actions": list(role.allowed_actions or []),
            "allowed_site_types": list(role.allowed_site_types or []),
        }

    if db is not None:
        return lookup(db)
    with SessionLocal() as session:
        return lookup(session)


def _attach_recovery_email_state(user_view, user_row, db):
    if str(user_row.account_type or "individual") == "display":
        user_view.recovery_email_status = "exempt"
        user_view.pending_email = None
        return user_view
    request = db.query(EmailChangeRequest).filter(
        EmailChangeRequest.user_id == user_row.id,
        EmailChangeRequest.status.in_(["pending_review", "pending_verification"]),
    ).order_by(EmailChangeRequest.requested_at.desc()).first()
    if request and request.status == "pending_review":
        user_view.recovery_email_status = "pending_approval"
    elif request:
        user_view.recovery_email_status = "pending_verification"
    elif user_row.email_verified_at:
        user_view.recovery_email_status = "verified"
    elif user_row.email:
        user_view.recovery_email_status = "unverified"
    else:
        user_view.recovery_email_status = "missing"
    user_view.pending_email = request.requested_email if request else None
    return user_view


def authenticate_user(username, password):
    with SessionLocal() as db:
        user = db.query(User).filter(User.username == username).first()
        if (user and user.is_active and user.password_hash
                and bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8'))):
            new_token = str(uuid.uuid4())
            now = datetime.utcnow()
            user.last_login_at = now
            user.last_activity_at = now
            db.add(UserSession(user_id=user.id, token=new_token))
            db.commit()
            u = to_dotdict(user)
            _attach_recovery_email_state(u, user, db)
            perms = get_role_permissions(u.role or "analyst", db=db)
            u.allowed_pages = perms["allowed_pages"]
            u.allowed_actions = perms["allowed_actions"]
            u.allowed_site_types = perms["allowed_site_types"]
            return u, new_token
        return None, None


def _normalize_failed_login_alert_recipients(value):
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ValueError("Failed login alert recipients must be a text list of email addresses.")

    email_pattern = re.compile(
        r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
        r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
        r"[A-Za-z]{2,63}$"
    )
    recipients = []
    seen = set()
    for candidate in re.split(r"[,;\n]+", value):
        address = candidate.strip()
        if not address:
            continue
        if len(address) > 254 or not email_pattern.fullmatch(address):
            raise ValueError(f"Invalid failed login alert email address: {address[:80]}")
        normalized = address.casefold()
        if normalized not in seen:
            recipients.append(address)
            seen.add(normalized)
    return ", ".join(recipients)


def record_failed_login_attempt(username, source_ip=None):
    """Persist enabled-alert login failures and claim at most one alert per window."""
    now = datetime.utcnow()
    with SessionLocal() as db:
        config = db.query(SystemConfig).first()
        if not config:
            logger.debug("Failed-login alerting skipped because system configuration is missing.")
            return None
        if not config.failed_login_alert_enabled:
            logger.debug("Failed-login alerting is disabled; attempt not retained for alerting.")
            return None

        try:
            recipients = _normalize_failed_login_alert_recipients(
                config.failed_login_alert_recipients
            )
        except ValueError:
            logger.warning("Failed login alerts are enabled but recipient configuration is invalid.")
            return None
        if not recipients:
            logger.warning("Failed login alerts are enabled but no recipients are configured.")
            return None

        try:
            threshold = int(config.failed_login_alert_threshold or 5)
        except (TypeError, ValueError):
            threshold = 5
        threshold = max(2, min(threshold, 100))
        try:
            window_minutes = int(config.failed_login_alert_window_minutes or 5)
        except (TypeError, ValueError):
            window_minutes = 5
        window_minutes = max(1, min(window_minutes, 60))

        submitted_username = "" if username is None else str(username)
        safe_username = "".join(
            character if character.isprintable() else " "
            for character in submitted_username
        )[:128] or "(blank)"
        safe_source_ip = None
        if source_ip:
            try:
                safe_source_ip = str(ipaddress.ip_address(str(source_ip)))[:64]
            except ValueError:
                safe_source_ip = None

        db.query(FailedLoginAttempt).filter(
            FailedLoginAttempt.attempted_at < now - timedelta(hours=24)
        ).delete(synchronize_session=False)
        db.add(FailedLoginAttempt(
            username=safe_username,
            source_ip=safe_source_ip,
            attempted_at=now,
        ))
        db.flush()

        cutoff = now - timedelta(minutes=window_minutes)
        recent_attempts = db.query(FailedLoginAttempt).filter(
            FailedLoginAttempt.attempted_at >= cutoff
        ).order_by(FailedLoginAttempt.attempted_at.asc(), FailedLoginAttempt.id.asc()).all()
        logger.info(
            "Failed-login attempt recorded window_count=%d threshold=%d window_minutes=%d",
            len(recent_attempts), threshold, window_minutes,
        )
        if len(recent_attempts) < threshold:
            db.commit()
            return None

        # The conditional update is a cross-worker claim: concurrent requests can
        # only claim this alert window once, even when the API has multiple workers.
        claimed = db.query(SystemConfig).filter(
            SystemConfig.id == config.id,
            SystemConfig.failed_login_alert_enabled.is_(True),
            or_(
                SystemConfig.failed_login_alert_last_sent.is_(None),
                SystemConfig.failed_login_alert_last_sent <= cutoff,
            ),
        ).update(
            {SystemConfig.failed_login_alert_last_sent: now},
            synchronize_session=False,
        )
        if not claimed:
            logger.info(
                "Failed-login threshold reached but an alert is already claimed for this window "
                "(attempts=%d threshold=%d window_minutes=%d).",
                len(recent_attempts), threshold, window_minutes,
            )
            db.commit()
            return None

        alert = {
            "recipients": recipients,
            "threshold": threshold,
            "window_minutes": window_minutes,
            "triggered_at": now.isoformat(timespec="seconds") + "Z",
            "attempts": [
                {
                    "username": attempt.username,
                    "source_ip": attempt.source_ip,
                    "attempted_at": attempt.attempted_at.isoformat(timespec="seconds") + "Z",
                }
                for attempt in recent_attempts
            ],
        }
        db.commit()
        logger.warning(
            "Failed-login alert threshold claimed attempts=%d threshold=%d window_minutes=%d",
            len(recent_attempts), threshold, window_minutes,
        )
        return alert


def _invite_token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


EMAIL_ADDRESS_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)


def normalize_user_email(value: str) -> tuple[str, str]:
    email = str(value or "").strip()
    if not email or len(email) > 254 or not EMAIL_ADDRESS_PATTERN.fullmatch(email):
        raise ValueError("Enter a valid email address.")
    return email, email.casefold()


def create_registration_invite(username: str, email: str, role: str, created_by: str, ttl_hours: int = 72):
    username = username.strip()
    role = role.strip()
    display_email, normalized_email = normalize_user_email(email)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{2,63}", username):
        raise ValueError("Username must be 3-64 characters and contain only letters, numbers, '.', '_' or '-'.")
    if not role or len(role) > 64:
        raise ValueError("A valid role is required.")
    ttl_hours = max(1, min(int(ttl_hours), 14 * 24))
    raw_token = secrets.token_urlsafe(32)
    now = datetime.utcnow()
    with SessionLocal() as db:
        if db.query(User).filter(User.username == username).first():
            raise ValueError("That username is already registered.")
        if db.query(User).filter(User.email_normalized == normalized_email).first():
            raise ValueError("That email address is already associated with an account.")
        if db.query(EmailChangeRequest).filter(
            EmailChangeRequest.requested_email_normalized == normalized_email,
            EmailChangeRequest.status.in_(["pending_review", "pending_verification"]),
        ).first():
            raise ValueError("That email address is pending recovery-email approval for another account.")
        if not db.query(Role).filter(Role.name == role).first():
            raise ValueError("That role does not exist.")
        same_username_pending = db.query(RegistrationInvite).filter(
            RegistrationInvite.username == username,
            RegistrationInvite.used_at.is_(None),
            RegistrationInvite.revoked_at.is_(None),
        ).all()
        other_email_invite = db.query(RegistrationInvite).filter(
            RegistrationInvite.email_normalized == normalized_email,
            RegistrationInvite.used_at.is_(None),
            RegistrationInvite.revoked_at.is_(None),
            RegistrationInvite.expires_at > now,
            RegistrationInvite.username != username,
        ).first()
        if other_email_invite:
            raise ValueError("That email address already has a pending invitation.")
        for old_invite in same_username_pending:
            old_invite.used_at = now
        db.add(RegistrationInvite(
            username=username,
            role=role,
            email=display_email,
            email_normalized=normalized_email,
            account_type="individual",
            token_hash=_invite_token_hash(raw_token),
            created_by=created_by,
            created_at=now,
            expires_at=now + timedelta(hours=ttl_hours),
        ))
        db.commit()
    return raw_token, now + timedelta(hours=ttl_hours)


def get_registration_invite(raw_token: str):
    if not raw_token:
        return None
    with SessionLocal() as db:
        invite = db.query(RegistrationInvite).filter(
            RegistrationInvite.token_hash == _invite_token_hash(raw_token),
            RegistrationInvite.used_at.is_(None),
            RegistrationInvite.revoked_at.is_(None),
            RegistrationInvite.expires_at > datetime.utcnow(),
        ).first()
        if not invite:
            return None
        return {
            "username": invite.username,
            "role": invite.role,
            "email": invite.email,
            "expires_at": invite.expires_at.isoformat(),
        }


def get_pending_registration_invites():
    now = datetime.utcnow()
    with SessionLocal() as db:
        rows = db.query(RegistrationInvite).filter(
            RegistrationInvite.used_at.is_(None),
            RegistrationInvite.revoked_at.is_(None),
            RegistrationInvite.expires_at > now,
        ).order_by(RegistrationInvite.created_at.desc()).all()
        return [{
            "id": invite.id,
            "username": invite.username,
            "email": invite.email,
            "role": invite.role,
            "created_at": invite.created_at.isoformat() if invite.created_at else None,
            "expires_at": invite.expires_at.isoformat(),
            "created_by": invite.created_by,
            "revoked_at": invite.revoked_at.isoformat() if invite.revoked_at else None,
        } for invite in rows]


def revoke_registration_invite(invite_id, actor_user_id=None):
    now = datetime.utcnow()
    with SessionLocal() as db:
        invite = db.query(RegistrationInvite).filter(
            RegistrationInvite.id == invite_id,
            RegistrationInvite.used_at.is_(None),
            RegistrationInvite.revoked_at.is_(None),
        ).first()
        if not invite:
            return False
        invite.revoked_at = now
        _audit_account_event(
            db, "registration_invite_revoked", actor_user_id=actor_user_id,
            detail={"invite_id": invite.id, "username": invite.username},
        )
        db.commit()
        return True


def complete_registration(raw_token, password, full_name, job_title, contact_info, default_shift, theme="standard"):
    if not raw_token or len(password or "") < 12:
        raise ValueError("Password must be at least 12 characters.")
    if theme not in VALID_THEMES:
        raise ValueError("Invalid theme.")
    now = datetime.utcnow()
    with SessionLocal() as db:
        invite = db.query(RegistrationInvite).filter(
            RegistrationInvite.token_hash == _invite_token_hash(raw_token),
            RegistrationInvite.used_at.is_(None),
            RegistrationInvite.revoked_at.is_(None),
            RegistrationInvite.expires_at > now,
        ).first()
        if not invite:
            raise ValueError("This registration link is invalid, expired, or already used.")
        if db.query(User).filter(User.username == invite.username).first():
            invite.used_at = now
            db.commit()
            raise ValueError("That registration has already been completed.")
        user = User(
            username=invite.username,
            password_hash=bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8"),
            role=invite.role,
            account_type="individual",
            email=invite.email,
            email_normalized=invite.email_normalized,
            email_verified_at=now,
            is_active=True,
            created_at=now,
            last_login_at=now,
            last_activity_at=now,
            full_name=(full_name or "").strip(),
            job_title=(job_title or "").strip(),
            contact_info=(contact_info or "").strip(),
            default_shift=(default_shift or "No Shift").strip(),
            theme=theme,
        )
        new_token = str(uuid.uuid4())
        user.session_token = new_token
        invite.used_at = now
        db.add(user)
        db.flush()
        db.add(UserSession(user_id=user.id, token=new_token))
        db.commit()
        u = to_dotdict(user)
        _attach_recovery_email_state(u, user, db)
        perms = get_role_permissions(u.role or "analyst", db=db)
        u.allowed_pages = perms["allowed_pages"]
        u.allowed_actions = perms["allowed_actions"]
        u.allowed_site_types = perms["allowed_site_types"]
        return u, new_token

def get_user_by_token(token):
    if not token:
        return None
    with SessionLocal() as db:
        user = db.query(User).join(UserSession, UserSession.user_id == User.id).filter(
            UserSession.token == token
        ).first()
        if not user:
            # Compatibility for sessions issued before user_sessions existed.
            user = db.query(User).filter(User.session_token == token).first()
        if not user or not user.is_active:
            return None

        now = datetime.utcnow()
        if not user.last_activity_at or user.last_activity_at <= now - timedelta(minutes=5):
            user.last_activity_at = now
            db.commit()

        u = to_dotdict(user)
        _attach_recovery_email_state(u, user, db)
        perms = get_role_permissions(u.role or "analyst", db=db)
        u.allowed_pages = perms["allowed_pages"]
        u.allowed_actions = perms["allowed_actions"]
        u.allowed_site_types = perms["allowed_site_types"]
        return u

def update_user_profile(username, full_name, job_title, contact_info, old_pwd, new_pwd, default_shift=""):
    with SessionLocal() as db:
        u = db.query(User).filter(User.username == username).first()
        if not u: return False, "User not found."
        u.full_name = full_name
        u.job_title = job_title
        u.contact_info = contact_info
        u.default_shift = default_shift
        if new_pwd:
            validate_password(new_pwd)
            if bcrypt.checkpw(old_pwd.encode('utf-8'), u.password_hash.encode('utf-8')):
                u.password_hash = hash_password(new_pwd)
            else:
                return False, "Incorrect current password."
        db.commit()
        return True, "Updated!"


def set_user_theme(username, theme):
    if theme not in VALID_THEMES:
        raise ValueError("Invalid theme.")
    with SessionLocal() as db:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise ValueError("User not found.")
        user.theme = theme
        db.commit()
    return True

def logout_user(username, token=None):
    with SessionLocal() as db:
        u = db.query(User).filter(User.username == username).first()
        if not u:
            return
        if token:
            db.query(UserSession).filter(
                UserSession.user_id == u.id, UserSession.token == token
            ).delete(synchronize_session=False)
            # Retain compatibility with sessions issued before user_sessions.
            if u.session_token == token:
                u.session_token = None
        else:
            # Legacy callers without a token retain the old all-sessions behavior.
            db.query(UserSession).filter(UserSession.user_id == u.id).delete(synchronize_session=False)
            u.session_token = None
        db.commit()


PASSWORD_MIN_LENGTH = 12
EMAIL_CHANGE_TOKEN_TTL_HOURS = 24
PASSWORD_RESET_TOKEN_TTL_MINUTES = 60


def validate_password(password):
    if not isinstance(password, str) or len(password) < PASSWORD_MIN_LENGTH:
        raise ValueError(f"Password must be at least {PASSWORD_MIN_LENGTH} characters.")


def hash_password(password):
    validate_password(password)
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _audit_account_event(db, event_type, actor_user_id=None, subject_user_id=None, detail=None):
    db.add(AccountAuditEvent(
        event_type=event_type,
        actor_user_id=actor_user_id,
        subject_user_id=subject_user_id,
        event_detail=detail or {},
        created_at=datetime.utcnow(),
    ))


def _recovery_reviewers(db, required_action):
    reviewers = []
    for reviewer in db.query(User).filter(
        User.is_active.is_(True),
        User.email_normalized.isnot(None),
        User.email_verified_at.isnot(None),
    ).all():
        if str(reviewer.role or "").casefold() in {"admin", "administrator"}:
            reviewers.append(reviewer)
            continue
        permissions = get_role_permissions(reviewer.role, db=db)
        grants = permissions["allowed_actions"]
        if (
            required_action in grants
            and "Settings & Admin" in permissions["allowed_pages"]
            and "Tab: Settings -> Users & Roles" in grants
        ):
            reviewers.append(reviewer)
    return reviewers


def get_recovery_reviewer_emails(required_action="Action: Review Account Recovery Requests", exclude_user_id=None):
    with SessionLocal() as db:
        return list(dict.fromkeys(
            reviewer.email for reviewer in _recovery_reviewers(db, required_action)
            if reviewer.email and reviewer.id != exclude_user_id
        ))


def get_user_directory():
    with SessionLocal() as db:
        users = db.query(User).order_by(User.username.asc()).all()
        pending_emails = {
            request.user_id: request
            for request in db.query(EmailChangeRequest).filter(
                EmailChangeRequest.status.in_(["pending_review", "pending_verification"])
            ).all()
        }
        pending_invites = db.query(RegistrationInvite).filter(
            RegistrationInvite.used_at.is_(None),
            RegistrationInvite.revoked_at.is_(None),
            RegistrationInvite.expires_at > datetime.utcnow(),
        ).all()
        invited_usernames = {invite.username.casefold() for invite in pending_invites}
        result = []
        for user in users:
            email_request = pending_emails.get(user.id)
            result.append({
                "id": user.id,
                "username": user.username,
                "full_name": user.full_name,
                "job_title": user.job_title,
                "contact_info": user.contact_info,
                "email": user.email,
                "email_verified": bool(user.email_verified_at),
                "email_status": (
                    "pending_approval" if email_request and email_request.status == "pending_review"
                    else "pending_verification" if email_request
                    else "verified" if user.email_verified_at
                    else "exempt" if user.account_type == "display" and not user.email
                    else "missing" if not user.email
                    else "unverified"
                ),
                "pending_email": email_request.requested_email if email_request else None,
                "account_type": user.account_type or "individual",
                "role": user.role,
                "is_active": bool(user.is_active),
                "created_at": user.created_at.isoformat() if user.created_at else None,
                "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
                "last_activity_at": user.last_activity_at.isoformat() if user.last_activity_at else None,
                "invitation_pending": user.username.casefold() in invited_usernames,
            })
        return result


def create_display_account(username, password, role, full_name="", created_by=None):
    username = str(username or "").strip()
    role = str(role or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{2,63}", username):
        raise ValueError("Username must be 3-64 characters and contain only letters, numbers, '.', '_' or '-'.")
    password_hash = hash_password(password)
    now = datetime.utcnow()
    with SessionLocal() as db:
        if db.query(User).filter(func.lower(User.username) == username.casefold()).first():
            raise ValueError("That username is already registered.")
        if not db.query(Role).filter(func.lower(Role.name) == role.casefold()).first():
            raise ValueError("That role does not exist.")
        user = User(
            username=username,
            password_hash=password_hash,
            role=role,
            account_type="display",
            is_active=True,
            full_name=str(full_name or "").strip(),
            created_at=now,
        )
        db.add(user)
        db.flush()
        _audit_account_event(
            db, "display_account_created", actor_user_id=created_by,
            subject_user_id=user.id, detail={"role": role},
        )
        db.commit()
        return user.id


def submit_email_change_request(user_id, requested_email):
    email, normalized = normalize_user_email(requested_email)
    now = datetime.utcnow()
    with SessionLocal() as db:
        user = db.query(User).filter(User.id == user_id, User.is_active.is_(True)).first()
        if not user:
            raise ValueError("User not found or disabled.")
        if user.email_normalized == normalized and user.email_verified_at:
            raise ValueError("That is already the approved recovery email.")
        if db.query(User).filter(
            User.email_normalized == normalized,
            User.id != user_id,
        ).first():
            raise ValueError("That email address is already associated with another account.")
        if db.query(RegistrationInvite).filter(
            RegistrationInvite.email_normalized == normalized,
            RegistrationInvite.used_at.is_(None),
            RegistrationInvite.revoked_at.is_(None),
            RegistrationInvite.expires_at > now,
        ).first():
            raise ValueError("That email address already has a pending invitation.")
        pending = db.query(EmailChangeRequest).filter(
            EmailChangeRequest.user_id == user_id,
            EmailChangeRequest.status.in_(["pending_review", "pending_verification"]),
        ).first()
        if pending:
            raise ValueError("An email change request is already pending.")
        if db.query(EmailChangeRequest).filter(
            EmailChangeRequest.requested_email_normalized == normalized,
            EmailChangeRequest.status == "pending_verification",
        ).first():
            raise ValueError("That email address is awaiting verification for another account.")
        request = EmailChangeRequest(
            user_id=user_id,
            requested_email=email,
            requested_email_normalized=normalized,
            status="pending_review",
            requested_at=now,
        )
        db.add(request)
        db.flush()
        _audit_account_event(
            db, "recovery_email_requested", subject_user_id=user_id,
            detail={"request_id": request.id},
        )
        db.commit()
        return request.id


def list_email_change_requests():
    with SessionLocal() as db:
        rows = db.query(EmailChangeRequest, User).join(
            User, User.id == EmailChangeRequest.user_id
        ).filter(
            EmailChangeRequest.status == "pending_review"
        ).order_by(EmailChangeRequest.requested_at.asc()).all()
        return [{
            "id": request.id,
            "user_id": user.id,
            "username": user.username,
            "full_name": user.full_name,
            "account_type": user.account_type,
            "current_email": user.email,
            "requested_email": request.requested_email,
            "requested_at": request.requested_at.isoformat() if request.requested_at else None,
        } for request, user in rows]


def review_email_change_request(request_id, reviewer_id, approve, reason=""):
    now = datetime.utcnow()
    with SessionLocal() as db:
        request = db.query(EmailChangeRequest).filter(
            EmailChangeRequest.id == request_id,
            EmailChangeRequest.status == "pending_review",
        ).first()
        if not request:
            raise ValueError("Pending recovery-email request not found.")
        user = db.query(User).filter(User.id == request.user_id).first()
        if not user or not user.is_active:
            raise ValueError("The account no longer exists or is disabled.")
        if user.id == reviewer_id:
            raise ValueError("A user administrator cannot approve their own recovery-email change.")
        request.reviewed_by_id = reviewer_id
        request.reviewed_at = now
        decision_reason = str(reason or "").strip()[:1000]
        if not approve and not decision_reason:
            raise ValueError("A reason is required when denying a recovery-email request.")
        request.decision_reason = decision_reason or "Approved by user administrator."
        if not approve:
            request.status = "denied"
            _audit_account_event(
                db, "recovery_email_denied", actor_user_id=reviewer_id,
                subject_user_id=user.id, detail={"request_id": request.id, "reason": request.decision_reason},
            )
            db.commit()
            return {"status": "denied", "email": user.email, "username": user.username}

        if db.query(User).filter(
            User.email_normalized == request.requested_email_normalized,
            User.id != user.id,
        ).first():
            raise ValueError("That email address is now associated with another account.")
        raw_token = secrets.token_urlsafe(32)
        request.status = "pending_verification"
        request.verification_token_hash = _invite_token_hash(raw_token)
        request.verification_expires_at = now + timedelta(hours=EMAIL_CHANGE_TOKEN_TTL_HOURS)
        _audit_account_event(
            db, "recovery_email_approved_pending_verification", actor_user_id=reviewer_id,
            subject_user_id=user.id, detail={"request_id": request.id},
        )
        db.commit()
        return {
            "status": "pending_verification",
            "email": request.requested_email,
            "username": user.username,
            "token": raw_token,
        }


def verify_recovery_email(raw_token):
    if not raw_token:
        return False
    now = datetime.utcnow()
    with SessionLocal() as db:
        request = db.query(EmailChangeRequest).filter(
            EmailChangeRequest.verification_token_hash == _invite_token_hash(raw_token),
            EmailChangeRequest.status == "pending_verification",
            EmailChangeRequest.verification_expires_at > now,
        ).first()
        if not request:
            return False
        user = db.query(User).filter(User.id == request.user_id, User.is_active.is_(True)).first()
        if not user:
            return False
        duplicate = db.query(User).filter(
            User.email_normalized == request.requested_email_normalized,
            User.id != user.id,
        ).first()
        if duplicate:
            request.status = "conflict"
            db.commit()
            return False
        user.email = request.requested_email
        user.email_normalized = request.requested_email_normalized
        user.email_verified_at = now
        request.status = "completed"
        request.verified_at = now
        request.verification_token_hash = None
        _audit_account_event(
            db, "recovery_email_verified", subject_user_id=user.id,
            detail={"request_id": request.id},
        )
        db.commit()
        return True


def resend_recovery_email_verification(user_id):
    now = datetime.utcnow()
    with SessionLocal() as db:
        request = db.query(EmailChangeRequest).filter(
            EmailChangeRequest.user_id == user_id,
            EmailChangeRequest.status == "pending_verification",
        ).order_by(EmailChangeRequest.requested_at.desc()).first()
        if not request:
            raise ValueError("There is no approved recovery-email verification waiting to be sent.")
        if request.reviewed_at and request.reviewed_at > now - timedelta(minutes=5):
            raise ValueError("Wait five minutes before requesting another verification email.")
        user = db.query(User).filter(User.id == user_id, User.is_active.is_(True)).first()
        if not user:
            raise ValueError("User not found or disabled.")
        raw_token = secrets.token_urlsafe(32)
        request.verification_token_hash = _invite_token_hash(raw_token)
        request.verification_expires_at = now + timedelta(hours=EMAIL_CHANGE_TOKEN_TTL_HOURS)
        request.reviewed_at = now
        db.commit()
        return {"email": request.requested_email, "username": user.username, "token": raw_token}


def submit_password_reset_request(identifier, requester_ip=None):
    submitted = str(identifier or "").strip()
    identifier_hash = hashlib.sha256(submitted.casefold().encode("utf-8")).hexdigest()
    safe_ip = None
    if requester_ip:
        try:
            safe_ip = str(ipaddress.ip_address(str(requester_ip)))[:64]
        except ValueError:
            safe_ip = None
    now = datetime.utcnow()
    with SessionLocal() as db:
        ip_attempts = db.query(PasswordResetRequest).filter(
            PasswordResetRequest.requester_ip == safe_ip,
            PasswordResetRequest.requested_at >= now - timedelta(hours=1),
        ).count() if safe_ip else 0
        identifier_attempts = db.query(PasswordResetRequest).filter(
            PasswordResetRequest.identifier_hash == identifier_hash,
            PasswordResetRequest.requested_at >= now - timedelta(hours=1),
        ).count()
        if ip_attempts >= 10 or identifier_attempts >= 5:
            return {"accepted": True, "notify": []}

        user = None
        if submitted:
            user = db.query(User).filter(
                or_(
                    func.lower(User.username) == submitted.casefold(),
                    User.email_normalized == submitted.casefold(),
                )
            ).first()
        if user and user.is_active:
            pending = db.query(PasswordResetRequest).filter(
                PasswordResetRequest.user_id == user.id,
                PasswordResetRequest.status == "pending_review",
                PasswordResetRequest.requested_at >= now - timedelta(minutes=30),
            ).first()
            if pending:
                request = pending
            else:
                request = PasswordResetRequest(
                    user_id=user.id,
                    identifier_hash=identifier_hash,
                    requester_ip=safe_ip,
                    status="pending_review",
                    requested_at=now,
                )
                db.add(request)
                db.flush()
                _audit_account_event(
                    db, "password_reset_requested", subject_user_id=user.id,
                    detail={"request_id": request.id, "account_type": user.account_type},
                )
            reviewers = [
                reviewer for reviewer in _recovery_reviewers(db, "Action: Review Account Recovery Requests")
                if reviewer.id != user.id
            ]
            db.commit()
            return {
                "accepted": True,
                "notify": list(dict.fromkeys(reviewer.email for reviewer in reviewers if reviewer.email)),
                "request_id": request.id,
            }

        # Persist unmatched attempts for IP throttling without preserving the
        # submitted username or revealing whether it matched an account.
        db.add(PasswordResetRequest(
            user_id=None,
            identifier_hash=identifier_hash,
            requester_ip=safe_ip,
            status="unmatched",
            requested_at=now,
        ))
        db.commit()
        return {"accepted": True, "notify": []}


def list_password_reset_requests():
    with SessionLocal() as db:
        rows = db.query(PasswordResetRequest, User).join(
            User, User.id == PasswordResetRequest.user_id
        ).filter(
            PasswordResetRequest.status == "pending_review"
        ).order_by(PasswordResetRequest.requested_at.asc()).all()
        return [{
            "id": request.id,
            "user_id": user.id,
            "username": user.username,
            "full_name": user.full_name,
            "email": user.email,
            "email_verified": bool(user.email_verified_at),
            "account_type": user.account_type,
            "requested_at": request.requested_at.isoformat() if request.requested_at else None,
        } for request, user in rows]


def review_password_reset_request(request_id, reviewer_id, approve, reason=""):
    now = datetime.utcnow()
    with SessionLocal() as db:
        request = db.query(PasswordResetRequest).filter(
            PasswordResetRequest.id == request_id,
            PasswordResetRequest.status == "pending_review",
        ).first()
        if not request or not request.user_id:
            raise ValueError("Pending password-reset request not found.")
        user = db.query(User).filter(User.id == request.user_id, User.is_active.is_(True)).first()
        if not user:
            raise ValueError("The account no longer exists or is disabled.")
        if user.id == reviewer_id:
            raise ValueError("A user administrator cannot approve their own password-reset request.")
        request.reviewed_by_id = reviewer_id
        request.reviewed_at = now
        decision_reason = str(reason or "").strip()[:1000]
        if not approve and not decision_reason:
            raise ValueError("A reason is required when denying a password-reset request.")
        request.decision_reason = decision_reason or "Approved by user administrator."
        if not approve:
            request.status = "denied"
            _audit_account_event(
                db, "password_reset_denied", actor_user_id=reviewer_id,
                subject_user_id=user.id, detail={"request_id": request.id, "reason": request.decision_reason},
            )
            db.commit()
            return {
                "status": "denied", "username": user.username,
                "email": user.email if user.email_verified_at else None,
            }
        if not user.email or not user.email_verified_at or user.account_type == "display":
            raise ValueError("This account has no approved recovery email. Use administrator-assisted recovery.")

        raw_token = secrets.token_urlsafe(32)
        expires_at = now + timedelta(minutes=PASSWORD_RESET_TOKEN_TTL_MINUTES)
        db.add(PasswordResetToken(
            request_id=request.id,
            user_id=user.id,
            token_hash=_invite_token_hash(raw_token),
            created_at=now,
            expires_at=expires_at,
        ))
        request.status = "approved"
        request.reset_email_sent_at = now
        _audit_account_event(
            db, "password_reset_approved", actor_user_id=reviewer_id,
            subject_user_id=user.id, detail={"request_id": request.id},
        )
        db.commit()
        return {
            "status": "approved",
            "username": user.username,
            "email": user.email,
            "token": raw_token,
            "expires_at": expires_at.isoformat(),
        }


def complete_password_reset(raw_token, new_password):
    password_hash = hash_password(new_password)
    now = datetime.utcnow()
    with SessionLocal() as db:
        token = db.query(PasswordResetToken).filter(
            PasswordResetToken.token_hash == _invite_token_hash(raw_token or ""),
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at > now,
        ).first()
        if not token:
            return False
        user = db.query(User).filter(User.id == token.user_id, User.is_active.is_(True)).first()
        if not user:
            return False
        user.password_hash = password_hash
        user.session_token = None
        db.query(UserSession).filter(UserSession.user_id == user.id).delete(synchronize_session=False)
        db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.id != token.id,
        ).update({PasswordResetToken.used_at: now}, synchronize_session=False)
        token.used_at = now
        request = db.query(PasswordResetRequest).filter(
            PasswordResetRequest.id == token.request_id
        ).first()
        if request:
            request.status = "completed"
        _audit_account_event(db, "password_reset_completed", subject_user_id=user.id)
        db.commit()
        return True


# ==========================================
# 2. OPERATIONAL DASHBOARD & ARTICLE ACTIONS
# ==========================================

@TTLCache(ttl=60)
def get_dashboard_metrics():
    with SessionLocal() as db:
        t = datetime.utcnow() - timedelta(days=1)
        return {
            "rss_count": db.query(Article).filter(Article.published_date >= t, Article.score >= 50).count(),
            "cve_count": db.query(CveItem).filter(CveItem.date_added >= t).count(),
            "hazard_count": db.query(RegionalHazard).filter(RegionalHazard.updated_at >= t).count(),
            "cloud_count": db.query(CloudOutage).filter(CloudOutage.updated_at >= t, CloudOutage.is_resolved == False).count()
        }

def get_pinned_articles():
    with SessionLocal() as db:
        return to_dotdict_list(db.query(Article).filter_by(is_pinned=True).order_by(Article.published_date.desc()).all())

def get_live_articles(limit=15):
    with SessionLocal() as db:
        t = datetime.utcnow() - timedelta(days=1)
        return to_dotdict_list(db.query(Article).filter(Article.published_date >= t, Article.score >= 50.0, Article.is_pinned == False).order_by(Article.score.desc()).limit(limit).all())

def toggle_pin(art_id):
    with SessionLocal() as db:
        a = db.query(Article).filter_by(id=art_id).first()
        if a: a.is_pinned = not a.is_pinned; db.commit()

def boost_score(art_id, amount=15):
    with SessionLocal() as db:
        a = db.query(Article).filter_by(id=art_id).first()
        if a: a.score = min(100.0, a.score + amount); db.commit()

def change_status(art_id, new_feedback):
    with SessionLocal() as db:
        a = db.query(Article).filter_by(id=art_id).first()
        if a:
            if a.human_feedback == 0 and new_feedback in [1, 2] and a.keywords_found:
                existing = {k.word: k for k in db.query(Keyword).filter(Keyword.word.in_(a.keywords_found)).all()}
                for kw in a.keywords_found:
                    kdb = existing.get(kw)
                    if kdb:
                        if new_feedback == 2: kdb.weight += 1
                        elif new_feedback == 1: kdb.weight = max(1, kdb.weight - 1)
            a.human_feedback = new_feedback
            db.commit()

def save_ai_bluf(art_id, bluf_text):
    with SessionLocal() as db:
        a = db.query(Article).filter_by(id=art_id).first()
        if a: a.ai_bluf = bluf_text; db.commit()


# ==========================================
# 3. EXECUTIVE DASHBOARD & CRIME INTELLIGENCE
# ==========================================

def get_recent_crimes(max_distance=None, grid_only=False, hours_back=168):
    """Queries the database for active perimeter incidents, with dynamic filtering for different dashboards."""
    from src.database import SessionLocal, CrimeIncident
    from datetime import datetime, timedelta
    
    with SessionLocal() as db:
        cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)
        query = db.query(CrimeIncident).filter(CrimeIncident.timestamp >= cutoff_time)
        
        if grid_only:
            # EXPANDED: Included Society crimes (Trespassing/Disturbances) to support FBI UCR taxonomy
            grid_threat_categories = [
                'Perimeter Breach/Vandalism', 
                'Violent Proximity Threat', 
                'Asset/Copper Theft Risk',
                'Trespassing/Suspicious Activity',
                'Public Disturbance/Narcotics'
            ]
            query = query.filter(CrimeIncident.category.in_(grid_threat_categories))
        
        if max_distance is not None:
            query = query.filter(CrimeIncident.distance_miles <= max_distance)
            
        crimes = query.order_by(CrimeIncident.timestamp.desc()).all()
        return [{
            "id": c.id, "category": c.category, "raw_title": c.raw_title,
            "timestamp": c.timestamp.isoformat() + "Z" if c.timestamp else None,
            "distance_miles": c.distance_miles, "severity": c.severity,
            "lat": c.lat, "lon": c.lon
        } for c in crimes]
        
def force_fetch_crime_data():
    """Triggers the crime worker logic manually from the UI."""
    try:
        from src.workers.crime_worker import fetch_live_crimes
        fetch_live_crimes()
        dispatch_perimeter_crime_alerts() # <-- ADD THIS LINE
        return True
    except Exception as e:
        logger.error("Manual fetch failed: %s", e)
        return False

def get_historical_threat_scores(days=14):
    """Fetches historical daily scores to calculate the operational baseline."""
    with SessionLocal() as db:
        cutoff = datetime.utcnow() - timedelta(days=days)
        scores = db.query(DailyThreatScore).filter(DailyThreatScore.record_date >= cutoff).order_by(DailyThreatScore.record_date.asc()).all()
        return to_dotdict_list(scores)

def save_threat_score(c_pts, p_pts, c_base, p_base):
    """Saves the highest daily score to maintain an accurate deviation baseline."""
    with SessionLocal() as db:
        today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        record = db.query(DailyThreatScore).filter(DailyThreatScore.record_date == today).first()
        if record:
            record.cyber_points = max(record.cyber_points, c_pts)
            record.physical_points = max(record.physical_points, p_pts)
            record.cyber_baseline = c_base
            record.physical_baseline = p_base
        else:
            db.add(DailyThreatScore(record_date=today, cyber_points=c_pts, physical_points=p_pts, cyber_baseline=c_base, physical_baseline=p_base))
        db.commit()



def get_executive_grid_intel(active_warn_count, recent_crimes):
    """Synthesizes LIVE OSINT and telemetry using the CIS Alert Level Framework and FBI UCR Taxonomy."""
    from src.database import SessionLocal, Article, CveItem
    from datetime import datetime, timedelta
    
    sys_config = get_cached_config()
    history = get_historical_threat_scores(14)
    
    if history:
        avg_cyber = sum(h.cyber_points for h in history) / len(history)
        avg_phys = sum(h.physical_points for h in history) / len(history)
    else:
        avg_cyber = avg_phys = 0.0
    baseline_cyber = float(sys_config.baseline_override_cyber) if sys_config and sys_config.get('baseline_override_cyber', 0.0) > 0 else max(avg_cyber, 20.0) if history else 20.0
    baseline_phys = float(sys_config.baseline_override_phys) if sys_config and sys_config.get('baseline_override_phys', 0.0) > 0 else max(avg_phys, 25.0) if history else 25.0

    with SessionLocal() as db:
        t24 = datetime.utcnow() - timedelta(hours=24)
        
        # PULLING CYBER TELEMETRY (Articles, ICS, and CVEs)
        raw_cyber_articles = db.query(Article).filter(Article.published_date >= t24, Article.category.in_(['Cyber: Exploits & Vulns', 'Cyber: Malware & Threats', 'ICS/OT & SCADA', 'Cloud & IT Infra']), Article.score >= 50).order_by(Article.score.desc()).limit(200).all()
        raw_ics_articles = db.query(Article).filter(Article.published_date >= t24).order_by(Article.published_date.desc()).limit(150).all()
        raw_phys_articles = db.query(Article).filter(Article.published_date >= t24, Article.category.in_(['Physical Security', 'Severe Weather', 'Geopolitics & Policy']), Article.score >= 50).order_by(Article.score.desc()).limit(100).all()
        
        recent_cves = db.query(CveItem).filter(CveItem.date_added >= t24).all()

        geopolitical_noise_words = ["troop", "missile", "election", "ballot", "warfare", "kinetic", "embassy"]
        threat_actors = ["volt typhoon", "sandworm", "dragos", "chernovite", "apt", "lazarus"]
        ransomware_kws = ["ransomware", "encryption", "extortion", "breach"]

        # --- 1. PROCESS CYBER ---
        pure_cyber_articles = []
        utility_keywords = ["grid", "power", "utility", "energy", "bes", "electric", "scada", "ics", "miso", "spp", "cooperative"]
        seen_cyber_titles = set() 
        
        for art in raw_cyber_articles:
            text_check = f"{art.title} {art.summary}".lower()
            if any(noise in text_check for noise in geopolitical_noise_words) and not any(k in text_check for k in ["infrastructure", "grid", "scada"]): 
                continue
            
            title_stub = art.title[:50].lower()
            if title_stub in seen_cyber_titles: continue
            seen_cyber_titles.add(title_stub)
            
            art.is_utility_related = any(ukw in text_check for ukw in utility_keywords)
            art.is_apt_related = any(apt in text_check for apt in threat_actors)
            art.is_ransomware = any(rw in text_check for rw in ransomware_kws)
            pure_cyber_articles.append(art)

        # --- 2. PROCESS PHYSICAL ---
        pure_phys_articles = []
        ar_keywords = ["arkansas", "little rock", "pulaski", "benton", "entergy", "cooperative"]
        threat_keywords = ["terror", "attack", "grid", "substation", "sabotage", "vandalism", "infrastructure", "transformer", "sniper", "shoot", "explosive"]
        seen_phys_titles = set()
        
        for art in raw_phys_articles:
            text_check = f"{art.title} {art.summary}".lower()
            source_lower = art.source.lower() if art.source else ""
            if "cisa" in source_lower or "cyber" in text_check or "cve-" in text_check or "ics-cert" in source_lower: continue
                
            title_stub = art.title[:50].lower()
            if title_stub in seen_phys_titles: continue
            
            if any(kw in text_check for kw in ar_keywords) and any(kw in text_check for kw in threat_keywords): 
                seen_phys_titles.add(title_stub)
                pure_phys_articles.append(art)

        # --- 3. PROCESS ICS & KEV ---
        ics_advisories = []
        critical_vendors = ["SEL", "SCHWEITZER", "SIEMENS", "SCHNEIDER", "GE ", "ABB", "ROCKWELL", "EMERSON", "HONEYWELL", "OMRON"]
        for art in raw_ics_articles:
            source_upper = art.source.upper() if art.source else ""
            if "ICS" in source_upper or "CISA" in source_upper:
                is_critical = any(v in art.title.upper() for v in critical_vendors)
                is_kev = "KEV" in art.title.upper() or "EXPLOITED IN THE WILD" in art.title.upper() 
                ics_advisories.append({"title": art.title, "link": art.link, "published": format_central(art.published_date)[:10], "is_critical": is_critical, "is_kev": is_kev})

# ==========================================
    # CIS-ALIGNED SCORING ALGORITHM
    # ==========================================

    evidence_log = []
    scoring_mode = str(sys_config.get('scoring_mode', 'auto') or 'auto')

    sys_counter = sys_config.get('sys_countermeasures', 3) if sys_config else 3
    net_counter = sys_config.get('net_countermeasures', 3) if sys_config else 3

    kev_count = critical_ics_count = 0
    for a in ics_advisories:
        if a['is_kev']: kev_count += 1
        if a['is_critical']: critical_ics_count += 1
    apt_count = ran_count = util_count = 0
    for a in pure_cyber_articles:
        if getattr(a, 'is_apt_related', False): apt_count += 1
        if getattr(a, 'is_ransomware', False): ran_count += 1
        if getattr(a, 'is_utility_related', False): util_count += 1
    cve_count = len(recent_cves)

    # --- AUTO-COMPUTE CYBER LETHALITY ---
    auto_l = 2
    if kev_count > 0:
        auto_l = 5
        evidence_log.append(f"**KEV Active Exploits:** {kev_count} Known Exploited Vulnerabilities. Attacker could gain root/admin or cause DoS. (L=5)")
    elif cve_count > 10:
        auto_l = 4
        evidence_log.append(f"**High CVE Volume:** {cve_count} recent CVEs. Exploits likely available. (L=4)")
    elif cve_count > 5:
        auto_l = 3
        evidence_log.append(f"**Moderate CVE Volume:** {cve_count} recent CVEs. Potential for targeted attacks. (L=3)")
    elif cve_count > 0:
        auto_l = 3
        evidence_log.append(f"**CVE Activity:** {cve_count} CVEs. No known exploits but potential for root/admin access. (L=3)")
    elif len(pure_cyber_articles) > 5:
        auto_l = 2
        evidence_log.append(f"**Elevated Cyber Activity:** {len(pure_cyber_articles)} threats. Potential for user-level access. (L=2)")
    else:
        auto_l = 1
        evidence_log.append(f"**Routine Cyber Activity:** Normal probing and known low-risk activity. (L=1)")

    # --- AUTO-COMPUTE CYBER CRITICALITY ---
    auto_c = 2
    if critical_ics_count > 0 or util_count > 0:
        auto_c = 5
        evidence_log.append(f"**Critical Infrastructure Target:** OT/SCADA or Utility sector targeted. Core services at risk. (C=5)")
    elif len(ics_advisories) > 0:
        auto_c = 4
        evidence_log.append(f"**ICS/SCADA Targeting:** {len(ics_advisories)} ICS advisories. Email, web, database servers at risk. (C=4)")
    elif apt_count > 0 or ran_count > 0:
        auto_c = 4
        evidence_log.append(f"**APT/Ransomware Activity:** {apt_count} APT, {ran_count} Ransomware campaigns. Critical systems targeted. (C=4)")
    elif len(pure_cyber_articles) > 3:
        auto_c = 3
        evidence_log.append(f"**Elevated Threat Activity:** {len(pure_cyber_articles)} threats to less critical applications. (C=3)")
    else:
        auto_c = 2
        evidence_log.append(f"**General Cyber Activity:** Business systems potentially affected. (C=2)")

    s = min(max(sys_counter, 1), 5)
    n = min(max(net_counter, 1), 5)

    # --- AUTO-COMPUTE PHYSICAL CRITICALITY & LETHALITY ---
    crimes_persons = []
    crimes_property = []
    crimes_society = []

    for c_item in recent_crimes:
        title_cat = (str(c_item.get('raw_title', '')) + " " + str(c_item.get('category', ''))).lower()
        if any(x in title_cat for x in ['assault', 'shoot', 'homicide', 'murder', 'violent', 'robbery', 'kidnap', 'battery', 'weapon', 'gun', 'stab']):
            c_item['fbi_category'] = "Crimes Against Persons"
            crimes_persons.append(c_item)
        elif any(x in title_cat for x in ['suspicious', 'disturbance', 'narcotic', 'drug', 'loiter', 'trespass']):
            c_item['fbi_category'] = "Crimes Against Society"
            crimes_society.append(c_item)
        elif any(x in title_cat for x in ['vandalism', 'theft', 'burglary', 'arson', 'property', 'copper', 'breach', 'damage', 'stolen']):
            c_item['fbi_category'] = "Crimes Against Property"
            crimes_property.append(c_item)
        else:
            c_item['fbi_category'] = "Crimes Against Society"
            crimes_society.append(c_item)

    phys_evidence = []
    total_crimes = len(crimes_persons) + len(crimes_property) + len(crimes_society)

    auto_p_l = 2
    if len(crimes_persons) >= 5 or len(crimes_property) >= 10:
        auto_p_l = 5
        phys_evidence.append(f"**Severe Crime Activity:** {len(crimes_persons)} violent crimes, {len(crimes_property)} property crimes. DoS to operations possible. (L=5)")
    elif len(crimes_persons) >= 3 or len(crimes_property) >= 6:
        auto_p_l = 4
        phys_evidence.append(f"**High Crime Activity:** {len(crimes_persons)} violent crimes, {len(crimes_property)} property crimes. User access possible. (L=4)")
    elif len(crimes_persons) >= 1 or len(crimes_property) >= 3:
        auto_p_l = 3
        phys_evidence.append(f"**Elevated Crime Activity:** Potential for damage/disruption. (L=3)")
    elif total_crimes >= 5:
        auto_p_l = 2
        phys_evidence.append(f"**General Crime Activity:** General risk of incidents. (L=2)")
    else:
        auto_p_l = 1
        phys_evidence.append(f"**Routine Activity:** Normal low-risk incidents. (L=1)")

    weather_weight = min((active_warn_count * 1.5), 15) / 15
    osint_phys_score = min(sum([10 if art.score >= 80 else 2 for art in pure_phys_articles]), 20) / 20

    auto_p_c = 2
    if len(pure_phys_articles) >= 3 or weather_weight >= 0.8:
        auto_p_c = 5
        phys_evidence.append(f"**Critical Physical Threats:** {len(pure_phys_articles)} OSINT threats, {active_warn_count} weather alerts. Core infrastructure targeted. (C=5)")
    elif len(pure_phys_articles) >= 1 or weather_weight >= 0.4:
        auto_p_c = 4
        phys_evidence.append(f"**Elevated Physical Threats:** {len(pure_phys_articles)} OSINT threats, {active_warn_count} weather alerts. Email/web/database services at risk. (C=4)")
    elif osint_phys_score > 0:
        auto_p_c = 3
        phys_evidence.append(f"**General Physical Threats:** Less critical systems affected. (C=3)")
    else:
        auto_p_c = 2
        phys_evidence.append(f"**Routine Physical Monitoring:** Business systems. (C=2)")

    # ==========================================
    # SCORING MODE DISPATCH
    # ==========================================
    mode_label = "Auto"
    if scoring_mode == "manual":
        c = min(max(int(sys_config.get('cyber_criticality_override', 0) or 0), 1), 5)
        l = min(max(int(sys_config.get('cyber_lethality_override', 0) or 0), 1), 5)
        p_c = min(max(int(sys_config.get('physical_criticality_override', 0) or 0), 1), 5)
        p_l = min(max(int(sys_config.get('physical_lethality_override', 0) or 0), 1), 5)
        mode_label = "Manual Override"
        evidence_log.insert(0, f"**Scoring Mode: {mode_label}** — C={c}, L={l}, P_C={p_c}, P_L={p_l} applied from config overrides")
    elif scoring_mode == "hybrid":
        c = auto_c
        l = auto_l
        p_c = auto_p_c
        p_l = auto_p_l
        offset = int(sys_config.get('global_risk_offset', 0) or 0)
        mode_label = f"Hybrid (offset={offset:+d})"
        evidence_log.insert(0, f"**Scoring Mode: {mode_label}** — Auto-computed with {offset:+d} offset")
    else:
        c = auto_c
        l = auto_l
        p_c = auto_p_c
        p_l = auto_p_l
        evidence_log.insert(0, f"**Scoring Mode: Auto** — Fully algorithmic CIS scoring")

    cis_cyber_score = (c + l) - (s + n)
    if scoring_mode == "hybrid":
        offset = int(sys_config.get('global_risk_offset', 0) or 0)
        cis_cyber_score = max(-8, min(8, cis_cyber_score + offset))

    if cis_cyber_score >= 6: cyber_score = "RED"
    elif cis_cyber_score >= 3: cyber_score = "ORANGE"
    elif cis_cyber_score >= -1: cyber_score = "YELLOW"
    elif cis_cyber_score >= -4: cyber_score = "BLUE"
    else: cyber_score = "GREEN"

    cyber_brief = f"**CIS Score: {cis_cyber_score}** | C={c}, L={l}, S={s}, N={n} | {len(pure_cyber_articles)} threats, {len(ics_advisories)} ICS, {cve_count} CVEs"

    cis_phys_score = (p_c + p_l) - (s + n)
    if scoring_mode == "hybrid":
        offset = int(sys_config.get('global_risk_offset', 0) or 0)
        cis_phys_score = max(-8, min(8, cis_phys_score + offset))

    if cis_phys_score >= 6: physical_score = "RED"
    elif cis_phys_score >= 3: physical_score = "ORANGE"
    elif cis_phys_score >= -1: physical_score = "YELLOW"
    elif cis_phys_score >= -4: physical_score = "BLUE"
    else: physical_score = "GREEN"

    physical_brief = f"**CIS Score: {cis_phys_score}** | C={p_c}, L={p_l}, S={s}, N={n} | {len(crimes_persons)} violent, {len(crimes_property)} property, {len(pure_phys_articles)} OSINT, {active_warn_count} alerts"

    # --- UNIFIED TIERING ---
    tier_weights = {"RED": 5, "ORANGE": 4, "YELLOW": 3, "BLUE": 2, "GREEN": 1}
    reverse_tiers = {5: "RED", 4: "ORANGE", 3: "YELLOW", 2: "BLUE", 1: "GREEN"}
    unified_risk = reverse_tiers[max(tier_weights[cyber_score], tier_weights[physical_score])]

    save_threat_score(cis_cyber_score, cis_phys_score, baseline_cyber, baseline_phys)

    return {
            "timestamp": datetime.now(LOCAL_TZ).strftime("%H:%M:%S %Z"),
            "unified_risk": unified_risk, "physical_score": physical_score, "physical_brief": physical_brief,
            "cyber_score": cyber_score, "cyber_brief": cyber_brief, "cis_cyber_score": cis_cyber_score,
            "recent_crimes": recent_crimes, "raw_cyber_articles": pure_cyber_articles, "raw_phys_articles": pure_phys_articles,
            "evidence_log": evidence_log,
            "current_cyber_pts": cis_cyber_score, "current_phys_pts": cis_phys_score,
            "baseline_cyber": baseline_cyber, "baseline_phys": baseline_phys,
            "scoring_mode": scoring_mode,
            "applied_overrides": {
                "cyber_criticality": {"auto": auto_c, "used": c},
                "cyber_lethality": {"auto": auto_l, "used": l},
                "physical_criticality": {"auto": auto_p_c, "used": p_c},
                "physical_lethality": {"auto": auto_p_l, "used": p_l},
            }
        }

def calculate_internal_cis_score(db_session):
    """
    Calculates an Internal CIS Threat Score based PURELY on OSINT correlations.
    Features a Tokenized Index, Double-Gatekeeper Context Filter for news noise, 
    and Bi-Directional Proximity Regex for ambiguous software names.
    """
    from src.database import HardwareAsset, SoftwareAsset, Article, CveItem
    from datetime import datetime, timedelta
    import re

    # Fetch raw assets from the database
    hw_assets_raw = db_session.query(HardwareAsset).all()
    sw_assets_raw = db_session.query(SoftwareAsset).all()
    
    # --- PRE-PROCESSING DEDUPLICATION ---
    # Eliminates redundant regex scanning and prevents duplicate rows in the UI
    hw_assets = list({hw.ip_address: hw for hw in hw_assets_raw if hw.ip_address}.values())
    sw_assets = list({sw.name.strip().lower(): sw for sw in sw_assets_raw if sw.name}.values())
    
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    recent_articles = db_session.query(Article).filter(Article.published_date >= thirty_days_ago).order_by(Article.published_date.desc()).limit(500).all()
    recent_cves = db_session.query(CveItem).order_by(CveItem.date_added.desc()).limit(300).all()

    # ==========================================
    # PHASE 1: ENGINE RULES & SIGNATURE COMPILATION
    # ==========================================
    STOP_WORDS = {"and", "the", "for", "with", "system", "server", "software", "application", "platform", "tool", "device"}
    
    IGNORE_LIST = {
        "apps", "app store", "books", "calculator", "calendar", "canvas", "chess", "clock", 
        "computer", "connect", "console", "contacts", "customer support", "dashboard", 
        "docs", "facetime", "family", "file", "games", "home", "installer", "keynote", 
        "launchpad", "login", "mail", "maps", "messages", "music", "network", "news", 
        "notes", "numbers", "pages", "paint", "passwords", "phone", "photos", "podcasts", 
        "preferences", "preview", "print", "protector", "reader", "reminders", "screenshot", 
        "script editor", "settings", "siri", "slides", "software update", "stress", 
        "system settings", "terminal", "terminals", "time", "tips", "utilities", 
        "voice memos", "weather", "wish", "xbox"
    }

    # Nouns that are common English words but legitimately need tracking
    COMMON_NOUNS = {
        "apt", "npm", "yum", "pip", "brew", "mac", "windows", "linux", "android", 
        "zoom", "cups", "ssh", "ftp", "telnet", "sudo", "mount", "ufw", "make", 
        "tracker", "patch", "bash", "cron", "less", "office", "info", "youtube", "surface", "google"
    }

    # Double-Gatekeeper Classification
    STRONG_CYBER_KWS = {"vulnerability", "cve", "malware", "ransomware", "phishing", "zero-day", "0-day", "exploit", "rce", "ddos", "cyber", "hacked", "botnet"}
    WEAK_CYBER_KWS = {"breach", "patch", "flaw", "leak", "bug", "actor", "bypass"}
    
    # Regex string for the 100-character proximity checking
    PROXIMITY_KWS = "|".join(list(STRONG_CYBER_KWS) + ["flaw", "bug", "bypass", "patch"])

    ACRONYM_COLLISIONS = {
        "apt": re.compile(r'\b(?:advanced persistent threat|apt\s*(?:group|actor|campaign|hacker|attack|malware|botnet|linked))\b', re.IGNORECASE),
        "mac": re.compile(r'\b(?:mac\s*(?:address|spoofing|layer|protocol))\b', re.IGNORECASE),
        "surface": re.compile(r'\b(?:attack\s*surface|surface\s*area)\b', re.IGNORECASE),
        "office": re.compile(r'\b(?:office\s*of)\b', re.IGNORECASE)
    }

    def get_trigger_token(name):
        """Extracts the longest valid word to act as an O(1) dictionary gatekeeper."""
        words = re.findall(r'\b[a-z]{3,}\b', str(name).lower())
        valid = [w for w in words if w not in STOP_WORDS]
        return max(valid, key=len) if valid else None

    # Pre-compile Advanced Regex Signatures
    hw_search_maps = []
    for hw in hw_assets:
        vendor = str(hw.os_vendor or "").strip().lower()
        name = str(hw.operating_system or hw.os_product or "").strip().lower()
        version = str(hw.os_version or "").strip().lower()
        
        if not name or len(name) < 2 or name in IGNORE_LIST: continue
            
        trigger = get_trigger_token(name) or get_trigger_token(vendor)
        if not trigger: continue
            
        exact_patterns = []
        if name in COMMON_NOUNS:
            # PROXIMITY CHECK: Product must be within ~100 chars of a security keyword
            pat = rf'(?:\b(?:{PROXIMITY_KWS})\b.{{0,100}}\b{re.escape(name)}\b)|(?:\b{re.escape(name)}\b.{{0,100}}\b(?:{PROXIMITY_KWS})\b)'
            if version:
                pat = rf'(?:\b(?:{PROXIMITY_KWS})\b.{{0,100}}\b{re.escape(name)}\b.{{0,50}}\b{re.escape(version)}\b)'
            exact_patterns.append(re.compile(pat, re.IGNORECASE | re.DOTALL))
        else:
            if version:
                exact_patterns.append(re.compile(rf'\b{re.escape(name)}\b.{{0,50}}\b{re.escape(version)}\b', re.IGNORECASE | re.DOTALL))
                if vendor and vendor not in name:
                     exact_patterns.append(re.compile(rf'\b{re.escape(vendor)}\b.{{0,50}}\b{re.escape(version)}\b', re.IGNORECASE | re.DOTALL))
            else:
                exact_patterns.append(re.compile(rf'\b{re.escape(name)}\b', re.IGNORECASE | re.DOTALL))
            
        hw_search_maps.append({'obj': hw, 'is_hw': True, 'trigger': trigger, 'exact': exact_patterns, 'raw_name': name, 'matches': []})

    sw_search_maps = []
    for sw in sw_assets:
        name = str(sw.name or "").strip().lower()
        if not name or len(name) < 2 or name in IGNORE_LIST: continue
        
        trigger = get_trigger_token(name)
        if not trigger: continue
            
        exact_patterns = []
        if name in COMMON_NOUNS:
            # PROXIMITY CHECK
            pat = rf'(?:\b(?:{PROXIMITY_KWS})\b.{{0,100}}\b{re.escape(name)}\b)|(?:\b{re.escape(name)}\b.{{0,100}}\b(?:{PROXIMITY_KWS})\b)'
            exact_patterns.append(re.compile(pat, re.IGNORECASE | re.DOTALL))
        else:
            exact_patterns.append(re.compile(rf'\b{re.escape(name)}\b', re.IGNORECASE | re.DOTALL))
            
        sw_search_maps.append({'obj': sw, 'is_hw': False, 'trigger': trigger, 'exact': exact_patterns, 'raw_name': name, 'matches': []})

    all_assets = hw_search_maps + sw_search_maps

    # ==========================================
    # PHASE 2: INVERTED INDEXING (DOUBLE-GATEKEEPER)
    # ==========================================
    article_index = []
    for art in recent_articles:
        if art.score >= 40:
            text_blob = f"{art.title} {art.summary or ''}".lower()
            
            # Tokenize into a set for O(1) matching
            word_set = set(re.findall(r'\b[a-z0-9]{2,}\b', text_blob))
            
            strong_hits = len(word_set.intersection(STRONG_CYBER_KWS))
            weak_hits = len(word_set.intersection(WEAK_CYBER_KWS))
            
            # GATEKEEPER: An article must have 1 Strong OR 2 Weak keywords to proceed.
            # This instantly drops stories about "whales breaching" or "leaking pipes".
            if strong_hits > 0 or weak_hits >= 2:
                article_index.append({
                    'obj': art, 'text': text_blob, 'word_set': word_set,
                    'is_critical': art.score >= 80
                })

    cve_index = []
    for cve in recent_cves:
        text_blob = f"{cve.product} {cve.description}".lower()
        cve_index.append({
            'obj': cve, 'text': text_blob,
            'word_set': set(re.findall(r'\b[a-z0-9]{2,}\b', text_blob)),
            'vendor': str(cve.vendor).lower(), 'product': str(cve.product).lower()
        })

    # ==========================================
    # PHASE 3: REVERSE-INDEXED BATCH CORRELATION SCAN
    # ==========================================
    
    # Build reverse index: trigger token -> [asset_map]
    trigger_to_assets = {}
    for asset_map in all_assets:
        trigger_to_assets.setdefault(asset_map['trigger'], []).append(asset_map)
    
    # 1. SCAN ARTICLES (O(C * avg_triggers_per_article) instead of O(C * A))
    # Cap matches per article to 5 to reduce repetitiveness
    for art in article_index:
        article_match_count = 0
        for trigger in art['word_set'].intersection(trigger_to_assets.keys()):
            if article_match_count >= 5: break
            for asset_map in trigger_to_assets[trigger]:
                if article_match_count >= 5: break
                collision_regex = ACRONYM_COLLISIONS.get(asset_map['raw_name'])
                if collision_regex and collision_regex.search(art['text']): continue

                for pat in asset_map['exact']:
                    if pat.search(art['text']):
                        asset_map['matches'].append({"title": art['obj'].title, "is_critical": art['is_critical']})
                        article_match_count += 1
                        break 

    # 2. SCAN CVE DATABASE (cap 3 matches per CVE)
    for cve in cve_index:
        candidate_triggers = cve['word_set']
        if cve['vendor']:
            candidate_triggers = candidate_triggers | {cve['vendor']}
        cve_match_count = 0
        
        for trigger in candidate_triggers.intersection(trigger_to_assets.keys()):
            if cve_match_count >= 3: break
            for asset_map in trigger_to_assets[trigger]:
                if cve_match_count >= 3: break
                if asset_map['is_hw']:
                    hw = asset_map['obj']
                    hw_vendor = str(hw.os_vendor or "").lower()
                    hw_name = str(hw.operating_system or hw.os_product or "").lower()
                    
                    if (hw_vendor and hw_vendor in cve['vendor']) and (hw_name and hw_name in cve['product']):
                        asset_map['matches'].append({"title": f"CISA KEV: {cve['obj'].cve_id}", "is_critical": True})
                        cve_match_count += 1
                        continue

                collision_regex = ACRONYM_COLLISIONS.get(asset_map['raw_name'])
                if collision_regex and collision_regex.search(cve['text']): continue

                for pat in asset_map['exact']:
                    if pat.search(cve['text']):
                        asset_map['matches'].append({"title": f"CISA KEV: {cve['obj'].cve_id}", "is_critical": True})
                        cve_match_count += 1
                        break

    # ==========================================
    # PHASE 4: POSTURE RECONSTRUCTION
    # ==========================================
    annotated_sw = []
    annotated_hw = []
    
    global_osint_titles = set()
    global_critical_titles = set()

    for asset_map in all_assets:
        if not asset_map['matches']: continue
            
        unique_intel = {}
        for m in asset_map['matches']:
            unique_intel[m['title']] = m
            global_osint_titles.add(m['title'])
            if m['is_critical']: global_critical_titles.add(m['title'])
            
        if asset_map['is_hw']:
            hw = asset_map['obj']
            display_name = hw.asset_name if hw.asset_name else f"Device ({hw.ip_address})"
            os_display = f"{hw.operating_system or 'Unknown'} {hw.os_version or ''}".strip()
            
            osint_risk_score = min(len(unique_intel) * 25, 100)
            annotated_hw.append({
                "Identifier": display_name,
                "IP Address": hw.ip_address,
                "OS": os_display,
                "OSINT Risk Score": osint_risk_score,
                "OSINT Threat Matches": len(unique_intel),
                "Top Threat Reference": list(unique_intel.keys())[0],
                "risk_score": osint_risk_score,
                "osint_threat_matches": len(unique_intel),
            })
        else:
            sw = asset_map['obj']
            osint_score = min(len(unique_intel) * 25, 100)
            annotated_sw.append({
                "Software Name": sw.name,
                "OSINT Risk Score": osint_score,
                "Active OSINT Matches": len(unique_intel),
                "Top Threat Reference": list(unique_intel.keys())[0],
                "osint_threat_matches": len(unique_intel),
                "risk_level": "HIGH" if osint_score >= 75 else "MEDIUM" if osint_score >= 40 else "LOW",
            })

    # ==========================================
    # PHASE 5: CIS RISK CALCULATION
    # ==========================================
    total_osint_hits = len(global_osint_titles)
    critical_osint_hits = len(global_critical_titles)

    total_assets = len(hw_assets) + len(sw_assets)
    assets_at_risk = len(annotated_hw) + len(annotated_sw)
    percent_at_risk = (assets_at_risk / total_assets) * 100 if total_assets > 0 else 0

    # --- AUTO-COMPUTE LETHALITY & CRITICALITY ---
    if critical_osint_hits > 10:
        auto_lethality = 5
    elif critical_osint_hits > 5:
        auto_lethality = 4
    elif critical_osint_hits > 2:
        auto_lethality = 3
    elif critical_osint_hits > 0:
        auto_lethality = 3
    elif total_osint_hits > 10:
        auto_lethality = 2
    else:
        auto_lethality = 1

    if percent_at_risk > 30:
        auto_criticality = 5
    elif percent_at_risk > 20:
        auto_criticality = 4
    elif percent_at_risk > 10:
        auto_criticality = 3
    elif percent_at_risk > 5:
        auto_criticality = 2
    else:
        auto_criticality = 1

    sys_config = get_cached_config()
    sys_counter = sys_config.get('sys_countermeasures', 3) if sys_config else 3
    net_counter = sys_config.get('net_countermeasures', 3) if sys_config else 3
    s = min(max(sys_counter, 1), 5)
    n = min(max(net_counter, 1), 5)

    scoring_mode = str(sys_config.get('scoring_mode', 'auto') or 'auto')

    if scoring_mode == "manual":
        criticality = min(max(int(sys_config.get('internal_criticality_override', 0) or 0), 1), 5)
        lethality = min(max(int(sys_config.get('internal_lethality_override', 0) or 0), 1), 5)
    elif scoring_mode == "hybrid":
        criticality = auto_criticality
        lethality = auto_lethality
    else:
        criticality = auto_criticality
        lethality = auto_lethality

    raw_score = (criticality + lethality) - (s + n)

    if scoring_mode == "hybrid":
        offset = int(sys_config.get('internal_risk_offset', 0) or 0)
        raw_score = raw_score + offset

    final_score = max(-8, min(8, raw_score))

    if final_score >= 6: risk_level = "RED"
    elif final_score >= 3: risk_level = "ORANGE"
    elif final_score >= -1: risk_level = "YELLOW"
    elif final_score >= -4: risk_level = "BLUE"
    else: risk_level = "GREEN"

    return {
        "score": final_score,
        "risk_level": risk_level,
        "total_assets": total_assets,
        "total_hw_loaded": len(hw_assets),
        "total_sw_loaded": len(sw_assets),
        "total_osint_hits": total_osint_hits,
        "critical_osint_hits": critical_osint_hits,
        "hw_data": sorted(annotated_hw, key=lambda x: x["OSINT Risk Score"], reverse=True),
        "sw_data": sorted(annotated_sw, key=lambda x: x["OSINT Risk Score"], reverse=True),
        "scoring_mode": scoring_mode,
        "applied_overrides": {
            "criticality": {"auto": auto_criticality, "used": criticality},
            "lethality": {"auto": auto_lethality, "used": lethality},
        }
    }
    
def generate_and_save_internal_risk_snapshot():
    """Runs the optimized CIS calculation and saves the snapshot to the DB for the dashboard."""
    from src.database import SessionLocal, InternalRiskSnapshot
    import json
    
    with SessionLocal() as db_session:
        # 1. Run the heavy calculation
        cis_data = calculate_internal_cis_score(db_session)
        
        # 2. Package it into a database snapshot
        snapshot = InternalRiskSnapshot(
            score=cis_data['score'],
            risk_level=cis_data['risk_level'],
            total_assets=cis_data['total_assets'],
            total_osint_hits=cis_data['total_osint_hits'],
            critical_osint_hits=cis_data['critical_osint_hits'],
            hw_data_json=json.dumps(cis_data['hw_data']),
            sw_data_json=json.dumps(cis_data['sw_data'])
        )
        
        # 3. Save to database
        db_session.add(snapshot)
        db_session.commit()

        # 4. Keep SystemConfig mirror in sync so email/alert paths read live value
        config = db_session.query(SystemConfig).first()
        if config:
            config.last_internal_risk = cis_data['risk_level']
            db_session.commit()

    return cis_data

import re

def generate_unified_brief_email_html(report_time, markdown_content, global_risk=None, internal_risk=None):
    if not global_risk or not internal_risk:
        session = SessionLocal()
        try:
            config = session.query(SystemConfig).first()
            if not global_risk:
                global_risk = (config.last_global_risk or "UNKNOWN").upper()
            if not internal_risk:
                latest_internal = session.query(InternalRiskSnapshot).order_by(InternalRiskSnapshot.timestamp.desc()).first()
                internal_risk = (latest_internal.risk_level if latest_internal else "UNKNOWN").upper()
        finally:
            session.close()
    else:
        global_risk = global_risk.upper()
        internal_risk = internal_risk.upper()

    risk_tiers = {"GREEN": 1, "BLUE": 2, "YELLOW": 3, "ORANGE": 4, "RED": 5}
    g_tier = risk_tiers.get(global_risk, 0)
    i_tier = risk_tiers.get(internal_risk, 0)

    if g_tier == 0 and i_tier == 0:
        overall_risk = "UNKNOWN"
    elif g_tier >= i_tier:
        overall_risk = global_risk
    else:
        overall_risk = internal_risk

    name_map = {
        "GREEN": "LOW", "BLUE": "GUARDED",
        "YELLOW": "ELEVATED", "ORANGE": "HIGH", "RED": "SEVERE"
    }

    color_map = {
        "GREEN": "#01a46d", "BLUE": "#377fc7", "YELLOW": "#f5d800",
        "ORANGE": "#ff9b2b", "RED": "#ec3e40", "UNKNOWN": "#6c757d"
    }
    overall_color = color_map.get(overall_risk, "#6c757d")
    global_color = color_map.get(global_risk, "#6c757d")
    internal_color = color_map.get(internal_risk, "#6c757d")

    overall_display = name_map.get(overall_risk, overall_risk)
    global_display = name_map.get(global_risk, global_risk)
    internal_display = name_map.get(internal_risk, internal_risk)

    disclaimer_html = ""
    disclaimer_match = re.search(
        r'^---\s*\n\*\*OSINT CORRELATION DISCLAIMER:\*\*\s*(.*?)\n\s*\n\*\*AI-GENERATED CONTENT:\*\*\s*(.*?)\n---',
        markdown_content, re.DOTALL | re.MULTILINE
    )
    if disclaimer_match:
        osint_text = disclaimer_match.group(1).strip()
        ai_text = disclaimer_match.group(2).strip()
        disclaimer_html = f'''
        <div style="background:#f8f9fa; border-left:4px solid #6b7280; border-radius:4px; padding:14px 18px; margin-bottom:24px;">
            <p style="font-size:11px; font-weight:700; color:#6b7280; margin:0 0 8px 0; text-transform:uppercase; letter-spacing:0.5px;">
                Disclaimers
            </p>
            <p style="font-size:12.5px; color:#4b5563; line-height:1.5; margin:0 0 8px 0;">
                <strong>OSINT Correlation:</strong> {osint_text}
            </p>
            <p style="font-size:12.5px; color:#4b5563; line-height:1.5; margin:0;">
                <strong>AI-Generated Content:</strong> {ai_text}
            </p>
        </div>
        '''
        markdown_content = markdown_content.replace(disclaimer_match.group(0), "").strip()

    def native_md_to_html(text):
        text = text.replace('\r', '').strip()

        text = re.sub(r'^# (.*?)$', r'<h1 style="color:#111827; font-size:22px; font-weight:600; margin-bottom:10px; margin-top:0;">\1</h1>', text, flags=re.MULTILINE)
        text = re.sub(r'^## (.*?)$', r'<h2 style="color:#111827; font-size:18px; font-weight:600; border-bottom:2px solid #e5e7eb; padding-bottom:8px; margin-top:25px; margin-bottom:12px;">\1</h2>', text, flags=re.MULTILINE)
        text = re.sub(r'^### (.*?)$', r'<h3 style="color:#374151; font-size:16px; margin-bottom:5px; margin-top:15px;">\1</h3>', text, flags=re.MULTILINE)

        text = re.sub(r'\*\*(.*?)\*\*', r'<strong style="color:#111827;">\1</strong>', text)
        text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2" style="color:#3498db; text-decoration:none;">\1</a>', text)

        text = re.sub(r'^\* (.*?)$', r'<div style="margin-bottom:6px; padding-left:10px;">&#8226; \1</div>', text, flags=re.MULTILINE)
        text = re.sub(r'^- (.*?)$', r'<div style="margin-bottom:6px; padding-left:10px;">&#8226; \1</div>', text, flags=re.MULTILINE)

        text = re.sub(r'\n{3,}', '\n\n', text)
        text = text.replace('\n', '<br>')

        text = re.sub(r'(<br>)*<h', '<h', text)
        text = re.sub(r'</h1>(<br>)*', '</h1>', text)
        text = re.sub(r'</h2>(<br>)*', '</h2>', text)
        text = re.sub(r'</h3>(<br>)*', '</h3>', text)
        text = re.sub(r'(<br>)*<div style="margin-bottom: 6px', '<div style="margin-bottom: 6px', text)
        text = re.sub(r'</div>(<br>)*', '</div>', text)

        return text

    raw_html = disclaimer_html + native_md_to_html(markdown_content)

    cyber_line = (
        f'The current Internal Threat Posture of {internal_display} '
        f'is assessed and determined by the AECC/CI Cyber Security Director.'
    )

    banners_html = f"""
    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:25px; table-layout:fixed;">
        <tr>
            <td width="33%" align="center" valign="top" style="padding:5px;">
                <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#f8f9fa; border:1px solid #e5e7eb; border-radius:8px;">
                    <tr><td align="center" style="padding:15px 10px;">
                        <div style="font-size:11px; font-weight:700; color:#6b7280; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:8px;">Unified Posture</div>
                        <div style="background-color:{overall_color}; color:#ffffff; font-size:14px; font-weight:bold; padding:6px 16px; border-radius:20px; display:inline-block;">{overall_display}</div>
                    </td></tr>
                </table>
            </td>
            <td width="33%" align="center" valign="top" style="padding:5px;">
                <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#f8f9fa; border:1px solid #e5e7eb; border-radius:8px;">
                    <tr><td align="center" style="padding:15px 10px;">
                        <div style="font-size:11px; font-weight:700; color:#6b7280; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:8px;">Global Risk</div>
                        <div style="background-color:{global_color}; color:#ffffff; font-size:14px; font-weight:bold; padding:6px 16px; border-radius:20px; display:inline-block;">{global_display}</div>
                    </td></tr>
                </table>
            </td>
            <td width="33%" align="center" valign="top" style="padding:5px;">
                <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#f8f9fa; border:1px solid #e5e7eb; border-radius:8px;">
                    <tr><td align="center" style="padding:15px 10px;">
                        <div style="font-size:11px; font-weight:700; color:#6b7280; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:8px;">Internal Cyber Risk</div>
                        <div style="background-color:{internal_color}; color:#ffffff; font-size:14px; font-weight:bold; padding:6px 16px; border-radius:20px; display:inline-block;">{internal_display}</div>
                    </td></tr>
                </table>
            </td>
        </tr>
    </table>
    """

    formatted_html = f"""
    <div style="margin:0; padding:20px; background-color:#f3f4f6;">
        <div style="font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; max-width:850px; margin:0 auto; background-color:#ffffff; border:1px solid #e5e7eb; border-radius:8px; overflow:hidden; box-shadow:0 4px 6px -1px rgba(0,0,0,0.1);">

            <div style="background-color:#1f2937; padding:25px 30px; text-align:left;">
                <h1 style="color:#ffffff; margin:0 0 5px 0; font-size:22px; font-weight:600; letter-spacing:-0.5px;">Executive Unified Risk Brief</h1>
                <p style="color:#9ca3af; margin:0; font-size:13px;">Generated: {report_time}</p>
            </div>

            <div style="padding:30px 30px 10px 30px; font-size:14px; line-height:1.6; color:#374151;">

                {banners_html}

                <p style="font-size:14px; line-height:1.6; color:#374151; margin:0 0 15px 0;">
                    <strong>{cyber_line}</strong>
                </p>

                <div>
                    {raw_html}
                </div>

            </div>

            <br>
            <div style="background-color:#f9fafb; padding:14px 30px; text-align:center; border-top:1px solid #e5e7eb;">
                <p style="margin:0; font-size:11px; color:#9ca3af; line-height:1.5;">
                    NOC Intelligence Fusion Center &middot; Internal Use Only
                </p>
            </div>

        </div>
    </div>
    """

    formatted_html = formatted_html.replace('\xa0', ' ')
    formatted_html = re.sub(r'>\s+<', '><', formatted_html)
    formatted_html = formatted_html.strip()

    return formatted_html
    
def generate_global_brief_email_html(report_time, markdown_content, global_risk=None, internal_risk=None):
    import re

    if not global_risk or not internal_risk:
        session = SessionLocal()
        try:
            config = session.query(SystemConfig).first()
            if not global_risk:
                global_risk = (config.last_global_risk or "UNKNOWN").upper()
            if not internal_risk:
                latest_internal = session.query(InternalRiskSnapshot).order_by(InternalRiskSnapshot.timestamp.desc()).first()
                internal_risk = (latest_internal.risk_level if latest_internal else "UNKNOWN").upper()
        finally:
            session.close()
    else:
        global_risk = global_risk.upper()
        internal_risk = internal_risk.upper()

    risk_tiers = {"GREEN": 1, "BLUE": 2, "YELLOW": 3, "ORANGE": 4, "RED": 5}
    g_tier = risk_tiers.get(global_risk, 0)
    i_tier = risk_tiers.get(internal_risk, 0)

    if g_tier == 0 and i_tier == 0:
        overall_risk = "UNKNOWN"
    elif g_tier >= i_tier:
        overall_risk = global_risk
    else:
        overall_risk = internal_risk

    name_map = {
        "GREEN": "LOW", "BLUE": "GUARDED",
        "YELLOW": "ELEVATED", "ORANGE": "HIGH", "RED": "SEVERE"
    }

    color_map = {
        "GREEN": "#01a46d", "BLUE": "#377fc7", "YELLOW": "#f5d800",
        "ORANGE": "#ff9b2b", "RED": "#ec3e40", "UNKNOWN": "#6c757d"
    }
    global_color = color_map.get(global_risk, "#6c757d")
    internal_color = color_map.get(internal_risk, "#6c757d")

    global_display = name_map.get(global_risk, global_risk)
    internal_display = name_map.get(internal_risk, internal_risk)

    disclaimer_html = ""
    disclaimer_match = re.search(
        r'^---\s*\n\*\*OSINT CORRELATION DISCLAIMER:\*\*\s*(.*?)\n\s*\n\*\*AI-GENERATED CONTENT:\*\*\s*(.*?)\n---',
        markdown_content, re.DOTALL | re.MULTILINE
    )
    if disclaimer_match:
        osint_text = disclaimer_match.group(1).strip()
        ai_text = disclaimer_match.group(2).strip()
        disclaimer_html = f'''
        <div style="background:#f8f9fa; border-left:4px solid #6b7280; border-radius:4px; padding:14px 18px; margin-bottom:24px;">
            <p style="font-size:11px; font-weight:700; color:#6b7280; margin:0 0 8px 0; text-transform:uppercase; letter-spacing:0.5px;">
                Disclaimers
            </p>
            <p style="font-size:12.5px; color:#4b5563; line-height:1.5; margin:0 0 8px 0;">
                <strong>OSINT Correlation:</strong> {osint_text}
            </p>
            <p style="font-size:12.5px; color:#4b5563; line-height:1.5; margin:0;">
                <strong>AI-Generated Content:</strong> {ai_text}
            </p>
        </div>
        '''
        markdown_content = markdown_content.replace(disclaimer_match.group(0), "").strip()

    def native_md_to_html(text):
        text = text.replace('\r', '').strip()
        text = re.sub(r'^# (.*?)$', r'<h1 style="color:#111827; font-size:22px; font-weight:600; margin-bottom:10px; margin-top:0;">\1</h1>', text, flags=re.MULTILINE)
        text = re.sub(r'^## (.*?)$', r'<h2 style="color:#111827; font-size:18px; font-weight:600; border-bottom:2px solid #e5e7eb; padding-bottom:8px; margin-top:25px; margin-bottom:12px;">\1</h2>', text, flags=re.MULTILINE)
        text = re.sub(r'^### (.*?)$', r'<h3 style="color:#374151; font-size:16px; margin-bottom:5px; margin-top:15px;">\1</h3>', text, flags=re.MULTILINE)
        text = re.sub(r'\*\*(.*?)\*\*', r'<strong style="color:#111827;">\1</strong>', text)
        text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2" style="color:#3498db; text-decoration:none;">\1</a>', text)
        text = re.sub(r'^\* (.*?)$', r'<div style="margin-bottom:6px; padding-left:10px;">&#8226; \1</div>', text, flags=re.MULTILINE)
        text = re.sub(r'^- (.*?)$', r'<div style="margin-bottom:6px; padding-left:10px;">&#8226; \1</div>', text, flags=re.MULTILINE)
        text = re.sub(r'\n{3,}', '\n\n', text)
        text = text.replace('\n', '<br>')
        text = re.sub(r'(<br>)*<h', '<h', text)
        text = re.sub(r'</h1>(<br>)*', '</h1>', text)
        text = re.sub(r'</h2>(<br>)*', '</h2>', text)
        text = re.sub(r'</h3>(<br>)*', '</h3>', text)
        text = re.sub(r'(<br>)*<div style="margin-bottom: 6px', '<div style="margin-bottom: 6px', text)
        text = re.sub(r'</div>(<br>)*', '</div>', text)
        return text

    raw_html = disclaimer_html + native_md_to_html(markdown_content)

    cyber_line = (
        f'The current Global Threat Posture of {global_display} '
        f'is assessed and determined by the AECC/CI Cyber Security Director.'
    )

    banners_html = f"""
    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:25px; table-layout:fixed;">
        <tr>
            <td width="50%" align="center" valign="top" style="padding:5px;">
                <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#f8f9fa; border:1px solid #e5e7eb; border-radius:8px;">
                    <tr><td align="center" style="padding:15px 10px;">
                        <div style="font-size:11px; font-weight:700; color:#6b7280; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:8px;">Global Threat Posture</div>
                        <div style="background-color:{global_color}; color:#ffffff; font-size:14px; font-weight:bold; padding:6px 16px; border-radius:20px; display:inline-block;">{global_display}</div>
                    </td></tr>
                </table>
            </td>
            <td width="50%" align="center" valign="top" style="padding:5px;">
                <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#f8f9fa; border:1px solid #e5e7eb; border-radius:8px;">
                    <tr><td align="center" style="padding:15px 10px;">
                        <div style="font-size:11px; font-weight:700; color:#6b7280; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:8px;">Internal Cyber Risk</div>
                        <div style="background-color:{internal_color}; color:#ffffff; font-size:14px; font-weight:bold; padding:6px 16px; border-radius:20px; display:inline-block;">{internal_display}</div>
                    </td></tr>
                </table>
            </td>
        </tr>
    </table>
    """

    formatted_html = f"""
    <div style="margin:0; padding:20px; background-color:#f3f4f6;">
        <div style="font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; max-width:850px; margin:0 auto; background-color:#ffffff; border:1px solid #e5e7eb; border-radius:8px; overflow:hidden; box-shadow:0 4px 6px -1px rgba(0,0,0,0.1);">
            <div style="background-color:#dc2626; padding:25px 30px; text-align:left;">
                <h1 style="color:#ffffff; margin:0 0 5px 0; font-size:22px; font-weight:600; letter-spacing:-0.5px;">Global Threat Brief — US CI & International</h1>
                <p style="color:#fecaca; margin:0; font-size:13px;">Generated: {report_time}</p>
            </div>
            <div style="padding:30px 30px 10px 30px; font-size:14px; line-height:1.6; color:#374151;">
                {banners_html}
                <p style="font-size:14px; line-height:1.6; color:#374151; margin:0 0 15px 0;">
                    <strong>{cyber_line}</strong>
                </p>
                <div>{raw_html}</div>
                <div style="background:#f8f9fa; border-left:4px solid #6b7280; border-radius:4px; padding:14px 18px; margin-top:24px;">
                    <p style="font-size:11px; font-weight:700; color:#6b7280; margin:0 0 8px 0; text-transform:uppercase; letter-spacing:0.5px;">
                        Disclaimers
                    </p>
                    <p style="font-size:12.5px; color:#4b5563; line-height:1.5; margin:0 0 8px 0;">
                        <strong>OSINT Correlation:</strong> This brief synthesizes external Open-Source Intelligence (OSINT) to provide situational awareness of the global threat landscape. It does NOT represent confirmed compromises of our systems or facilities.
                    </p>
                    <p style="font-size:12.5px; color:#4b5563; line-height:1.5; margin:0;">
                        <strong>AI-Generated Content:</strong> This brief was generated by the internal NOC AIOps system using automated intelligence analysis. This report has not been thoroughly reviewed by a Human Security Analyst.
                    </p>
                </div>
            </div>
            <br>
            <div style="background-color:#f9fafb; padding:14px 30px; text-align:center; border-top:1px solid #e5e7eb;">
                <p style="margin:0; font-size:11px; color:#9ca3af; line-height:1.5;">
                    NOC Intelligence Fusion Center &middot; Internal Use Only
                </p>
            </div>
        </div>
    </div>
    """
    formatted_html = formatted_html.replace('\xa0', ' ')
    formatted_html = re.sub(r'>\s+<', '><', formatted_html)
    formatted_html = formatted_html.strip()
    return formatted_html


def generate_internal_brief_email_html(report_time, markdown_content, global_risk=None, internal_risk=None):
    import re

    if not global_risk or not internal_risk:
        session = SessionLocal()
        try:
            config = session.query(SystemConfig).first()
            if not global_risk:
                global_risk = (config.last_global_risk or "UNKNOWN").upper()
            if not internal_risk:
                latest_internal = session.query(InternalRiskSnapshot).order_by(InternalRiskSnapshot.timestamp.desc()).first()
                internal_risk = (latest_internal.risk_level if latest_internal else "UNKNOWN").upper()
        finally:
            session.close()
    else:
        global_risk = global_risk.upper()
        internal_risk = internal_risk.upper()

    risk_tiers = {"GREEN": 1, "BLUE": 2, "YELLOW": 3, "ORANGE": 4, "RED": 5}
    g_tier = risk_tiers.get(global_risk, 0)
    i_tier = risk_tiers.get(internal_risk, 0)

    if g_tier == 0 and i_tier == 0:
        overall_risk = "UNKNOWN"
    elif i_tier >= g_tier:
        overall_risk = internal_risk
    else:
        overall_risk = global_risk

    name_map = {
        "GREEN": "LOW", "BLUE": "GUARDED",
        "YELLOW": "ELEVATED", "ORANGE": "HIGH", "RED": "SEVERE"
    }

    color_map = {
        "GREEN": "#01a46d", "BLUE": "#377fc7", "YELLOW": "#f5d800",
        "ORANGE": "#ff9b2b", "RED": "#ec3e40", "UNKNOWN": "#6c757d"
    }
    global_color = color_map.get(global_risk, "#6c757d")
    internal_color = color_map.get(internal_risk, "#6c757d")

    global_display = name_map.get(global_risk, global_risk)
    internal_display = name_map.get(internal_risk, internal_risk)

    disclaimer_html = ""
    disclaimer_match = re.search(
        r'^---\s*\n\*\*OSINT CORRELATION DISCLAIMER:\*\*\s*(.*?)\n\s*\n\*\*AI-GENERATED CONTENT:\*\*\s*(.*?)\n---',
        markdown_content, re.DOTALL | re.MULTILINE
    )
    if disclaimer_match:
        osint_text = disclaimer_match.group(1).strip()
        ai_text = disclaimer_match.group(2).strip()
        disclaimer_html = f'''
        <div style="background:#f8f9fa; border-left:4px solid #6b7280; border-radius:4px; padding:14px 18px; margin-bottom:24px;">
            <p style="font-size:11px; font-weight:700; color:#6b7280; margin:0 0 8px 0; text-transform:uppercase; letter-spacing:0.5px;">
                Disclaimers
            </p>
            <p style="font-size:12.5px; color:#4b5563; line-height:1.5; margin:0 0 8px 0;">
                <strong>OSINT Correlation:</strong> {osint_text}
            </p>
            <p style="font-size:12.5px; color:#4b5563; line-height:1.5; margin:0;">
                <strong>AI-Generated Content:</strong> {ai_text}
            </p>
        </div>
        '''
        markdown_content = markdown_content.replace(disclaimer_match.group(0), "").strip()

    def native_md_to_html(text):
        text = text.replace('\r', '').strip()
        text = re.sub(r'^# (.*?)$', r'<h1 style="color:#111827; font-size:22px; font-weight:600; margin-bottom:10px; margin-top:0;">\1</h1>', text, flags=re.MULTILINE)
        text = re.sub(r'^## (.*?)$', r'<h2 style="color:#111827; font-size:18px; font-weight:600; border-bottom:2px solid #e5e7eb; padding-bottom:8px; margin-top:25px; margin-bottom:12px;">\1</h2>', text, flags=re.MULTILINE)
        text = re.sub(r'^### (.*?)$', r'<h3 style="color:#374151; font-size:16px; margin-bottom:5px; margin-top:15px;">\1</h3>', text, flags=re.MULTILINE)
        text = re.sub(r'\*\*(.*?)\*\*', r'<strong style="color:#111827;">\1</strong>', text)
        text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2" style="color:#3498db; text-decoration:none;">\1</a>', text)
        text = re.sub(r'^\* (.*?)$', r'<div style="margin-bottom:6px; padding-left:10px;">&#8226; \1</div>', text, flags=re.MULTILINE)
        text = re.sub(r'^- (.*?)$', r'<div style="margin-bottom:6px; padding-left:10px;">&#8226; \1</div>', text, flags=re.MULTILINE)
        text = re.sub(r'\n{3,}', '\n\n', text)
        text = text.replace('\n', '<br>')
        text = re.sub(r'(<br>)*<h', '<h', text)
        text = re.sub(r'</h1>(<br>)*', '</h1>', text)
        text = re.sub(r'</h2>(<br>)*', '</h2>', text)
        text = re.sub(r'</h3>(<br>)*', '</h3>', text)
        text = re.sub(r'(<br>)*<div style="margin-bottom: 6px', '<div style="margin-bottom: 6px', text)
        text = re.sub(r'</div>(<br>)*', '</div>', text)
        return text

    raw_html = disclaimer_html + native_md_to_html(markdown_content)

    cyber_line = (
        f'The current Internal Threat Posture of {internal_display} '
        f'is assessed and determined by the AECC/CI Cyber Security Director.'
    )

    banners_html = f"""
    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:25px; table-layout:fixed;">
        <tr>
            <td width="50%" align="center" valign="top" style="padding:5px;">
                <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#f8f9fa; border:1px solid #e5e7eb; border-radius:8px;">
                    <tr><td align="center" style="padding:15px 10px;">
                        <div style="font-size:11px; font-weight:700; color:#6b7280; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:8px;">Internal Cyber Risk</div>
                        <div style="background-color:{internal_color}; color:#ffffff; font-size:14px; font-weight:bold; padding:6px 16px; border-radius:20px; display:inline-block;">{internal_display}</div>
                    </td></tr>
                </table>
            </td>
            <td width="50%" align="center" valign="top" style="padding:5px;">
                <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#f8f9fa; border:1px solid #e5e7eb; border-radius:8px;">
                    <tr><td align="center" style="padding:15px 10px;">
                        <div style="font-size:11px; font-weight:700; color:#6b7280; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:8px;">Global Threat Posture</div>
                        <div style="background-color:{global_color}; color:#ffffff; font-size:14px; font-weight:bold; padding:6px 16px; border-radius:20px; display:inline-block;">{global_display}</div>
                    </td></tr>
                </table>
            </td>
        </tr>
    </table>
    """

    formatted_html = f"""
    <div style="margin:0; padding:20px; background-color:#f3f4f6;">
        <div style="font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; max-width:850px; margin:0 auto; background-color:#ffffff; border:1px solid #e5e7eb; border-radius:8px; overflow:hidden; box-shadow:0 4px 6px -1px rgba(0,0,0,0.1);">
            <div style="background-color:#7c3aed; padding:25px 30px; text-align:left;">
                <h1 style="color:#ffffff; margin:0 0 5px 0; font-size:22px; font-weight:600; letter-spacing:-0.5px;">Internal Asset Risk Brief</h1>
                <p style="color:#ddd6fe; margin:0; font-size:13px;">Generated: {report_time}</p>
            </div>
            <div style="padding:30px 30px 10px 30px; font-size:14px; line-height:1.6; color:#374151;">
                {banners_html}
                <p style="font-size:14px; line-height:1.6; color:#374151; margin:0 0 15px 0;">
                    <strong>{cyber_line}</strong>
                </p>
                <div>{raw_html}</div>
            </div>
            <br>
            <div style="background-color:#f9fafb; padding:14px 30px; text-align:center; border-top:1px solid #e5e7eb;">
                <p style="margin:0; font-size:11px; color:#9ca3af; line-height:1.5;">
                    NOC Intelligence Fusion Center &middot; Internal Use Only
                </p>
            </div>
        </div>
    </div>
    """
    formatted_html = formatted_html.replace('\xa0', ' ')
    formatted_html = re.sub(r'>\s+<', '><', formatted_html)
    formatted_html = formatted_html.strip()
    return formatted_html


def generate_outlook_html_report(intel):
    """Generates the static fallback report if the LLM generation fails or is bypassed."""
    color_map = {
        "GREEN": "#01a46d",   # CIS Alert Level: Low
        "BLUE": "#377fc7",    # CIS Alert Level: Guarded
        "YELLOW": "#f5d800",  # CIS Alert Level: Elevated
        "ORANGE": "#ff9b2b",  # CIS Alert Level: High
        "RED": "#ec3e40",     # CIS Alert Level: Severe
        "UNKNOWN": "#6c757d"  # Utility (Retained)
    }
    badge_color = color_map.get(intel["unified_risk"].upper(), "#28a745")
    
    name_map = {
        "GREEN": "LOW", "BLUE": "GUARDED",
        "YELLOW": "ELEVATED", "ORANGE": "HIGH", "RED": "SEVERE"
    }
    display_risk = name_map.get(intel["unified_risk"].upper(), "UNKNOWN")
    
    html = f"""
    <html>
    <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px;">
        <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: #ffffff; max-width: 600px; margin: 0 auto; border: 1px solid #dddddd; border-radius: 8px;">
            <tr>
                <td style="padding: 20px; background-color: #0f172a; border-radius: 8px 8px 0 0; text-align: center;">
                    <h2 style="color: #ffffff; margin: 0;">BES Threat Intelligence Summary</h2>
                    <p style="color: #94a3b8; margin: 5px 0 0 0; font-size: 12px;">Generated: {intel['timestamp']}</p>
                </td>
            </tr>
            <tr>
                <td style="padding: 30px 20px; text-align: center;">
                    <h3 style="margin: 0; color: #333333; text-transform: uppercase;">Unified Threat Posture</h3>
                    <div style="margin-top: 15px; padding: 10px 20px; background-color: {badge_color}; color: #ffffff; display: inline-block; font-size: 24px; font-weight: bold; border-radius: 4px;">
                        {display_risk}
                    </div>
                </td>
            </tr>
            <tr>
                <td style="padding: 20px;">
                    <h4 style="color: #0056b3; border-bottom: 2px solid #eeeeee; padding-bottom: 5px;">Physical & Crime Intelligence</h4>
                    <p style="color: #444444; line-height: 1.6; font-size: 14px;"><strong>Status: {name_map.get(intel['physical_score'], 'UNKNOWN')}</strong><br/>{intel['physical_brief']}</p>
                </td>
            </tr>
            <tr>
                <td style="padding: 20px; padding-top: 0;">
                    <h4 style="color: #0056b3; border-bottom: 2px solid #eeeeee; padding-bottom: 5px;">Cyber & SCADA Intelligence</h4>
                    <p style="color: #444444; line-height: 1.6; font-size: 14px;"><strong>Status: {name_map.get(intel['cyber_score'], 'UNKNOWN')}</strong><br/>{intel['cyber_brief']}</p>
                </td>
            </tr>
        </table>
    </body>
    </html>
    """
    return html

def send_executive_report(recipient_email, intel, sys_config):
    try:
        html_body = generate_outlook_html_report(intel)
        from src.utils.mailer import send_alert_email
        success, msg = send_alert_email(
            subject=f"Grid Threat Intelligence Update - Posture: {intel['unified_risk']}", 
            body=html_body, recipient_override=recipient_email, is_html=True
        )
        return success, msg
    except Exception as e: return False, f"Email Dispatch Failed: {e}"


# ==========================================
# 4. DAILY FUSION REPORT
# ==========================================

def get_all_daily_briefings():
    with SessionLocal() as db:
        reports = db.query(DailyBriefing).order_by(DailyBriefing.report_date.desc()).all()
        return to_dotdict_list(reports)

def get_daily_briefing(target_date):
    with SessionLocal() as db:
        return to_dotdict(db.query(DailyBriefing).filter(DailyBriefing.report_date == target_date).first())

def save_daily_briefing(target_date, content):
    with SessionLocal() as db:
        b = db.query(DailyBriefing).filter(DailyBriefing.report_date == target_date).first()
        if b:
            b.content = content
            b.created_at = datetime.utcnow()
        else:
            db.add(DailyBriefing(report_date=target_date, content=content))
        db.commit()

def generate_daily_report_email_html(report_date, markdown_content):
    def native_md_to_html(text):
        text = re.sub(r'^### (.*?)$', r'<h3 style="color:#2c3e50; margin-bottom:5px;">\1</h3>', text, flags=re.MULTILINE)
        text = re.sub(r'^## (.*?)$', r'<h2 style="color:#2980b9; margin-bottom:5px; border-bottom:1px solid #eee;">\1</h2>', text, flags=re.MULTILINE)
        text = re.sub(r'^# (.*?)$', r'<h1 style="color:#2c3e50;">\1</h1>', text, flags=re.MULTILINE)
        text = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', text)
        text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2" style="color:#3498db; text-decoration:none;">\1</a>', text)
        text = re.sub(r'^\* (.*?)$', r'&#8226; \1<br>', text, flags=re.MULTILINE)
        text = re.sub(r'^- (.*?)$', r'&#8226; \1<br>', text, flags=re.MULTILINE)
        text = text.replace('\n', '<br>').replace('<br><br><h', '<br><h')
        return text

    raw_html = native_md_to_html(markdown_content)
    
    formatted_html = f"""
    <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 900px; margin: 0 auto; color: #333; line-height: 1.5;">
        <div style="background-color: #fcfcfc; padding: 20px; border-radius: 6px; border-left: 4px solid #d9534f; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
            <h2 style="color: #2c3e50; margin-top: 0;">NOC Daily Fusion Report</h2>
            <p style="color: #7f8c8d; font-size: 0.9em; margin-bottom: 20px;"><strong>Date:</strong> {report_date}</p>
            <div style="font-size: 14px; background-color: #ffffff; padding: 15px; border-radius: 4px; border: 1px solid #eee;">
                {raw_html}
            </div>
        </div>
    </div>
    """
    return formatted_html


def generate_custom_report_email_html(title, report_time, markdown_content):
    """Render a custom intelligence report in a readable HTML email layout."""
    from html import escape

    def native_md_to_html(text):
        text = escape(text)
        text = re.sub(r'^### (.*?)$', r'<h3 style="color:#374151; font-size:16px; margin:20px 0 8px;">\1</h3>', text, flags=re.MULTILINE)
        text = re.sub(r'^## (.*?)$', r'<h2 style="color:#111827; font-size:19px; border-bottom:2px solid #e5e7eb; padding-bottom:8px; margin:28px 0 12px;">\1</h2>', text, flags=re.MULTILINE)
        text = re.sub(r'^# (.*?)$', r'<h1 style="color:#111827; font-size:23px; margin:0 0 12px;">\1</h1>', text, flags=re.MULTILINE)
        text = re.sub(r'\*\*(.*?)\*\*', r'<strong style="color:#111827;">\1</strong>', text)
        text = re.sub(r'^\s*[-*] (.*?)$', r'<div style="margin:0 0 7px 10px; padding-left:10px;">&#8226; \1</div>', text, flags=re.MULTILINE)
        text = re.sub(r'\n{3,}', '\n\n', text)
        text = text.replace('\n', '<br>')
        text = re.sub(r'(<br>)*<h', '<h', text)
        text = re.sub(r'</h([123])>(<br>)*', r'</h\1>', text)
        text = re.sub(r'(<br>)*<div style="margin:0 0 7px', '<div style="margin:0 0 7px', text)
        text = re.sub(r'</div>(<br>)*', '</div>', text)
        return text

    raw_html = native_md_to_html(markdown_content.strip())
    return f"""
    <div style="margin:0; padding:20px; background:#f3f4f6;">
      <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif; max-width:850px; margin:0 auto; background:#fff; border:1px solid #e5e7eb; border-radius:8px; overflow:hidden;">
        <div style="background:#1d4ed8; padding:24px 30px;">
          <h1 style="color:#fff; margin:0 0 6px; font-size:22px; font-weight:600;">{escape(title)}</h1>
          <p style="color:#dbeafe; margin:0; font-size:13px;">Generated: {escape(report_time)}</p>
        </div>
        <div style="padding:25px 30px; font-size:14px; line-height:1.6; color:#374151;">{raw_html}</div>
        <div style="background:#f9fafb; padding:13px 30px; text-align:center; border-top:1px solid #e5e7eb;">
          <p style="margin:0; font-size:11px; color:#9ca3af;">NOC Intelligence Fusion Center &middot; Internal Use Only</p>
        </div>
      </div>
    </div>
    """.strip()


# ==========================================
# 5. THREAT TELEMETRY (CISA, Cloud, NWS, Regional Grid)
# ==========================================

def get_paginated_articles(feed_type, cat_filter, page, page_size, search_term=None, min_score=0):
    with SessionLocal() as db:
        q = db.query(Article)
        if feed_type == "pinned": q = q.filter_by(is_pinned=True)
        elif feed_type == "live": q = q.filter(Article.score >= 50.0, Article.is_pinned == False)
        elif feed_type == "low": q = q.filter(Article.score < 50.0, Article.is_pinned == False)

        if cat_filter != "All": q = q.filter_by(category=cat_filter)
        if search_term: q = q.filter(Article.title.ilike(f"%{search_term}%") | Article.summary.ilike(f"%{search_term}%"))
        q = q.filter(Article.score >= min_score)

        total_items = q.count()
        total_pages = max(1, (total_items + page_size - 1) // page_size)
        page = min(max(1, page), total_pages)

        if feed_type in ["pinned", "live", "low"]: q = q.order_by(Article.published_date.desc())
        else: q = q.order_by(Article.score.desc(), Article.published_date.desc())

        items = q.offset((page - 1) * page_size).limit(page_size).all()
        return to_dotdict_list(items), total_items, total_pages, page

def get_article_detail(article_id):
    with SessionLocal() as db:
        art = db.query(Article).filter_by(id=article_id).first()
        if not art:
            return None

        article_dict = to_dotdict(art)

        kw_dict = {k.word.lower(): k.weight for k in db.query(Keyword).all()}
        matched_keywords = []
        total_kw_score = 0
        if art.keywords_found and isinstance(art.keywords_found, list):
            for w in art.keywords_found:
                wt = kw_dict.get(w.lower(), 0)
                total_kw_score += wt
                matched_keywords.append({"word": w, "weight": wt})

        article_dict["keywords_with_weights"] = matched_keywords
        article_dict["total_keyword_score"] = total_kw_score

        iocs = db.query(ExtractedIOC).filter_by(article_id=art.id).all()
        article_dict["iocs"] = [
            {"indicator_type": i.indicator_type, "indicator_value": i.indicator_value, "context": i.context}
            for i in iocs
        ]

        return article_dict


def get_cves(limit=15, days_back=None):
    with SessionLocal() as db:
        q = db.query(CveItem)
        if days_back: q = q.filter(CveItem.date_added >= datetime.utcnow() - timedelta(days=days_back))
        return to_dotdict_list(q.order_by(CveItem.date_added.desc()).limit(limit).all())

def get_cloud_outages(active_only=True, limit=None, days_back=None):
    with SessionLocal() as db:
        q = db.query(CloudOutage)
        if active_only: q = q.filter_by(is_resolved=False)
        if days_back:
            cutoff = datetime.utcnow() - timedelta(days=days_back)
            q = q.filter(CloudOutage.updated_at >= cutoff)
        q = q.order_by(CloudOutage.updated_at.desc())
        if limit: q = q.limit(limit)
        return to_dotdict_list(q.all())

def get_user_weather_prefs(username):
    from src.database import SessionLocal, UserWeatherPreference
    with SessionLocal() as db:
        prefs = db.query(UserWeatherPreference).filter_by(username=username).all()
        return [p.alert_type for p in prefs]

def set_user_weather_prefs(username, alerts):
    from src.database import SessionLocal, UserWeatherPreference
    with SessionLocal() as db:
        # Clear existing and replace
        db.query(UserWeatherPreference).filter_by(username=username).delete()
        for alert in alerts:
            db.add(UserWeatherPreference(username=username, alert_type=alert))
        db.commit()

WFCA_WFS_URL = "https://prod-geoserver-lb.wfca.com/geoserver/wfs"
WFCA_WILDFIRE_BBOX = "-95.6,32.1,-88.6,37.4,EPSG:4326"
WFCA_WFS_PAGE_SIZE = 2000


def _fetch_wfca_wfs_features(layer_name):
    """Fetch all features for a regional WFCA GeoServer WFS layer."""
    features = []
    offset = 0
    while True:
        params = {
            "service": "WFS",
            "version": "2.0.0",
            "request": "GetFeature",
            "typeNames": layer_name,
            "outputFormat": "application/json",
            "srsName": "EPSG:4326",
            "bbox": WFCA_WILDFIRE_BBOX,
            "count": WFCA_WFS_PAGE_SIZE,
            # WFCA's WFS layers do not have a database primary key exposed for
            # natural-order paging; use a public attribute for stable offsets.
            "sortBy": (
                "objectid A" if layer_name.endswith("Incidents")
                else "irwinid A" if layer_name.endswith("Footprints")
                else "attr_irwinid A"
            ),
            "startIndex": offset,
        }
        response = requests.get(WFCA_WFS_URL, params=params, timeout=20)
        response.raise_for_status()
        payload = response.json()
        page = payload.get("features") if isinstance(payload, dict) else None
        if not isinstance(page, list):
            raise ValueError(f"WFCA WFS returned an invalid FeatureCollection for {layer_name}")
        features.extend(page)

        try:
            matched = int(payload.get("numberMatched"))
        except (TypeError, ValueError):
            matched = None
        if not page or (matched is not None and len(features) >= matched):
            break
        if matched is None and len(page) < WFCA_WFS_PAGE_SIZE:
            break
        offset += len(page)
    return features


def _normalize_fire_id(value):
    return str(value or "").strip().strip("{}").casefold()


def _fire_number(value, default=None):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return number if math.isfinite(number) else default


def _get_wildfire_site_coordinates():
    """Load monitored-site coordinates for filtering distant small fires."""
    try:
        with SessionLocal() as db:
            rows = db.query(MonitoredLocation.lat, MonitoredLocation.lon).filter(
                MonitoredLocation.lat.isnot(None), MonitoredLocation.lon.isnot(None)
            ).all()
        return [
            (lon, lat)
            for lat_value, lon_value in rows
            if (lat := _fire_number(lat_value)) is not None
            and (lon := _fire_number(lon_value)) is not None
        ]
    except Exception:
        logger.warning("Unable to load monitored-site coordinates for wildfire filtering", exc_info=True)
        return None


def _haversine_miles(lon1, lat1, lon2, lat2):
    earth_radius_miles = 3958.7613
    lat1_r, lat2_r = math.radians(lat1), math.radians(lat2)
    dlat = lat2_r - lat1_r
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2) ** 2 + math.cos(lat1_r) * math.cos(lat2_r) * math.sin(dlon / 2) ** 2
    return earth_radius_miles * 2 * math.asin(min(1.0, math.sqrt(a)))


def _shape_site_distances_miles(geo_shape, site_coordinates):
    """Measure distances from a lon/lat geometry to site points in miles."""
    from shapely.geometry import Point
    from shapely.ops import transform

    if geo_shape.is_empty:
        return [float("inf")] * len(site_coordinates)
    _, min_lat, _, max_lat = geo_shape.bounds
    reference_lat = (min_lat + max_lat) / 2
    miles_per_longitude_degree = 69.172 * math.cos(math.radians(reference_lat))
    projected_shape = transform(
        lambda lon, lat, z=None: (lon * miles_per_longitude_degree, lat * 69.0),
        geo_shape,
    )
    return [
        projected_shape.distance(Point(lon * miles_per_longitude_degree, lat * 69.0))
        for lon, lat in site_coordinates
    ]


def _wildfire_within_one_mile(fire, perimeter, site_coordinates):
    """Check the perimeter edge, or incident point when no perimeter exists."""
    from shapely.geometry import shape

    geometry = perimeter.get("geometry") if perimeter else None
    if geometry:
        try:
            fire_shape = shape(geometry)
            if not fire_shape.is_empty:
                return any(distance <= 1.0 for distance in _shape_site_distances_miles(fire_shape, site_coordinates))
        except Exception:
            logger.warning("Unable to measure WFCA perimeter distance for %s", fire.get("name"), exc_info=True)

    return any(
        _haversine_miles(fire["lon"], fire["lat"], lon, lat) <= 1.0
        for lon, lat in site_coordinates
    )


@TTLCache(ttl=300, max_entries=1)
def get_active_wildfires():
    """Fetch current wildfire incidents and perimeters from the WFCA fire map."""
    try:
        from shapely.geometry import Point, mapping, shape
        from shapely.ops import unary_union

        # Keep the WFCA request small while covering Arkansas and the nearby
        # operational area; apply the exact county buffer to features below.
        counties = get_regional_counties_mapping()
        arkansas_counties = [
            shape(info["geometry"])
            for info in counties.values()
            if info.get("state_fips") == "05" and info.get("geometry")
        ]
        if not arkansas_counties:
            raise ValueError("Arkansas county boundaries are unavailable")
        arkansas = unary_union(arkansas_counties).buffer(0.75)

        incident_features = _fetch_wfca_wfs_features("WFCA:WFIGS_Incidents")
        active_fires = []
        active_fires_by_id = {}
        for feature in incident_features:
            if not isinstance(feature, dict):
                continue
            props = feature.get("properties") or {}
            if str(props.get("incidenttypecategory") or "").upper() != "WF":
                continue
            if str(props.get("stale_flag") or "").casefold() in {"true", "1", "yes"}:
                continue

            contained = _fire_number(props.get("percentcontained"))
            if contained is not None and contained >= 100:
                continue

            geometry = feature.get("geometry") or {}
            coordinates = geometry.get("coordinates") or []
            if len(coordinates) >= 2:
                lon, lat = coordinates[:2]
            else:
                lon = props.get("initiallongitude")
                lat = props.get("initiallatitude")
            lon, lat = _fire_number(lon), _fire_number(lat)
            if lon is None or lat is None:
                continue
            fire_point = Point(lon, lat)
            if not arkansas.covers(fire_point):
                continue

            acres = _fire_number(props.get("wfca_reportedacres"))
            if acres is None or acres <= 0:
                acres = _fire_number(props.get("discoveryacres"), 0)
            incident_id = props.get("irwinid")
            unique_id = props.get("uniquefireidentifier")
            state = str(props.get("poostate") or "Unknown")
            if state.startswith("US-"):
                state = state[3:]
            fire = {
                "name": props.get("incidentname") or "Unnamed",
                "state": state,
                "acres": round(acres or 0, 2),
                "contained": contained,
                "lon": lon,
                "lat": lat,
                "started": props.get("firediscoverydatetime"),
                "updated": props.get("modifiedondatetime_dt"),
                "cause": props.get("firecause"),
                "county": props.get("poocounty"),
                "irwin_id": incident_id,
                "unique_id": unique_id,
                "source": "WFCA",
                "color": [220, 20, 60, 230],
            }
            active_fires.append(fire)
            normalized_id = _normalize_fire_id(incident_id)
            if normalized_id:
                active_fires_by_id[normalized_id] = fire

        perimeters_by_id = {}
        try:
            perimeter_features = _fetch_wfca_wfs_features("WFCA:WFIGS_Perimeters")
        except Exception:
            logger.warning("Unable to retrieve WFCA fire perimeters; using incident points", exc_info=True)
            perimeter_features = []

        for feature in perimeter_features:
            if not isinstance(feature, dict):
                continue
            props = feature.get("properties") or {}
            normalized_id = _normalize_fire_id(props.get("attr_irwinid"))
            fire = active_fires_by_id.get(normalized_id)
            geometry = feature.get("geometry")
            if not fire or not geometry:
                continue
            try:
                fire_perimeter = shape(geometry)
                if fire_perimeter.is_empty or not fire_perimeter.intersects(arkansas):
                    continue
            except Exception:
                logger.warning("Skipping invalid WFCA perimeter for %s", fire["name"], exc_info=True)
                continue

            current = perimeters_by_id.setdefault(normalized_id, {
                "fire": fire,
                "geometries": [],
                "updated": None,
            })
            current["geometries"].append(fire_perimeter)
            perimeter_updated = props.get("poly_datecurrent") or props.get("attr_modifiedondatetime_dt")
            if perimeter_updated and (current["updated"] is None or str(perimeter_updated) > str(current["updated"])):
                current["updated"] = perimeter_updated

        current_perimeters = []
        for current in perimeters_by_id.values():
            fire = current["fire"]
            try:
                perimeter_geometry = mapping(unary_union(current["geometries"]))
                # Convert Shapely's tuple coordinates to plain JSON lists for the API.
                perimeter_geometry = json.loads(json.dumps(perimeter_geometry))
            except Exception:
                logger.warning("Unable to combine WFCA perimeters for %s", fire["name"], exc_info=True)
                continue
            current_perimeters.append({
                "geometry": perimeter_geometry,
                "name": fire["name"],
                "irwin_id": fire["irwin_id"],
                "acres": fire["acres"],
                "perimeter_updated": current["updated"],
                "map_method": "WFCA Fire Map",
                "contained": fire["contained"],
                "started": fire["started"],
                "cause": fire["cause"],
                "state": fire["state"],
                "county": fire["county"],
                "source": "WFCA",
            })

        # WFCA's recent FIRMS satellite footprints provide polygon geometry
        # when an active incident has no reported WFIGS perimeter. Keep them
        # separate from official perimeters so alert distances remain based on
        # reported perimeters or incident locations.
        footprints_by_id = {}
        try:
            footprint_features = (
                _fetch_wfca_wfs_features("WFCA:FIRMS_Footprints") if active_fires else []
            )
        except Exception:
            logger.warning("Unable to retrieve WFCA satellite footprints", exc_info=True)
            footprint_features = []

        for feature in footprint_features:
            if not isinstance(feature, dict):
                continue
            props = feature.get("properties") or {}
            normalized_id = _normalize_fire_id(props.get("irwinid"))
            fire = active_fires_by_id.get(normalized_id)
            if not fire or normalized_id in perimeters_by_id:
                continue
            age_bucket = str(props.get("age_bucket") or "").casefold()
            hours_since = _fire_number(props.get("hours_since"))
            if age_bucket not in {"newest", "recent"} or (hours_since is not None and hours_since > 48):
                continue
            geometry = feature.get("geometry")
            if not geometry:
                continue
            try:
                footprint = shape(geometry)
                if footprint.is_empty or not footprint.intersects(arkansas):
                    continue
            except Exception:
                logger.warning("Skipping invalid WFCA satellite footprint for %s", fire["name"], exc_info=True)
                continue

            current = footprints_by_id.setdefault(normalized_id, {
                "fire": fire,
                "geometries": [],
                "area_acres": 0.0,
                "detection_count": 0,
                "sensors": set(),
                "updated_epoch": None,
                "wfca_updated": None,
            })
            current["geometries"].append(footprint)
            area_acres = _fire_number(props.get("area_acres"), 0)
            current["area_acres"] = max(current["area_acres"], area_acres or 0)
            current["detection_count"] += int(_fire_number(props.get("detection_count"), 0) or 0)
            sensor = props.get("sensor")
            if sensor:
                current["sensors"].add(str(sensor))
            updated_epoch = _fire_number(props.get("latest_acq_epoch"))
            if updated_epoch is not None and (
                current["updated_epoch"] is None or updated_epoch > current["updated_epoch"]
            ):
                current["updated_epoch"] = updated_epoch
            wfca_updated = props.get("wfca_timestamp")
            if wfca_updated and (
                current["wfca_updated"] is None or str(wfca_updated) > str(current["wfca_updated"])
            ):
                current["wfca_updated"] = wfca_updated

        current_footprints = []
        for current in footprints_by_id.values():
            fire = current["fire"]
            try:
                footprint_geometry = mapping(unary_union(current["geometries"]))
                footprint_geometry = json.loads(json.dumps(footprint_geometry))
            except Exception:
                logger.warning("Unable to combine WFCA footprints for %s", fire["name"], exc_info=True)
                continue
            updated = current["wfca_updated"]
            if current["updated_epoch"] is not None:
                try:
                    updated = datetime.fromtimestamp(
                        current["updated_epoch"], ZoneInfo("UTC")
                    ).isoformat()
                except (OSError, OverflowError, ValueError):
                    pass
            current_footprints.append({
                "geometry": footprint_geometry,
                "name": fire["name"],
                "irwin_id": fire["irwin_id"],
                "area_acres": round(current["area_acres"], 1),
                "detection_count": current["detection_count"],
                "sensors": sorted(current["sensors"]),
                "updated": updated,
                "source": "WFCA FIRMS satellite footprint",
            })

        # Suppress <=1-acre incidents that are not within one mile of any
        # monitored site. Keep their matching perimeter lists in sync so the
        # map, site-risk calculations, and alert worker all use the same set.
        site_coordinates = (
            _get_wildfire_site_coordinates()
            if any(fire["acres"] <= 1 for fire in active_fires)
            else []
        )
        if site_coordinates:
            perimeters_by_fire_id = {
                _normalize_fire_id(perimeter.get("irwin_id")): perimeter
                for perimeter in current_perimeters
                if perimeter.get("irwin_id")
            }
            retained_fires = []
            retained_fire_ids = set()
            for fire in active_fires:
                fire_id = _normalize_fire_id(fire.get("irwin_id"))
                if fire["acres"] <= 1 and not _wildfire_within_one_mile(
                    fire, perimeters_by_fire_id.get(fire_id), site_coordinates
                ):
                    continue
                retained_fires.append(fire)
                if fire_id:
                    retained_fire_ids.add(fire_id)
            active_fires = retained_fires
            current_perimeters = [
                perimeter for perimeter in current_perimeters
                if _normalize_fire_id(perimeter.get("irwin_id")) in retained_fire_ids
            ]
            current_footprints = [
                footprint for footprint in current_footprints
                if _normalize_fire_id(footprint.get("irwin_id")) in retained_fire_ids
            ]

        return {
            "incidents": active_fires,
            "perimeters": current_perimeters,
            "footprints": current_footprints,
        }
    except Exception:
        logger.warning("Unable to retrieve current WFCA wildfire data", exc_info=True)
        return []

def dispatch_perimeter_crime_alerts():
    """Checks for un-dispatched high severity crimes within 0.4 miles and sends an SMS-friendly alert."""
    from src.database import SessionLocal, CrimeIncident
    from src.core.config import CRIME_ALERT_SMS, CRIME_ALERT_EMAIL
    from zoneinfo import ZoneInfo

    # Reads the recipient(s) from your .env file. Supports comma-separated lists!
    alert_sms = CRIME_ALERT_SMS
    if not alert_sms:
        # Fallback to the old env var
        alert_sms = CRIME_ALERT_EMAIL
        if not alert_sms:
            return False, "CRIME_ALERT_SMS not set in environment variables."
            
    # Clean up the string just in case there are weird spaces in the .env file
    alert_sms = ", ".join([email.strip() for email in alert_sms.split(",")])
        
    with SessionLocal() as db:
        # Find all un-dispatched crimes within 0.4 miles that are categorized as High severity
        new_crimes = db.query(CrimeIncident).filter(
            CrimeIncident.distance_miles <= 0.4,
            CrimeIncident.severity.ilike('%High%'),
            CrimeIncident.is_alert_dispatched == False
        ).all()
        
        if not new_crimes:
            return True, "No new alerts to dispatch."
            
        for crime in new_crimes:
            # Standard Google Maps query link (mobile SMS click-through)
            gmaps_link = f"https://www.google.com/maps?q={crime.lat},{crime.lon}"
            
            # Formatted to be slightly shorter for SMS reading
            local_time = format_central(crime.timestamp)[:-3]  # Remove seconds for brevity
            
            # Concise Plain Text format for SMS
            sms_body = (
                f"[ALERT] PERIMETER ALERT [ALERT]\n"
                f"{crime.raw_title}\n"
                f"Dist: {crime.distance_miles} mi\n"
                f"Time: {local_time}\n"
                f"Map: {gmaps_link}"
            )
            
            from src.utils.mailer import send_alert_email
            success, msg = send_alert_email(
                subject=f"Crime Alert: {crime.distance_miles}mi",
                body=sms_body,
                recipient_override=alert_sms,  # Passes the cleaned, comma-separated list
                is_html=False 
            )
            
            # If the SMS sent successfully, mark it as dispatched so we never send it again
            if success:
                crime.is_alert_dispatched = True
                
        db.commit()
    return True, "Perimeter SMS alerts processed."

def get_hazards(limit=15, hours_back=None):
    with SessionLocal() as db:
        q = db.query(RegionalHazard)
        if hours_back: q = q.filter(RegionalHazard.updated_at >= datetime.utcnow() - timedelta(hours=hours_back))
        return to_dotdict_list(q.order_by(RegionalHazard.updated_at.desc()).limit(limit).all())

def _hazard_color(event_type, severity, is_oos):
    event_lower = event_type.lower()
    if is_oos:
        base = _hazard_color(event_type, severity, False)
        return [max(0, c - 60) for c in base[:3]] + [base[3]]
    if "tornado" in event_lower:
        return [180, 0, 0, 100] if severity == "Warning" else [180, 0, 0, 60]
    if "severe thunderstorm" in event_lower:
        return [255, 120, 0, 100] if severity == "Warning" else [255, 140, 0, 60]
    if "flash flood" in event_lower:
        return [0, 180, 0, 100] if severity == "Warning" else [0, 140, 0, 60]
    if "flood" in event_lower and "watch" in event_lower:
        return [80, 140, 0, 60]
    if "flood" in event_lower:
        return [0, 150, 0, 100] if severity == "Warning" else [80, 140, 0, 60]
    if "winter storm" in event_lower or "winter weather" in event_lower:
        return [200, 90, 160, 100] if severity == "Warning" else [180, 100, 140, 60]
    if "blizzard" in event_lower:
        return [180, 60, 180, 100]
    if "ice storm" in event_lower or "freezing" in event_lower:
        return [160, 100, 140, 100] if severity == "Warning" else [140, 100, 120, 60]
    if "heat" in event_lower or "excessive heat" in event_lower:
        return [255, 140, 0, 100] if severity == "Warning" else [255, 160, 0, 60]
    if "wind" in event_lower or "high wind" in event_lower:
        return [255, 255, 0, 100] if severity == "Warning" else [220, 220, 0, 60]
    if "red flag" in event_lower or "fire weather" in event_lower or "fire warning" in event_lower:
        return [255, 69, 0, 120]
    if "hurricane" in event_lower:
        return [200, 0, 200, 100]
    if "tropical storm" in event_lower:
        return [200, 80, 170, 100]
    if "snow squall" in event_lower:
        return [160, 190, 220, 100]
    if "special weather" in event_lower:
        return [100, 160, 220, 70]
    if "dense fog" in event_lower or "dense smoke" in event_lower:
        return [140, 140, 160, 70]
    if "dust" in event_lower:
        return [180, 140, 80, 70]
    if "coastal" in event_lower or "marine" in event_lower or "high surf" in event_lower:
        return [0, 100, 180, 80]
    if "severe weather" in event_lower:
        return [255, 100, 0, 80]
    if severity == "Warning":
        return [255, 60, 60, 100]
    if "watch" in event_lower:
        return [255, 165, 0, 60]
    return [255, 200, 0, 60]


def _hazard_line_color(fill):
    r, g, b, a = fill
    return [min(255, r + 60), min(255, g + 60), min(255, b + 60), 255]


def process_nws_alerts(data, selected_events, is_oos=False):
    from shapely.geometry import shape
    map_diagnostics = []
    warn_geo = {"type": "FeatureCollection", "features": []}
    watch_geo = {"type": "FeatureCollection", "features": []}
    zonewide_alerts = []

    if not data or "features" not in data:
        map_diagnostics.append(f"[WARN] {'OOS' if is_oos else 'AR'} data empty or missing 'features'.")
        return warn_geo, watch_geo, zonewide_alerts, map_diagnostics

    regional_counties_geom = get_regional_counties_mapping()

    for idx, f_raw in enumerate(data.get("features", [])):
        geom, props = f_raw.get("geometry"), f_raw.get("properties", {})
        event_type, headline = props.get("event", "Unknown"), props.get("headline", "")

        if event_type not in selected_events: continue
        prefix = "[OOS]" if is_oos else "[AR]"
        geometries_to_process = []

        if geom:
            geometries_to_process.append(geom)
        else:
            # THE ENTERPRISE FIX: Strict FIPS Code Matching
            geocode_dict = props.get("geocode", {})
            same_codes = geocode_dict.get("SAME", [])

            for same_code in same_codes:
                # NWS SAME codes are 6 chars (e.g., 005001). Extract last 5 for standard FIPS.
                fips = same_code[-5:]
                if fips in regional_counties_geom:
                    state_fips = regional_counties_geom[fips]["state_fips"]

                    # Strict Border Enforcement:
                    # AR feed gets only AR counties. OOS feed gets only non-AR counties.
                    if (not is_oos and state_fips == "05") or (is_oos and state_fips != "05"):
                        geometries_to_process.append(regional_counties_geom[fips]["geometry"])

            if not geometries_to_process:
                zonewide_alerts.append({"Event": f"{prefix} {event_type}", "Affected Area": props.get("areaDesc", "Unknown"), "Details": headline})
                continue

        for g in geometries_to_process:
            try:
                poly_shape = shape(g)
                is_pds = "PDS" in event_type or "Particularly Dangerous Situation" in headline or "PDS" in headline
                is_severe = "Warning" in event_type or "Emergency" in event_type or is_pds
                severity = "PDS Watch" if (is_pds and not ("Warning" in event_type or "Emergency" in event_type)) else ("Warning" if is_severe else "Watch/Advisory")

                fill_color = _hazard_color(event_type, severity, is_oos)
                line_color = _hazard_line_color(fill_color)

                micro_feature = {
                    "type": "Feature", "geometry": g,
                    "properties": {
                        "info": f"{prefix} {event_type}", "severity": severity,
                        "event": event_type, "headline": headline,
                        "shapely_obj": poly_shape,
                        "fill_color": fill_color, "line_color": line_color,
                    }
                }

                if is_severe:
                    warn_geo["features"].append(micro_feature)
                else:
                    watch_geo["features"].append(micro_feature)
            except Exception as e: continue

    return warn_geo, watch_geo, zonewide_alerts, map_diagnostics

def get_weather_alerts_log(ar_data, oos_data, selected_events, usgs_ar_data=None, usgs_oos_data=None):
    all_alert_details = []
    
    # NWS Alerts (existing code)
    for geo_ds, is_oos in [(ar_data, False), (oos_data, True)]:
        if geo_ds and "features" in geo_ds:
            for f in geo_ds["features"]:
                props = f.get("properties", {})
                event = props.get("event", "Unknown")
                if selected_events and event not in selected_events: continue
                
                prefix = "[OOS]" if is_oos else "[AR]"
                all_alert_details.append({
                    "Event": f"{prefix} {event}", "Severity": props.get("severity", "Unknown"), "Certainty": props.get("certainty", "Unknown"),
                    "Headline": props.get("headline", "No headline available."), "Affected Area": props.get("areaDesc", "Unknown Area"),
                    "Effective": props.get("effective", "N/A"), "Expires": props.get("expires", "N/A"),
                    "Description": props.get("description", "No detailed description provided by NWS."),
                    "Instructions": props.get("instruction", "No explicit instructions provided.")
                })
    
    # USGS Earthquakes
    for usgs_data, label in [(usgs_ar_data, "AR"), (usgs_oos_data, "OOS")]:
        if usgs_data and "features" in usgs_data:
            for f in usgs_data["features"]:
                props = f.get("properties", {})
                mag = props.get("mag", 0)
                if mag < 2.0:
                    continue
                
                coords = f.get("geometry", {}).get("coordinates", [0, 0, 0])
                depth = coords[2] if len(coords) > 2 else 0
                time_ms = props.get("time", 0)
                time_str = datetime.fromtimestamp(time_ms/1000, LOCAL_TZ).strftime('%Y-%m-%d %H:%M') if time_ms else "Unknown"
                
                all_alert_details.append({
                    "Event": f"[USGS {label}] Earthquake", "Severity": _get_eq_severity(mag), "Certainty": "Confirmed",
                    "Headline": f"M{mag:.1f} Earthquake - {props.get('place', 'Unknown')}", "Affected Area": f"{label} Region",
                    "Effective": time_str, "Expires": "N/A",
                    "Description": f"Magnitude {mag:.1f} earthquake at depth {depth:.1f}km. Location: {props.get('place', 'Unknown')}",
                    "Instructions": f"Monitor for aftershocks. Check structural integrity at nearby facilities."
                })
    
    return all_alert_details

def _get_eq_severity(mag):
    """Map earthquake magnitude to severity level."""
    if mag >= 5.0: return "Severe"
    if mag >= 4.0: return "High"
    if mag >= 3.0: return "Moderate"
    return "Minor"

def _mapping_value(row, *keys, default=None):
    for key in keys:
        value = row.get(key)
        if value is not None:
            return value
    return default


def calculate_site_intersections(map_rows, master_polygons):
    from math import isfinite
    from shapely.geometry import Point

    toggled_affected_sites, master_affected_sites = [], []
    if not map_rows or not master_polygons:
        return toggled_affected_sites, master_affected_sites

    for polygon in master_polygons:
        polygon["bounds"] = polygon["shape"].bounds

    for row in map_rows:
        try:
            lat = float(_mapping_value(row, "Lat", "lat"))
            lon = float(_mapping_value(row, "Lon", "lon"))
        except (TypeError, ValueError):
            continue
        if not isfinite(lat) or not isfinite(lon):
            continue

        site_name = _mapping_value(row, "Name", "Monitored Site", "name", default="Unknown")
        facility_type = _mapping_value(row, "Type", "Facility Type", "loc_type", "type", default="General")
        district = _mapping_value(row, "District", "district", default="Central")
        priority = _mapping_value(row, "Priority", "priority", default="P3-Moderate")
        site_point = Point(lon, lat)
        toggled_events = []

        for polygon in master_polygons:
            minx, miny, maxx, maxy = polygon["bounds"]
            if minx <= lon <= maxx and miny <= lat <= maxy and site_point.within(polygon["shape"]):
                master_affected_sites.append({
                    "Monitored Site": site_name,
                    "Type": facility_type,
                    "District": district,
                    "Priority": priority,
                    "Hazard": polygon["event"],
                    "Severity": polygon["severity"],
                })
                if polygon.get("is_toggled", False):
                    toggled_events.append(polygon["event"])

        if toggled_events:
            toggled_affected_sites.append({
                "Monitored Site": site_name,
                "District": district,
                "Facility Type": facility_type,
                "Priority": priority,
                "Intersecting Hazards": ", ".join(dict.fromkeys(toggled_events)),
            })

    return toggled_affected_sites, master_affected_sites


def get_infrastructure_analytics(map_rows, master_affected_sites):
    """Aggregate the regional map's small site/hazard lists without DataFrames."""
    from collections import Counter, defaultdict

    payload = {
        "total_sites": len(map_rows),
        "at_risk_sites": 0,
        "highest_risk": "None",
        "spc_distribution": [],
        "nws_distribution": [],
        "type_distribution": [],
        "district_distribution": [],
        "priority_risk_matrix": [],
        "type_risk_matrix": [],
        "district_risk_matrix": [],
    }
    severity_rank = {
        "HIGH": 100, "MDT": 90, "ENH": 80, "SLGT": 70, "MRGL": 60, "TSTM": 50,
        "EXTREME": 95, "SEVERE": 85, "MODERATE": 75, "MINOR": 65,
        "WARNING": 85, "WATCH": 75, "ADVISORY": 65, "STATEMENT": 55, "NONE": 0,
    }

    def rank_hazard(hazard):
        hazard_text = str(hazard).upper()
        return max((rank for level, rank in severity_rank.items() if level in hazard_text), default=10)

    def primary_label(hazard):
        text_value = str(hazard).upper()
        for label in ("HIGH", "MDT", "ENH", "SLGT", "MRGL", "TSTM", "WARNING", "WATCH", "ADVISORY"):
            if label in text_value:
                return label
        return "OTHER"

    spc_risks, nws_alerts = {}, {}
    worst_by_site = {}
    for row in master_affected_sites:
        site = row.get("Monitored Site")
        hazard = str(row.get("Hazard", ""))
        hazard_upper = hazard.upper()
        score = rank_hazard(hazard)
        prior = worst_by_site.get(site)
        if prior is None or score > prior[0]:
            worst_by_site[site] = (score, row)

        if "SPC:" in hazard_upper:
            risk_level = next(
                (level for level in ("HIGH", "MDT", "ENH", "SLGT", "MRGL", "TSTM") if level in hazard_upper),
                "TSTM",
            )
            if severity_rank.get(risk_level, 0) > severity_rank.get(spc_risks.get(site, "NONE"), 0):
                spc_risks[site] = risk_level
        else:
            alert_type = next(
                (level for level in ("WARNING", "WATCH", "ADVISORY") if level in hazard_upper),
                "STATEMENT",
            )
            if severity_rank.get(alert_type, 0) > severity_rank.get(nws_alerts.get(site, "NONE"), 0):
                nws_alerts[site] = alert_type

    worst_rows = [row for _, row in sorted(worst_by_site.values(), key=lambda item: item[0], reverse=True)]
    if worst_rows:
        payload["at_risk_sites"] = len(worst_rows)
        payload["highest_risk"] = primary_label(worst_rows[0].get("Hazard"))

        type_counts = Counter(row.get("Type") for row in worst_rows if row.get("Type") is not None)
        district_counts = Counter(row.get("District") for row in worst_rows if row.get("District") is not None)
        payload["type_distribution"] = [
            {"Facility Type": value, "Count": count} for value, count in type_counts.most_common()
        ]
        payload["district_distribution"] = [
            {"District": value, "Count": count} for value, count in district_counts.most_common()
        ]

        labels = {primary_label(row.get("Hazard")) for row in worst_rows}
        for field, output_key in (
            ("Priority", "priority_risk_matrix"),
            ("Type", "type_risk_matrix"),
            ("District", "district_risk_matrix"),
        ):
            matrix = defaultdict(Counter)
            for row in worst_rows:
                value = row.get(field)
                if value is not None:
                    matrix[value][primary_label(row.get("Hazard"))] += 1
            payload[output_key] = [
                {field: value, **{label: matrix[value].get(label, 0) for label in sorted(labels)}}
                for value in sorted(matrix)
            ]

    def ordered_distribution(values, order, key):
        counts = Counter(values)
        order_index = {value: index for index, value in enumerate(order)}
        return [
            {key: value, "count": counts.get(value, 0)}
            for value in sorted(order, key=lambda value: (-counts.get(value, 0), order_index[value]))
        ]

    site_names = [_mapping_value(row, "Name", "name", "Monitored Site") for row in map_rows]
    payload["spc_distribution"] = ordered_distribution(
        [spc_risks.get(site, "None") for site in site_names],
        ["HIGH", "MDT", "ENH", "SLGT", "MRGL", "TSTM", "None"],
        "SPC Risk",
    )
    payload["nws_distribution"] = ordered_distribution(
        [nws_alerts.get(site, "None") for site in site_names],
        ["WARNING", "WATCH", "ADVISORY", "STATEMENT", "None"],
        "NWS Alert",
    )
    return payload


def import_locations(data, mode="add"):
    with SessionLocal() as db:
        count = 0
        if mode == "replace":
            db.query(MonitoredLocation).delete(synchronize_session=False)
            db.commit()
            existing_names = set()
        else:
            existing_names = {l[0] for l in db.query(MonitoredLocation.name).all()}
        for item in data:
            name = item.get("name")
            if not name:
                continue
            lat, lon = item.get("lat"), item.get("lon")
            if lat is None or lon is None:
                continue
            kwargs = {
                "name": name,
                "lat": float(lat),
                "lon": float(lon),
                "loc_type": item.get("type") or item.get("loc_type") or "General",
                "district": item.get("district", "Central"),
                "priority": item.get("priority", "P3-Moderate"),
            }
            if mode == "upsert" and name in existing_names:
                db.query(MonitoredLocation).filter_by(name=name).update(kwargs)
                count += 1
            elif name not in existing_names:
                db.add(MonitoredLocation(**kwargs))
                existing_names.add(name)
                count += 1
        db.commit()
    get_cached_locations.clear()
    return count

def update_locations(edited_rows):
    """Update location rows from records, loading existing rows in one query."""
    if hasattr(edited_rows, "to_dict"):
        edited_rows = edited_rows.to_dict(orient="records")
    rows = [row for row in edited_rows if isinstance(row, dict)]

    normalized_rows = [
        {str(key).lower(): value for key, value in row.items()}
        for row in rows
    ]
    location_ids = {
        row.get("id") for row in normalized_rows if row.get("id") is not None
    }
    with SessionLocal() as db:
        locations = (
            db.query(MonitoredLocation).filter(MonitoredLocation.id.in_(location_ids)).all()
            if location_ids else []
        )
        locations_by_id = {location.id: location for location in locations}
        for row in normalized_rows:
            db_loc = locations_by_id.get(row.get("id"))
            if not db_loc:
                continue
            db_loc.name = row.get("name") or db_loc.name
            db_loc.loc_type = row.get("loc_type") or row.get("type") or db_loc.loc_type
            db_loc.district = row.get("district") or db_loc.district
            db_loc.priority = row.get("priority") or db_loc.priority
            db_loc.lat = float(row.get("lat") or db_loc.lat)
            db_loc.lon = float(row.get("lon") or db_loc.lon)
        db.commit()
    get_cached_locations.clear()

def import_software_assets_csv(text: str):
    """Parse CSV text and replace all SoftwareAsset records."""
    import io, csv
    from src.database import SoftwareAsset
    reader = csv.DictReader(io.StringIO(text))
    col_map = {k.strip().lower(): k for k in (reader.fieldnames or [])}
    if 'name' not in col_map:
        return False, "CSV must contain a 'name' column."
    names = []
    for row in reader:
        val = row.get(col_map['name'], '').strip()
        if val:
            names.append(val)
    if not names:
        return False, "No valid rows found."
    with SessionLocal() as db:
        db.query(SoftwareAsset).delete()
        for n in names:
            db.add(SoftwareAsset(name=n))
        db.commit()
    return True, f"Imported {len(names)} software assets."


def import_hardware_assets_csv(text: str):
    """Parse CSV text and replace all HardwareAsset records."""
    import io, csv
    from src.database import HardwareAsset
    reader = csv.DictReader(io.StringIO(text))
    col_map = {k.strip().lower().replace(' ', '_'): k for k in (reader.fieldnames or [])}
    if 'ip_address' not in col_map:
        return False, "CSV must contain an 'IP Address' column."
    valid_columns = {c.name for c in HardwareAsset.__table__.columns}
    rows = []
    for row in reader:
        row_dict = {}
        for norm_key, orig_key in col_map.items():
            if norm_key in valid_columns:
                val = row.get(orig_key, '').strip()
                if val:
                    row_dict[norm_key] = val
        if row_dict.get('ip_address'):
            rows.append(row_dict)
    if not rows:
        return False, "No valid rows found."
    with SessionLocal() as db:
        db.query(HardwareAsset).delete()
        for rd in rows:
            db.add(HardwareAsset(**rd))
        db.commit()
    return True, f"Imported {len(rows)} hardware assets."


def nuke_crime_data():
    """Wipes all records from Little Rock crime table."""
    from src.database import CrimeIncident
    with SessionLocal() as db:
        try:
            # Delete rows from both tables and combine the count
            lr_deleted = db.query(CrimeIncident).delete()
            db.commit()
            return True, (lr_deleted)
        except Exception as e:
            db.rollback()
            return False, str(e)


# ==========================================
# 6. THREAT HUNTING & IOCs
# ==========================================

def get_iocs(days_back=3, limit=1000):
    with SessionLocal() as db:
        t = datetime.utcnow() - timedelta(days=days_back)
        rows = (
            db.query(ExtractedIOC, Article)
            .outerjoin(Article, Article.id == ExtractedIOC.article_id)
            .filter(ExtractedIOC.detected_at >= t)
            .order_by(ExtractedIOC.detected_at.desc(), ExtractedIOC.id.desc())
            .limit(min(max(int(limit), 1), 1000))
            .all()
        )

        cve_groups = {}
        non_cve = []

        for ioc, art in rows:
            source_link = art.link if art else "Unknown"
            source_title = art.title if art else "Unknown"

            if ioc.indicator_type == "CVE":
                key = ioc.indicator_value
                if key not in cve_groups:
                    cve_groups[key] = {
                        "Type": "CVE",
                        "Indicator": key,
                        "Context": ioc.context or "Context unavailable.",
                        "Detected": format_central(ioc.detected_at),
                        "Source Article": source_link,
                        "sources": [],
                        "article_count": 0,
                    }
                cve_groups[key]["sources"].append({
                    "link": source_link,
                    "title": source_title,
                })
                cve_groups[key]["article_count"] += 1
            else:
                non_cve.append({
                    "Type": ioc.indicator_type,
                    "Indicator": ioc.indicator_value,
                    "Context": ioc.context if hasattr(ioc, 'context') else "Context unavailable.",
                    "Detected": format_central(ioc.detected_at),
                    "Source Article": source_link,
                    "sources": [{"link": source_link, "title": source_title}],
                    "article_count": 1,
                })

        result = non_cve + list(cve_groups.values())
        return result

def parse_search_terms(target: str) -> list[str]:
    """Parse comma/semicolon/space-separated terms while preserving quoted phrases."""
    target = (target or "").strip()
    if not target:
        return []
    if len(target) > 500:
        raise ValueError("Search input must be 500 characters or fewer.")
    if target.count('"') % 2:
        raise ValueError("Search phrases must use balanced quotation marks.")
    terms = []
    for match in re.finditer(r'"([^"\r\n]+)"|([^,;\s]+)', target):
        value = (match.group(1) or match.group(2)).strip()
        if value and value.casefold() not in {term.casefold() for term in terms}:
            terms.append(value)
    return terms[:50]


def search_articles_for_hunting(target, days_back):
    terms = parse_search_terms(target)
    if not terms:
        return []
    days_back = max(1, min(int(days_back), 30))
    with SessionLocal() as db:
        cutoff = datetime.utcnow() - timedelta(days=days_back)
        def like_pattern(term):
            escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            return f"%{escaped}%"

        term_filters = []
        for term in terms:
            pattern = like_pattern(term)
            term_filters.append(
                Article.title.ilike(pattern, escape="\\")
                | Article.summary.ilike(pattern, escape="\\")
                | Article.full_content.ilike(pattern, escape="\\")
            )
        arts = (
            db.query(Article)
            .filter(Article.published_date >= cutoff, or_(*term_filters))
            .order_by(Article.published_date.desc(), Article.id.desc())
            .limit(30)
            .all()
        )
        return to_dotdict_list(arts)

def get_articles_by_ids(ids):
    with SessionLocal() as db:
        arts = db.query(Article).filter(Article.id.in_(ids)).all()
        return to_dotdict_list(arts)

def get_osint_pivot_link(ioc_type, value):
    value = str(value or "").strip()
    if not value or len(value) > 512:
        return None
    if ioc_type in ["SHA256", "MD5", "SHA1"]:
        expected = {"SHA256": 64, "SHA1": 40, "MD5": 32}[ioc_type]
        if not re.fullmatch(rf"[a-fA-F0-9]{{{expected}}}", value):
            return None
        return f"https://www.virustotal.com/gui/file/{value}"
    if ioc_type == "IPv4":
        try:
            if ipaddress.ip_address(value).version != 4:
                return None
        except ValueError:
            return None
        return f"https://www.shodan.io/host/{quote(value, safe='')}"
    if ioc_type == "Domain" and re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}", value):
        return f"https://www.virustotal.com/gui/domain/{quote(value, safe='')}"
    if ioc_type == "CVE" and re.fullmatch(r"CVE-\d{4}-\d{4,7}", value, re.IGNORECASE):
        return f"https://nvd.nist.gov/vuln/detail/{quote(value.upper(), safe='')}"
    if ioc_type == "MITRE ATT&CK" and re.fullmatch(r"T\d{4}(?:\.\d{3})?", value, re.IGNORECASE):
        return f"https://attack.mitre.org/techniques/{quote(value.replace('.', '/').upper(), safe='/')}"
    return None


def get_elastic_events(hours_back=24, page=1, page_size=100):
    hours_back = max(1, min(int(hours_back), 168))
    page = max(1, int(page))
    page_size = max(1, min(int(page_size), 500))
    with SessionLocal() as db:
        cutoff = datetime.utcnow() - timedelta(hours=hours_back)
        query = db.query(ElasticEvent).filter(ElasticEvent.timestamp >= cutoff)
        total = query.count()
        events = query.order_by(ElasticEvent.timestamp.desc(), ElasticEvent.id.desc()).offset((page - 1) * page_size).limit(page_size).all()
        return {
            "items": [
                {
                    "id": event.id,
                    "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                    "index_name": event.index_name,
                    "severity": event.severity,
                    "message": event.message,
                    "source_ip": event.source_ip,
                    "event_category": event.event_category,
                }
                for event in events
            ],
            "total": total,
            "page": page,
            "page_size": page_size,
            "hours_back": hours_back,
        }


# ==========================================
# 7. AIOps RCA (Root Cause Analysis)
# ==========================================

def _query_aiops_timeline_events(db, allowed_site_names=None):
    query = db.query(TimelineEvent)
    if allowed_site_names is not None:
        allowed_names = {str(name) for name in allowed_site_names if name}
        if not allowed_names:
            return []
        query = query.filter(TimelineEvent.site_name.in_(allowed_names))
    events = query.order_by(TimelineEvent.timestamp.desc()).limit(50).all()
    # Sanitize event messages at the data layer (not in UI loops).
    for event in events:
        event.message = sanitize_text(event.message)
    return to_dotdict_list(events)


def get_aiops_timeline_events(allowed_site_names=None):
    """Return the latest timeline events, optionally scoped before the limit."""
    with SessionLocal() as db:
        return _query_aiops_timeline_events(db, allowed_site_names)


def get_aiops_dashboard_data(allowed_site_names=None):
    with SessionLocal() as db:
        alerts = db.query(SolarWindsAlert).filter(SolarWindsAlert.status != 'Resolved', SolarWindsAlert.is_correlated == False).all()
        events = _query_aiops_timeline_events(db, allowed_site_names)
        grid = db.query(RegionalOutage).filter_by(is_resolved=False).all()
        return to_dotdict_list(alerts), events, to_dotdict_list(grid)


def get_allowed_site_names(allowed_site_types):
    allowed_types = set(allowed_site_types or [])
    if not allowed_types:
        return set()
    with SessionLocal() as db:
        rows = db.query(MonitoredLocation.name).filter(
            MonitoredLocation.loc_type.in_(allowed_types)
        ).all()
    return {str(name) for (name,) in rows if name}


def get_allowed_site_names_for_user(user, locations=None):
    is_admin = str(getattr(user, "role", "") or "").casefold() in {"admin", "administrator"}
    if locations is not None:
        allowed_types = set(getattr(user, "allowed_site_types", []) or [])
        return {
            str(location.get("name"))
            for location in locations
            if location.get("name")
            and (is_admin or location.get("loc_type") in allowed_types)
        }
    if is_admin:
        with SessionLocal() as db:
            return {str(name) for (name,) in db.query(MonitoredLocation.name).all() if name}
    return get_allowed_site_names(getattr(user, "allowed_site_types", []))


def user_has_all_site_type_access(user):
    if str(getattr(user, "role", "") or "").casefold() in {"admin", "administrator"}:
        return True
    return set(getattr(user, "allowed_site_types", []) or []).issuperset(set(get_all_site_types()))


def user_can_access_site(user, site_name):
    if str(getattr(user, "role", "") or "").casefold() in {"admin", "administrator"}:
        return True
    return bool(site_name) and site_name in get_allowed_site_names_for_user(user)


def ensure_user_can_access_alerts(user, alert_ids):
    if str(getattr(user, "role", "") or "").casefold() in {"admin", "administrator"}:
        return
    ids = list({int(value) for value in alert_ids if int(value) > 0})
    if not ids:
        return
    with SessionLocal() as db:
        rows = db.query(SolarWindsAlert.id, SolarWindsAlert.mapped_location).filter(
            SolarWindsAlert.id.in_(ids)
        ).all()
    requested = set(ids)
    found = {row_id for row_id, _ in rows}
    allowed_sites = get_allowed_site_names_for_user(user)
    if found != requested or any(not location or location not in allowed_sites for _, location in rows):
        raise ValueError("One or more alerts are outside your permitted site types.")


def filter_aiops_payload_for_user(payload, user, locations=None):
    """Filter the pushed AIOps payload before it crosses the WebSocket boundary."""
    role = str(getattr(user, "role", "") or "").casefold()
    if role in {"admin", "administrator"}:
        return payload

    locations = locations if locations is not None else get_cached_locations()
    allowed_names = get_allowed_site_names_for_user(user, locations=locations)
    if not allowed_names:
        return {
            **payload,
            "alerts": [],
            "events": [],
            "grid": [],
            "alert_count": 0,
        }

    alerts = [
        row for row in payload.get("alerts", [])
        if row.get("mapped_location") in allowed_names
    ]
    # Timeline messages are display text, not an authorization attribute. Only
    # expose events carrying a structured site name that is in the user's scope.
    events = [
        row for row in payload.get("events", [])
        if row.get("site_name") in allowed_names
    ]
    grid = [
        row for row in payload.get("grid", [])
        if any(name.casefold() in str(row.get("affected_area", "")).casefold() for name in allowed_names)
    ]
    return {**payload, "alerts": alerts, "events": events, "grid": grid, "alert_count": len(alerts)}

def clear_timeline_events():
    with SessionLocal() as db: db.query(TimelineEvent).delete(); db.commit()

def nuke_active_alerts():
    with SessionLocal() as db: db.query(SolarWindsAlert).delete(); db.commit()

def resolve_alert(alert_id, node_name):
    with SessionLocal() as db:
        a = db.query(SolarWindsAlert).filter_by(id=alert_id).first()
        site_name = a.mapped_location if a else None
        if a:
            a.status = 'Resolved'
            a.needs_dispatch = False
            db.add(TimelineEvent(
                source="User", event_type="Resolution",
                message=f"[OK] Operator manually resolved {node_name}",
                site_name=site_name,
            ))
            db.commit()

def acknowledge_cluster(alert_ids, username="unknown"):
    with SessionLocal() as db:
        now_utc = datetime.utcnow()
        updated_sites = set()
        for aid in alert_ids:
            a = db.query(SolarWindsAlert).filter_by(id=aid).first()
            if a:
                a.is_correlated = True
                a.needs_dispatch = False
                a.acknowledged_by = username
                a.acknowledged_at = now_utc
                if a.mapped_location:
                    updated_sites.add(a.mapped_location)
        for site in updated_sites:
            loc = db.query(MonitoredLocation).filter(MonitoredLocation.name == site).first()
            if loc:
                loc.status_modified_by = username
                loc.status_modified_at = now_utc
        db.commit()

def save_alias(alias_id, new_mapped_name):
    with SessionLocal() as db:
        a = db.query(NodeAlias).filter_by(id=alias_id).first()
        if a:
            a.mapped_location_name, a.is_verified, a.confidence_score = new_mapped_name, True, 100.0
            db.commit()

def generate_global_sitrep(sys_config_dict):
    """Generates the Global Correlation SitRep using the Enterprise AIOps Engine."""
    from src.database import RegionalHazard, CloudOutage, BgpAnomaly, SolarWindsAlert
    from src.services.aiops_engine import EnterpriseAIOpsEngine
    
    with SessionLocal() as db:
        # FIX 1: Capture ALL active alerts, not just strings matching 'Down'
        raw_alerts = db.query(SolarWindsAlert).filter(
            SolarWindsAlert.is_correlated == False, 
            SolarWindsAlert.status != 'Resolved'
        ).all()
        
        active_clouds = db.query(CloudOutage).filter_by(is_resolved=False).all()
        active_weather = db.query(RegionalHazard).all()
        active_bgp = db.query(BgpAnomaly).filter_by(is_resolved=False).all()

        report = f"### Global Situation Report (SitRep)\n\n"
        report += f"**Active Infrastructure Alerts:** {len(raw_alerts)} | "
        report += f"**Cloud Outages:** {len(active_clouds)} | "
        report += f"**Grid/Weather Anomalies:** {len(active_weather)}\n\n"

        if not raw_alerts:
            report += "[OK] **Grid Operational:** No active un-correlated infrastructure alerts detected.\n"
            return report

        # FIX 2: Route the alerts through our Supreme AI Engine!
        ai_engine = EnterpriseAIOpsEngine(db)
        incidents = ai_engine.analyze_and_cluster(raw_alerts)

        report += "#### Intelligence Causal Clusters\n"
        
        for site, data in incidents.items():
            cause, score, priority, evidence, blast, p0, cascade = ai_engine.calculate_root_cause(
                site, data, active_weather, active_clouds, active_bgp
            )
            
            icon = "[CRIT]" if score >= 80 else "[HIGH]" if score >= 50 else "[MEDIUM]"
            
            report += f"**{icon} {site} [{priority}]**\n"
            report += f"- **Impact:** {len(data['alerts'])} nodes offline across {len(data['domains_affected'])} topology layers ({blast}).\n"
            report += f"- **Patient Zero:** `{p0}` (Cascade Delay: {cascade})\n"
            report += f"- **Root Cause:** {cause}\n\n"

        # AI Summary Generator
        if sys_config_dict and sys_config_dict.get('is_active'):
            from src.utils.llm import call_llm
            sys_prompt = "You are an elite NOC AIOps Engine. Summarize the following deterministic IT SitRep into a technical 2-sentence executive summary. Do not use pleasantries."
            ai_summary = call_llm([{"role": "system", "content": sys_prompt}, {"role": "user", "content": report}], sys_config_dict, temperature=0.1)

            if ai_summary and "[WARN]" not in ai_summary:
                report = f"### AI Executive Summary\n> {ai_summary}\n\n---\n\n" + report

        return report
def generate_rca_ticket_text(site, data, priority, patient_zero, root_cause):
    priority = sanitize_text(priority)
    root_cause = sanitize_text(root_cause)
    pz_obj = data.get('patient_zero')
    pz_received = _get_attr(pz_obj, 'received_at') if pz_obj else None
    if pz_received:
        if isinstance(pz_received, str):
            pz_dt = datetime.fromisoformat(pz_received.replace('Z', '+00:00'))
        else:
            pz_dt = pz_received.replace(tzinfo=ZoneInfo("UTC")) if pz_received.tzinfo is None else pz_received
        trigger_time = pz_dt.astimezone(LOCAL_TZ).strftime('%m/%d/%Y %I:%M %p %Z')
    else:
        trigger_time = "Unknown Time"
    
    district = data.get('site_metadata', {}).get('district', 'Unknown')
    
    # Dynamically grab the affected domains for the ticket description (e.g. TRANSPORT_CORE, SCADA_OT)
    domains = list(data.get('domains_affected', []))
    affecting_str = ", ".join(domains).title().replace("_", " ") if domains else "SCADA connectivity"
    
    ticket_text = f"Automated Comms Outage\nDistrict: {district}\n\n{site} - Trouble\n\n"
    ticket_text += f"A communications issue was identified on {trigger_time}. This is affecting {affecting_str}. For more information, please see additional notes.\n\n"
    
    ticket_text += f"\nPRIORITY: {priority}" + f"\n{root_cause}\n\nAFFECTED INFRASTRUCTURE DETAILS:\n"
    
    for idx, alert in enumerate(data.get('alerts', []), 1):
        alert_rcv = _get_attr(alert, 'received_at')
        rcv_time = format_central(alert_rcv) if alert_rcv else "Unknown"
        # Compact single-line device format
        node_name = _get_attr(alert, 'node_name', 'Unknown')
        ip_address = _get_attr(alert, 'ip_address', 'Unknown')
        status = _get_attr(alert, 'status', 'Unknown')
        event_category = _get_attr(alert, 'event_category', 'Unknown')
        ticket_text += f"[{idx}] {node_name} ({ip_address}) - {status} | {event_category} | Since: {rcv_time}\n"
        
    return ticket_text


# ==========================================
# 8. REPORT CENTER
# ==========================================

def search_articles(query, limit):
    with SessionLocal() as db:
        q = db.query(Article)
        if query: q = q.filter(Article.title.ilike(f"%{query}%") | Article.summary.ilike(f"%{query}%"))
        return to_dotdict_list(q.order_by(Article.published_date.desc()).limit(limit).all())

def get_saved_reports():
    with SessionLocal() as db:
        return to_dotdict_list(db.query(SavedReport).order_by(SavedReport.created_at.desc()).all())

def save_custom_report(title, author, content):
    with SessionLocal() as db:
        db.add(SavedReport(title=title, author=author, content=content))
        db.commit()


# ==========================================
# 9. SETTINGS & ADMINISTRATION
# ==========================================

@TTLCache(ttl=300)
def get_all_roles():
    with SessionLocal() as db:
        return to_dotdict_list(db.query(Role).all())

def create_role(name, allowed_pages, allowed_actions, allowed_site_types=None):
    name = str(name or "").strip()
    allowed_pages = list(dict.fromkeys(allowed_pages or []))
    allowed_actions = list(dict.fromkeys(allowed_actions or []))
    allowed_site_types = list(dict.fromkeys(allowed_site_types or []))
    valid_permissions = set(PAGE_KEYS) | set(ACTION_KEYS) | set(TAB_KEYS)
    if not name or len(name) > 64:
        raise ValueError("Role name must contain 1-64 characters.")
    if set(allowed_pages) - set(PAGE_KEYS):
        raise ValueError("Role contains an unknown page permission.")
    if set(allowed_actions) - valid_permissions:
        raise ValueError("Role contains an unknown action or tab permission.")
    if set(allowed_site_types) - set(get_all_site_types()):
        raise ValueError("Role contains an unknown site type.")
    with SessionLocal() as db:
        if db.query(Role).filter(func.lower(Role.name) == name.casefold()).first():
            return False
        db.add(Role(name=name, allowed_pages=allowed_pages, allowed_actions=allowed_actions, allowed_site_types=allowed_site_types))
        db.commit()
    get_all_roles.clear()
    return True

def update_role(name, allowed_pages, allowed_actions, allowed_site_types=None):
    allowed_pages = list(dict.fromkeys(allowed_pages or []))
    allowed_actions = list(dict.fromkeys(allowed_actions or []))
    allowed_site_types = list(dict.fromkeys(allowed_site_types or []))
    valid_permissions = set(PAGE_KEYS) | set(ACTION_KEYS) | set(TAB_KEYS)
    valid_site_types = set(get_all_site_types())
    with SessionLocal() as db:
        role = db.query(Role).filter(Role.name == name).first()
        if not role:
            return False

        # Existing roles may contain grants from site types or permission names
        # removed from the current catalog. Let administrators retain or remove
        # those legacy grants while rejecting newly submitted unknown values.
        existing_pages = set(role.allowed_pages or [])
        existing_actions = set(role.allowed_actions or [])
        existing_site_types = set(role.allowed_site_types or [])
        if set(allowed_pages) - set(PAGE_KEYS) - existing_pages:
            raise ValueError("Role contains an unknown page permission.")
        if set(allowed_actions) - valid_permissions - existing_actions:
            raise ValueError("Role contains an unknown action or tab permission.")
        if set(allowed_site_types) - valid_site_types - existing_site_types:
            raise ValueError("Role contains an unknown site type.")

        role.allowed_pages = allowed_pages
        role.allowed_actions = allowed_actions
        role.allowed_site_types = allowed_site_types
        db.commit()
    get_all_roles.clear()
    return True

def create_user(username, password, role, full_name=""):
    create_display_account(username, password, role, full_name)
    return True

def force_reset_pwd(username, new_password, actor_user_id=None):
    password_hash = hash_password(new_password)
    with SessionLocal() as db:
        user = db.query(User).filter(User.username == username).first()
        if user:
            user.password_hash, user.session_token = password_hash, None
            db.query(UserSession).filter(UserSession.user_id == user.id).delete(synchronize_session=False)
            db.query(PasswordResetToken).filter(
                PasswordResetToken.user_id == user.id,
                PasswordResetToken.used_at.is_(None),
            ).update({PasswordResetToken.used_at: datetime.utcnow()}, synchronize_session=False)
            _audit_account_event(
                db, "administrator_password_reset", actor_user_id=actor_user_id,
                subject_user_id=user.id,
            )
            db.commit()
            return True
        return False

def update_user_role(username, new_role, actor_user_id=None):
    with SessionLocal() as db:
        if not db.query(Role).filter(Role.name == new_role).first():
            raise ValueError("That role does not exist.")
        u = db.query(User).filter_by(username=username).first()
        if u:
            old_role = u.role
            u.role, u.session_token = new_role, None
            db.query(UserSession).filter(UserSession.user_id == u.id).delete(synchronize_session=False)
            _audit_account_event(
                db, "user_role_changed", actor_user_id=actor_user_id,
                subject_user_id=u.id, detail={"from": old_role, "to": new_role},
            )
            db.commit()
            return True
        return False


def set_user_active(username, is_active, actor_user_id=None):
    with SessionLocal() as db:
        user = db.query(User).filter_by(username=username).first()
        if not user:
            return False
        user.is_active = bool(is_active)
        if not user.is_active:
            user.session_token = None
            db.query(UserSession).filter(UserSession.user_id == user.id).delete(synchronize_session=False)
        _audit_account_event(
            db, "user_activated" if user.is_active else "user_disabled",
            actor_user_id=actor_user_id, subject_user_id=user.id,
        )
        db.commit()
        return True


def set_user_account_type(username, account_type, actor_user_id=None):
    account_type = str(account_type or "").strip().lower()
    if account_type not in {"individual", "display"}:
        raise ValueError("Account type must be 'individual' or 'display'.")
    with SessionLocal() as db:
        user = db.query(User).filter_by(username=username).first()
        if not user:
            return False
        old_type = user.account_type or "individual"
        user.account_type = account_type
        if old_type != account_type:
            user.session_token = None
            db.query(UserSession).filter(UserSession.user_id == user.id).delete(synchronize_session=False)
        _audit_account_event(
            db, "account_type_changed", actor_user_id=actor_user_id,
            subject_user_id=user.id, detail={"from": old_type, "to": account_type},
        )
        db.commit()
        return True


def update_user_identity(username, full_name="", job_title="", contact_info="", actor_user_id=None):
    full_name = str(full_name or "").strip()
    job_title = str(job_title or "").strip()
    contact_info = str(contact_info or "").strip()
    with SessionLocal() as db:
        user = db.query(User).filter_by(username=username).first()
        if not user:
            return False
        user.full_name = full_name
        user.job_title = job_title
        user.contact_info = contact_info
        _audit_account_event(
            db, "user_profile_updated", actor_user_id=actor_user_id,
            subject_user_id=user.id,
        )
        db.commit()
        return True


def revoke_user_sessions(username, actor_user_id=None):
    with SessionLocal() as db:
        user = db.query(User).filter_by(username=username).first()
        if not user:
            return False
        user.session_token = None
        db.query(UserSession).filter(UserSession.user_id == user.id).delete(synchronize_session=False)
        _audit_account_event(db, "user_sessions_revoked", actor_user_id=actor_user_id, subject_user_id=user.id)
        db.commit()
        return True


def get_scheduler_settings():
    with SessionLocal() as db:
        config = db.query(SystemConfig).first()
        revision = int(config.scheduler_revision or 0) if config else 0
        applied_revision = int(config.scheduler_applied_revision or 0) if config else 0
        saved = {row.job_key: row for row in db.query(SchedulerJobConfig).all()}
        jobs = []
        for key, metadata in JOB_REGISTRY.items():
            row = saved.get(key)
            schedule = default_schedule(key)
            if row:
                schedule = {
                    "schedule_type": row.schedule_type,
                    "every_value": row.every_value,
                    "unit": row.unit,
                    "run_at": row.run_at,
                    "weekday": row.weekday,
                    "timezone": row.timezone,
                    "enabled": bool(row.enabled),
                }
            jobs.append({
                "key": key,
                "label": metadata["label"],
                "description": metadata["description"],
                "schedule": schedule,
                "min_value": metadata.get("min_value"),
                "max_value": metadata.get("max_value"),
                "can_disable": bool(metadata.get("can_disable", True)),
                "startup_run": bool(metadata.get("startup_run", False)),
                "updated_by": row.updated_by if row else None,
                "updated_at": row.updated_at.isoformat() if row and row.updated_at else None,
            })
        return {"revision": revision, "applied_revision": applied_revision, "jobs": jobs}


def save_scheduler_setting(job_key, schedule, updated_by, actor_user_id=None):
    normalized = validate_schedule(job_key, schedule)
    now = datetime.utcnow()
    with SessionLocal() as db:
        config = db.query(SystemConfig).first()
        if not config:
            config = SystemConfig()
            db.add(config)
            db.flush()
        row = db.query(SchedulerJobConfig).filter_by(job_key=job_key).first()
        if not row:
            row = SchedulerJobConfig(job_key=job_key)
            db.add(row)
        row.schedule_type = normalized["schedule_type"]
        row.every_value = normalized.get("every_value")
        row.unit = normalized.get("unit")
        row.run_at = normalized.get("run_at")
        row.weekday = normalized.get("weekday")
        row.timezone = normalized.get("timezone", "America/Chicago")
        row.enabled = normalized["enabled"]
        row.updated_by = str(updated_by or "")[:128]
        row.updated_at = now
        config.scheduler_revision = int(config.scheduler_revision or 0) + 1
        _audit_account_event(
            db, "scheduler_setting_changed", actor_user_id=actor_user_id,
            detail={"job_key": job_key, "schedule": normalized, "revision": config.scheduler_revision},
        )
        db.commit()
        return {"revision": config.scheduler_revision, "job_key": job_key, "schedule": normalized}


def mark_scheduler_revision_applied(revision):
    with SessionLocal() as db:
        config = db.query(SystemConfig).first()
        if not config:
            config = SystemConfig()
            db.add(config)
        config.scheduler_applied_revision = int(revision)
        db.commit()

def save_global_config(data, allow_system_fields=True):
    # The frontend historically used these labels; normalize them before the
    # strict allowlist so configuration updates remain compatible.
    data = dict(data)
    if "cyber_baseline" in data:
        data.setdefault("baseline_override_cyber", data.pop("cyber_baseline"))
    if "physical_baseline" in data:
        data.setdefault("baseline_override_phys", data.pop("physical_baseline"))
    if "failed_login_alert_recipients" in data:
        data["failed_login_alert_recipients"] = _normalize_failed_login_alert_recipients(
            data["failed_login_alert_recipients"]
        )
    if "failed_login_alert_enabled" in data and not isinstance(data["failed_login_alert_enabled"], bool):
        raise ValueError("failed_login_alert_enabled must be a boolean.")
    for field_name, minimum, maximum in (
        ("failed_login_alert_threshold", 2, 100),
        ("failed_login_alert_window_minutes", 1, 60),
    ):
        if field_name in data:
            value = data[field_name]
            if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
                raise ValueError(f"{field_name} must be an integer between {minimum} and {maximum}.")
    editable_fields = {
        "llm_endpoint", "llm_api_key", "llm_model_name", "is_active", "tech_stack",
        "monitored_asns", "smtp_server", "smtp_port", "smtp_username", "smtp_password",
        "smtp_sender", "smtp_recipient", "smtp_enabled", "baseline_override_cyber",
        "baseline_override_phys", "sys_countermeasures", "net_countermeasures",
        "scoring_mode", "cyber_criticality_override", "cyber_lethality_override",
        "physical_criticality_override", "physical_lethality_override",
        "internal_criticality_override", "internal_lethality_override", "global_risk_offset",
        "internal_risk_offset", "llm_context_window",
        "public_app_url", "failed_login_alert_enabled", "failed_login_alert_recipients",
        "failed_login_alert_threshold", "failed_login_alert_window_minutes",
    }
    system_fields = {
        "alerted_eq_ids", "rolling_summary", "rolling_summary_time",
        "unified_brief", "unified_brief_time", "global_brief", "global_brief_time",
        "internal_brief", "internal_brief_time", "last_global_risk", "last_internal_risk",
        "last_risk_alert_time",
    }
    if allow_system_fields:
        editable_fields |= system_fields
    else:
        data = {key: value for key, value in data.items() if key not in system_fields}
    unknown = set(data) - editable_fields
    if unknown:
        raise ValueError(f"Unsupported configuration fields: {', '.join(sorted(unknown))}")
    if "public_app_url" in data:
        public_url = str(data["public_app_url"] or "").strip().rstrip("/")
        parsed = urlparse(public_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.query or parsed.fragment:
            raise ValueError("public_app_url must be an HTTP(S) URL without a query or fragment.")
        data = {**data, "public_app_url": public_url}
    with SessionLocal() as db:
        config = db.query(SystemConfig).first()
        if not config:
            config = SystemConfig()
            db.add(config)
        effective_alert_enabled = data.get(
            "failed_login_alert_enabled", bool(config.failed_login_alert_enabled)
        )
        effective_recipients = data.get(
            "failed_login_alert_recipients", config.failed_login_alert_recipients or ""
        )
        if effective_alert_enabled:
            if not effective_recipients:
                raise ValueError("Configure at least one failed login alert recipient before enabling alerts.")
            smtp_enabled = data.get("smtp_enabled", bool(config.smtp_enabled))
            smtp_server = data.get("smtp_server", config.smtp_server)
            smtp_sender = data.get("smtp_sender", config.smtp_sender)
            if not smtp_enabled or not smtp_server or not smtp_sender:
                raise ValueError("Failed login alerts require enabled SMTP with a server and sender configured.")
        for key, value in data.items(): setattr(config, key, value)
        db.commit()
    get_cached_config.clear()

def get_latest_internal_risk():
    from src.database import InternalRiskSnapshot
    with SessionLocal() as db:
        snap = db.query(InternalRiskSnapshot).order_by(InternalRiskSnapshot.timestamp.desc()).first()
        if not snap:
            return None
        sys_config = get_cached_config()
        scoring_mode = str(sys_config.get('scoring_mode', 'auto') or 'auto') if sys_config else 'auto'
        return {
            "id": snap.id,
            "timestamp": snap.timestamp.isoformat() if snap.timestamp else None,
            "score": snap.score,
            "risk_level": snap.risk_level,
            "total_assets": snap.total_assets,
            "total_osint_hits": snap.total_osint_hits,
            "critical_osint_hits": snap.critical_osint_hits,
            "hw_data": json.loads(snap.hw_data_json) if snap.hw_data_json else [],
            "sw_data": json.loads(snap.sw_data_json) if snap.sw_data_json else [],
            "scoring_mode": scoring_mode,
            "applied_overrides": {
                "criticality": {"auto": "stored", "used": "stored"},
                "lethality": {"auto": "stored", "used": "stored"},
            }
        }

def get_internal_risk_history(days: int = 28):
    from src.database import InternalRiskSnapshot
    from datetime import timedelta
    cutoff = datetime.utcnow() - timedelta(days=days)
    with SessionLocal() as db:
        snaps = db.query(InternalRiskSnapshot).filter(InternalRiskSnapshot.timestamp >= cutoff).order_by(InternalRiskSnapshot.timestamp.asc()).all()
        return [
            {"timestamp": s.timestamp.isoformat() if s.timestamp else None, "score": s.score, "risk_level": s.risk_level}
            for s in snaps
        ]

def trigger_unified_brief(progress_generation_id=None):
    """Force-generate the unified risk brief (same logic as scheduler's job_unified_brief)."""
    from src.utils.llm import generate_unified_risk_brief, update_brief_progress
    from src.database import InternalRiskSnapshot, RegionalHazard
    from src.services import get_executive_grid_intel, get_recent_crimes, save_global_config
    logger = logging.getLogger(__name__)
    logger.info("trigger_unified_brief: starting manual generation")

    def _progress(**kw):
        if progress_generation_id:
            update_brief_progress(progress_generation_id, **kw)

    _progress(stage="gathering", message="Gathering telemetry data...", percent=0)

    with SessionLocal() as session:
        latest_internal = session.query(InternalRiskSnapshot).order_by(InternalRiskSnapshot.timestamp.desc()).first()
        active_nws = session.query(RegionalHazard).count()
    crime_data = get_recent_crimes(max_distance=1.0, grid_only=True, hours_back=24)
    global_intel = get_executive_grid_intel(active_nws, crime_data)

    with SessionLocal() as session:
        brief_text = generate_unified_risk_brief(session, global_intel, latest_internal, progress_callback=_progress)

    if brief_text and "AI is currently disabled" not in brief_text and "generate_unified_risk_brief" not in str(type(brief_text)):
        save_global_config({"unified_brief": brief_text, "unified_brief_time": datetime.utcnow()})
        logger.info("trigger_unified_brief: saved successfully (len=%d)", len(brief_text))
        _progress(stage="complete", message="Brief generation complete.", percent=100)
        return {"status": "ok", "brief": brief_text}
    logger.warning("trigger_unified_brief: generation failed or AI disabled")
    _progress(stage="error", message=brief_text or "AI is disabled or generation failed.", percent=0)
    return {"status": "error", "message": brief_text or "AI is disabled or generation failed."}

def trigger_global_brief(progress_generation_id=None):
    """Force-generate the global threat brief focused on US critical infrastructure."""
    from src.utils.llm import generate_global_threat_brief, update_brief_progress
    from src.services import save_global_config
    logger = logging.getLogger(__name__)
    logger.info("trigger_global_brief: starting manual generation")

    def _progress(**kw):
        if progress_generation_id:
            update_brief_progress(progress_generation_id, **kw)

    _progress(stage="gathering", message="Gathering global threat intelligence...", percent=0)

    with SessionLocal() as session:
        brief_text = generate_global_threat_brief(session, progress_callback=_progress)

    if brief_text and "AI is currently disabled" not in brief_text and "generate_global_threat_brief" not in str(type(brief_text)):
        save_global_config({"global_brief": brief_text, "global_brief_time": datetime.utcnow()})
        logger.info("trigger_global_brief: saved successfully (len=%d)", len(brief_text))
        _progress(stage="complete", message="Global brief generation complete.", percent=100)
        return {"status": "ok", "brief": brief_text}
    logger.warning("trigger_global_brief: generation failed or AI disabled")
    _progress(stage="error", message=brief_text or "AI is disabled or generation failed.", percent=0)
    return {"status": "error", "message": brief_text or "AI is disabled or generation failed."}

def trigger_internal_brief(progress_generation_id=None):
    """Force-generate the internal asset risk brief tuned to OSINT correlations."""
    from src.utils.llm import generate_internal_risk_brief, update_brief_progress
    from src.services import save_global_config
    from src.database import InternalRiskSnapshot
    logger = logging.getLogger(__name__)
    logger.info("trigger_internal_brief: starting manual generation")

    def _progress(**kw):
        if progress_generation_id:
            update_brief_progress(progress_generation_id, **kw)

    _progress(stage="gathering", message="Gathering internal asset data...", percent=0)

    with SessionLocal() as session:
        latest_internal = session.query(InternalRiskSnapshot).order_by(InternalRiskSnapshot.timestamp.desc()).first()
        if not latest_internal:
            _progress(stage="error", message="No internal risk snapshot available.", percent=0)
            return {"status": "error", "message": "No internal risk snapshot available. Trigger an internal risk calculation first."}
        brief_text = generate_internal_risk_brief(session, latest_internal, progress_callback=_progress)

    if brief_text and "AI is currently disabled" not in brief_text and "generate_internal_risk_brief" not in str(type(brief_text)):
        save_global_config({"internal_brief": brief_text, "internal_brief_time": datetime.utcnow()})
        logger.info("trigger_internal_brief: saved successfully (len=%d)", len(brief_text))
        _progress(stage="complete", message="Internal brief generation complete.", percent=100)
        return {"status": "ok", "brief": brief_text}
    logger.warning("trigger_internal_brief: generation failed or AI disabled")
    _progress(stage="error", message=brief_text or "AI is disabled or generation failed.", percent=0)
    return {"status": "error", "message": brief_text or "AI is disabled or generation failed."}

def trigger_rolling_summary():
    """Force-generate and save the rolling shift handover summary."""
    from src.utils.llm import generate_rolling_summary
    from src.services import save_global_config
    logger = logging.getLogger(__name__)
    logger.info("trigger_rolling_summary: starting manual generation")

    with SessionLocal() as session:
        summary = generate_rolling_summary(session)

    if summary and "[WARN]" not in summary and "Generation failed" not in summary:
        save_global_config({
            "rolling_summary": summary,
            "rolling_summary_time": datetime.utcnow()
        })
        logger.info("trigger_rolling_summary: saved successfully (len=%d)", len(summary))
        return {"status": "ok", "summary": summary}
    logger.warning("trigger_rolling_summary: generation failed")
    return {"status": "error", "message": summary or "Generation failed."}

def trigger_scoring_rationale(intel_data: dict):
    """Force-generate the dynamic scoring report using provided intel."""
    from src.utils.llm import generate_dynamic_scoring_report
    logger = logging.getLogger(__name__)
    logger.info("trigger_scoring_rationale: starting manual generation")

    with SessionLocal() as session:
        report = generate_dynamic_scoring_report(session, intel_data)

    if report and "[WARN]" not in report and "Brief generation failed" not in report:
        logger.info("trigger_scoring_rationale: success (len=%d)", len(report))
        return {"status": "ok", "report": report}
    logger.warning("trigger_scoring_rationale: generation failed: %s", (report or "None")[:200])
    return {"status": "error", "message": report or "Generation failed."}

def _build_fallback_summary(logs, timeframe_label, target_role, generated_by, generated_by_role):
    """Build a narrative handoff summary without an LLM."""
    handoff_title = timeframe_label if "handoff" in timeframe_label.lower() else f"{timeframe_label} Operational Handoff"
    timeline = []
    open_items = []
    for log in reversed(logs):
        ts = log.created_at.strftime("%Y-%m-%d %H:%M") if log.created_at else "an unknown time"
        text = " ".join((log.content or "").split())
        analyst = log.analyst or "the on-duty analyst"
        timeline.append(f"- **{ts} — {analyst}:** {text[:1000]}")
        if re.search(r"\b(open|pending|unresolved|outstanding|follow[- ]?up|awaiting|monitor|escalat|ticket)\b", text, re.IGNORECASE):
            open_items.append(f"- **{ts} — {analyst}:** {text[:500]}")
    scope = "all available roles" if str(target_role).lower() == "all" else f"the {target_role.upper()} team"
    open_text = "\n".join(open_items) if open_items else "No explicit open items, pending actions, or follow-ups were recorded."
    return (
        f"# {handoff_title} — {scope}\n\n"
        f"**Prepared by:** {generated_by}\n\n"
        f"**Prepared for role:** {generated_by_role}\n\n"
        f"## Executive Narrative\n"
        f"The {timeframe_label.lower()} record contains {len(logs)} operational log entries covering {scope}. "
        f"The timeline below preserves each recorded event in chronological order; the open-items section isolates entries containing explicit follow-up or operational-state language. "
        f"No facts were inferred because AI narrative generation was unavailable.\n\n"
        f"## Chronological Activity\n{chr(10).join(timeline)}\n\n"
        f"## Open Items and Dependencies\n{open_text}\n\n"
        f"## Incoming Shift Priorities\n"
        f"Review the open items above, verify the current state of any referenced tickets or services, and record a follow-up update when the status changes."
    )


def trigger_shift_summary(role_filter: str = "All", shift_period: str = "Morning", timeframe_label: str = "Morning Shift", auto_append: bool = False, timeframe: str = "shift", generated_by: str = "Unknown", generated_by_role: str = "analyst"):
    """Force-generate an aggregated shift summary from log entries.
    timeframe: 'shift' = today only, 'week' = last 7 days.
    """
    import threading
    from src.utils.llm import generate_aggregated_shift_summary
    from src.database import ShiftLogEntry
    from zoneinfo import ZoneInfo
    logger = logging.getLogger(__name__)
    logger.info("trigger_shift_summary: role=%s shift=%s timeframe=%s auto_append=%s timeframe=%s", role_filter, shift_period, timeframe_label, auto_append, timeframe)

    with SessionLocal() as session:
        query = session.query(ShiftLogEntry).filter(ShiftLogEntry.is_deleted == False)
        if role_filter != "All":
            query = query.filter(ShiftLogEntry.author_role == role_filter.lower())
        if shift_period and timeframe != "fullday":
            query = query.filter(ShiftLogEntry.shift_period == shift_period)
        elif timeframe == "fullday":
            shift_period = "End of Day"

        now_chicago = datetime.now(ZoneInfo("America/Chicago"))
        if timeframe == "fullday":
            today_start_chicago = now_chicago.replace(hour=0, minute=0, second=0, microsecond=0)
            today_start_utc = today_start_chicago.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
            query = query.filter(ShiftLogEntry.created_at >= today_start_utc)
            if not timeframe_label or timeframe_label == shift_period + " Shift":
                timeframe_label = "End of Day"
        elif timeframe == "week":
            week_start_chicago = now_chicago - timedelta(days=7)
            week_start_utc = week_start_chicago.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
            query = query.filter(ShiftLogEntry.created_at >= week_start_utc)
            if not timeframe_label or timeframe_label == shift_period + " Shift":
                timeframe_label = "Current Week"
        else:
            today_start_chicago = now_chicago.replace(hour=0, minute=0, second=0, microsecond=0)
            today_start_utc = today_start_chicago.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
            query = query.filter(ShiftLogEntry.created_at >= today_start_utc)

        logs = query.order_by(ShiftLogEntry.created_at.desc()).limit(200).all()
        logger.info("trigger_shift_summary: fetched %d logs", len(logs))

        if not logs:
            return {"status": "ok", "summary": f"No log entries found for {timeframe_label} ({role_filter})."}

        llm_result = [None]
        llm_error = [None]
        done = threading.Event()

        def run_llm():
            try:
                llm_result[0] = generate_aggregated_shift_summary(session, logs, timeframe_label, target_role=role_filter, generated_by=generated_by, generated_by_role=generated_by_role)
            except Exception as e:
                llm_error[0] = e
            finally:
                done.set()

        t = threading.Thread(target=run_llm, daemon=True)
        t.start()
        ok = done.wait(timeout=30)

        if ok and not llm_error[0] and llm_result[0] and "[WARN]" not in llm_result[0] and "Summary generation failed" not in llm_result[0]:
            summary = llm_result[0]
            logger.info("trigger_shift_summary: LLM success (len=%d)", len(summary))
        else:
            if not ok:
                logger.warning("trigger_shift_summary: LLM timed out (>30s), using fallback")
            elif llm_error[0]:
                logger.error("trigger_shift_summary: LLM exception: %s", llm_error[0])
            else:
                logger.warning("trigger_shift_summary: LLM failed or unavailable, using fallback")
            summary = _build_fallback_summary(logs, timeframe_label, role_filter, generated_by, generated_by_role)

    if auto_append:
        save_shift_log(
            analyst=generated_by,
            role=generated_by_role,
            shift_period=shift_period,
            content=summary,
        )
        logger.info("trigger_shift_summary: auto-appended to shift log")
    return {"status": "ok", "summary": summary}

def add_bulk_keywords(raw_text):
    with SessionLocal() as db:
        for line in raw_text.split('\n'):
            if line.strip():
                parts = line.split(',')
                word = parts[0].strip().lower()
                raw_weight = parts[1].strip() if len(parts) > 1 else "10"
                try:
                    weight = int(raw_weight)
                    if weight < 1 or weight > 100:
                        weight = 10
                except ValueError:
                    weight = 10
                if not db.query(Keyword).filter_by(word=word).first(): db.add(Keyword(word=word, weight=weight))
        db.commit()

def update_keyword_weight(keyword_id: int, weight: int):
    if not isinstance(weight, int) or weight < 1 or weight > 100:
        raise ValueError("Weight must be an integer between 1 and 100")
    with SessionLocal() as db:
        kw = db.query(Keyword).filter_by(id=keyword_id).first()
        if not kw:
            raise ValueError(f"Keyword with id {keyword_id} not found")
        kw.weight = weight
        db.commit()
        from src.services.logic import force_reload_scorer
        force_reload_scorer()
        return {"id": kw.id, "word": kw.word, "weight": kw.weight}

def add_bulk_feeds(raw_text):
    with SessionLocal() as db:
        for line in raw_text.split('\n'):
            if line.strip():
                parts = line.split(',')
                url, name = parts[0].strip(), parts[1].strip() if len(parts) > 1 else "New Feed"
                if not db.query(FeedSource).filter_by(url=url).first(): db.add(FeedSource(url=url, name=name))
        db.commit()

def delete_record(model_name, record_id):
    models = {"Keyword": Keyword, "FeedSource": FeedSource, "User": User, "Role": Role, "SavedReport": SavedReport}
    with SessionLocal() as db:
        record = db.query(models[model_name]).filter_by(id=record_id).first()
        if record: db.delete(record); db.commit()

def get_admin_lists():
    with SessionLocal() as db:
        return to_dotdict_list(db.query(Keyword).order_by(Keyword.weight.desc()).all()), to_dotdict_list(db.query(FeedSource).all()), to_dotdict_list(db.query(User).all())

def get_ml_counts():
    with SessionLocal() as db:
        pos, neg = db.query(Article).filter(Article.human_feedback == 2).count(), db.query(Article).filter(Article.human_feedback == 1).count()
        return pos, neg, pos + neg

def get_backup_data():
    with SessionLocal() as db:
        return {
            "keywords": [{"word": k.word, "weight": k.weight} for k in db.query(Keyword).all()],
            "feeds": [{"url": f.url, "name": f.name} for f in db.query(FeedSource).all()],
            "locations": [{"name": l.name, "lat": l.lat, "lon": l.lon, "type": l.loc_type, "prio": l.priority} for l in db.query(MonitoredLocation).all()],
            "aliases": [{"pattern": a.node_pattern, "mapped": a.mapped_location_name, "conf": a.confidence_score, "ver": a.is_verified} for a in db.query(NodeAlias).all()]
        }

def restore_backup_data(data):
    added = {"kw": 0, "feeds": 0, "locs": 0, "alias": 0}
    with SessionLocal() as db:
        for kw in data.get("keywords", []):
            if not db.query(Keyword).filter_by(word=kw["word"]).first(): db.add(Keyword(word=kw["word"], weight=kw["weight"])); added["kw"] += 1
        for f in data.get("feeds", []):
            if not db.query(FeedSource).filter_by(url=f["url"]).first(): db.add(FeedSource(url=f["url"], name=f["name"])); added["feeds"] += 1
        for l in data.get("locations", []):
            if not db.query(MonitoredLocation).filter_by(name=l["name"]).first(): db.add(MonitoredLocation(name=l["name"], lat=l["lat"], lon=l["lon"], loc_type=l.get("type", "General"), priority=str(l.get("prio", "P3-Moderate")))); added["locs"] += 1
        for a in data.get("aliases", []):
            if not db.query(NodeAlias).filter_by(node_pattern=a["pattern"]).first(): db.add(NodeAlias(node_pattern=a["pattern"], mapped_location_name=a["mapped"], confidence_score=a["conf"], is_verified=a["ver"])); added["alias"] += 1
        db.commit()
    return added

ALL_MODELS = {
    "users": User,
    "roles": Role,
    "saved_reports": SavedReport,
    "feed_sources": FeedSource,
    "keywords": Keyword,
    "system_config": SystemConfig,
    "shift_logs": ShiftLogEntry,
    "software_assets": SoftwareAsset,
    "hardware_assets": HardwareAsset,
    "internal_risk_snapshots": InternalRiskSnapshot,
    "articles": Article,
    "extracted_iocs": ExtractedIOC,
    "cve_items": CveItem,
    "elastic_events": ElasticEvent,
    "daily_briefings": DailyBriefing,
    "daily_threat_scores": DailyThreatScore,
    "regional_hazards": RegionalHazard,
    "regional_outages": RegionalOutage,
    "cloud_outages": CloudOutage,
    "bgp_anomalies": BgpAnomaly,
    "solarwinds_alerts": SolarWindsAlert,
    "timeline_events": TimelineEvent,
    "monitored_locations": MonitoredLocation,
    "crime_incidents": CrimeIncident,
    "geojson_cache": GeoJsonCache,
    "user_weather_prefs": UserWeatherPreference,
    "node_aliases": NodeAlias,
}


def _serialize_record(record):
    d = {}
    for col in record.__table__.columns:
        val = getattr(record, col.name)
        if isinstance(val, datetime):
            d[col.name] = val.isoformat()
        else:
            d[col.name] = val
    return d


def export_all_tables():
    """Export ALL tables as a dict of table_name -> list of records."""
    result = {}
    with SessionLocal() as db:
        for table_name, model_cls in ALL_MODELS.items():
            rows = db.query(model_cls).all()
            result[table_name] = [_serialize_record(r) for r in rows]
    return result


def import_all_tables(data, merge=False):
    """Import a full JSON dump of all tables.

    If merge=True, inserts only non-duplicate records (by 'id').
    If merge=False (default), truncates tables first then inserts.
    """
    counts = {}
    with SessionLocal() as db:
        try:
            db.execute(text("PRAGMA foreign_keys=OFF"))
            for table_name, model_cls in ALL_MODELS.items():
                rows = data.get(table_name, [])
                if not rows:
                    counts[table_name] = 0
                    continue
                if not merge:
                    db.query(model_cls).delete(synchronize_session=False)
                inserted = 0
                for row_data in rows:
                    if merge:
                        rid = row_data.get("id")
                        if rid and db.query(model_cls).filter_by(id=rid).first():
                            continue
                    kwargs = {}
                    for col in model_cls.__table__.columns:
                        if col.name not in row_data:
                            continue
                        val = row_data[col.name]
                        if isinstance(col.type, DateTime) and isinstance(val, str):
                            try:
                                kwargs[col.name] = datetime.fromisoformat(val)
                            except ValueError:
                                kwargs[col.name] = val
                        elif isinstance(col.type, Boolean):
                            kwargs[col.name] = bool(val) if val is not None else None
                        else:
                            kwargs[col.name] = val
                    db.add(model_cls(**kwargs))
                    inserted += 1
                counts[table_name] = inserted
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.execute(text("PRAGMA foreign_keys=ON"))
    return counts


def restore_from_db_upload(db_file_path):
    """Read a SQLite .db file and import all its tables into the current database."""
    import sqlite3
    conn = sqlite3.connect(db_file_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    table_names = [row[0] for row in cursor.fetchall()]
    imported = {}
    with SessionLocal() as db:
        try:
            db.execute(text("PRAGMA foreign_keys=OFF"))
            for table_name in table_names:
                cursor.execute(f"SELECT * FROM \"{table_name}\"")
                rows = [dict(row) for row in cursor.fetchall()]
                if not rows:
                    imported[table_name] = 0
                    continue
                model_cls = ALL_MODELS.get(table_name)
                if model_cls is not None:
                    db.query(model_cls).delete(synchronize_session=False)
                    inserted = 0
                    for row_data in rows:
                        kwargs = {}
                        for col in model_cls.__table__.columns:
                            if col.name not in row_data:
                                continue
                            val = row_data[col.name]
                            if isinstance(col.type, DateTime) and isinstance(val, str):
                                try:
                                    kwargs[col.name] = datetime.fromisoformat(val)
                                except ValueError:
                                    kwargs[col.name] = val
                            elif isinstance(col.type, Boolean):
                                kwargs[col.name] = bool(val) if val is not None else None
                            else:
                                kwargs[col.name] = val
                        db.add(model_cls(**kwargs))
                        inserted += 1
                    imported[table_name] = inserted
                else:
                    db.execute(text(f"DELETE FROM \"{table_name}\""))
                    for row_data in rows:
                        placeholders = ", ".join([f":{k}" for k in row_data])
                        cols = ", ".join(row_data.keys())
                        db.execute(text(f"INSERT INTO \"{table_name}\" ({cols}) VALUES ({placeholders})"), row_data)
                    imported[table_name] = len(rows)
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.execute(text("PRAGMA foreign_keys=ON"))
    conn.close()
    return imported


def recategorize_all_articles():
    from src.services.categorizer import categorize_text
    with SessionLocal() as db:
        # Fetch ALL articles, not just "General"
        arts = db.query(Article).all()
        count = 0
        
        for a in arts:
            fc = getattr(a, 'full_content', None)
            if fc and len(fc) > 100:
                text = f"{a.title} {fc}"
            else:
                text = f"{a.title} {a.summary}"
            new_cat = categorize_text(text)
            
            # Only update and count if the category actually changed
            if a.category != new_cat: 
                a.category = new_cat
                count += 1
                
        db.commit()
        return count

def rescore_all_articles():
    """Re-score all existing articles using current keywords and categorizer."""
    from src.services.logic import HybridScorer
    from src.services.categorizer import categorize_text
    from src.services.ioc_extractor import ioc_engine

    scorer = HybridScorer()
    ALERT_THRESHOLD = 45
    count = 0

    with SessionLocal() as db:
        arts = db.query(Article).all()
        for a in arts:
            fc = getattr(a, 'full_content', None)
            if fc and len(fc) > 100:
                full_text = f"{a.title} {fc}"
            else:
                full_text = f"{a.title} {a.summary or ''}"
            score, reasons = scorer.score(full_text)
            category = categorize_text(full_text)

            a.score = float(score)
            a.category = category
            a.keywords_found = reasons
            a.is_bubbled = (score >= ALERT_THRESHOLD)

            if score >= 50.0 and category.startswith("Cyber"):
                iocs = ioc_engine.extract(full_text)
                for ioc in iocs:
                    existing = db.query(ExtractedIOC).filter_by(
                        article_id=a.id,
                        indicator_type=ioc["Type"],
                        indicator_value=ioc["Indicator"]
                    ).first()
                    if not existing:
                        db.add(ExtractedIOC(
                            article_id=a.id, indicator_type=ioc["Type"],
                            indicator_value=ioc["Indicator"], context=ioc["Context"]
                        ))

            count += 1

        db.commit()
        logger.info(f"Rescored {count} articles.")
    return count


def nuke_tables(model_names):
    models_map = {"CloudOutage": CloudOutage, "MonitoredLocation": MonitoredLocation, "Article": Article, "ExtractedIOC": ExtractedIOC, "FeedSource": FeedSource, "Keyword": Keyword}
    with SessionLocal() as db:
        for name in model_names:
            if name in models_map: db.query(models_map[name]).delete(synchronize_session=False)
        db.commit()

def truncate_db_table(table_query):
    if "monitored_locations" in table_query.lower():
        nuke_tables(["MonitoredLocation"])
        get_cached_locations.clear()

def nuke_weather_data():
    """Wipes all records from Regional Hazards and the GeoJSON cache, and resets location risks."""
    from src.database import RegionalHazard, GeoJsonCache, MonitoredLocation
    with SessionLocal() as db:
        try:
            # Delete all active NWS alerts and the massive map JSON payloads
            haz_deleted = db.query(RegionalHazard).delete()
            geo_deleted = db.query(GeoJsonCache).delete()
            
            # Reset all facility SPC risk levels back to "None"
            db.query(MonitoredLocation).update({MonitoredLocation.current_spc_risk: "None"})
            
            db.commit()
            
            # Clear the Streamlit RAM cache so the map instantly goes blank
            get_cached_geojson.clear()
            
            return True, (haz_deleted + geo_deleted)
        except Exception as e:
            db.rollback()
            return False, str(e)


# ==========================================
# 10. UI MAP GENERATION ENGINE (PyDeck)
# ==========================================

@TTLCache(ttl=120, max_entries=4)
def _precompute_geo_matrix(spc_data, ar_data, oos_data, usgs_ar_data, usgs_oos_data, selected_events_tuple, map_rows):
    """Heavy Math Engine: Parses JSON, builds Shapely objects, and calculates all intersections ONCE."""
    from shapely.affinity import scale as scale_geometry
    from shapely.geometry import Point, shape
    from datetime import datetime
    
    master_polygons = []
    map_diagnostics = []
    
    # 1. Process SPC
    spc_micro = {"type": "FeatureCollection", "features": []}
    if spc_data:
        color_map = {"TSTM": [192, 232, 192, 100], "MRGL": [124, 205, 124, 150], "SLGT": [246, 246, 123, 150], "ENH": [230, 153, 0, 150], "MDT": [255, 0, 0, 150], "HIGH": [255, 0, 255, 150]}
        for f in spc_data.get('features', []):
            label = f.get('properties', {}).get('LABEL', '')
            try:
                poly_shape = shape(f.get("geometry"))
                master_polygons.append({"event": f"SPC: {label}", "shape": poly_shape, "severity": "Watch"})
                spc_micro["features"].append({
                    "type": "Feature", "geometry": f.get("geometry"),
                    "properties": {"fill_color": color_map.get(label, [0, 0, 0, 0]), "line_color": [0, 0, 0, 255], "info": f"SPC Risk: {label}"}
                })
            except Exception: pass

    # 2. Process NWS
    ar_warn, ar_watch, _, ar_logs = process_nws_alerts(ar_data, selected_events_tuple, is_oos=False)
    oos_warn, oos_watch, _, oos_logs = process_nws_alerts(oos_data, selected_events_tuple, is_oos=True)
    map_diagnostics.extend(ar_logs + oos_logs)

    for geo_dict in [ar_warn, ar_watch, oos_warn, oos_watch]:
        for f in geo_dict["features"]:
            master_polygons.append({
                "event": f['properties']['info'], 
                "shape": f['properties']['shapely_obj'], 
                "severity": f['properties']['severity']
            })
            # MUST remove shapely_obj so Streamlit can serialize the dict into RAM cache
            f['properties'].pop('shapely_obj', None)

    # 3. Process Fire Risk
    ar_fire_geo = {"type": "FeatureCollection", "features": []}
    regional_counties = get_regional_counties_mapping()
    fire_fips_to_process = {}
    for geo_ds in [ar_data, oos_data]:
        if geo_ds:
            for f in geo_ds.get('features', []):
                event = f.get('properties', {}).get('event', '')
                if any(k in event for k in ["Fire Weather", "Red Flag", "Fire Warning", "Extreme Fire"]):
                    severity = "Extreme (Burn Ban / Red Flag)" if "Red Flag" in event or "Warning" in event else "High (Fire Weather Watch)"
                    fill_color = [139, 0, 0, 160] if "Red Flag" in event or "Warning" in event else [255, 140, 0, 120]
                    line_color = [255, 0, 0, 255] if "Red Flag" in event or "Warning" in event else [255, 140, 0, 255]
                    
                    same_codes = f.get('properties', {}).get('geocode', {}).get('SAME', [])
                    for same_code in same_codes:
                        fips = same_code[-5:]
                        if fips in regional_counties and regional_counties[fips]["state_fips"] == "05":
                            fire_fips_to_process[fips] = {"severity": severity, "color": fill_color, "line_color": line_color, "event": event, "county_name": regional_counties[fips]["name"]}

    for fips, info in fire_fips_to_process.items():
        geom = regional_counties[fips]["geometry"]
        ar_fire_geo["features"].append({"type": "Feature", "geometry": geom, "properties": {"info": f"{info['county_name'].title()} County\nRisk Level: {info['severity']}\nNWS Alert: {info['event']}", "fill_color": info["color"], "line_color": info["line_color"]}})
        try:
            master_polygons.append({"event": f"Wildfire Risk: {info['event']}", "shape": shape(geom), "severity": "High"})
        except: pass

    # 4. Process active WFCA wildfire incidents, preferring their perimeter
    # geometry and falling back to a small incident-point area when needed.
    wfca_data = get_active_wildfires()
    if isinstance(wfca_data, dict):
        perimeter_shapes = {
            _normalize_fire_id(perimeter.get("irwin_id")): perimeter.get("geometry")
            for perimeter in wfca_data.get("perimeters", [])
            if perimeter.get("irwin_id") and perimeter.get("geometry")
        }
        for row in wfca_data.get("incidents", []):
            try:
                perimeter = perimeter_shapes.get(_normalize_fire_id(row.get("irwin_id")))
                if perimeter:
                    fire_poly = shape(perimeter)
                elif row.get("acres", 0) <= 1:
                    lon, lat = float(row["lon"]), float(row["lat"])
                    lon_radius = 1.0 / (69.172 * math.cos(math.radians(lat)))
                    lat_radius = 1.0 / 69.0
                    fire_poly = scale_geometry(
                        Point(lon, lat).buffer(1.0),
                        xfact=lon_radius, yfact=lat_radius, origin=(lon, lat),
                    )
                else:
                    fire_poly = Point(row["lon"], row["lat"]).buffer(0.03)
                master_polygons.append({"event": f"Active Wildfire: {row['name']}", "shape": fire_poly, "severity": "High"})
            except: pass

    # 5. Process USGS Earthquakes
    eq_data = []
    def get_eq_color(mag):
        if mag >= 5.0: return [255, 0, 0, 200]
        if mag >= 4.0: return [255, 165, 0, 200]
        if mag >= 3.0: return [255, 255, 0, 200]
        return [0, 0, 255, 200]
    
    def process_usgs_quakes(usgs_data, label_prefix):
        if not usgs_data or 'features' not in usgs_data:
            return
        for f in usgs_data['features']:
            props = f.get('properties', {})
            mag = props.get('mag', 0)
            if mag < 2.0:
                continue
            coords = f.get('geometry', {}).get('coordinates', [0, 0, 0])
            lon, lat, depth = coords[0], coords[1], coords[2]
            place = props.get('place', 'Unknown')
            time_ms = props.get('time', 0)
            time_str = datetime.fromtimestamp(time_ms/1000).strftime('%Y-%m-%d %H:%M') if time_ms else 'Unknown'
            
            fill_color = get_eq_color(mag)
            quake_info = f"M{mag:.1f}: {place}\nDepth: {depth:.1f}km\nTime: {time_str}"
            eq_data.append({
                "lon": lon, "lat": lat, "mag": mag, "place": place,
                "depth": depth, "time": time_str, "info": quake_info,
                "color": fill_color
            })
            
            try:
                eq_point = Point(lon, lat).buffer(0.02)
                severity = "High" if mag >= 4.0 else "Medium"
                master_polygons.append({"event": f"EQ ({label_prefix}): M{mag:.1f}", "shape": eq_point, "severity": severity})
            except: pass
    
    for usgs_d, prefix in [(usgs_ar_data, "AR"), (usgs_oos_data, "OOS")]:
        if usgs_d:
            process_usgs_quakes(usgs_d, prefix)

    # 6. Execute CPU-Heavy Bounding Box Math ONCE
    _, master_affected_sites = calculate_site_intersections(map_rows, master_polygons)
    
    return {
        "spc_micro": spc_micro,
        "ar_warn": ar_warn, "ar_watch": ar_watch,
        "oos_warn": oos_warn, "oos_watch": oos_watch,
        "ar_fire_geo": ar_fire_geo,
        "wfca_data": wfca_data,
        "eq_data": eq_data,
        "master_affected_sites": master_affected_sites,
        "map_diagnostics": map_diagnostics
    }

def deduplicate_articles(session):
    """De-duplicate articles by link and similar titles within the past 24 hours.
    
    Uses bucket pre-filtering and RapidFuzz's native ratio implementation to
    reduce the cost of title comparisons:
    articles are grouped by (source_domain, hour_bucket, len_bucket) so only
    articles within the same bucket are compared for similarity.
    """
    from rapidfuzz.fuzz import ratio as title_ratio

    removed = 0
    cutoff = datetime.utcnow() - timedelta(hours=24)

    # 1. Exact link duplicates
    links = session.query(Article.id, Article.link).filter(
        Article.published_date >= cutoff
    ).all()

    seen_links = {}
    for art_id, link in links:
        if link in seen_links:
            dup = session.query(Article).get(art_id)
            if dup:
                session.delete(dup)
                removed += 1
        else:
            seen_links[link] = art_id

    # 2. Title similarity — bucket pre-filter to avoid O(n²)
    from urllib.parse import urlparse
    articles = session.query(Article).filter(
        Article.published_date >= cutoff
    ).all()

    # Build buckets: (source_domain, hour_key, length_bucket)
    buckets = {}
    for art in articles:
        t = (art.title or "").lower().strip()
        if not t:
            continue
        try:
            domain = urlparse(art.link or "").netloc or art.source or ""
        except Exception:
            domain = art.source or ""
        hour_key = (art.published_date or datetime.utcnow()).strftime("%Y%m%d%H")
        # Length bucket: group titles within 20 chars of each other
        len_bucket = len(t) // 20
        key = (domain, hour_key, len_bucket)
        buckets.setdefault(key, []).append(art)

    # Only compare within buckets
    for bucket_arts in buckets.values():
        for i in range(len(bucket_arts)):
            if bucket_arts[i] is None:
                continue
            t1 = (bucket_arts[i].title or "").lower().strip()
            if not t1:
                continue
            for j in range(i + 1, len(bucket_arts)):
                if bucket_arts[j] is None:
                    continue
                t2 = (bucket_arts[j].title or "").lower().strip()
                if not t2:
                    continue
                if title_ratio(t1, t2) > 85:
                    dup = bucket_arts[j]
                    session.delete(dup)
                    bucket_arts[j] = None
                    removed += 1

    if removed:
        session.commit()
    return removed
