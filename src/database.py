"""
Backward-compatible shim: re-exports from the new modular structure.
"""

from src.core.db import engine, SessionLocal, init_db, get_db
from src.models.schema import (
    Base,
    User,
    Role,
    SavedReport,
    FeedSource,
    Keyword,
    SystemConfig,
    ShiftLogEntry,
    SoftwareAsset,
    HardwareAsset,
    InternalRiskSnapshot,
    Article,
    ExtractedIOC,
    CveItem,
    ElasticEvent,
    DailyBriefing,
    DailyThreatScore,
    RegionalHazard,
    RegionalOutage,
    CloudOutage,
    BgpAnomaly,
    SolarWindsAlert,
    TimelineEvent,
    MonitoredLocation,
    CrimeIncident,
    GeoJsonCache,
    UserWeatherPreference,
    NodeAlias,
)
