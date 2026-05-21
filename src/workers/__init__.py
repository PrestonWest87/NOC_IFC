"""
Workers package for background data ingestion.
Exposes a unified interface for worker lifecycle management.
"""

from .cloud_worker import fetch_cloud_outages
from .crime_worker import fetch_live_crimes
from .cve_worker import fetch_cisa_kev
from .elastic_worker import sync_elastic_telemetry, execute_live_query, purge_stale_elastic_data
from .infra_worker import fetch_regional_hazards
from .report_worker import start_report_scheduler, run_daily_report
from .telemetry_worker import run_telemetry_sync


def start_all_workers():
    """Start all background workers (placeholder for future lifecycle management)."""
    pass


def stop_all_workers():
    """Stop all background workers (placeholder for future lifecycle management)."""
    pass
