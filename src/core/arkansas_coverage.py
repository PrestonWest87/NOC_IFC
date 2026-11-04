"""Geospatial scope and current-alert filtering for the Arkansas border region."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any

from pyproj import Transformer
from shapely.geometry import shape
from shapely.ops import transform as transform_geometry, unary_union


BUFFER_MILES = 50.0
METERS_PER_MILE = 1609.344
ARKANSAS_STATE_FIPS = "05"
NEIGHBOR_STATE_CODES = ("LA", "TX", "MS", "MO", "OK", "TN")
REQUEST_STATE_CODES = ("AR", *NEIGHBOR_STATE_CODES)

STATE_FIPS_BY_CODE = {
    "AL": "01", "AK": "02", "AZ": "04", "AR": "05", "CA": "06",
    "CO": "08", "CT": "09", "DE": "10", "DC": "11", "FL": "12",
    "GA": "13", "HI": "15", "ID": "16", "IL": "17", "IN": "18",
    "IA": "19", "KS": "20", "KY": "21", "LA": "22", "ME": "23",
    "MD": "24", "MA": "25", "MI": "26", "MN": "27", "MS": "28",
    "MO": "29", "MT": "30", "NE": "31", "NV": "32", "NH": "33",
    "NJ": "34", "NM": "35", "NY": "36", "NC": "37", "ND": "38",
    "OH": "39", "OK": "40", "OR": "41", "PA": "42", "RI": "44",
    "SC": "45", "SD": "46", "TN": "47", "TX": "48", "UT": "49",
    "VT": "50", "VA": "51", "WA": "53", "WV": "54", "WI": "55",
    "WY": "56",
}
STATE_CODE_BY_FIPS = {fips: code for code, fips in STATE_FIPS_BY_CODE.items()}


@dataclass(frozen=True)
class ArkansasCoverage:
    """Projected Arkansas geometry and its exact-distance outward buffer."""

    arkansas: Any
    buffered: Any
    neighbor_strip: Any
    arkansas_wgs84: Any
    buffered_wgs84: Any
    county_geometries: dict[str, Any]
    forward_transformer: Transformer
    reverse_transformer: Transformer
    bounds: tuple[float, float, float, float]
    arkansas_bounds: tuple[float, float, float, float]
    border_states: tuple[str, ...] = NEIGHBOR_STATE_CODES

    def project(self, geometry):
        """Project one WGS84 Shapely geometry into the local distance CRS."""
        return transform_geometry(self.forward_transformer.transform, geometry)

    def includes_point(self, longitude: float, latitude: float, scope: str = "border") -> bool:
        """Test a WGS84 point against Arkansas or the outward 50-mile strip."""
        from shapely.geometry import Point

        point = self.project(Point(float(longitude), float(latitude)))
        if scope == "arkansas":
            return self.arkansas.covers(point)
        if scope == "border":
            return self.neighbor_strip.covers(point)
        return self.buffered.covers(point)

    def contains_alert(self, feature: dict) -> tuple[str | None, str]:
        """Return the matching scope and precision for one NWS alert feature."""
        properties = feature.get("properties") or {}
        geometry_data = feature.get("geometry")
        if geometry_data:
            try:
                projected = self.project(shape(geometry_data))
                if not projected.is_empty and projected.is_valid:
                    if projected.intersects(self.arkansas):
                        return "arkansas", "alert_geometry"
                    if projected.intersects(self.neighbor_strip):
                        return "border", "alert_geometry"
                    return None, "alert_geometry"
            except Exception:
                pass

        county_geometries = [
            self.county_geometries[fips]
            for fips in alert_county_fips(properties)
            if fips in self.county_geometries
        ]
        if county_geometries:
            for county in county_geometries:
                projected_county = self.project(county)
                if projected_county.intersects(self.arkansas):
                    return "arkansas", "county_geocode"
                if projected_county.intersects(self.neighbor_strip):
                    return "border", "county_geocode"
            return None, "county_geocode"

        state_codes = alert_state_codes(properties)
        regional_codes = set(REQUEST_STATE_CODES).intersection(state_codes)
        if "AR" in regional_codes:
            return "arkansas", "state_fallback"
        if regional_codes:
            return "border", "state_fallback"

        # A successful state-area query can include a valid CAP message without
        # usable geometry or UGC/SAME values. Retain it rather than risk a false
        # negative, and expose that its exact corridor location is unresolved.
        if feature.get("geometry") is None:
            return "border", "unresolved_state_fallback"
        return None, "alert_geometry"


def build_arkansas_coverage(counties: dict, buffer_miles: float = BUFFER_MILES) -> ArkansasCoverage:
    """Build a meter-based 50-mile buffer from cached US county GeoJSON."""
    arkansas_shapes = []
    county_shapes = {}
    for fips, record in (counties or {}).items():
        if not isinstance(record, dict) or not record.get("geometry"):
            continue
        state_fips = str(record.get("state_fips") or str(fips)[:2]).zfill(2)
        try:
            geometry = shape(record["geometry"])
        except Exception:
            continue
        if geometry.is_empty or not geometry.is_valid:
            continue
        normalized_fips = str(fips).zfill(5)
        if len(normalized_fips) >= 5:
            county_shapes[normalized_fips[-5:]] = geometry
        if state_fips == ARKANSAS_STATE_FIPS:
            arkansas_shapes.append(geometry)

    if not arkansas_shapes:
        raise ValueError("Arkansas county boundary geometry is unavailable")
    arkansas_wgs84 = unary_union(arkansas_shapes)
    center = arkansas_wgs84.representative_point()
    local_crs = (
        f"+proj=aeqd +lat_0={center.y:.8f} +lon_0={center.x:.8f} "
        "+datum=WGS84 +units=m +no_defs +type=crs"
    )
    forward = Transformer.from_crs("EPSG:4326", local_crs, always_xy=True)
    reverse = Transformer.from_crs(local_crs, "EPSG:4326", always_xy=True)
    arkansas = transform_geometry(forward.transform, arkansas_wgs84)
    buffered = arkansas.buffer(float(buffer_miles) * METERS_PER_MILE)
    neighbor_strip = buffered.difference(arkansas)
    bounds_geometry = transform_geometry(reverse.transform, buffered)
    arkansas_geometry_wgs84 = transform_geometry(reverse.transform, arkansas)
    return ArkansasCoverage(
        arkansas=arkansas,
        buffered=buffered,
        neighbor_strip=neighbor_strip,
        arkansas_wgs84=arkansas_wgs84,
        buffered_wgs84=bounds_geometry,
        county_geometries=county_shapes,
        forward_transformer=forward,
        reverse_transformer=reverse,
        bounds=bounds_geometry.bounds,
        arkansas_bounds=arkansas_geometry_wgs84.bounds,
    )


@lru_cache(maxsize=1)
def get_arkansas_coverage() -> ArkansasCoverage:
    """Load boundaries from the shared cached county geometry and memoize the buffer."""
    # Import lazily to avoid a services/core module import cycle.
    from src.services import get_regional_counties_mapping

    return build_arkansas_coverage(get_regional_counties_mapping())


def _code_values(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip().upper() for item in value if item is not None]
    return [part.strip().upper() for part in str(value).replace(";", ",").split(",") if part.strip()]


def alert_county_fips(properties: dict) -> set[str]:
    """Extract county FIPS IDs from NWS SAME and county UGC geocodes."""
    geocode = properties.get("geocode") or {}
    if not isinstance(geocode, dict):
        return set()
    county_ids: set[str] = set()
    for same in _code_values(geocode.get("SAME")):
        digits = "".join(character for character in same if character.isdigit())
        if len(digits) >= 5:
            county_ids.add(digits[-5:])
    for ugc in _code_values(geocode.get("UGC")):
        if len(ugc) >= 6 and ugc[2] == "C" and ugc[:2] in STATE_FIPS_BY_CODE:
            county_ids.add(STATE_FIPS_BY_CODE[ugc[:2]] + ugc[-3:])
    return county_ids


def alert_state_codes(properties: dict) -> set[str]:
    """Extract state abbreviations represented by NWS SAME or UGC geocodes."""
    geocode = properties.get("geocode") or {}
    if not isinstance(geocode, dict):
        return set()
    states: set[str] = set()
    for same in _code_values(geocode.get("SAME")):
        digits = "".join(character for character in same if character.isdigit())
        if len(digits) >= 5:
            state_code = STATE_CODE_BY_FIPS.get(digits[-5:-3])
            if state_code:
                states.add(state_code)
    for ugc in _code_values(geocode.get("UGC")):
        if len(ugc) >= 2 and ugc[:2] in STATE_FIPS_BY_CODE:
            states.add(ugc[:2])
    return states


def parse_nws_datetime(value) -> datetime | None:
    """Parse an ISO NWS timestamp as a UTC-aware datetime."""
    if not value:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def is_current_alert(feature: dict, now: datetime | None = None) -> bool:
    """Apply CAP message timing; event-ending time is intentionally not expiry."""
    properties = feature.get("properties") or {}
    if not is_unexpired_alert(feature, now):
        return False
    current_time = now or datetime.now(timezone.utc)
    if current_time.tzinfo is None:
        current_time = current_time.replace(tzinfo=timezone.utc)
    effective = parse_nws_datetime(properties.get("effective"))
    if effective and effective > current_time:
        return False
    return True


def is_unexpired_alert(feature: dict, now: datetime | None = None) -> bool:
    """Check message expiry without hiding a future-effective alert from storage."""
    properties = feature.get("properties") or {}
    if str(properties.get("messageType") or "").casefold() == "cancel":
        return False
    current_time = now or datetime.now(timezone.utc)
    if current_time.tzinfo is None:
        current_time = current_time.replace(tzinfo=timezone.utc)
    expires = parse_nws_datetime(properties.get("expires"))
    return not expires or expires > current_time


def filter_current_alerts(collection: dict | None, now: datetime | None = None) -> dict:
    """Return a current-alert snapshot without mutating the cached provider payload."""
    features = collection.get("features", []) if isinstance(collection, dict) else []
    return {
        "type": "FeatureCollection",
        "features": [feature for feature in features if is_current_alert(feature, now)],
    }


def split_alerts_for_region(data: dict, now: datetime | None = None) -> tuple[dict, dict, dict]:
    """Select active NWS alerts touching Arkansas or its neighbor-state border strip."""
    arkansas_features = []
    border_features = []
    precision_counts: dict[str, int] = {}
    coverage = get_arkansas_coverage()
    features = data.get("features", []) if isinstance(data, dict) else []
    for feature in features:
        if not isinstance(feature, dict) or not is_unexpired_alert(feature, now):
            continue
        scope, precision = coverage.contains_alert(feature)
        if scope is None:
            continue
        normalized = dict(feature)
        properties = dict(feature.get("properties") or {})
        properties["noc_coverage_scope"] = scope
        properties["noc_coverage_precision"] = precision
        normalized["properties"] = properties
        precision_counts[precision] = precision_counts.get(precision, 0) + 1
        if scope == "arkansas":
            arkansas_features.append(normalized)
        else:
            border_features.append(normalized)

    return (
        {"type": "FeatureCollection", "features": arkansas_features},
        {"type": "FeatureCollection", "features": border_features},
        {
            "source_feature_count": len(features),
            "arkansas_alert_count": len(arkansas_features),
            "border_alert_count": len(border_features),
            "coverage_precision_counts": precision_counts,
            "border_states": list(NEIGHBOR_STATE_CODES),
            "buffer_miles": BUFFER_MILES,
        },
    )
