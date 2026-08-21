import requests
import uuid
import math
import json
import logging
import concurrent.futures
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from src.core.db import SessionLocal
from src.models.schema import RegionalHazard, GeoJsonCache, MonitoredLocation, SystemConfig

CENTRAL_TZ = ZoneInfo("America/Chicago")
logger = logging.getLogger(__name__)


def save_geojson_to_db(session, feed_name, data):
    cache_entry = session.query(GeoJsonCache).filter_by(feed_name=feed_name).first()
    if cache_entry:
        cache_entry.data = data
        cache_entry.updated_at = datetime.utcnow()
    else:
        session.add(GeoJsonCache(feed_name=feed_name, data=data))


def fetch_spc_outlooks():
    SPC_URLS = {
        "spc_day1": "https://www.spc.noaa.gov/products/outlook/day1otlk_cat.nolyr.geojson",
        "spc_day2": "https://www.spc.noaa.gov/products/outlook/day2otlk_cat.nolyr.geojson",
        "spc_day3": "https://www.spc.noaa.gov/products/outlook/day3otlk_cat.nolyr.geojson"
    }

    logger.debug("fetch_spc_outlooks: fetching %d SPC outlooks", len(SPC_URLS))
    headers = {'User-Agent': 'Mozilla/5.0 (NOC_Fusion_Center)'}

    def _fetch_spc(item):
        feed_name, url = item
        try:
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                return feed_name, response.json(), None
            return feed_name, None, f"HTTP {response.status_code}"
        except Exception as e:
            return feed_name, None, str(e)

    with SessionLocal() as session:
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                results = list(executor.map(_fetch_spc, SPC_URLS.items()))
            for feed_name, data, error in results:
                if error:
                    logger.error(f"Failed to fetch {feed_name}. {error}")
                elif data:
                    save_geojson_to_db(session, feed_name, data)
                    logger.debug(f"Downloaded and cached {feed_name} GeoJSON to DB.")
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"SPC Fetch Error: {e}", exc_info=True)


def fetch_nws_alerts_for_region(area_str, feed_name):
    logger.debug("fetch_nws_alerts_for_region: area=%s feed=%s", area_str, feed_name)
    with SessionLocal() as session:
        try:
            url = f"https://api.weather.gov/alerts/active?area={area_str}"
            headers = {'User-Agent': 'Mozilla/5.0 (NOC_Fusion_Center)'}
            logger.debug("fetch_nws_alerts_for_region: fetching %s", url)
            response = requests.get(url, headers=headers, timeout=15)

            if response.status_code == 200:
                data = response.json()
                save_geojson_to_db(session, feed_name, data)
                features = data.get('features', [])
                added, updated = 0, 0
                logger.debug("fetch_nws_alerts_for_region: got %d features", len(features))

                for f in features:
                    props = f.get('properties', {})
                    hazard_id = props.get('id', str(uuid.uuid4()))
                    existing_hazard = session.query(RegionalHazard).filter_by(hazard_id=hazard_id).first()

                    if existing_hazard:
                        existing_hazard.updated_at = datetime.utcnow()
                        updated += 1
                    else:
                        session.add(RegionalHazard(
                            hazard_id=hazard_id,
                            hazard_type=props.get('event', 'Unknown'),
                            severity=props.get('severity', 'Unknown'),
                            title=props.get('headline', 'Weather Alert'),
                            description=props.get('description', ''),
                            location=props.get('areaDesc', 'Regional'),
                            updated_at=datetime.utcnow()
                        ))
                        added += 1

                session.commit()
                logger.debug(f"NWS ({area_str}) Sync complete. Added {added}, updated {updated}.")
            else:
                logger.error(f"NWS API returned HTTP {response.status_code} for {area_str}")

        except Exception as e:
            session.rollback()
            logger.error(f"NWS Fetch Error for {area_str}: {e}", exc_info=True)


USGS_BOUNDS = {
    "ar": {"minlat": 33.0, "maxlat": 36.5, "minlon": -94.5, "maxlon": -89.6},
    "oos": {"minlat": 33.0, "maxlat": 37.5, "minlon": -95.5, "maxlon": -89.0}
}


def fetch_usgs_earthquakes(area_key, feed_name):
    bounds = USGS_BOUNDS.get(area_key, USGS_BOUNDS["ar"])
    start_time = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%d")

    url = (
        f"https://earthquake.usgs.gov/fdsnws/event/1/query?"
        f"format=geojson&starttime={start_time}&minmagnitude=2.0"
        f"&minlatitude={bounds['minlat']}&maxlatitude={bounds['maxlat']}"
        f"&minlongitude={bounds['minlon']}&maxlongitude={bounds['maxlon']}"
    )

    with SessionLocal() as session:
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (NOC_Fusion_Center)'}
            response = requests.get(url, headers=headers, timeout=20)

            if response.status_code == 200:
                data = response.json()
                save_geojson_to_db(session, feed_name, data)
                session.commit()
                count = len(data.get('features', []))
                logger.debug(f"USGS ({area_key}) Fetched {count} earthquakes.")
            else:
                logger.error(f"USGS API returned HTTP {response.status_code} for {area_key}")

        except Exception as e:
            session.rollback()
            logger.error(f"USGS Fetch Error for {area_key}: {e}")


def haversine_distance(lat1, lon1, lat2, lon2):
    R = 3959
    lat1_r, lat2_r = math.radians(lat1), math.radians(lat2)
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat/2)**2 + math.cos(lat1_r) * math.cos(lat2_r) * math.sin(dlon/2)**2
    c = 2 * math.asin(math.sqrt(a))
    return R * c


def check_earthquake_proximity(equake_data, distance_miles=50):
    from src.utils.risk_alert import send_alert, get_alert_recipients, build_eq_alert_email_body
    from src.services import get_cached_config, save_global_config

    if not equake_data or 'features' not in equake_data:
        return

    # Read previously alerted earthquake IDs
    sys_config = get_cached_config()
    try:
        alerted_ids = set(json.loads(sys_config.get('alerted_eq_ids', '[]')))
    except Exception:
        alerted_ids = set()

    with SessionLocal() as session:
        sites = session.query(MonitoredLocation).filter(
            MonitoredLocation.lat.isnot(None),
            MonitoredLocation.lon.isnot(None)
        ).all()

        new_alerts = []
        triggered_ids = []

        for f in equake_data['features']:
            props = f.get('properties', {})
            eq_id = f.get('id', '') or f"{props.get('time', '0')}_{props.get('place', 'unknown')}_{props.get('mag', 0)}"
            if eq_id in alerted_ids:
                continue

            mag = props.get('mag', 0)
            if mag < 2.5:
                continue

            coords = f.get('geometry', {}).get('coordinates', [0, 0, 0])
            eq_lon, eq_lat = coords[0], coords[1]
            place = props.get('place', 'Unknown')
            time_ms = props.get('time', 0)
            time_str = datetime.fromtimestamp(time_ms/1000, CENTRAL_TZ).strftime('%Y-%m-%d %H:%M') if time_ms else 'Unknown'
            depth = coords[2]

            hit = False
            for site in sites:
                if not site.lat or not site.lon:
                    continue
                dist = haversine_distance(eq_lat, eq_lon, site.lat, site.lon)
                if dist <= distance_miles:
                    new_alerts.append({
                        'site': site.name,
                        'site_type': site.loc_type,
                        'distance': round(dist, 1),
                        'mag': mag,
                        'place': place,
                        'depth': depth,
                        'time': time_str,
                        'lat': eq_lat,
                        'lon': eq_lon
                    })
                    hit = True

            if hit:
                triggered_ids.append(eq_id)

        if new_alerts:
            recipients = get_alert_recipients()
            if recipients:
                body = build_eq_alert_email_body(new_alerts)
                send_alert(recipients, f"NOC Alert: Earthquake Proximity Warning", body)
                logger.info(f"Earthquake alert sent for {len(new_alerts)} site proximities")

                # Persist alerted IDs so we never re-alert the same quake
                updated = alerted_ids | set(triggered_ids)
                save_global_config({'alerted_eq_ids': json.dumps(list(updated))})


def check_wildfire_proximity(distance_miles=5):
    """Email NOC_NOTIFY_EMAIL when an active NIFC fire reaches a site."""
    import os
    from shapely.geometry import Point, shape
    from src.services import get_active_wildfires
    from src.utils.mailer import send_alert_email

    recipient = os.environ.get("NOC_NOTIFY_EMAIL", "").strip()
    if not recipient:
        logger.warning("Wildfire proximity alert skipped: NOC_NOTIFY_EMAIL is not set")
        return

    payload = get_active_wildfires()
    if not isinstance(payload, dict):
        return
    incidents = payload.get("incidents", [])
    perimeters = payload.get("perimeters", [])
    if not incidents and not perimeters:
        return

    with SessionLocal() as db:
        sites = db.query(MonitoredLocation).filter(
            MonitoredLocation.lat.isnot(None), MonitoredLocation.lon.isnot(None)
        ).all()
        config = db.query(SystemConfig).first()
        try:
            alerted = set(json.loads(config.alerted_wildfire_ids or "[]")) if config else set()
        except (TypeError, ValueError):
            alerted = set()
        try:
            proximity_state = json.loads(config.wildfire_proximity_state or "{}") if config else {}
            if not isinstance(proximity_state, dict):
                proximity_state = {}
        except (TypeError, ValueError):
            proximity_state = {}

        matches = []
        perimeter_names = set()
        closest_sites = {}
        for perimeter in perimeters:
            name = str(perimeter.get("name") or "Unknown Fire")
            perimeter_names.add(name.strip().upper())
            geometry = perimeter.get("geometry")
            if not geometry:
                continue
            try:
                fire_shape = shape(geometry)
            except Exception:
                logger.warning("Skipping invalid NIFC perimeter for %s", name, exc_info=True)
                continue
            fire_id = str(perimeter.get("irwin_id") or name).strip()
            for site in sites:
                # One degree of latitude is approximately 69 miles. This is
                # conservative for the Arkansas operating area and evaluates
                # the perimeter itself, not just its incident centroid.
                distance = fire_shape.distance(Point(float(site.lon), float(site.lat))) * 69.0
                nearest = closest_sites.setdefault(name, [])
                if not nearest or distance < nearest[0][0] - 0.1:
                    closest_sites[name] = [(distance, site.name)]
                elif abs(distance - nearest[0][0]) <= 0.1:
                    nearest.append((distance, site.name))
                alert_key = f"{fire_id}:{site.id}"
                previous = proximity_state.get(alert_key, {})
                last_alert_distance = previous.get("last_alert_distance")
                if distance <= distance_miles and (
                    alert_key not in alerted or
                    last_alert_distance is None or
                    float(last_alert_distance) - distance >= 0.5
                ):
                    matches.append((alert_key, name, distance, perimeter, site.name, bool(alert_key in alerted)))
                proximity_state[alert_key] = {
                    "last_seen_distance": round(distance, 3),
                    "last_alert_distance": last_alert_distance,
                }

        # The map uses perimeter geometry as authoritative. Point incidents
        # are only eligible when the perimeter feed returned no polygons.
        for incident in (incidents if not perimeters else []):
            name = str(incident.get("name") or "Unknown Fire")
            if name.strip().upper() in perimeter_names:
                continue
            if incident.get("lat") is None or incident.get("lon") is None:
                continue
            fire_id = str(incident.get("irwin_id") or incident.get("unique_id") or name).strip()
            fire_point = Point(float(incident["lon"]), float(incident["lat"]))
            for site in sites:
                distance = fire_point.distance(Point(float(site.lon), float(site.lat))) * 69.0
                nearest = closest_sites.setdefault(name, [])
                if not nearest or distance < nearest[0][0] - 0.1:
                    closest_sites[name] = [(distance, site.name)]
                elif abs(distance - nearest[0][0]) <= 0.1:
                    nearest.append((distance, site.name))
                alert_key = f"{fire_id}:{site.id}"
                previous = proximity_state.get(alert_key, {})
                last_alert_distance = previous.get("last_alert_distance")
                if distance <= distance_miles and (
                    alert_key not in alerted or
                    last_alert_distance is None or
                    float(last_alert_distance) - distance >= 0.5
                ):
                    matches.append((alert_key, name, distance, incident, site.name, bool(alert_key in alerted)))
                proximity_state[alert_key] = {
                    "last_seen_distance": round(distance, 3),
                    "last_alert_distance": last_alert_distance,
                }

        if not matches:
            if config:
                config.wildfire_proximity_state = json.dumps(proximity_state)
                db.commit()
            return

        def fmt_date(value):
            if not value:
                return "Unknown"
            try:
                return datetime.fromtimestamp(float(value) / 1000, CENTRAL_TZ).strftime("%Y-%m-%d %H:%M %Z")
            except (TypeError, ValueError, OSError):
                return str(value)

        lines = ["NOC WILDFIRE PROXIMITY ALERT", "", f"Active NIFC wildfire activity detected within {distance_miles} miles of a monitored site.", ""]
        for _, name, distance, details, site_name, previously_alerted in matches:
            encroaching = previously_alerted
            nearest = closest_sites.get(name, [])
            closest_text = ", ".join(f"{site} ({miles:.1f} mi)" for miles, site in nearest) or "Unknown"
            lines.extend([
                f"FIRE: {name}",
                f"ALERT TYPE: {'WARNING - FIRE ENCROACHING' if encroaching else 'INITIAL PROXIMITY ALERT'}",
                f"CLOSEST MONITORED SITE(S): {closest_text}",
                f"MONITORED SITE: {site_name}", f"DISTANCE: {distance:.1f} miles",
                f"STATE: {details.get('state', 'Unknown')}", f"COUNTY: {details.get('county', 'Unknown')}",
                f"STARTED: {fmt_date(details.get('started'))}",
                f"ACRES: {details.get('acres', details.get('perimeter_acres', 'Unknown'))}",
                f"MAPPED ACRES: {details.get('perimeter_acres', details.get('acres', 'Unknown'))}",
                f"CONTAINMENT: {details.get('contained', 'Unknown')}%",
                f"CAUSE: {details.get('cause', 'Unknown')}",
                f"PERIMETER UPDATED: {fmt_date(details.get('perimeter_updated'))}",
                f"MAP METHOD: {details.get('map_method', 'Unknown')}", "",
            ])
        success, message = send_alert_email(
            "Wildfire Proximity Alert", "\n".join(lines), recipient_override=recipient, is_html=False
        )
        if success and config:
            for alert_key, _, distance, _, _, _ in matches:
                proximity_state[alert_key]["last_alert_distance"] = round(distance, 3)
            config.alerted_wildfire_ids = json.dumps(sorted(alerted | {match[0] for match in matches}))
            config.wildfire_proximity_state = json.dumps(proximity_state)
            db.commit()
            logger.info("Wildfire proximity alert sent for %d site matches", len(matches))
        elif not success:
            logger.warning("Wildfire proximity alert email failed: %s", message)


def fetch_regional_hazards():
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [
            executor.submit(fetch_spc_outlooks),
            executor.submit(fetch_nws_alerts_for_region, "AR", "nws_ar"),
            executor.submit(fetch_nws_alerts_for_region, "OK,MS,MO", "nws_oos"),
            executor.submit(fetch_usgs_earthquakes, "ar", "usgs_ar"),
        ]
        executor.submit(fetch_usgs_earthquakes, "oos", "usgs_oos")

        for f in concurrent.futures.as_completed(futures):
            try:
                f.result()
            except Exception as e:
                logger.error("infra_worker: parallel fetch error: %s", e)

    with SessionLocal() as db:
        usgs_ar = db.query(GeoJsonCache).filter_by(feed_name="usgs_ar").first()
        usgs_oos = db.query(GeoJsonCache).filter_by(feed_name="usgs_oos").first()
        if usgs_ar and usgs_ar.data:
            check_earthquake_proximity(usgs_ar.data, 50)
        if usgs_oos and usgs_oos.data:
            check_earthquake_proximity(usgs_oos.data, 50)
    check_wildfire_proximity(5)


if __name__ == "__main__":
    fetch_regional_hazards()
