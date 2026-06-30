import requests
import uuid
import gc
import math
import logging
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from src.core.db import SessionLocal
from src.models.schema import RegionalHazard, GeoJsonCache, MonitoredLocation

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

    logger.info("fetch_spc_outlooks: fetching %d SPC outlooks", len(SPC_URLS))
    with SessionLocal() as session:
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (NOC_Fusion_Center)'}
            for feed_name, url in SPC_URLS.items():
                logger.debug("fetch_spc_outlooks: fetching %s from %s", feed_name, url)
                response = requests.get(url, headers=headers, timeout=15)
                if response.status_code == 200:
                    save_geojson_to_db(session, feed_name, response.json())
                    logger.info(f"Downloaded and cached {feed_name} GeoJSON to DB.")
                else:
                    logger.error(f"Failed to fetch {feed_name}. HTTP {response.status_code}")
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"SPC Fetch Error: {e}", exc_info=True)


def fetch_nws_alerts_for_region(area_str, feed_name):
    logger.info("fetch_nws_alerts_for_region: area=%s feed=%s", area_str, feed_name)
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
                logger.info(f"NWS ({area_str}) Sync complete. Added {added}, updated {updated}.")
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
                logger.info(f"USGS ({area_key}) Fetched {count} earthquakes.")
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

    if not equake_data or 'features' not in equake_data:
        return

    with SessionLocal() as session:
        sites = session.query(MonitoredLocation).filter(
            MonitoredLocation.lat.isnot(None),
            MonitoredLocation.lon.isnot(None)
        ).all()

        new_alerts = []
        for f in equake_data['features']:
            props = f.get('properties', {})
            mag = props.get('mag', 0)
            if mag < 2.5:
                continue

            coords = f.get('geometry', {}).get('coordinates', [0, 0, 0])
            eq_lon, eq_lat = coords[0], coords[1]
            place = props.get('place', 'Unknown')
            time_ms = props.get('time', 0)
            time_str = datetime.fromtimestamp(time_ms/1000, CENTRAL_TZ).strftime('%Y-%m-%d %H:%M') if time_ms else 'Unknown'
            depth = coords[2]

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

        if new_alerts:
            recipients = get_alert_recipients()
            if recipients:
                body = build_eq_alert_email_body(new_alerts)
                send_alert(recipients, f"NOC Alert: Earthquake Proximity Warning", body)
                logger.info(f"Earthquake alert sent for {len(new_alerts)} site proximities")


def fetch_regional_hazards():
    fetch_spc_outlooks()
    fetch_nws_alerts_for_region("AR", "nws_ar")
    fetch_nws_alerts_for_region("OK,MS,MO", "nws_oos")
    fetch_usgs_earthquakes("ar", "usgs_ar")
    fetch_usgs_earthquakes("oos", "usgs_oos")

    with SessionLocal() as db:
        usgs_ar = db.query(GeoJsonCache).filter_by(feed_name="usgs_ar").first()
        usgs_oos = db.query(GeoJsonCache).filter_by(feed_name="usgs_oos").first()
        if usgs_ar and usgs_ar.data:
            check_earthquake_proximity(usgs_ar.data, 50)
        if usgs_oos and usgs_oos.data:
            check_earthquake_proximity(usgs_oos.data, 50)

    gc.collect()


if __name__ == "__main__":
    fetch_regional_hazards()
