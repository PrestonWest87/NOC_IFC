import feedparser
import requests
from datetime import datetime, timedelta
import re
import concurrent.futures
from src.core.db import SessionLocal
from src.models.schema import CloudOutage

CLOUD_FEEDS = {
    "AWS": "https://status.aws.amazon.com/rss/all.rss",
    "Google Cloud": "https://status.cloud.google.com/en/feed.atom",
    "Azure": "https://azurestatuscdn.azureedge.net/en-us/status/feed/",
    "Cisco Umbrella": "https://status.umbrella.com/history.rss",
    "Cisco Webex": "https://status.webex.com/history.rss",
    "Cisco Meraki": "https://status.meraki.net/history.rss",
    "Cloudflare": "https://www.cloudflarestatus.com/history.rss",
    "GitHub": "https://www.githubstatus.com/history.rss",
    "Slack": "https://status.slack.com/feed/rss",
    "Zoom": "https://status.zoom.us/history.rss",
    "Atlassian": "https://developer.status.atlassian.com/history.rss",
    "Datadog": "https://status.datadoghq.com/history.rss",
    "PagerDuty": "https://status.pagerduty.com/history.rss",
    "Twilio": "https://status.twilio.com/history.rss",
    "Okta": "https://status.okta.com/history.rss",
    "Zscaler": "https://trust.zscaler.com/feed",
    "CrowdStrike": "https://status.crowdstrike.com/history.rss",
    "Mimecast": "https://status.meraki.net/history.rss"
}

US_REGIONS = {
    "us-east-1": "US-East (N. Virginia)", "us-east-2": "US-East (Ohio)",
    "us-west-1": "US-West (N. California)", "us-west-2": "US-West (Oregon)",
    "eastus": "US-East (Virginia)", "eastus2": "US-East (Virginia)",
    "westus": "US-West (California)", "westus2": "US-West (Washington)",
    "centralus": "US-Central (Iowa)", "southcentralus": "US-South Central (Texas)",
    "us-central1": "US-Central (Iowa)", "us-east1": "US-East (S. Carolina)",
    "us-east4": "US-East (N. Virginia)", "us-west1": "US-West (Oregon)",
    "us-west2": "US-West (Los Angeles)", "us-south1": "US-South (Texas)"
}

FOREIGN_IDENTIFIERS = [
    "eu-", "ap-", "sa-", "af-", "me-", "ca-",
    "europe", "asia", "africa", "south america", "canada", "australia",
    "tokyo", "seoul", "mumbai", "singapore", "sydney", "london", "frankfurt",
    "paris", "ireland", "sao paulo", "bahrain", "cape town", "hong kong", "dublin"
]

_RESOLVED_KEYWORDS = ("[RESOLVED]", "RESOLVED", "OPERATIONAL", "COMPLETED", "MITIGATED")
_MAINTENANCE_KEYWORDS = ("maintenance", "scheduled", "upcoming", "update")
_MAINTENANCE_ACTIVE = ("in progress", "started", "currently undergoing")
_RESOLVED_RE = re.compile(r'\b(' + '|'.join(re.escape(k) for k in FOREIGN_IDENTIFIERS) + r')\b', re.IGNORECASE)
_US_RE = re.compile(r'\bus-|united states|north america|global|all regions\b', re.IGNORECASE)
_US_EXTRACT_RE = re.compile(r'us-|united states|north america', re.IGNORECASE)
_TITLE_SPLIT_RE = re.compile(r'\s*(?: - |: \| |\| )\s*')


def is_foreign_region(text):
    text_lower = text.lower()
    for f in FOREIGN_IDENTIFIERS:
        if re.search(r'\b' + re.escape(f), text_lower):
            if not any(us in text_lower for us in ["us-", "united states", "north america", "global", "all regions"]):
                return True
    return False


def extract_us_regions(text):
    text_lower = text.lower()
    affected = set()
    for key, display in US_REGIONS.items():
        if key in text_lower:
            affected.add(display)
    if not affected and any(w in text_lower for w in ["us-", "united states", "north america"]):
        affected.add("US-General / Multi-Region")
    return list(affected)


def is_future_maintenance(title, description):
    text = (title + " " + description).lower()
    if not any(k in text for k in _MAINTENANCE_KEYWORDS):
        return False
    if any(k in text for k in _MAINTENANCE_ACTIVE):
        return False
    now = datetime.utcnow()
    today_formats = [
        now.strftime("%b %d").lower(),
        now.strftime("%B %d").lower(),
        now.strftime("%Y-%m-%d"),
        now.strftime("%m/%d/%Y")
    ]
    if any(fmt in text for fmt in today_formats):
        return False
    return True


def extract_service_name(provider, title):
    clean_title = title.replace("[Investigating]", "").replace("[Resolved]", "").replace("[Update]", "").strip()
    parts = _TITLE_SPLIT_RE.split(clean_title, maxsplit=1)
    if len(parts) > 1:
        return parts[0].strip()
    if provider == "AWS": return "AWS Infrastructure"
    if provider == "Google Cloud": return "Google Cloud Platform"
    if provider == "Azure": return "Microsoft Azure"
    return "General/Multiple Services"


def _fetch_single_feed(provider_url_pair):
    """Fetch a single RSS feed. Returns (provider, content, error)."""
    provider, url = provider_url_pair
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            return provider, None, f"HTTP {response.status_code}"
        return provider, response.content, None
    except requests.Timeout:
        return provider, None, "timeout"
    except Exception as e:
        return provider, None, str(e)


def fetch_cloud_outages():
    import logging
    logger = logging.getLogger(__name__)
    logger.info(f"Fetching status feeds from {len(CLOUD_FEEDS)} providers...")
    added_count = 0
    resolved_count = 0
    filtered_count = 0
    failed_providers = []

    try:
        recent_cutoff = datetime.utcnow() - timedelta(days=7)

        # Phase 1: Parallel HTTP fetch
        feed_items = list(CLOUD_FEEDS.items())
        feed_results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(_fetch_single_feed, item): item[0] for item in feed_items}
            for future in concurrent.futures.as_completed(futures):
                provider, content, error = future.result()
                if error:
                    failed_providers.append(provider)
                    logger.warning("cloud_worker: error fetching %s: %s", provider, error)
                else:
                    feed_results[provider] = content

        # Phase 2: Process feeds sequentially (DB writes)
        with SessionLocal() as session:
            for provider, content in feed_results.items():
                try:
                    feed = feedparser.parse(content)
                    feed_entries = len(feed.entries)
                    logger.debug("cloud_worker: %s returned %d entries", provider, feed_entries)

                    for entry in feed.entries[:15]:
                        published_tuple = entry.get('published_parsed')
                        if published_tuple:
                            updated_at = datetime(*published_tuple[:6])
                        else:
                            updated_at = datetime.utcnow()

                        if updated_at < recent_cutoff:
                            continue

                        title = entry.get('title', 'Unknown Alert')
                        link = entry.get('link', '')
                        description = entry.get('summary', entry.get('description', ''))

                        if is_future_maintenance(title, description):
                            filtered_count += 1
                            continue

                        if is_foreign_region(title + " " + description):
                            filtered_count += 1
                            continue

                        text_to_check = (title + " " + description).upper()
                        is_resolved = any(kw in text_to_check for kw in _RESOLVED_KEYWORDS)

                        base_service = extract_service_name(provider, title)
                        us_impact = extract_us_regions(title + " " + description)
                        region_tag = f" [{', '.join(us_impact)}]" if us_impact else ""
                        final_service_name = f"{base_service}{region_tag}"

                        exists = session.query(CloudOutage).filter_by(
                            provider=provider,
                            title=title,
                            updated_at=updated_at
                        ).first()

                        if not exists:
                            new_outage = CloudOutage(
                                provider=provider,
                                service=final_service_name,
                                title=title,
                                description=description,
                                link=link,
                                is_resolved=is_resolved,
                                updated_at=updated_at
                            )
                            session.add(new_outage)
                            added_count += 1
                        else:
                            if is_resolved and not exists.is_resolved:
                                exists.is_resolved = True
                                exists.updated_at = updated_at
                                resolved_count += 1

                except Exception as e:
                    logger.warning("cloud_worker: error processing %s: %s", provider, e)
                    continue

            purge_cutoff = datetime.utcnow() - timedelta(days=3)
            deleted = session.query(CloudOutage).filter(CloudOutage.is_resolved == True, CloudOutage.updated_at < purge_cutoff).delete()
            logger.debug("cloud_worker: purged %d old resolved outages", deleted)

            session.commit()

        summary = f"Added {added_count} new alerts. Marked {resolved_count} resolved. Filtered {filtered_count} future/foreign noise events."
        if failed_providers:
            summary += f" (Failed to reach: {', '.join(failed_providers)})"
        logger.info(summary)

    except Exception as e:
        logger.error(f"Critical failure in cloud worker: {e}", exc_info=True)
