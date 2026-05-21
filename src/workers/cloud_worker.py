import feedparser
import requests
from datetime import datetime, timedelta
import re
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
    if not any(k in text for k in ["maintenance", "scheduled", "upcoming", "update"]):
        return False
    if any(k in text for k in ["in progress", "started", "currently undergoing"]):
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
    delimiters = [' - ', ': ', ' | ']
    for delim in delimiters:
        if delim in clean_title:
            return clean_title.split(delim)[0].strip()
    if provider == "AWS": return "AWS Infrastructure"
    if provider == "Google Cloud": return "Google Cloud Platform"
    if provider == "Azure": return "Microsoft Azure"
    return "General/Multiple Services"


def fetch_cloud_outages():
    import logging
    logger = logging.getLogger(__name__)
    logger.info(f"Fetching status feeds from {len(CLOUD_FEEDS)} providers...")
    session = SessionLocal()
    added_count = 0
    resolved_count = 0
    filtered_count = 0
    failed_providers = []

    try:
        recent_cutoff = datetime.utcnow() - timedelta(days=7)

        for provider, url in CLOUD_FEEDS.items():
            try:
                response = requests.get(url, timeout=10)
                if response.status_code != 200:
                    raise Exception(f"HTTP {response.status_code}")

                feed = feedparser.parse(response.content)

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
                    resolved_keywords = ["[RESOLVED]", "RESOLVED", "OPERATIONAL", "COMPLETED", "MITIGATED"]
                    is_resolved = any(kw in text_to_check for kw in resolved_keywords)

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
                failed_providers.append(provider)
                logger.warning(f"Skipping {provider} due to timeout/error: {e}")
                continue

        purge_cutoff = datetime.utcnow() - timedelta(days=3)
        session.query(CloudOutage).filter(CloudOutage.is_resolved == True, CloudOutage.updated_at < purge_cutoff).delete()

        session.commit()

        summary = f"Added {added_count} new alerts. Marked {resolved_count} resolved. Filtered {filtered_count} future/foreign noise events."
        if failed_providers:
            summary += f" (Failed to reach: {', '.join(failed_providers)})"
        logger.info(summary)

    except Exception as e:
        logger.error(f"Critical failure in cloud worker: {e}")
        session.rollback()
    finally:
        session.close()


if __name__ == "__main__":
    fetch_cloud_outages()
