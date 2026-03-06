import feedparser
from datetime import datetime, timedelta
from database import SessionLocal, CloudOutage

# ADDED AZURE STATUS FEED
CLOUD_FEEDS = {
    "AWS": "https://status.aws.amazon.com/rss/all.rss",
    "Google Cloud": "https://status.cloud.google.com/en/feed.atom",
    "Azure": "https://azurestatuscdn.azureedge.net/en-us/status/feed/",
    "Cisco Umbrella": "https://status.umbrella.com/history.rss",
    "Cisco Webex": "https://status.webex.com/history.rss"
}

def fetch_cloud_outages():
    print("☁️ [CLOUD WORKER] Fetching AWS, GCP, Azure, and Cisco status feeds...")
    session = SessionLocal()
    added_count = 0
    resolved_count = 0
    
    try:
        recent_cutoff = datetime.utcnow() - timedelta(days=7)
        
        for provider, url in CLOUD_FEEDS.items():
            feed = feedparser.parse(url)
            for entry in feed.entries:
                published_tuple = entry.get('published_parsed')
                if published_tuple:
                    updated_at = datetime(*published_tuple[:6])
                else:
                    updated_at = datetime.utcnow()
                    
                if updated_at < recent_cutoff:
                    continue 
                
                title = entry.get('title', 'Unknown Alert')
                link = entry.get('link', '')
                description = entry.get('description', '')
                
                is_resolved = False
                if "[RESOLVED]" in title.upper() or "RESOLVED" in description.upper():
                    is_resolved = True
                    
                service = "General/Multiple"
                if provider == "AWS":
                    service = title.split('-')[0].strip() if '-' in title else "AWS Service"
                elif provider == "Google Cloud":
                    service = "Google Cloud Platform"
                elif provider == "Azure":
                    service = "Microsoft Azure"
                    
                # Check for exact event duplication instead of relying on the URL
                exists = session.query(CloudOutage).filter_by(
                    provider=provider, 
                    title=title, 
                    updated_at=updated_at
                ).first()
                
                if not exists:
                    new_outage = CloudOutage(
                        provider=provider,
                        service=service,
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

        # Self-cleaning: Purge resolved incidents older than 3 days
        purge_cutoff = datetime.utcnow() - timedelta(days=3)
        session.query(CloudOutage).filter(CloudOutage.is_resolved == True, CloudOutage.updated_at < purge_cutoff).delete()
        
        session.commit()
        print(f"✅ [CLOUD WORKER] Added {added_count} new cloud alerts. Marked {resolved_count} as resolved.")
        
    except Exception as e:
        print(f"❌ [CLOUD WORKER] Failed to fetch cloud status: {e}")
        session.rollback()
    finally:
        session.close()

if __name__ == "__main__":
    fetch_cloud_outages()