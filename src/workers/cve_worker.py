import requests
from datetime import datetime
from src.core.db import SessionLocal
from src.models.schema import CveItem

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_cisa_kev():
    import logging
    logger = logging.getLogger(__name__)
    logger.debug("Fetching latest CISA KEV catalog...")

    try:
        response = requests.get(CISA_KEV_URL, timeout=30)
        response.raise_for_status()
        data = response.json()

        vulnerabilities = data.get('vulnerabilities', [])
        added_count = 0

        with SessionLocal() as session:
            incoming_ids = list(dict.fromkeys(
                vuln.get("cveID") for vuln in vulnerabilities if vuln.get("cveID")
            ))
            existing_ids = set()
            # Query only the IDs in this CISA response; the catalog grows over time.
            for offset in range(0, len(incoming_ids), 500):
                id_chunk = incoming_ids[offset:offset + 500]
                existing_ids.update(
                    row[0] for row in session.query(CveItem.cve_id)
                    .filter(CveItem.cve_id.in_(id_chunk)).all()
                )
            logger.debug("cve_worker: %d of %d incoming CVEs already exist", len(existing_ids), len(incoming_ids))

            batch = []
            for vuln in vulnerabilities:
                cve_id = vuln.get('cveID')
                if not cve_id or cve_id in existing_ids:
                    continue

                date_added_str = vuln.get('dateAdded')
                date_added = datetime.strptime(date_added_str, '%Y-%m-%d') if date_added_str else datetime.utcnow()

                batch.append(CveItem(
                    cve_id=cve_id,
                    vendor=vuln.get('vendorProject', 'Unknown'),
                    product=vuln.get('product', 'Unknown'),
                    vulnerability_name=vuln.get('vulnerabilityName', 'Unknown'),
                    date_added=date_added,
                    description=vuln.get('shortDescription', ''),
                    required_action=vuln.get('requiredAction', ''),
                    due_date=vuln.get('dueDate', '')
                ))
                existing_ids.add(cve_id)

            if batch:
                session.add_all(batch)
                added_count = len(batch)

            session.commit()
            logger.info(f"Success! Added {added_count} new exploited vulnerabilities.")

    except Exception as e:
        logger.error(f"Failed to fetch or parse KEV data: {e}")


if __name__ == "__main__":
    fetch_cisa_kev()
