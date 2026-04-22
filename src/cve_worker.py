import requests
from datetime import datetime
from database import SessionLocal, CveItem

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_cisa_kev():
    print("[CVE WORKER] Fetching latest CISA KEV catalog...")
    session = SessionLocal()
    
    try:
        response = requests.get(CISA_KEV_URL, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        vulnerabilities = data.get('vulnerabilities', [])
        added_count = 0
        
        for vuln in vulnerabilities:
            cve_id = vuln.get('cveID')
            
            # Check if we already have this CVE in the database
            exists = session.query(CveItem).filter_by(cve_id=cve_id).first()
            if not exists:
                # Convert the date string (YYYY-MM-DD) to a datetime object
                date_added_str = vuln.get('dateAdded')
                date_added = datetime.strptime(date_added_str, '%Y-%m-%d') if date_added_str else datetime.utcnow()
                
                new_cve = CveItem(
                    cve_id=cve_id,
                    vendor=vuln.get('vendorProject', 'Unknown'),
                    product=vuln.get('product', 'Unknown'),
                    vulnerability_name=vuln.get('vulnerabilityName', 'Unknown'),
                    date_added=date_added,
                    description=vuln.get('shortDescription', ''),
                    required_action=vuln.get('requiredAction', ''),
                    due_date=vuln.get('dueDate', '')
                )
                session.add(new_cve)
                added_count += 1
                
        session.commit()
        print(f"[OK] [CVE WORKER] Success! Added {added_count} new exploited vulnerabilities.")
        
    except Exception as e:
        print(f"[ERROR] [CVE WORKER] Failed to fetch or parse KEV data: {e}")
        session.rollback()
    finally:
        session.close()

if __name__ == "__main__":
    fetch_cisa_kev()