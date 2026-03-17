import re

# Defanging/Refanging Helper
def refang(text):
    """Restores broken IOCs (e.g., 1.1.1[.]1 -> 1.1.1.1, hxxp -> http)"""
    if not text: return ""
    text = text.replace('[.]', '.').replace('(.)', '.').replace('{.}', '.')
    text = text.replace('hxxp', 'http').replace('HXXP', 'HTTP')
    text = text.replace('[@]', '@')
    return text

# Expanded, Pre-compiled Regex for Extreme Speed
REGEX_IPV4 = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
REGEX_SHA256 = re.compile(r'\b[A-Fa-f0-9]{64}\b')
REGEX_SHA1 = re.compile(r'\b[A-Fa-f0-9]{40}\b')
REGEX_MD5 = re.compile(r'\b[A-Fa-f0-9]{32}\b')
REGEX_CVE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
REGEX_EMAIL = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
REGEX_URL = re.compile(r'(?:https?|ftp):\/\/[\w/\-?=%.]+\.[\w/\-&?=%.]+')
REGEX_MITRE = re.compile(r'\bT\d{4}(?:\.\d{3})?\b') # Matches T1059 or T1059.001

# Strict domain regex to avoid matching sentence endings (e.g., "The end. The next...")
REGEX_DOMAIN = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|info|biz|co|us|uk|ru|cn|gov|edu|mil|int)\b', re.IGNORECASE)

# Common false positives to ignore
IGNORE_IPS = {'0.0.0.0', '127.0.0.1', '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '255.255.255.255'}
IGNORE_DOMAINS = {'example.com', 'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'github.com', 'mitre.org', 'nist.gov'}

def is_private_ip(ip):
    """Filters out internal routing IPs."""
    parts = ip.split('.')
    if parts[0] == '10': return True
    if parts[0] == '172' and 16 <= int(parts[1]) <= 31: return True
    if parts[0] == '192' and parts[1] == '168': return True
    if parts[0] == '169' and parts[1] == '254': return True
    return False

def extract_all_iocs(raw_text):
    """Scans text and returns a deduplicated list of dicts with IOCs."""
    if not raw_text: return []
    
    text = refang(raw_text)
    iocs = []
    seen = set()

    def add_ioc(ioc_type, value):
        if value not in seen:
            iocs.append({"type": ioc_type, "value": value})
            seen.add(value)

    for ip in REGEX_IPV4.findall(text):
        if ip not in IGNORE_IPS and not is_private_ip(ip):
            add_ioc("IPv4", ip)

    for sha in REGEX_SHA256.findall(text): add_ioc("SHA256", sha.lower())
    for sha1 in REGEX_SHA1.findall(text): add_ioc("SHA1", sha1.lower())
    for md5 in REGEX_MD5.findall(text): add_ioc("MD5", md5.lower())
    
    for cve in REGEX_CVE.findall(text): add_ioc("CVE", cve.upper())
    for mitre in REGEX_MITRE.findall(text): add_ioc("MITRE ATT&CK", mitre.upper())
    
    for email in REGEX_EMAIL.findall(text): add_ioc("Email", email.lower())
    for url in REGEX_URL.findall(text): add_ioc("URL", url)
    
    for domain in REGEX_DOMAIN.findall(text):
        domain_lower = domain.lower()
        if domain_lower not in IGNORE_DOMAINS:
            add_ioc("Domain", domain_lower)

    return iocs