import re
from collections import Counter

# ==========================================
# ENTERPRISE NOC/SOC ONTOLOGY
# ==========================================
# Grouped into highly specific operational domains
CATEGORIES = {
    "Cyber: Exploits & Vulns": r'\b(cve-\d{4}|zero-day|0-day|vulnerab|exploit|patch|buffer overflow|rce|privilege escalation|bypass)\b',
    
    "Cyber: Malware & Threats": r'\b(malware|ransomware|botnet|trojan|spyware|keylogger|phishing|apt\d+|threat actor|dark web|breach|exfiltration)\b',
    
    "ICS/OT & SCADA": r'\b(scada|ics-cert|industrial control|modbus|dnp3|plc|rtu|hmi|stuxnet|bes|bulk electric|smart grid|substation)\b',
    
    "Cloud & IT Infra": r'\b(aws|azure|gcp|outage|bgp|route leak|dns|cloudflare|cdn|solarwinds|active directory|vmware|cisco|fortinet)\b',
    
    "Physical Security": r'\b(vandalism|sabotage|active shooter|trespass|drone|cut fiber|perimeter|unauthorized access|arson|copper theft)\b',
    
    "Severe Weather": r'\b(tornado|hurricane|flood|wildfire|earthquake|tsunami|nws|spc|convective|derecho|blizzard)\b',
    
    "Geopolitics & Policy": r'\b(sanctions|nation-state|cisa|nsa|fbi|legislation|congress|parliament|cybercom|fcc|nerc|ferc)\b',
    
    "AI & Emerging Tech": r'\b(artificial intelligence|llm|chatgpt|machine learning|deepfake|quantum|blockchain)\b'
}

# Pre-compile regexes in memory once at startup for lightning-fast bulk processing
COMPILED_CATEGORIES = {cat: re.compile(pattern, re.IGNORECASE) for cat, pattern in CATEGORIES.items()}

def categorize_text(text):
    """
    Scoring-based categorizer. Evaluates the whole text against all categories 
    and assigns the one with the highest term-hit density, preventing miscategorization 
    from single off-topic words.
    """
    if not text: 
        return "General"
        
    scores = Counter()
    
    # Run the text through every regex pattern
    for cat, pattern in COMPILED_CATEGORIES.items():
        # findall() returns a list of all matches. We count the length of that list.
        matches = pattern.findall(text)
        if matches:
            scores[cat] += len(matches)
            
    # If no keywords matched from any category, default to General
    if not scores:
        return "General"
        
    # Return the category with the absolute highest keyword density
    top_category = scores.most_common(1)[0][0]
    return top_category
