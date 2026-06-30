import logging
import re
from collections import Counter

logger = logging.getLogger(__name__)

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

COMPILED_CATEGORIES = {cat: re.compile(pattern, re.IGNORECASE) for cat, pattern in CATEGORIES.items()}

def categorize_text(text):
    if not text:
        logger.debug("categorize_text: empty text, returning General")
        return "General"

    scores = Counter()

    for cat, pattern in COMPILED_CATEGORIES.items():
        matches = pattern.findall(text)
        if matches:
            scores[cat] += len(matches)
            logger.debug("categorize_text: category=%s matches=%d", cat, len(matches))

    if not scores:
        logger.debug("categorize_text: no categories matched, returning General")
        return "General"

    top_category = scores.most_common(1)[0][0]
    logger.debug("categorize_text: top_category=%s score=%d", top_category, scores[top_category])
    return top_category
