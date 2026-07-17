import logging
import re
from collections import Counter

logger = logging.getLogger(__name__)

CATEGORIES = {
    "Cyber: Exploits & Vulns": (
        r'\b(cve-\d{4}-\d+|cve-\d{4}|zero-day|0-day|vulnerab|exploit|patch\s+management|buffer overflow|'
        r'rce|remote code execution|privilege escalation|bypass|sql injection|xss|cross-site|'
        r'use.after.free|heap overflow|stack overflow|out.of.bounds|injection|code injection|'
        r'command injection|path traversal|ssrf|xxe|deserialization|authentication bypass|'
        r'write.up|exploit code|proof of concept|poc exploit|in the wild|actively exploited|'
        r'kev\b|known exploited|attack vector|attack surface|cvss|severity.*critical|severity.*high|'
        r'patch.*available|patch tuesday|emergency patch|hotfix|security update|security advisory|'
        r'security bulletin|advisory\b|vendora?dvisory|microsoft.*patch|cisco.*patch|paloalto.*patch|'
        r'fortinet.*patch|vmware.*patch|citrix.*patch|apache.*patch|openssl.*patch)'
    ),
    "Cyber: Malware & Threats": (
        r'\b(malware|ransomware|botnet|trojan|spyware|keylogger|phishing|spearphish|whaling|'
        r'apt\d+|apt\s+\d+|threat\s+actor|advanced persistent|dark\s+web|darknet|'
        r'breach|data\s+breach|exfiltration|data\s+leak|data\s+exposure|credential\s+stuffing|'
        r'lockbit|blackcat|alphv|cl0p|play\s+ransom|black\s+basta|akira|royal|black\s+cat|'
        r'conti|revil|ryuk|maze|darkside|darkside|hive\b|royal\s+malware|'
        r'cobalt\s+strike|mimikatz|metasploit|empire|brute\s+ratel|sliver|'
        r'malvertising|drive.by|watering\s+hole|supply\s+chain.*compromise|'
        r'info-stealer|infostealer|stealer|redline|raccoon|vidar|'
        r'ddos|denial.of.service|botnet.*attack|volumetric|amplification|'
        r'backdoor|webshell|web\s+shell|c2\b|c&c|command.and.control|'
        r'cryptojack|cryptominer|crypto.*mining|xmrig|'
        r'defacement|website.*hack|website.*deface|'
        r'wiper|shamoon|notpetya|wannacry|hermetic|'
        r'malware.*campaign|malware.*strain|malware.*variant|malware.*family|'
        r'phishing.*campaign|phishing.*kit|phishing.*lure|'
        r'threat.*intel|threat.*landscape|threat.*report|threat.*brief|'
        r'adversary|offensive|tactic.*technique|ttp|mitre.*attack|'
        r'ioc\b|indicators?\s+of\s+compromise|hash.*malware|yara|sigma)'
    ),
    "ICS/OT & SCADA": (
        r'\b(scada|ics[-\s]?cert|industrial\s+control|ics[-\s]scada|operational\s+technology|'
        r'modbus|dnp3|opc[-\s]?ua|bacnet|ethercat|profinet|iec\s+61850|iec\s+62443|'
        r'plc|programmable\s+logic|rtu|remote\s+terminal|hmi|human.machine|'
        r'stuxnet|triton|trisis|industroyer|incontroller|'
        r'bes\b|bulk\s+electric|smart\s+grid|substation|power\s+grid|electric\s+grid|'
        r'transmission\s+line|distribution\s+line|power\s+plant|generation\s+station|'
        r'oil\s+pipeline|gas\s+pipeline|liquified|lng|natural\s+gas.*infrastructure|'
        r'water\s+treatment|wastewater|water\s+utility|water\s+plant|'
        r'nuclear\s+plant|nuclear\s+facility|nrc\b|'
        r'ics.*vulnerab|ot.*vulnerab|scada.*attack|ics.*attack|'
        r'control\s+system|process\s+control|distributed\s+control|dcs\b|'
        r'safety\s+instrumented|sis\b|emergency\s+shutdown|'
        r'oil\s*&?\s*gas|oil\s+and\s+gas|petroleum|refinery|pipeline|'
        r'electric|power\s+utility|power\s+company|energy\s+grid|'
        r'telecom|communications?\s+infrastructure|cell\s+tower|'
        r'water\s+infrastructure|critical\s+infrastructure|ci\s+sector|'
        r'noaa|nws|usgs.*earthquake|fema|homeland\s+security|dhs)'
    ),
    "Cloud & IT Infrastructure": (
        r'\b(aws|amazon\s+web\s+services|azure|microsoft\s+cloud|gcp|google\s+cloud|'
        r'cloud\s+outage|cloud\s+disruption|cloud\s+service.*down|'
        r'bgp|border\s+gateway|route\s+leak|route\s+hijack|prefix\s+hijack|'
        r'dns\s+(?:attack|failure|poisoning|tunneling|infrastructure)|'
        r'cloudflare|akamai|fastly|cdn\s+(?:attack|outage)|'
        r'solarwinds|solar\s+winds|fireeye|mandiant|'
        r'active\s+directory|azure\s+ad|entra\s+id|okta|'
        r'vmware|esxi|vsphere|hyper.v|kubernetes|docker|container|'
        r'cisco\s+(?:ios|asa|firepower|meraki|umbrella)|'
        r'fortinet|fortigate|fortiguard|palo\s+alto|panos|'
        r'juni?per|sophos|checkpoint|watchguard|'
        r'microsoft\s+(?:exchange|office|365|defender|teams|sharepoint)|'
        r'linux|windows\s+server|red\s+hat|ubuntu|debian|centos|'
        r'oracle|mysql|postgresql|sql\s+server|mongodb|redis|'
        r'aws\s+(?:s3|ec2|rds|lambda|iam)|'
        r'sase|sd.wan|zero\s+trust|sase\b|'
        r'internet\s+outage|service\s+outage|service\s+degradation|'
        r'network\s+(?:outage|failure|disruption)|'
        r'it\s+(?:outage|infrastructure|system|environment)|'
        r'server\s+(?:outage|crash|failure)|'
        r'api\s+(?:outage|failure|vulnerab)|'
        r'certificate\s+(?:expire|revok|ssl|tls)|'
        r'microsoft\s+patch|patch\s+tuesday)'
    ),
    "Physical Security & Crime": (
        r'\b(vandalism|sabotage|active\s+shooter|active\s+gunman|'
        r'trespass|trespassing|unauthorized\s+access|break.in|'
        r'drone\s+(?:sighting|intrusion|threat)|'
        r'cut\s+fiber|fiber\s+(?:cut|optic)|copper\s+theft|cable\s+theft|'
        r'perimeter\s+(?:breach|violation|intrusion)|'
        r'arson|fire.*set.*intentional|fire.*sabotage|'
        r'surveillance|security\s+(?:camera|footage|breach)|'
        r'guard|security\s+personnel|armed\s+guard|'
        r'bomb\s+(?:threat|suspicious|package)|'
        r'protest.*infrastructure|civil\s+unrest.*infrastructure|'
        r'shoot|gunman|gunfire|weapon|'
        r'power\s+(?:outage|failure|line\s+down)|'
        r'crime|criminal|vandal|burglary|theft|larceny|'
        r'suspicious\s+(?:package|activity|person|vehicle)|'
        r'law\s+enforcement|police|fbi\s+(?:investigation|raid|search)|'
        r'arrest|indictment|charged\s+with|convicted|'
        r'physical\s+security|facility\s+security|site\s+security|'
        r'access\s+control|badge|credential.*physical|'
        r'incident\s+report|security\s+incident|'
        r'terrorism|terrorist|extremism|extremist|domestic\s+terrorism|'
        r'infrastructure\s+(?:attack|threat|sabotage|damage)|'
        r'bombing|explosion|detonat|'
        r'workplace\s+violence|insider\s+threat.*physical)'
    ),
    "Severe Weather & Natural Hazards": (
        r'\b(tornado|hurricane|typhoon|cyclone|tropical\s+(?:storm|depression|cyclone)|'
        r'flood|flash\s+flood|river\s+flood|coastal\s+flood|storm\s+surge|'
        r'wildfire|brush\s+fire|forest\s+fire|grass\s+fire|'
        r'earthquake|seismic|aftershock|richter|magnitude\s+\d|'
        r'tsunami|landslide|mudslide|avalanche|'
        r'nws|national\s+weather|spc|storm\s+prediction|'
        r'convective|derecho|microburst|downburst|'
        r'blizzard|winter\s+storm|ice\s+storm|freezing\s+rain|sleet|'
        r'heat\s+wave|extreme\s+heat|heat\s+index|'
        r'cold\s+wave|wind\s+chill|freeze|frost|'
        r'lightning\s+(?:strike|storm)|hail|hailstorm|'
        r'drought|dust\s+storm|sandstorm|'
        r'power\s+outage.*storm|power\s+outage.*weather|'
        r'storm\s+damage|storm\s+surge|'
        r'emergency\s+declaration|state\s+of\s+emergency|'
        r'evacuation|mandatory\s+evacuation|shelter.in.place|'
        r'red\s+flag\s+warning|tornado\s+watch|tornado\s+warning|'
        r'hurricane\s+(?:watch|warning)|winter\s+storm\s+(?:watch|warning)|'
        r'flood\s+(?:watch|warning|advisory)|'
        r'severe\s+(?:thunderstorm|weather)|'
        r'meteorolog|weather\s+(?:forecast|alert|advisory|update)|'
        r'regional\s+(?:hazard|weather|climate))'
    ),
    "Geopolitics & Policy": (
        r'\b(sanctions?\b|OFAC|trade\s+sanctions|economic\s+sanctions|'
        r'nation.state|state.sponsored|state.actor|foreign\s+(?:actor|adversary|threat)|'
        r'cisa\b|cybersecurity.*infrastructure|'
        r'nsa\b|national\s+security|cybercom|us\s+cyber\s+command|'
        r'fbi\s+(?:cyber|investigation|warning)|'
        r'legislation|congress|senate|house\s+of\s+representatives|'
        r'executive\s+order|white\s+house|'
        r'nerc\s+cip|ferc\b|epa\b|osha\b|fcc\b|sec\b|'
        r'compliance|regulation|regulatory|mandate|'
        r'government.*(?:cyber|security|infrastructure)|'
        r'intelligence\s+(?:community|report|brief|assessment)|'
        r'cia\b|odi|intelligence\s+(?:agency|officer)|'
        r'nato\b|eu\b|european\s+union|un\b|united\s+nations|'
        r'trade\s+war|geopolit|geopolitical|'
        r'espionage|spying|intelligence\s+operation|'
        r'foreign\s+(?:policy|relation|interference)|'
        r'election\s+(?:security|integrity|interference)|'
        r'supply\s+chain\s+(?:risk|security|disruption)|'
        r'tariff|import\s+ban|export\s+control|'
        r'conflict|warfare|military|defense.*appropriat|'
        r'taiwan|china|russia|iran|north\s+korea|'
        r'ukraine|middle\s+east|'
        r'defense\s+(?:bill|act|budget|authorization)|'
        r'cyber\s+(?:strategy|policy|doctrine)|'
        r'infrastructure\s+(?:bill|investment|law|act)|'
        r'executive\s+order.*cyber|executive\s+order.*security)'
    ),
    "AI & Emerging Tech": (
        r'\b(artificial\s+intelligence|machine\s+learning|deep\s+learning|'
        r'llm|large\s+language\s+model|chatgpt|openai|gpt.?\d|claude|gemini|'
        r'generative\s+ai|gen\s*ai|foundation\s+model|'
        r'deepfake|deep\s+fake|synthetic\s+(?:media|content|voice)|'
        r'quantum\s+(?:computing|cryptograph|resistant|safe)|'
        r'blockchain|bitcoin|ethereum|cryptocurrency|crypto\b|'
        r'ransomware.*ai|ai.*ransomware|ai.*threat|ai.*attack|'
        r'automation|autonomous|robot|robotics|'
        r'5g\b|6g\b|edge\s+computing|iot\b|internet\s+of\s+things|'
        r'biometric|facial\s+recognition|'
        r'augmented\s+reality|virtual\s+reality|'
        r'satellite\s+(?:communication|internet)|starlink|'
        r'neuromorphic|photonic|'
        r'ai\s+(?:security|safety|risk|regulation|governance)|'
        r'computer\s+vision|natural\s+language|speech\s+recognition|'
        r'cyber.*ai|ai.*cyber|ml.*security|security.*ml)'
    ),
    "Data Breach & Privacy": (
        r'\b(data\s+breach|data\s+leak|data\s+(?:exposure|compromise)|'
        r'personally\s+identifiable|pii\b|phi\b|hipaa\b|gdpr\b|'
        r'credential\s+(?:leak|dump|stuffing|compromise)|'
        r'password\s+(?:dump|leak|breach)|'
        r'database\s+(?:breach|leak|exposed|compromised)|'
        r'million\s+records?|billion\s+records?|'
        r'customer\s+data|user\s+data|patient\s+data|'
        r'identity\s+(?:theft|fraud|compromise)|'
        r'financial\s+(?:data|records?|information).*breach|'
        r'class.action|lawsuit.*data|settlement.*breach|'
        r'notification.*breach|breach.*notification|'
        r'fcc.*fine|sec.*fine|ftc.*fine|state\s+attorney|'
        r'privacy\s+(?:violation|breach|incident|concern)|'
        r'doxing|doxxing|'
        r'ransomware.*data|double\s+extortion)'
    ),
}

COMPILED_CATEGORIES = {cat: re.compile(pattern, re.IGNORECASE | re.VERBOSE) for cat, pattern in CATEGORIES.items()}


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
    logger.debug("categorize_text: top_category=%s score=%d all_scores=%s",
                 top_category, scores[top_category], dict(scores))
    return top_category
