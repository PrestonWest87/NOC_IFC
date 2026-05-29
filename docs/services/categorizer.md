# Article Categorizer Documentation

**File:** `/home/weast/docker/NOC_IFC/src/services/categorizer.py`

---

## Constants

### `CATEGORIES` (dict)
Maps category names to regex patterns used for text classification:

| Category | Pattern |
|----------|---------|
| `Cyber: Exploits & Vulns` | CVE IDs, zero-day, vulnerability, exploit, patch, buffer overflow, RCE, privilege escalation, bypass |
| `Cyber: Malware & Threats` | malware, ransomware, botnet, trojan, spyware, keylogger, phishing, APT, threat actor, dark web, breach, exfiltration |
| `ICS/OT & SCADA` | scada, ics-cert, industrial control, modbus, dnp3, PLC, RTU, HMI, stuxnet, BES, bulk electric, smart grid, substation |
| `Cloud & IT Infra` | AWS, Azure, GCP, outage, BGP, route leak, DNS, Cloudflare, CDN, SolarWinds, Active Directory, VMware, Cisco, Fortinet |
| `Physical Security` | vandalism, sabotage, active shooter, trespass, drone, cut fiber, perimeter, unauthorized access, arson, copper theft |
| `Severe Weather` | tornado, hurricane, flood, wildfire, earthquake, tsunami, NWS, SPC, convective, derecho, blizzard |
| `Geopolitics & Policy` | sanctions, nation-state, CISA, NSA, FBI, legislation, congress, parliament, Cybercom, FCC, NERC, FERC |
| `AI & Emerging Tech` | artificial intelligence, LLM, ChatGPT, machine learning, deepfake, quantum, blockchain |

### `COMPILED_CATEGORIES` (dict)
Pre-compiled regex patterns compiled from `CATEGORIES` using `re.IGNORECASE`.

---

## Functions

### `categorize_text(text) -> str`

**Purpose:** Classifies a text string into a predefined category based on keyword matches.

**Parameters:**
- `text` (str) -- Input text to classify (typically concatenated title + summary)

**Returns:** `str` -- The best-matching category name, or `"General"` if no matches found.

**Flow:**
1. Returns `"General"` immediately if text is empty or None
2. Initializes a `Counter` for category scores
3. For each compiled category pattern, finds all regex matches in the text
4. Accumulates match count as score for the matching category
5. If no scores, returns `"General"`
6. Returns the category with the highest match count (`most_common(1)`)

**Dependencies:** `re`, `collections.Counter`
