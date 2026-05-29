# Threat Hunter Documentation

**File:** `/home/weast/docker/NOC_IFC/src/services/threat_hunter.py`

---

## Constants

### `IGNORE_IPS` (set)
Common benign IP addresses to skip during extraction:
- `0.0.0.0`, `127.0.0.1` (loopback)
- `8.8.8.8`, `8.8.4.4` (Google DNS)
- `1.1.1.1`, `1.0.0.1` (Cloudflare DNS)
- `255.255.255.255` (broadcast)

### `IGNORE_DOMAINS` (set)
Common benign domains to skip during extraction:
- `example.com`, `google.com`, `microsoft.com`, `apple.com`, `amazon.com`
- `github.com`, `mitre.org`, `nist.gov`

---

## Pre-compiled Regex Patterns

| Variable | Pattern | Purpose |
|----------|---------|---------|
| `REGEX_IPV4` | Standard IPv4 octet regex | Extracts public IPv4 addresses |
| `REGEX_SHA256` | 64 hex characters | SHA256 hash extraction |
| `REGEX_SHA1` | 40 hex characters | SHA1 hash extraction |
| `REGEX_MD5` | 32 hex characters | MD5 hash extraction |
| `REGEX_CVE` | `CVE-\d{4}-\d{4,7}` (case-insensitive) | CVE identifier extraction |
| `REGEX_EMAIL` | RFC-like email pattern | Email address extraction |
| `REGEX_URL` | http/https/ftp URL pattern | URL extraction |
| `REGEX_MITRE` | `T\d{4}(\.\d{3})?` | MITRE ATT&CK technique ID extraction |
| `REGEX_DOMAIN` | Standard domain with common TLDs | Domain name extraction |

---

## Functions

### `refang(text: str) -> str`

**Purpose:** De-obfuscates defanged indicators (simple version).

**Parameters:**
- `text` (str) -- Text containing defanged indicators

**Returns:** `str` -- Refanged text with indicators restored.

**Transformations:**
- `[.]`, `(.)`, `{.}` -> `.`
- `hxxp`/`HXXP` -> `http`/`HTTP`
- `[@]` -> `@`

---

### `is_private_ip(ip: str) -> bool`

**Purpose:** Checks if an IP address is in a private/reserved range using simple octet matching.

**Parameters:**
- `ip` (str) -- IPv4 address as dot-decimal string

**Returns:** `bool` -- True if the IP is private (10.x.x.x, 172.16-31.x.x, 192.168.x.x, 169.254.x.x).

**Flow:** Splits on `.` and checks:
- First octet == 10
- First octet == 172 and second octet between 16-31
- First octet == 192 and second octet == 168
- First octet == 169 and second octet == 254

---

### `extract_all_iocs(raw_text: str) -> list[dict]`

**Purpose:** Extracts all Indicators of Compromise (IOCs) from raw text using regex matching with deduplication.

**Parameters:**
- `raw_text` (str) -- Raw input text to extract IOCs from

**Returns:** `list[dict]` -- List of IOC dicts with keys:
- `type` (str) -- IOC type (IPv4, SHA256, SHA1, MD5, CVE, MITRE ATT&CK, Email, URL, Domain)
- `value` (str) -- The extracted indicator value

**Flow:**
1. Returns empty list if input is empty
2. Refangs the input text via `refang()`
3. For each IOC type regex:
   - **IPv4:** Filters out IGNORE_IPS and private IPs via `is_private_ip()`
   - **SHA256/SHA1/MD5:** Converts to lowercase
   - **CVE/MITRE ATT&CK:** Converts to uppercase
   - **Email:** Converts to lowercase
   - **Domain:** Converts to lowercase, filters IGNORE_DOMAINS
   - **URL:** Kept as-is
4. Deduplicates using a `seen` set to prevent duplicate IOCs
5. Returns the collected IOC list
