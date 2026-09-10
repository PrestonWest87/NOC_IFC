# Enterprise IOC Extractor Documentation

**File:** `/home/weast/docker/NOC_IFC/src/services/ioc_extractor.py`

---

## Class: `EnterpriseIOCExtractor`

**Purpose:** Enterprise-grade Indicator of Compromise (IOC) extraction engine that scans raw text for network indicators, host artifacts, actor infrastructure, cloud/DevOps artifacts, and threat taxonomy references.

### `__init__(self)`

**Purpose:** Initializes the extractor: compiles regex rulesets and loads whitelists.

**Flow:**
1. Sets `CONTEXT_WINDOW` to 45 characters
2. Calls `_compile_rulesets()` to build compiled regex patterns
3. Calls `_initialize_whitelists()` to populate ignore lists

---

### `_initialize_whitelists(self)`

**Purpose:** Initializes sets of domains and IPs to ignore during extraction (common benign infrastructure).

**Sets:**
- `ignore_domains` -- Major tech companies, security/mitre/gov references (example.com, google.com, microsoft.com, apple.com, github.com, mitre.org, etc.)
- `ignore_ips` -- DNS/anycast addresses (0.0.0.0, 255.255.255.255, Cloudflare 1.1.1.1, Google 8.8.8.8, etc.)

---

### `_compile_rulesets(self)`

**Purpose:** Defines and compiles all IOC extraction regex rules organized by category.

**Categories and Patterns:**

| Category | Type | Pattern |
|----------|------|---------|
| **Network** | IPv4 | Standard IPv4 octet regex |
| | IPv6 | 7-colon-1 hex block format |
| | URL | http/https/ftp/tcp/udp/ldap URLs |
| | Domain | Standard domain names with common TLDs |
| | Email | RFC-like email pattern |
| | ASN | Autonomous System Numbers (AS followed by 3-6 digits) |
| **Host Artifacts** | SHA256 | 64 hex characters |
| | SHA1 | 40 hex characters |
| | MD5 | 32 hex characters |
| | Registry Key | Windows registry paths (HKLM, HKCU, etc.) |
| | Windows Path | Drive-letter paths |
| | Linux Path | Absolute paths starting with /bin, /etc, /var, etc. |
| **Actor Infrastructure** | BTC Wallet | Bitcoin wallet addresses |
| | XMR Wallet | Monero wallet addresses |
| | Discord C2 | Discord webhook URLs |
| | Telegram C2 | Telegram bot API URLs |
| **Cloud & DevOps** | AWS API Key | AKIA-prefixed 20-char keys |
| | AWS S3 Bucket | S3 bucket Amazonaws URLs |
| | Azure Blob | Azure blob storage URLs |
| **Taxonomy** | CVE | CVE-YYYY-NNNNN pattern |
| | MITRE ATT&CK | T followed by 4 digits, optional .NNN |

All patterns are compiled with `re.IGNORECASE` and stored in `self.compiled_rules`.

---

### `refang_payload(self, text: str) -> str`

**Purpose:** De-obfuscates defanged indicators back to their original form.

**Parameters:**
- `text` (str) -- Text containing potentially defanged IOCs

**Returns:** `str` -- Refanged text.

**Transformations:**
- `hxxps://` and `hxxp://` -> `https://` and `http://`
- `fxp://` -> `ftp://`
- `[.]`, `(.)`, `{.}`, `[dot]`, `(dot)` -> `.`
- `[:]`, `(:)` -> `:`
- `[/]`, `(/)` -> `/`
- `[@]`, `(@)`, ` AT ` -> `@`
- ` DOT ` -> `.`

---

### `_is_valid_ip(self, ip_str: str) -> bool`

**Purpose:** Validates whether a string is a public, routable IP address.

**Parameters:**
- `ip_str` (str) -- IP address string

**Returns:** `bool` -- True if valid and public (not private, loopback, multicast, link-local, or reserved).

**Flow:** Checks ignore_ips set, then uses `ipaddress.ip_address()`. Rejects if private, loopback, multicast, link-local, or reserved. Returns False on `ValueError`.

---

### `_get_context(self, text: str, match: re.Match) -> str`

**Purpose:** Extracts surrounding context window around a matched IOC.

**Parameters:**
- `text` (str) -- Full source text
- `match` (re.Match) -- Regex match object

**Returns:** `str` -- Context string with 45 characters before and after the match, wrapped in `...`.

---

### `extract(self, raw_text: str) -> list[dict]`

**Purpose:** Main extraction method: scans raw text for all known IOC types.

**Parameters:**
- `raw_text` (str) -- Raw input text to scan

**Returns:** `list[dict]` -- List of IOC dictionaries with keys:
- `Category` (str) -- Category name (Network, Host Artifacts, etc.)
- `Type` (str) -- Indicator type (IPv4, SHA256, CVE, etc.)
- `Indicator` (str) -- The extracted indicator value
- `Context` (str) -- Surrounding context text

**Flow:**
1. Returns empty list if input is empty
2. Refangs the input text via `refang_payload()`
3. For each compiled ruleset category and type:
   - Iterates all regex matches in the refanged text
   - Deduplicates by lowercase value
   - For IPs: validates via `_is_valid_ip()`
   - For domains: checks ignore_domains, filters subdomain-of-URL duplicates
   - For hash/CVE/MITRE: converts to uppercase
   - For emails: converts to lowercase
   - Extracts surrounding context via `_get_context()`
4. Returns collected IOC dictionaries

---

## Module-Level Singleton

### `ioc_engine` (EnterpriseIOCExtractor)

A pre-initialized singleton instance of `EnterpriseIOCExtractor`, created at module load time for reuse across the application.

**Dependencies:** `re`, `ipaddress`, `urllib.parse.unquote`, `typing`
