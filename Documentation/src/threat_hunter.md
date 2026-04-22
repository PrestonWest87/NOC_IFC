# Enterprise Architecture & Functional Specification: `src/threat_hunter.py`

## 1. Executive Overview

The `src/threat_hunter.py` module acts as the **Automated Indicator of Compromise (IOC) Extraction Engine** for the Intelligence Fusion Center. Its primary purpose is to rapidly scan unstructured threat intelligence text (articles, summaries, alerts) and deterministically pull out actionable, structured artifacts—such as IP addresses, cryptographic hashes, Domains, and MITRE ATT&CK techniques.

By executing entirely via pre-compiled Regular Expressions (Regex) rather than relying on an LLM, this module operates at extreme speed with minimal CPU overhead, making it perfectly suited to run inside the multiprocessing ingestion pipeline. The output feeds the Global IOC Matrix, enabling analysts to pivot directly from an intelligence article into external OSINT tools (e.g., VirusTotal, Shodan).

---

## 2. Data Normalization: The Refanging Pipeline

Cybersecurity analysts and intelligence feeds intentionally "defang" malicious indicators to prevent accidental clicks or execution (e.g., replacing `http` with `hxxp` or `1.1.1.1` with `1.1.1[.]1`). However, automated SIEMs, firewalls, and OSINT APIs require the true string.

### `refang(text)`
This function acts as a pre-processor, executing string replacements to sanitize the text back to a machine-readable format *before* the regex engine evaluates it.
* **Transforms:**
  * `[.]`, `(.)`, `{.} ` $\rightarrow$ `.`
  * `hxxp`, `HXXP` $\rightarrow$ `http`, `HTTP`
  * `[@]` $\rightarrow$ `@`

---

## 3. Core Extraction Engine: Regex Taxonomy

To maximize performance, the module pre-compiles all Regex objects (`re.compile`) into memory at initialization.

### Tracked Artifact Vectors
* **Network Infrastructure:**
  * `REGEX_IPV4`: Strict bounds checking to ensure valid IPv4 octet ranges (0-255).
  * `REGEX_DOMAIN`: Identifies fully qualified domain names (FQDNs) belonging to standard Top-Level Domains (.com, .org, .ru, .cn), carefully bounded to ignore end-of-sentence punctuation false positives.
  * `REGEX_URL`: Extracts full HTTP/HTTPS/FTP paths.
* **Cryptographic Hashes:**
  * `REGEX_SHA256`: Matches exactly 64 hexadecimal characters.
  * `REGEX_SHA1`: Matches exactly 40 hexadecimal characters.
  * `REGEX_MD5`: Matches exactly 32 hexadecimal characters.
* **Contextual Classifiers:**
  * `REGEX_CVE`: Matches MITRE Common Vulnerabilities and Exposures format (`CVE-YYYY-XXXX`).
  * `REGEX_MITRE`: Matches MITRE ATT&CK technique IDs, including sub-techniques (e.g., `T1059` or `T1059.001`).

---

## 4. False Positive Mitigation & Heuristics

Blindly extracting regex matches from IT articles results in massive database pollution (e.g., extracting "8.8.8.8" from a tutorial on DNS configuration and labeling it a threat). The module implements aggressive filtering to ensure only high-fidelity IOCs are saved.

### 4.1 Static Exclusions
* **`IGNORE_IPS`**: A predefined set of safe/ubiquitous IPs that are frequently mentioned in documentation (e.g., `127.0.0.1`, `8.8.8.8`, `1.1.1.1`, `255.255.255.255`).
* **`IGNORE_DOMAINS`**: A predefined set of benign domains (e.g., `example.com`, `google.com`, `github.com`, `mitre.org`).

### 4.2 Dynamic Internal Filtering: `is_private_ip(ip)`
This function evaluates an extracted IP address against IANA RFC 1918 (Private Address Space) and RFC 3927 (APIPA).
* **Filters:**
  * `10.x.x.x`
  * `172.16.x.x` through `172.31.x.x`
  * `192.168.x.x`
  * `169.254.x.x`
* **Purpose:** Ensures the system never flags internal, non-routable corporate subnets as external Indicators of Compromise.

---

## 5. Algorithmic Orchestration

### `extract_all_iocs(raw_text)`
This is the primary callable function exposed to the broader application.

**Execution Flow:**
1.  **Ingestion & Refanging:** Takes the raw article text and passes it through `refang()`.
2.  **State Management:** Initializes an empty `iocs` list for output and a `seen` set for deduplication.
3.  **Regex Application:** Sequentially applies every `findall()` regex operation against the refanged text.
4.  **Deduplication & Formatting:** Uses the internal `add_ioc()` helper function. If an artifact is found, it is evaluated against the `seen` set to ensure the same IP/Hash is not saved multiple times per article.
5.  **Output Structure:** Returns a standardized list of dictionaries (e.g., `[{"type": "IPv4", "value": "185.20.10.1"}, ...]`).

---

## 6. System Integration Context

Within the Intelligence Fusion Center ecosystem, this module is deeply integrated into the ingestion pipeline:
* **The Master Scheduler (`src/scheduler.py`):** Inside the `parse_and_score_feed()` multiprocessing child threads, every incoming RSS article is evaluated.
* **Threshold Gating:** To conserve database space, `extract_all_iocs()` is *only* triggered if an article achieves an AI/Keyword Threat Score $\ge$ 50 **AND** is NLP-categorized as "Cyber".
* **Database Target:** The resulting dictionaries are instantiated as `ExtractedIOC` objects and committed to the database via foreign-key relationships to the parent `Article`.
* **User Interface (`app.py`):** Drives the "Live Global IOC Matrix" in the Threat Hunting UI, generating immediate Virustotal and Shodan pivot links based on the `indicator_type`.

---

## 7. Complete Function Reference

| Function | Signature | Purpose |
|----------|----------|---------|
| `refang` | `(text) -> str` | Refang text |
| `is_private_ip` | `(ip) -> bool` | Check private IP |
| `extract_all_iocs` | `(raw_text) -> list` | Extract all IOCs |

### Constants

| Constant | Type | Description |
|----------|-----|-------------|
| `REGEX_IPV4` | `Pattern` | IPv4 regex |
| `REGEX_SHA256` | `Pattern` | SHA256 regex |
| `REGEX_SHA1` | `Pattern` | SHA1 regex |
| `REGEX_MD5` | `Pattern` | MD5 regex |
| `REGEX_CVE` | `Pattern` | CVE regex |
| `REGEX_EMAIL` | `Pattern` | Email regex |
| `REGEX_URL` | `Pattern` | URL regex |
| `REGEX_MITRE` | `Pattern` | MITRE regex |
| `REGEX_DOMAIN` | `Pattern` | Domain regex |
| `IGNORE_IPS` | `set` | Safe IPs |
| `IGNORE_DOMAINS` | `set` | Safe domains |

---

## 8. API Citations

| API / Service | Purpose | Documentation |
|---------------|---------|-------------|
| re | Regex | https://docs.python.org/3/library/re.html |
