# Enterprise Architecture & Functional Specification: `src/threat_hunter.py` *(Updated)*

## 1. Executive Overview

The `src/threat_hunter.py` module is the **Tier-1 Threat Intelligence Extraction Engine** for the Intelligence Fusion Center. In its latest architectural iteration, the module has been completely refactored from a procedural script into a highly optimized, Object-Oriented class: `EnterpriseIOCExtractor`.

This upgrade massively expands the engine's detection capabilities beyond basic networking, introducing deep extraction rules for Cloud infrastructure, Host artifacts, and Cryptocurrency wallets. Crucially, it introduces **Contextual Awareness**—capturing the surrounding sentence fragment of an IOC so analysts can understand *how* an indicator was used without reading the entire source article.

---

## 2. Data Normalization: The Refanging Pipeline

Cybersecurity analysts intentionally obfuscate malicious indicators (e.g., `1.1.1[.]1` or `hxxps`) to prevent accidental execution. The extractor must reverse this before applying regular expressions.

### `refang_payload(self, text: str)`
* **URL Decoding:** The engine now applies `urllib.parse.unquote()` first, neutralizing attackers or automated systems that use URL-encoding (e.g., `%2E`) to hide malicious domains.
* **Lexical Reversal:** Applies a chained sequence of `re.sub()` operations to standardize protocols (`hxxps` $\rightarrow$ `http`), punctuation (`[dot]` $\rightarrow$ `.`), and email structures (`AT` $\rightarrow$ `@`).

---

## 3. Core Extraction Engine: The Regex Taxonomy

The engine's brain is the `self.rules` dictionary, which pre-compiles (`re.compile`) dozens of Regex patterns into memory upon initialization. The taxonomy has been vastly expanded into specific intelligence categories:

### 3.1 Network & Infrastructure
* **IPv4 / IPv6:** Extracts valid IP addressing schemas.
* **Domain / URL:** Extracts FQDNs and full web paths.
* **ASN:** Extracts Autonomous System Numbers (e.g., `AS701`).

### 3.2 Host Artifacts (Endpoint Intelligence)
* **Cryptographic Hashes:** `SHA256`, `SHA1`, `MD5`.
* **Registry Keys:** Detects Windows persistence mechanisms (e.g., `HKLM\Software\Microsoft\Windows...`).
* **File Paths:** Captures both Windows (`C:\Windows\System32...`) and Linux (`/etc/shadow`, `/var/log/...`) absolute paths.

### 3.3 Actor Infrastructure & C2
* **Cryptocurrency Wallets:** Detects Bitcoin (BTC) and Monero (XMR) wallet addresses, highly indicative of ransomware payout locations or cryptojacking campaigns.
* **Modern C2 Channels:** Detects malicious Telegram Bot APIs and Discord Webhook URLs abused for Command and Control.

### 3.4 Cloud & DevOps (New)
* **API Keys & Storage:** Actively hunts for exposed `AWS API Keys` (AKIA...), `AWS S3 Buckets`, and `Azure Blob` storage URLs within threat reports.

---

## 4. Strict Fidelity Filtering & Contextual Awareness

To prevent database pollution and false-positive alerts, the engine employs rigorous filtering and a major UI enhancement feature.

### 4.1 Cryptographic IP Validation (`_is_valid_ip`)
The previous version used basic string splitting. The updated engine utilizes Python's native `ipaddress` library.
* **Action:** It mathematically validates the extracted string and drops it if it belongs to `is_private`, `is_loopback`, `is_multicast`, `is_link_local`, or `is_reserved` CIDR blocks. This guarantees that internal corporate subnets (e.g., `10.0.0.0/8`) are never flagged as malicious external infrastructure.

### 4.2 Intelligent Deduplication
If the engine extracts a full URL (e.g., `http://malicious-site.com/payload.exe`), it intelligently suppresses the extraction of the bare domain (`malicious-site.com`) to prevent duplicate entries cluttering the analyst's dashboard.

### 4.3 Analyst Context Extraction (`_get_context`)
A massive upgrade to the analyst experience. 
* **Mechanism:** Instead of using `re.findall()`, the master loop uses `re.finditer()`, which returns the exact index position of the match (`match.start()`, `match.end()`).
* **Execution:** The engine slices the original string to grab `self.CONTEXT_WINDOW` (45 characters) before and after the IOC.
* **Result:** In the UI, instead of just seeing the IP `185.20.10.1`, the analyst sees: `...the payload beaconed out to the C2 server at 185.20.10.1 over port 443...`, providing instant situational awareness.

---

## 5. Algorithmic Orchestration

### `extract(self, raw_text: str)`
This is the master execution loop exposed to the application.
1.  **Refang:** Sanitizes the raw article text.
2.  **Iterate:** Loops through the pre-compiled `self.compiled_rules` dictionary.
3.  **Validate:** Applies the strict fidelity filters (`ipaddress` checks, whitelist exclusion).
4.  **Assemble:** Constructs a standardized dictionary containing the `Category`, `Type`, `Indicator`, and newly added `Context`.
5.  **Deduplicate:** Tracks `seen_values` to ensure the exact same hash or IP isn't saved 10 times if mentioned repeatedly in a single paragraph.

---

## 6. System Integration Context

* **Singleton Instantiation:** At the bottom of the file, the module instantiates a singleton object: `ioc_engine = EnterpriseIOCExtractor()`. 
* **Performance Impact:** Other modules (like the Multiprocessing workers in `scheduler.py`) import this pre-initialized `ioc_engine` rather than creating a new class instance. This ensures the massive dictionary of Regex rules is only compiled into CPU memory once per process, retaining lightning-fast parsing speeds during massive intelligence feed syncs.
