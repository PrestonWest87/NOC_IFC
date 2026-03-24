# Enterprise Architecture & Functional Specification: `src/categorizer.py`

## 1. Executive Overview

The `src/categorizer.py` module serves as the primary **High-Speed Triage Engine** for incoming intelligence. Rather than relying on computationally expensive and high-latency LLM calls to sort every ingested RSS article or telemetry node, this module utilizes a highly optimized, rule-based Regular Expression (Regex) pipeline. 

In its latest architectural iteration, the categorizer has been upgraded from a simple "first-match" router to a **Term-Hit Density Scoring Engine**. It evaluates text against 8 distinct enterprise NOC/SOC operational domains, calculating keyword density to prevent miscategorization caused by single, off-topic terms in an article. This ensures that the Operational Dashboard and Threat Telemetry modules can dynamically filter massive data streams with extremely high fidelity.

---

## 2. Core Architecture: The NOC/SOC Taxonomy

At the heart of the module is the `CATEGORIES` dictionary. This constant maps formalized operational domains to extensive, pre-compiled Regex objects (`re.compile()`). 

### 2.1 Optimization Strategies
* **Pre-Compilation (`COMPILED_CATEGORIES`):** By compiling the regex patterns globally via dictionary comprehension at module load, the system completely avoids the CPU overhead of recompiling patterns every time a new article is evaluated.
* **Word Boundaries (`\b...\b`):** Every pattern is strictly wrapped in word boundaries. This enterprise safeguard prevents sub-string false positives (e.g., ensuring the system matches the acronym "APT" but does not accidentally trigger on the word "c**apt**ure").
* **Case Insensitivity (`re.IGNORECASE`):** Ensures that "Zero-Day", "ZERO-DAY", and "zero-day" are all captured seamlessly without requiring exhaustive explicit pattern definitions.

### 2.2 The 8 Operational Domains
The ontology has been expanded to reflect a mature, multi-domain Fusion Center:
1. **Cyber: Exploits & Vulns:** Focuses on code-level flaws (e.g., `cve-\d{4}`, `zero-day`, `rce`, `buffer overflow`).
2. **Cyber: Malware & Threats:** Focuses on active campaigns and actors (e.g., `ransomware`, `botnet`, `apt\d+`, `phishing`).
3. **ICS/OT & SCADA:** Focuses on industrial control systems and Bulk Electric System (BES) grids (e.g., `scada`, `modbus`, `plc`, `stuxnet`).
4. **Cloud & IT Infra:** Focuses on enterprise SaaS, IaaS, and core routing (e.g., `aws`, `bgp`, `route leak`, `active directory`).
5. **Physical Security:** Focuses on kinetic threats to facilities (e.g., `sabotage`, `active shooter`, `arson`, `cut fiber`).
6. **Severe Weather:** Focuses on meteorological hazards (e.g., `derecho`, `blizzard`, `spc`, `hurricane`).
7. **Geopolitics & Policy:** Focuses on nation-state actions and regulatory bodies (e.g., `sanctions`, `cisa`, `fcc`, `ferc`).
8. **AI & Emerging Tech:** Focuses on next-generation vectors (e.g., `llm`, `deepfake`, `quantum`).

---

## 3. Algorithmic Processing: Term-Hit Density

### `categorize_text(text)`

This is the primary callable function exposed by the module. It acts as a scoring engine for raw text (typically the combined `title` and `summary` of an incoming intelligence article).

**Parameters:**
* `text` *(str)*: The raw string of content to be evaluated.

**Returns:**
* *(str)*: The string label of the identified category (e.g., `"ICS/OT & SCADA"`). If no matches are found, it returns `"General"`.

**Execution Flow:**
1. **Null Check (Failsafe):** The function evaluates `if not text:`. If the pipeline feeds it a `None` type or an empty string, it fails safely and returns `"General"`.
2. **Scoring Initialization:** It instantiates a `collections.Counter()` object to track the frequency of keyword hits across all categories simultaneously.
3. **Exhaustive Density Scanning:** Unlike legacy short-circuit logic, the engine iterates through *every* category using `pattern.findall(text)`. This returns a list of all non-overlapping matches.
4. **Weight Accumulation:** The length of the `matches` list is added to the Counter for that specific category. This means an article that casually mentions "AWS" once, but uses the word "ransomware" and "botnet" seven times, will be correctly weighted toward the Malware category rather than Cloud Infrastructure.
5. **Resolution & Fallback:** * If the Counter is empty (no keywords matched any category), it defaults to `"General"`.
    * If matches exist, it uses `scores.most_common(1)[0][0]` to extract the absolute highest-scoring category and returns it to the pipeline.

---

## 4. System Integration Context
Within the broader Intelligence Fusion Center (IFC) architecture, this module is primarily leveraged by:
* **The Intelligence Ingestion Pipeline (e.g., `telemetry_worker`, `scheduler`, or RSS parsers):** Applied to every new article saved to the database to automatically populate the `Article.category` column, allowing the UI to instantly filter data into respective dashboard tabs.
* **Administrative Maintenance (`src/app.py` - Danger Zone):** Used in the "Recategorize Articles" tool (`svc.recategorize_all_articles()`) to retroactively apply this new 8-domain density scoring logic to legacy database records that were previously uncategorized or miscategorized.
