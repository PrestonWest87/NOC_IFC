# Enterprise Architecture & Functional Specification: `src/categorizer.py`

## 1. Executive Overview

The `src/categorizer.py` module serves as the primary **High-Speed Triage Engine** for incoming intelligence. Rather than relying on computationally expensive and high-latency LLM calls to sort every ingested RSS article or telemetry node, this module utilizes a highly optimized, rule-based Regular Expression (Regex) pipeline. 

By pre-compiling lexical patterns associated with specific threat vectors, the categorizer can evaluate and route thousands of intelligence articles per second. This ensures that the Operational Dashboard and Threat Telemetry modules can dynamically filter data streams into distinct operational domains (Cyber, Physical, Geopolitical) instantly.

---

## 2. Core Architecture: The Regex Taxonomy Dictionary

At the heart of the module is the `CATEGORIES` dictionary. This constant maps formalized string labels to pre-compiled Regex objects (`re.compile()`). 

### 2.1 Optimization Strategies
* **Pre-Compilation**: By compiling the regex patterns globally at module load, the system avoids the overhead of recompiling the pattern every time a new article is evaluated.
* **Word Boundaries (`\b`)**: Every pattern is wrapped in `\b...\b`. This is a critical enterprise safeguard that prevents sub-string false positives. For example, it ensures the system matches the word "war" but does not accidentally trigger on "soft**war**e" or "a**war**e".
* **Case Insensitivity (`re.IGNORECASE`)**: Ensures that "Zero-Day", "ZERO-DAY", and "zero-day" are all captured seamlessly without requiring exhaustive pattern definitions.
* **Optional Pluralization/Suffixes (`(?:...)`)**: Non-capturing groups with the `?` quantifier are heavily used to catch grammatical variations (e.g., `hack(?:er|ers|ed|ing)?` efficiently catches "hack", "hacker", "hackers", "hacked", and "hacking").

### 2.2 Operational Buckets (Taxonomies)

#### 🛡️ Category: `Cyber`
* **Focus:** Digital threat vectors, network infrastructure compromises, and software vulnerabilities.
* **Key Indicators:** `malware`, `cve`, `ransomware`, `breach`, `hack`, `exploit`, `zero-day`, `ddos`, `phish`, `apt`, `vulnerability`, `botnet`, `backdoor`, etc.

#### 🌪️ Category: `Physical/Weather`
* **Focus:** Kinetic hazards, environmental threats, and physical infrastructure failures that could impact geofenced Data Centers or NOC locations.
* **Key Indicators:** `weather`, `flood`, `tornado`, `hurricane`, `earthquake`, `power grid`, `outage`, `storm`, `wildfire`, `tsunami`.

#### 🌍 Category: `Geopolitics/News`
* **Focus:** Nation-state activities, regulatory shifts, and macro-level events that could precede coordinated cyber campaigns.
* **Key Indicators:** `government`, `election`, `war`, `military`, `sanctions`, `terrorism`, `kinetic`, `congress`.

---

## 3. Algorithmic Processing

### `categorize_text(text)`

This is the primary callable function exposed by the module. It acts as a routing function for raw text (typically the combined `title` and `summary` of an incoming intelligence article).

**Parameters:**
* `text` *(str)*: The raw string of content to be evaluated.

**Returns:**
* *(str)*: The string label of the identified category (e.g., `"Cyber"`). If no match is found, it returns `"General"`.

**Execution Flow:**
1. **Null Check (Failsafe):** The function immediately evaluates `if not text:`. If the pipeline feeds it a `None` type or an empty string, it fails safely and returns `"General"`.
2. **Iterative Search:** It iterates through the `CATEGORIES.items()`. Note: Because modern Python dictionaries maintain insertion order, there is an implicit priority hierarchy. The system checks for `Cyber` threats first, then `Physical/Weather`, then `Geopolitics`.
3. **First-Match Short Circuit:** `if pattern.search(text):` executes the compiled regex against the text. If a match is found, the function *immediately* returns the associated category string, halting further execution. This "first-match wins" logic prevents wasted CPU cycles on articles that have already been successfully classified.
4. **Fallback:** If the loop exhausts all categories without a positive regex match, the text is fundamentally classified as `"General"`. 

---

## 4. System Integration Context
Within the broader Intelligence Fusion Center (IFC) architecture, this module is primarily leveraged by:
* **The Intelligence Ingestion Pipeline (e.g., `telemetry_worker` or `scheduler`)**: Applied to every new RSS article saved to the database to populate the `Article.category` column.
* **Administrative Maintenance (`app.py` - Danger Zone)**: Used in the "Recategorize Old Articles" tool to retroactively apply these lexical rules to legacy database records that were previously uncategorized.
