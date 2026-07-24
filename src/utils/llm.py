import logging
import re
import threading
import requests
import json
from types import SimpleNamespace
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from src.models.schema import SystemConfig, Article, CveItem, RegionalHazard, CloudOutage, CrimeIncident

logger = logging.getLogger(__name__)
LOCAL_TZ = ZoneInfo("America/Chicago")

_ollama_ctx_cache: dict[str, int] = {}

_brief_progress_store: dict[str, dict] = {}
_brief_progress_lock = threading.Lock()

def init_brief_progress(generation_id: str):
    with _brief_progress_lock:
        _brief_progress_store[generation_id] = {
            "stage": "starting",
            "message": "Starting generation...",
            "total_items": 0,
            "processed_items": 0,
            "percent": 0,
            "error": None,
        }

def update_brief_progress(generation_id: str, *, stage: str = None, message: str = None, total_items: int = None, processed_items: int = None, percent: int = None):
    with _brief_progress_lock:
        entry = _brief_progress_store.get(generation_id)
        if not entry:
            return
        if stage is not None:
            entry["stage"] = stage
        if message is not None:
            entry["message"] = message
        if total_items is not None:
            entry["total_items"] = total_items
        if processed_items is not None:
            entry["processed_items"] = processed_items
        if percent is not None:
            entry["percent"] = percent
        elif entry["total_items"] > 0 and entry["processed_items"] > 0:
            entry["percent"] = min(99, int((entry["processed_items"] / entry["total_items"]) * 100))

def get_brief_progress(generation_id: str) -> dict | None:
    with _brief_progress_lock:
        return _brief_progress_store.get(generation_id)

def clear_brief_progress(generation_id: str):
    with _brief_progress_lock:
        _brief_progress_store.pop(generation_id, None)

MODEL_CONTEXT_WINDOWS = {
    # OpenAI
    "gpt-4o": 128000, "gpt-4o-2024-08-06": 128000, "gpt-4o-mini": 128000,
    "gpt-4-turbo": 128000, "gpt-4": 8192, "gpt-3.5-turbo": 16384,
    "o1-preview": 128000, "o1-mini": 128000,
    # Anthropic
    "claude-3-5-sonnet-20241022": 200000, "claude-3-opus-20240229": 200000,
    "claude-3-haiku-20240307": 200000, "claude-2": 100000,
    # Ollama / local
    "llama3.1": 128000, "llama3": 8192, "llama2": 4096,
    "mistral": 32768, "mistral-nemo": 128000, "mixtral": 32768,
    "qwen2.5": 128000, "qwen2": 128000, "qwen": 32768,
    "deepseek-r1": 128000, "deepseek-coder": 16384,
    "codellama": 16384, "phi3": 128000, "phi": 128000,
    "gemma2": 8192, "gemma": 8192,
    "falcon": 2048, "falcon2": 8192,
    "yi": 200000, "yi-coder": 128000,
    "nemotron": 4096, "dbrx": 32768,
}

def _query_ollama_context_window(endpoint: str, model: str) -> int | None:
    """Query Ollama /api/show for the model's context length. Returns None on failure."""
    cache_key = f"{endpoint}|{model}"
    if cache_key in _ollama_ctx_cache:
        return _ollama_ctx_cache[cache_key]
    try:
        base = endpoint.rstrip("/").replace("/v1", "").replace("/chat/completions", "")
        url = f"{base}/api/show"
        resp = requests.post(url, json={"name": model}, timeout=10)
        resp.raise_for_status()
        info = resp.json().get("model_info", {})
        # Iterate known context_length keys from different model architectures
        for key in ("llama.context_length", "mistral.context_length", "qwen2.context_length",
                     "deepseek2.context_length", "gemma2.context_length", "phi3.context_length",
                     "mixtral.context_length", "yi.context_length", "command-r.context_length",
                     "dbrx.context_length", "nemotron.context_length"):
            if key in info:
                val = int(info[key])
                _ollama_ctx_cache[cache_key] = val
                logger.info("Ollama /api/show: model=%s context_length=%d (key=%s)", model, val, key)
                return val
        logger.warning("Ollama /api/show: no known context_length key in model_info for %s", model)
    except requests.ConnectionError:
        logger.warning("Ollama /api/show: connection refused to %s — is Ollama running?", base)
    except Exception as e:
        logger.warning("Ollama /api/show: error for %s: %s", model, e)
    return None

def get_effective_context_window(config):
    manual = getattr(config, 'llm_context_window', 128000) or 128000
    api_key = getattr(config, 'llm_api_key', None) or getattr(config, 'llm_api_key', '')
    model = getattr(config, 'llm_model_name', '') or ''
    endpoint = getattr(config, 'llm_endpoint', '') or ''
    # If API key is set, trust the manual setting (cloud API, user knows their model)
    if api_key:
        return manual
    # No API key → likely Ollama → try lookup table first
    model_lower = model.lower().strip()
    if model_lower in MODEL_CONTEXT_WINDOWS:
        return MODEL_CONTEXT_WINDOWS[model_lower]
    # Strip version suffix (e.g. "llama3.1:8b" → "llama3.1")
    base = model_lower.split(":")[0].split("-latest")[0].strip()
    if base in MODEL_CONTEXT_WINDOWS:
        return MODEL_CONTEXT_WINDOWS[base]
    # Unknown model — query Ollama directly
    ollama_ctx = _query_ollama_context_window(endpoint, model)
    if ollama_ctx is not None:
        return ollama_ctx
    logger.warning("Unknown model '%s' with no API key — falling back to manual setting %d", model, manual)
    return manual

def get_llm_config(session):
    config = session.query(SystemConfig).filter_by(is_active=True).first()
    logger.debug("get_llm_config: found=%s endpoint=%s model=%s", config is not None,
                 config.llm_endpoint if config else 'N/A',
                 config.llm_model_name if config else 'N/A')
    return config

def call_llm(messages, config, temperature=0.1, max_tokens=None):
    if isinstance(config, dict):
        config = SimpleNamespace(**config)
    headers = {"Content-Type": "application/json"}
    if config.llm_api_key:
        headers["Authorization"] = f"Bearer {config.llm_api_key}"

    ctx = get_effective_context_window(config)
    if max_tokens is None:
        max_tokens = min(ctx // 2, 8192)

    payload = {
        "model": config.llm_model_name,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens
    }

    url = config.llm_endpoint.rstrip('/') + "/chat/completions"
    logger.debug("call_llm: url=%s model=%s messages_count=%d", url, config.llm_model_name, len(messages))

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=300)
        response.raise_for_status()
        result = response.json()['choices'][0]['message']['content']
        logger.debug("call_llm: success, response_length=%d", len(result))
        return result

    except requests.exceptions.Timeout:
        logger.error("call_llm: timeout after 300s to %s (model=%s, max_tokens=%d)", url, config.llm_model_name, max_tokens)
        return "[WARN] **AI NETWORK ERROR:** Request timed out after 300 seconds. Is the LLM online?"
    except requests.exceptions.ConnectionError:
        logger.error("call_llm: connection refused to %s", url)
        return "[WARN] **AI NETWORK ERROR:** Connection Refused. Check your Endpoint URL."
    except Exception as e:
        logger.error("call_llm: unexpected error: %s", str(e), exc_info=True)
        return f"[WARN] **AI SYSTEM ERROR:** {str(e)}"

def chunk_list(data, size):
    for i in range(0, len(data), size):
        yield data[i:i + size]

def truncate_text(text, max_chars=300):
    if not text: return "No details provided."
    return text if len(text) <= max_chars else text[:max_chars] + "..."

def _map_reduce_summarize(items, formatter_func, map_prompt, reduce_prompt, config, chunk_size=6, progress_callback=None, map_temperature=0.1, reduce_temperature=0.2, skip_reduce=False):
    if not items: return None

    ctx = get_effective_context_window(config)
    scale = max(1.0, ctx / 128000)
    effective_chunk = max(1, int(chunk_size * scale))

    batch_summaries = []
    chunks = list(chunk_list(items, effective_chunk))
    total_chunks = len(chunks)
    total_items = len(items)

    for idx, chunk in enumerate(chunks):
        if progress_callback:
            progress_callback(idx + 1, total_chunks, total_items, idx * effective_chunk)

        context = "\n".join([formatter_func(x) for x in chunk])
        logger.info("_map_reduce_summarize: chunk %d/%d, items=%d, context_length=%d", idx + 1, total_chunks, len(chunk), len(context))

        import time
        chunk_start = time.time()
        resp = call_llm([
            {"role": "system", "content": map_prompt},
            {"role": "user", "content": context}
        ], config, temperature=map_temperature)
        chunk_elapsed = time.time() - chunk_start

        if resp and "[WARN]" not in resp:
            logger.info("_map_reduce_summarize: chunk %d/%d OK in %.1fs, response_length=%d", idx + 1, total_chunks, chunk_elapsed, len(resp))
            batch_summaries.append(resp)
        else:
            logger.error("_map_reduce_summarize: chunk %d/%d FAILED in %.1fs: %s", idx + 1, total_chunks, chunk_elapsed, (resp[:300] if resp else "empty"))

    if not batch_summaries: 
        logger.error("_map_reduce_summarize: all chunks failed, returning error")
        return "AI failed to process batch."

    if skip_reduce:
        logger.info("_map_reduce_summarize: skip_reduce=True, returning %d map outputs (total %d chars)", len(batch_summaries), sum(len(s) for s in batch_summaries))
        return batch_summaries

    if len(batch_summaries) > 1:
        if progress_callback:
            progress_callback(total_chunks, total_chunks, total_items, total_items)
        final_context = "\n\n".join(batch_summaries)
        logger.info("_map_reduce_summarize: reduce step, summaries=%d, final_context_length=%d", len(batch_summaries), len(final_context))
        reduce_start = time.time()
        reduce_resp = call_llm([
            {"role": "system", "content": reduce_prompt},
            {"role": "user", "content": final_context}
        ], config, temperature=reduce_temperature)
        reduce_elapsed = time.time() - reduce_start
        if reduce_resp and "[WARN]" not in reduce_resp:
            logger.info("_map_reduce_summarize: reduce OK in %.1fs, response_length=%d", reduce_elapsed, len(reduce_resp))
        else:
            logger.error("_map_reduce_summarize: reduce FAILED in %.1fs: %s", reduce_elapsed, (reduce_resp[:300] if reduce_resp else "empty"))
        return reduce_resp
    else:
        logger.info("_map_reduce_summarize: single chunk, skipping reduce step")
        return batch_summaries[0]

def generate_bluf(article, session):
    config = get_llm_config(session)
    if not config: return None

    fc = getattr(article, 'full_content', None)
    if fc and len(fc) > 200:
        article_context = f"Title: {article.title}\nContent: {str(fc)[:3000]}"
    else:
        article_context = f"Title: {article.title}\nSummary: {str(article.summary)[:1500]}"

    sys_prompt = """You are a Senior Threat Intelligence Analyst providing a BLUF (Bottom Line Up Front) for a NOC dashboard. 
    Analyze the intelligence and output EXACTLY four concise, hard-hitting bullet points. 
    Do NOT include conversational filler. Use this exact markdown structure:
    - **Core Event:** [1 sentence detailing the specific threat, actor, or incident. Bold key entities.]
    - **Impact Radius:** [1 sentence identifying targeted sectors, affected software versions, or systemic blast radius.]
    - **Technical Details:** [1 sentence extracting known CVEs, TTPs, or technical mechanisms. If none are mentioned, state 'N/A'.]
    - **Actionable Posture:** [1 sentence detailing a defensive pivot, monitoring recommendation, or immediate mitigation step.]"""

    response = call_llm([
        {"role": "system", "content": sys_prompt},
        {"role": "user", "content": article_context}
    ], config, temperature=0.1)

    return response.strip() if response else None

def analyze_cascading_impacts(articles, session):
    config = get_llm_config(session)
    if not config or not articles: return None

    map_p = "Identify the core threat, vulnerable system, or affected infrastructure sector in these events. Be extremely concise."
    reduce_p = """You are a Strategic Threat Intelligence Analyst monitoring critical infrastructure. 
    Review the summarized events and identify converging threats (e.g., severe weather overlapping with cyber vulnerabilities). 
    Output your analysis strictly under these two headers:
    **Converging Threat Vectors:** [Bullet points of overlapping risks]
    **Cascading Fallout Assessment:** [Short paragraph detailing potential operational degradation]
    If no overlaps exist, output: "No cascading operational intersections identified." """

    return _map_reduce_summarize(
        articles,
        lambda a: f"- {a.title}: {truncate_text(a.summary, 200)}",
        map_p, reduce_p, config, chunk_size=8
    )

def generate_unified_risk_brief(session, global_intel, internal_snapshot, progress_callback=None):
    """Generates an exhaustive, unembellished OSINT risk brief translated for an executive audience."""
    import json

    config = get_llm_config(session)
    if not config:
        logger.warning("generate_unified_risk_brief: AI is disabled, skipping")
        return "AI is currently disabled in settings."

    global_risk = global_intel.get('unified_risk', 'UNKNOWN')
    internal_risk = internal_snapshot.risk_level if internal_snapshot else 'NONE'

    logger.info("generate_unified_risk_brief: global_risk=%s internal_risk=%s", global_risk, internal_risk)

    if progress_callback:
        progress_callback(stage="gathering", message="Gathering threat intelligence data...", percent=0)

    t24 = datetime.utcnow() - timedelta(hours=24)

    recent_cves = session.query(CveItem).filter(CveItem.date_added >= t24).limit(200).all()
    active_hazards = session.query(RegionalHazard).filter(RegionalHazard.updated_at >= t24).limit(30).all()
    cloud_outages = session.query(CloudOutage).filter(CloudOutage.updated_at >= t24).limit(20).all()

    hw_data = json.loads(internal_snapshot.hw_data_json) if internal_snapshot and internal_snapshot.hw_data_json else []
    sw_data = json.loads(internal_snapshot.sw_data_json) if internal_snapshot and internal_snapshot.sw_data_json else []
    top_hw = hw_data[:20]
    top_sw = sw_data[:20]

    cyber_arts = global_intel.get('raw_cyber_articles', [])[:150]
    phys_arts = global_intel.get('raw_phys_articles', [])[:100]
    crimes = global_intel.get('recent_crimes', [])[:20]

    cyber_payload = []
    for a in cyber_arts:
        cyber_payload.append(f"OSINT Article - Title: {a.title} | Source: {a.source} | Summary: {truncate_text(a.summary, 1200)}")
    for c in recent_cves:
        cyber_payload.append(f"CISA KEV - CVE: {c.cve_id} | Vendor: {c.vendor} | Product: {c.product} | Vuln: {c.vulnerability_name}")
    for cl in cloud_outages:
        state = "Resolved" if cl.is_resolved else "Active/Ongoing"
        cyber_payload.append(f"Cloud Outage - Provider: {cl.provider} | Service: {cl.service} | Status: {state} | Details: {cl.title}")

    if cyber_payload:
        if progress_callback:
            progress_callback(stage="cyber_map", message=f"Processing cyber intelligence ({len(cyber_payload)} items)...", total_items=len(cyber_payload), processed_items=0, percent=1)
        map_p = "Extract factual data points regarding threat actors, vulnerabilities (CVEs), cloud service disruptions, and active exploits. Provide reason why an item is applicable. DO NOT embellish. Use strict bullet points."
        reduce_p = "Compile an exhaustive, purely factual Cyber Threat Intelligence digest. Preserve all CVE IDs, specific threat actor names, targeted vendors, and cloud providers. Do not extrapolate risks; report only what is explicitly stated in the data. Provide reason why item is applicable."
        def _cyber_progress(done, total_chunks, total_items, processed):
            if progress_callback:
                pct = int((done / total_chunks) * 49) + 1
                progress_callback(stage="cyber_map", message=f"Cyber intelligence map-reduce: chunk {done}/{total_chunks} ({total_items} items)", total_items=total_items, processed_items=processed, percent=pct)
        cyber_digest = _map_reduce_summarize(
            cyber_payload, lambda x: x, map_p, reduce_p, config, chunk_size=15, progress_callback=_cyber_progress
        )
    else:
        cyber_digest = "No active cyber OSINT, KEVs, or cloud outages reported in the last 48 hours."

    phys_payload = []
    for a in phys_arts:
        phys_payload.append(f"Physical Intel - Title: {a.title} | Source: {a.source}")
    for h in active_hazards:
        phys_payload.append(f"Weather/Hazard - Alert: {h.title} | Severity: {h.severity} | Location: {h.location} | Details: {truncate_text(h.description, 500)}")
    for c in crimes:
        phys_payload.append(f"Perimeter Crime - Type: {c.get('raw_title', 'Unknown')} | Distance from HQ: {c.get('distance_miles', 0)} miles | FBI Category: {c.get('fbi_category', 'Unknown')}")

    if phys_payload:
        if progress_callback:
            progress_callback(stage="phys_map", message=f"Processing physical intelligence ({len(phys_payload)} items)...", total_items=len(phys_payload), processed_items=0, percent=50)
        map_p = "Extract precise factual details regarding weather severity, regional infrastructure hazards, and perimeter crimes (including distance and FBI categories). Be purely objective."
        reduce_p = "Compile an exhaustive physical risk digest. Categorize strictly into: 1) Severe Weather/Geospatial Hazards and 2) Local Perimeter Crimes. Retain exact distances, locations, and severity classifications. DO NOT embellish."
        def _phys_progress(done, total_chunks, total_items, processed):
            if progress_callback:
                pct = int((done / total_chunks) * 49) + 50
                progress_callback(stage="phys_map", message=f"Physical intelligence map-reduce: chunk {done}/{total_chunks} ({total_items} items)", total_items=total_items, processed_items=processed, percent=pct)
        phys_digest = _map_reduce_summarize(
            phys_payload, lambda x: x, map_p, reduce_p, config, chunk_size=15, progress_callback=_phys_progress
        )
    else:
        phys_digest = "No significant weather hazards, regional disruptions, or perimeter crimes reported."

    hw_lines = [f"- {hw.get('Identifier', 'Unknown')} ({hw.get('OS', 'Unknown')}): {hw.get('OSINT Threat Matches', 0)} Matches. Threat Ref: {hw.get('Top Threat Reference', 'None')}" for hw in top_hw if hw.get('OSINT Threat Matches', 0) > 0]
    sw_lines = [f"- {sw.get('Software Name', 'Unknown')}: {sw.get('Active OSINT Matches', 0)} Matches. Threat Ref: {sw.get('Top Threat Reference', 'None')}" for sw in top_sw if sw.get('Active OSINT Matches', 0) > 0]

    threat_refs = set()
    for hw in top_hw:
        ref = hw.get('Top Threat Reference', '')
        if ref != 'None': threat_refs.add(ref)
    for sw in top_sw:
        ref = sw.get('Top Threat Reference', '')
        if ref != 'None': threat_refs.add(ref)

    deduped_vulns = "\n".join([f"- {ref}" for ref in sorted(threat_refs)]) if threat_refs else "No specific vulnerability references correlate at this time."

    hw_context = "\n".join(hw_lines) or "No hardware vulnerabilities correlated with active OSINT."
    sw_context = "\n".join(sw_lines) or "No software vulnerabilities correlated with active OSINT."

    compiled_intel = f"""
    === MACRO THREAT POSTURE ===
    Global OSINT Risk Level: {global_risk}
    Internal Exposure Level: {internal_risk}

    === DEEP CYBER OSINT DIGEST (Includes KEVs & Cloud Outages) ===
    {cyber_digest}

    === DEEP PHYSICAL OSINT DIGEST (Includes Weather & Perimeter Crimes) ===
    {phys_digest}

    === INTERNAL ASSET EXPOSURE (OSINT CORRELATIONS) ===
    --- HARDWARE ---
    {hw_context}

    --- SOFTWARE ---
    {sw_context}

    --- DEDUPLICATED VULNERABILITY REFERENCES ---
    {deduped_vulns}
    """

    master_sys_prompt = f"""You are an intelligence analyst preparing a Unified OSINT Risk Digest for executive leadership.

    FORMATTING & TONE DIRECTIVES:
    1. VISUAL HIERARCHY: Use bolding for emphasis, bulleted lists for data points, and blockquotes for notable warnings.
    2. OPERATIONAL TRANSLATION: For every vulnerability or threat, briefly state the business relevance (e.g., instead of just listing "ZDI-26-339", note that it "affects our Windows fleet and could allow unauthorized access").
    3. THREAT LEVEL TERMINOLOGY: When referring to threat levels or risk levels, use the terms: Low, Guarded, Elevated, High, or Severe. Do NOT use colors (e.g., yellow, blue, red) to describe threat levels.
    4. EXPAND THE NARRATIVE: Do not just list data. Synthesize it. Group similar threats together (e.g., group all ransomware actors, group all weather events) and explain their relevance to business continuity, personnel safety, or infrastructure.
    5. WORDING PRECISION — INTERNAL CYBER RISK: When describing the internal cyber risk exposure, use "continued attention" rather than "immediate attention". For example: "The convergence of these risk levels indicates a heightened threat landscape that requires continued attention."

    REQUIRED STRUCTURE:
    ## Executive OSINT Summary (BLUF)
    * Provide a 5-6 sentence high-level narrative explaining the convergence of the Global and Internal risk levels (using the terminology: Low, Guarded, Elevated, High, Severe).
    * Follow with a bulleted list of the top concerns across all domains.

    ## Internal Asset Threat Correlations (OSINT Overlaps)
    * Use a structured bulleted list for each exposed asset.
    * Format as: **[Asset Name]**: [Vulnerability/CVE] - Reason this is applicable - *[Specific Business/Operational Impact]*

    ## Global Cyber & Cloud Threat Landscape
    * Break this into two sub-bulleted sections: **Active Cyber Threats** (Ransomware, Malicious Campaigns) and **Cloud & Infrastructure Disruptions**.
    * Detail the specific threat actors, CISA KEVs, and affected cloud providers. Explain how these trends relate to our industry or supply chain.

    ## Physical, Weather & Perimeter Posture
    * Break into two sub-bulleted sections: **Regional Weather Hazards** and **Local Perimeter Crimes**.
    * List distances, severity levels, and FBI categories. Explain the relevance to facility operations, power stability, and personnel safety.

    ## Strategic Recommendations
    * Provide 3-5 recommended next steps (e.g., "Prioritize patching for Adobe products," "Review facility lockdown procedures due to perimeter crime data").
    """

    if progress_callback:
        progress_callback(stage="synthesizing", message="Synthesizing executive brief...", percent=99)

    logger.info("generate_unified_risk_brief: calling LLM with master prompt")
    response = call_llm([
        {"role": "system", "content": master_sys_prompt},
        {"role": "user", "content": compiled_intel}
    ], config, temperature=0.5)

    if response and "[WARN]" not in response:
        logger.info("generate_unified_risk_brief: success, response_length=%d", len(response))
    else:
        logger.error("generate_unified_risk_brief: LLM returned error: %s", response[:200] if response else "None")

    if response and "Brief generation failed" not in response:
        disclaimer = """
---
**OSINT CORRELATION DISCLAIMER:** This brief correlates external Open-Source Intelligence (OSINT) with our internal asset types to provide situational awareness. It highlights potential external exposures and does NOT represent confirmed internal breaches or active system compromises.

**AI-GENERATED CONTENT:** This brief was generated by the internal NOC AIOps system using automated intelligence analysis. This report has not been thoroughly reviewed by a Human Security Analyst. Some content in this report may not be applicable to our organization or may be mitigated by security controls.

---
"""
        response = disclaimer + response.strip()
    else:
        response = response.strip() if response else "Brief generation failed."

    if progress_callback:
        progress_callback(stage="complete", message="Brief generation complete.", percent=100)

    return response

def _assemble_global_brief_from_maps(map_outputs, phys_map_outputs, config):
    """Assemble a global threat brief from map outputs using programmatic classification.

    Instead of relying on an LLM reduce step that collapses data, this function:
    1. Extracts all bullet points from map outputs
    2. Classifies items by sector, actor, region using keyword matching
    3. Builds markdown report structure programmatically
    4. Uses LLM only for the BLUF executive summary
    """
    import re

    sector_keywords = {
        "ICS/SCADA/OT": ["scada", "ics", "ot network", "operational technology", "supervisory control", "plc", "rtu", "siemens", "rockwell", "schneider", "ge electric", "abb", "honeywell", "emerson", "wonderware", "allen-bradley", "substation", "grid control"],
        "Oil & Gas": ["oil", "gas pipeline", "pipeline", "petroleum", "refinery", "lng", "propane", "barrel", "crude", "drilling"],
        "Electric/Power Grid": ["electric", "power grid", "power company", "energy supplier", "energy company", "grid", "transmission", "distribution", "generat", "utility", "outage"],
        "Water & Wastewater": ["water", "wastewater", "sewage", "drinking water", "treatment plant"],
        "Telecommunications": ["telecom", "telecommunications", "broadband", "isp", "cellular", "5g", "mobile network", "satellite"],
        "Transportation": ["transportation", "rail", "railway", "port", "aviation", "airport", "shipping", "freight", "logistics", "train", "maritime"],
        "Healthcare": ["healthcare", "hospital", "medical", "health", "pharma", "biotech", "clinic", "patient"],
        "Government": ["government", "federal", "municipal", "state department", "dhs", "cisa", "fbi", "nsa", "white house", "congress", "ministry", "embassy", "agency"],
        "Defense": ["defense", "military", "pentagon", "dod", "army", "navy", "air force", "defense contractor", "weapon"],
        "Financial Services": ["financial", "bank", "finance", "fintech", "payment", "swift", "stock", "exchange", "crypto", "bitcoin", "blockchain", "swiss"],
        "IT/Technology": ["microsoft", "google", "aws", "azure", "cloud", "saas", "data center", "github", "openai", "anthropic", "check point", "cisco", "vmware", "oracle", "linux", "kernel", "android", "apple", "samsung"],
    }

    actor_patterns = [
        (r'\bapt[\s-]?\d+\b', None),
        (r'lazarus\b', 'LAZARUS'),
        (r'cozy\s+bear\b', 'COZY BEAR'),
        (r'fancy\s+bear\b', 'FANCY BEAR'),
        (r'sandworm\b', 'SANDWORM'),
        (r'turla\b', 'TURLA'),
        (r'darkside\b', 'DARKSIDE'),
        (r'revil\b', 'REVIL'),
        (r'blackcat\b', 'BLACKCAT'),
        (r'alphv\b', 'ALPHV'),
        (r'cl0p\b', 'CLOP'),
        (r'clop\b', 'CLOP'),
        (r'lockbit\b', 'LOCKBIT'),
        (r'volt\s+typhoon\b', 'VOLT TYPHOON'),
        (r'salt\s+typhoon\b', 'SALT TYPHOON'),
        (r'flax\s+typhoon\b', 'FLAX TYPHOON'),
        (r'brass\s+typhoon\b', 'BRASS TYPHOON'),
        (r'kimsuky\b', 'KIMSUKY'),
        (r'gamaredon\b', 'GAMAREDON'),
        (r'apt41\b', 'APT41'),
        (r'winnti\b', 'WINNTI'),
        (r'mustang\s+panda\b', 'MUSTANG PANDA'),
        (r'earth\s+preta\b', 'EARTH PRETA'),
        (r'voodoo\s+bear\b', 'VOODOO BEAR'),
        (r'laundry\s+bear\b', 'LAUNDRY BEAR'),
        (r'kyberpandit\b', 'KYBERPANDIT'),
        (r'jade[\s-]?prox?\b', 'JADEPROX'),
        (r'chaos\s+ransomware\b', 'CHAOS RANSOMWARE'),
        (r'china[\s-]nexus\b', 'CHINA-NEXUS'),
        (r'china[\s-]linked\b', 'CHINA-LINKED'),
        (r'russia[\s-]linked\b', 'RUSSIA-LINKED'),
        (r'krebston\b', 'RUSSIA-LINKED'),
        (r'kremlin[\s-]backed\b', 'RUSSIA-LINKED'),
        (r'iran[\s-]linked\b', 'IRAN-LINKED'),
        (r'north\s+korea\b', 'DPRK'),
        (r'lazarus\s+group\b', 'LAZARUS'),
    ]

    us_indicators = [
        'united states', 'u.s.', 'us ', 'american', 'domestic', 'homeland',
        'dhs', 'cisa', 'fbi', 'nsa', 'white house', 'state department',
        'texas', 'california', 'florida', 'new york', 'chicago',
        'washington dc', 'colorado', 'oklahoma', 'ohio', 'virginia',
    ]

    cve_pattern = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)

    ignore_patterns = [
        r'^\s*\*\*[^*]+\*\*\s*$',  # Section headers like **Security Vulnerabilities**
        r'^\s*Exploit code available:',
        r'^\s*Requires:',
        r'^\s*Fixed by',
        r'^\s*CVSS score:',
        r'^\s*No exploit code',
        r'^\s*\d+\.\s*\*\*[A-Z]',  # Numbered section headers
    ]

    all_items = []
    for chunk_output in map_outputs:
        if not chunk_output or "[WARN]" in chunk_output:
            continue
        lines = chunk_output.split('\n')
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            text = stripped.lstrip('-*•').strip()
            if not text:
                continue
            if any(re.match(pat, text, re.IGNORECASE) for pat in ignore_patterns):
                continue
            if len(text) < 15:
                continue
            all_items.append(text)

    logger.info("_assemble_global_brief_from_maps: extracted %d bullet items from %d map chunks", len(all_items), len(map_outputs))

    classified_items = []
    for text in all_items:
        text_lower = text.lower()

        matched_sector = "General"
        for sector_name, keywords in sector_keywords.items():
            if any(kw in text_lower for kw in keywords):
                matched_sector = sector_name
                break

        found_actors = []
        for pattern, name in actor_patterns:
            if re.search(pattern, text_lower):
                actor_name = name or re.search(pattern, text_lower).group(0).upper()
                if actor_name not in found_actors:
                    found_actors.append(actor_name)

        found_cves = [m.upper() for m in cve_pattern.findall(text)]

        is_us = any(ind in text_lower for ind in us_indicators)

        classified_items.append({
            'text': text,
            'sector': matched_sector,
            'actors': found_actors,
            'cves': found_cves,
            'is_us': is_us,
        })

    us_items = [i for i in classified_items if i['is_us']]
    global_items = [i for i in classified_items if not i['is_us']]

    sector_groups = {}
    for item in us_items:
        sector_groups.setdefault(item['sector'], []).append(item)

    actor_groups = {}
    for item in classified_items:
        for actor in item['actors']:
            actor_groups.setdefault(actor, []).append(item)

    all_cves = []
    seen_cves = set()
    for item in classified_items:
        for cve in item['cves']:
            if cve not in seen_cves:
                seen_cves.add(cve)
                all_cves.append(cve)

    total = len(classified_items)
    us_count = len(us_items)
    global_count = len(global_items)
    sector_count = len(sector_groups)
    actor_count = len(actor_groups)
    cve_count = len(all_cves)

    threat_level = "ELEVATED"
    if actor_count >= 3 and cve_count >= 5:
        threat_level = "HIGH"
    elif actor_count >= 2 or cve_count >= 3:
        threat_level = "ELEVATED"
    elif total >= 5:
        threat_level = "ELEVATED"
    else:
        threat_level = "MODERATE"

    report_parts = []

    bluf_points = []
    if actor_count > 0:
        top_actors = sorted(actor_groups.keys())[:5]
        bluf_points.append(f"Active threat actors tracked: **{', '.join(top_actors)}**")
    if sector_count > 1:
        top_sectors = sorted(sector_groups.keys())[:5]
        bluf_points.append(f"Targeted CI sectors: **{', '.join(top_sectors)}**")
    if cve_count > 0:
        bluf_points.append(f"**{cve_count} CVE indicators** tracked in the current threat landscape")
    if us_count > 0:
        us_sectors = sorted(set(i['sector'] for i in us_items))
        bluf_points.append(f"**{us_count} US domestic threats** identified across: {', '.join(us_sectors[:4])}")
    if global_count > 0:
        bluf_points.append(f"**{global_count} international threats** under active monitoring")
    if not bluf_points:
        bluf_points.append(f"**{total} total threat indicators** processed across the intelligence cycle")

    report_parts.append(f"## Executive Summary (BLUF)\n")
    report_parts.append(f"**THREAT LEVEL: {threat_level}**\n")
    report_parts.append('\n'.join(f"- {p}" for p in bluf_points))
    report_parts.append('')

    if us_items:
        report_parts.append('## US Critical Infrastructure Threat Assessment\n')
        for sector in sorted(sector_groups.keys()):
            items = sector_groups[sector]
            report_parts.append(f"### {sector}\n")
            for item in items[:15]:
                report_parts.append(f"- {item['text']}")
            report_parts.append('')

    if actor_groups:
        report_parts.append('## Advanced Persistent Threat (APT) & Nation-State Activity\n')
        for actor in sorted(actor_groups.keys()):
            items = actor_groups[actor]
            report_parts.append(f"### {actor}\n")
            for item in items[:10]:
                report_parts.append(f"- {item['text']}")
            report_parts.append('')

    non_actor_global = [i for i in global_items if not i['actors']]
    if non_actor_global:
        report_parts.append('## Global Threat Landscape\n')
        for item in non_actor_global[:25]:
            report_parts.append(f"- {item['text']}")
        report_parts.append('')

    if all_cves or any(i['sector'] in ('IT/Technology', 'Financial Services') for i in classified_items):
        report_parts.append('## Vulnerability & Exploit Intelligence\n')
        if all_cves:
            report_parts.append('### CISA Known Exploited Vulnerabilities\n')
            for cve in all_cves[:25]:
                report_parts.append(f"- **{cve}**")
            report_parts.append('')
        report_parts.append('### Ransomware & Cybercriminal Operations\n')
        ransomware_items = [i for i in classified_items if any(rw in ' '.join(i['actors']).lower() for rw in ['lockbit', 'blackcat', 'alphv', 'cl0p', 'clop', 'darkside', 'revil', 'chaos'])]
        if ransomware_items:
            for item in ransomware_items[:10]:
                report_parts.append(f"- {item['text']}")
        else:
            report_parts.append("- No named ransomware operations tracked in current window.")
        report_parts.append('')

    report_parts.append('## Local Weather & Perimeter Posture\n')
    if phys_map_outputs and phys_map_outputs != ["No hazards or perimeter crimes reported."]:
        phys_combined = '\n\n'.join([p for p in phys_map_outputs if p and '[WARN]' not in p])
        if phys_combined.strip():
            report_parts.append(phys_combined)
        else:
            report_parts.append("No significant weather hazards or perimeter crimes reported in the last 24 hours.")
    else:
        report_parts.append("No significant weather hazards or perimeter crimes reported in the last 24 hours.")

    main_report = '\n'.join(report_parts)
    logger.info("_assemble_global_brief_from_maps: assembled %d chars from %d items, %d sectors, %d actors, %d CVEs, US=%d Global=%d",
                len(main_report), total, sector_count, actor_count, cve_count, us_count, global_count)

    if config:
        condensed = f"THREAT LEVEL: {threat_level}\n"
        condensed += f"Total items: {total}, US: {us_count}, Global: {global_count}\n"
        condensed += f"Sectors: {', '.join(sorted(sector_groups.keys())[:8])}\n"
        condensed += f"Actors: {', '.join(sorted(actor_groups.keys())[:8])}\n"
        condensed += f"CVEs: {', '.join(all_cves[:10])}\n\n"
        for sector in sorted(sector_groups.keys())[:6]:
            condensed += f"\n{sector}:\n"
            for item in sector_groups[sector][:3]:
                condensed += f"- {item['text'][:150]}\n"
        for actor in sorted(actor_groups.keys())[:5]:
            condensed += f"\n{actor}:\n"
            for item in actor_groups[actor][:2]:
                condensed += f"- {item['text'][:150]}\n"

        bluf_prompt = f"""You are a NOC intelligence analyst. Write a 4-6 sentence BLUF (Bottom Line Up Front) executive summary for a threat brief.
Include: specific threats, actors, CVEs, affected sectors. Highlight OT/SCADA/ICS if present.
Use threat terminology: Critical, High, Elevated, Moderate, Low.
Do NOT use colors. Be direct and specific. One paragraph only, no headers."""

        bluf_response = call_llm([
            {"role": "system", "content": bluf_prompt},
            {"role": "user", "content": condensed}
        ], config, temperature=0.3, max_tokens=min(config.llm_context_window or 128000 // 4, 512))

        if bluf_response and "[WARN]" not in bluf_response:
            report_parts_with_bluf = [f"## Executive Summary (BLUF)\n{bluf_response.strip()}\n"]
            report_parts_with_bluf.extend(report_parts[1:])
            main_report = '\n'.join(report_parts_with_bluf)
            logger.info("_assemble_global_brief_from_maps: BLUF generated, final report %d chars", len(main_report))
        else:
            logger.warning("_assemble_global_brief_from_maps: BLUF LLM call failed, using template summary")

    return main_report


def generate_global_threat_brief(session, progress_callback=None):
    """Generates a global threat brief with US focus and global section.

    Map-reduce pipeline covering relevant articles from the last 24 hours.
    US-focused primary structure with a dedicated global threats section.
    Includes local weather hazards and perimeter crime intelligence.
    Uses programmatic assembly from map outputs (skips LLM reduce step).
    """
    config = get_llm_config(session)
    if not config:
        logger.warning("generate_global_threat_brief: AI is disabled, skipping")
        return "AI is currently disabled in settings."

    ctx = get_effective_context_window(config)
    logger.info("generate_global_threat_brief: starting generation (context_window=%d)", ctx)
    if progress_callback:
        progress_callback(stage="gathering", message="Gathering threat intelligence...", percent=0)

    t24 = datetime.utcnow() - timedelta(hours=24)

    recent_cves = session.query(CveItem).filter(CveItem.date_added >= t24).limit(300).all()
    cloud_outages = session.query(CloudOutage).filter(CloudOutage.updated_at >= t24).limit(30).all()
    active_hazards = session.query(RegionalHazard).filter(RegionalHazard.updated_at >= t24).limit(30).all()

    from src.services import get_recent_crimes
    crime_data = get_recent_crimes(max_distance=1.0, grid_only=True, hours_back=24)

    all_cyber = session.query(Article).filter(
        Article.published_date >= t24,
        Article.score >= 30,
    ).order_by(Article.score.desc()).all()
    logger.info("generate_global_threat_brief: found %d articles in last 24h (score>=30)", len(all_cyber))

    if progress_callback:
        progress_callback(stage="filtering", message="Filtering articles for relevance...", percent=1)

    ci_keywords = [
        "critical infrastructure", "water", "wastewater", "electric", "power grid", "power",
        "oil", "gas", "pipeline", "energy", "telecom", "nuclear", "dams", "dam",
        "transportation", "rail", "port", "aviation", "chemical", "healthcare", "hospital",
        "food", "agriculture", "defense", "military", "government", "federal", "municipal",
        "scada", "ics", "ot", "operational technology", "supervisory control",
        "grid", "substation", "transmission", "distribution", "natural gas",
        "petroleum", "refinery", "lng", "propane", "sewage", "drinking water",
        "treatment plant", "water authority", "electric authority", "power authority",
    ]

    ci_relevant = []
    non_ci_articles = []
    for art in all_cyber:
        text = f"{art.title} {art.summary or ''}".lower()
        if any(kw in text for kw in ci_keywords):
            ci_relevant.append(art)
        else:
            non_ci_articles.append(art)

    logger.info("generate_global_threat_brief: %d CI-relevant, %d non-CI", len(ci_relevant), len(non_ci_articles))

    apt_keywords = [
        "apt", "apt1", "apt28", "apt29", "apt38", "lazarus", "cozy bear", "fancy bear",
        "sandworm", "turla", "darkside", "revil", "blackcat", "alphv", "cl0p", "clop",
        "lockbit", "ransomware", "nation-state", "state-sponsored", "kyberpandit",
        "volt typhoon", "salt typhoon", "flax typhoon", "brass typhoon",
        "kimsuky", "gamaredon", "apt41", "winnti", "stone panda", "mustang panda",
        "earth preta", "aqua blizzard", "bluebreeze", "voodoo bear",
    ]

    apt_relevant = []
    ci_ids = {a.id for a in ci_relevant}
    for art in all_cyber:
        text = f"{art.title} {art.summary or ''}".lower()
        if any(kw in text for kw in apt_keywords):
            if art.id not in ci_ids:
                apt_relevant.append(art)

    us_patterns = re.compile(
        r'\b(?:united\s+states|u\.s\.|american|domestic|homeland|dhs|cisa|fbi|nsa|white\s+house|'
        r'california|texas|florida|new\s+york|chicago|washington\s+dc)\b',
        re.IGNORECASE
    )
    us_articles = []
    global_articles = []
    combined_pool = ci_relevant + apt_relevant
    seen_ids = set()
    for art in combined_pool:
        if art.id in seen_ids:
            continue
        seen_ids.add(art.id)
        text = f"{art.title} {art.summary or ''}"
        if us_patterns.search(text):
            us_articles.append(art)
        else:
            global_articles.append(art)

    for art in non_ci_articles:
        if art.id not in seen_ids:
            text = f"{art.title} {art.summary or ''}"
            if us_patterns.search(text):
                us_articles.append(art)
            else:
                global_articles.append(art)
            seen_ids.add(art.id)

    logger.info("generate_global_threat_brief: US=%d Global=%d", len(us_articles), len(global_articles))

    max_summary = 400 if ctx < 4000 else 800
    max_content = 600 if ctx < 4000 else 1200

    def _article_content(art):
        content = getattr(art, 'full_content', None)
        if content and len(content) > 200:
            return truncate_text(content, max_content)
        return truncate_text(art.summary, max_summary)

    cyber_payload = []
    for a in us_articles:
        cyber_payload.append(f"[US] {a.title} | {a.source} | {_article_content(a)}")
    for a in global_articles:
        cyber_payload.append(f"[GLOBAL] {a.title} | {a.source} | {_article_content(a)}")
    for c in recent_cves:
        cyber_payload.append(f"KEV: {c.cve_id} {c.vendor}/{c.product} - {c.vulnerability_name}")
    for cl in cloud_outages:
        state = "Down" if not cl.is_resolved else "Resolved"
        cyber_payload.append(f"Cloud: {cl.provider}/{cl.service} {state} - {cl.title}")

    if not cyber_payload:
        logger.warning("generate_global_threat_brief: no intelligence data available")
        if progress_callback:
            progress_callback(stage="complete", message="No intelligence data available.", percent=100)
        return "No significant threat intelligence data available in the last 24 hours."

    if progress_callback:
        progress_callback(stage="cyber_map", message=f"Processing intelligence ({len(cyber_payload)} items)...", total_items=len(cyber_payload), processed_items=0, percent=5)

    map_p = """For EACH threat item, extract these key facts as bullet points:
- THREAT: [actor if known] targeting [specific target/product] using [method/technique]
- SECTOR: [which CI sector: Energy, Water, Telecom, Healthcare, Transport, Gov, Defense, Finance, IT, Oil&Gas, SCADA/ICS/OT, or General]
- CVE: [CVE-ID if any, with product name]
- SCOPE: [US domestic or International]
- SEVERITY: [Critical/High/Medium/Low]
Include every detail from the source. No filler. One bullet set per item."""

    reduce_p = """Compile ALL bullet points into a comprehensive intelligence summary organized into these groups:

GROUP 1 - US CRITICAL INFRASTRUCTURE THREATS:
For each CI sector that has threats, list ALL threats to that sector with full detail. Include actor, method, target, CVE, severity. Do not skip any sector with even one threat.

GROUP 2 - APT AND NATION-STATE ACTORS:
Every named actor group, their targets, methods, and campaigns.

GROUP 3 - INTERNATIONAL THREATS:
All non-US threats organized by region.

GROUP 4 - VULNERABILITIES:
Every CVE with product, severity, and affected sector.

GROUP 5 - RANSOMWARE AND CRIMINAL OPERATIONS:
Every named group and their activity.

GROUP 6 - CLOUD AND SERVICE DISRUPTIONS:
Every provider outage with affected services.

Include EVERY bullet point from the input. Do not summarize, skip, or deduplicate. Specific details matter: exact CVE numbers, exact product names, exact actor names."""

    def _global_progress(done, total_chunks, total_items, processed):
        if progress_callback:
            pct = int((done / total_chunks) * 89) + 5
            progress_callback(stage="cyber_map", message=f"Intelligence map: chunk {done}/{total_chunks}", total_items=total_items, processed_items=processed, percent=pct)

    cyber_map_outputs = _map_reduce_summarize(
        cyber_payload, lambda x: x, map_p, reduce_p, config, chunk_size=8, progress_callback=_global_progress,
        map_temperature=0.3, reduce_temperature=0.2, skip_reduce=True
    )

    if not cyber_map_outputs or (isinstance(cyber_map_outputs, list) and len(cyber_map_outputs) == 0):
        logger.error("generate_global_threat_brief: cyber map failed")
        if progress_callback:
            progress_callback(stage="error", message="Intelligence processing failed.", percent=0)
        return "Brief generation failed during intelligence processing."

    if isinstance(cyber_map_outputs, str):
        logger.info("generate_global_threat_brief: cyber map returned single output (%d chars)", len(cyber_map_outputs))
        cyber_map_outputs = [cyber_map_outputs]
    else:
        total_cyber_chars = sum(len(s) for s in cyber_map_outputs)
        logger.info("generate_global_threat_brief: cyber map completed, %d chunks, %d total chars", len(cyber_map_outputs), total_cyber_chars)

    phys_payload = []
    for h in active_hazards:
        phys_payload.append(f"HAZARD: {h.title} | Severity: {h.severity} | Location: {h.location} | {truncate_text(h.description, 300)}")
    for c in crime_data:
        phys_payload.append(f"CRIME: {c.get('raw_title', 'Unknown')} | Distance: {c.get('distance_miles', 0)}mi | Category: {c.get('category', 'Unknown')} | Severity: {c.get('severity', 'Unknown')}")

    phys_map_outputs = []
    if phys_payload:
        if progress_callback:
            progress_callback(stage="phys_map", message=f"Processing physical intelligence ({len(phys_payload)} items)...", total_items=len(phys_payload), processed_items=0, percent=90)
        phys_map_p = """Extract EVERY detail from each item. For weather hazards:
TYPE: [exact hazard type - e.g. "Extreme Heat Warning", "Severe Thunderstorm Warning", "Tropical Storm Watch"]
SEVERITY: [exact severity level from NWS]
LOCATION: [exact counties/regions affected]
TIMESTAMP: [issue and expiry times]
IMPACT: [potential infrastructure impact]

For perimeter crimes:
TYPE: [exact crime category]
LOCATION: [specific area or zone]
DISTANCE: [distance from facility in miles]
SEVERITY: [threat level]
TIME: [when reported]

Be specific with every number, location name, and time. No generalizations."""

        def _phys_progress(done, total_chunks, total_items, processed):
            if progress_callback:
                pct = int((done / total_chunks) * 8) + 90
                progress_callback(stage="phys_map", message=f"Physical intel: chunk {done}/{total_chunks}", total_items=total_items, processed_items=processed, percent=pct)

        phys_map_outputs = _map_reduce_summarize(
            phys_payload, lambda x: x, phys_map_p, "", config, chunk_size=6, progress_callback=_phys_progress,
            map_temperature=0.3, reduce_temperature=0.2, skip_reduce=True
        )
        if isinstance(phys_map_outputs, str):
            phys_map_outputs = [phys_map_outputs]
        logger.info("generate_global_threat_brief: physical map completed, %d chunks", len(phys_map_outputs) if phys_map_outputs else 0)
    else:
        phys_map_outputs = ["No hazards or perimeter crimes reported."]

    if progress_callback:
        progress_callback(stage="synthesizing", message="Assembling brief from map outputs...", percent=96)

    response = _assemble_global_brief_from_maps(cyber_map_outputs, phys_map_outputs, config)

    if response and len(response) > 100:
        logger.info("generate_global_threat_brief: assembled brief, response_length=%d", len(response))
    else:
        logger.error("generate_global_threat_brief: assembly produced thin output: %d chars", len(response) if response else 0)
        if progress_callback:
            progress_callback(stage="error", message="Brief assembly produced thin output.", percent=0)
        return "Brief generation produced insufficient output."

    if progress_callback:
        progress_callback(stage="complete", message="Brief generation complete.", percent=100)

    return response.strip()

def generate_internal_risk_brief(session, internal_snapshot, progress_callback=None):
    """Generates an internal asset risk brief focused on OSINT correlations to our infrastructure.

    This brief is heavily tuned to:
    - Analyze each hardware/software asset against recent OSINT and CISA KEVs
    - Identify which specific threats are targeting our exact asset stack
    - Prioritize by risk score and criticality
    - Provide actionable patching/hardening guidance per asset
    """
    config = get_llm_config(session)
    if not config:
        logger.warning("generate_internal_risk_brief: AI is disabled, skipping")
        return "AI is currently disabled in settings."

    logger.info("generate_internal_risk_brief: starting generation")
    if progress_callback:
        progress_callback(stage="gathering", message="Gathering internal asset intelligence...", percent=0)

    if not internal_snapshot:
        logger.warning("generate_internal_risk_brief: no internal snapshot available")
        return "No internal risk snapshot available. Trigger an internal risk calculation first."

    import json
    hw_data = json.loads(internal_snapshot.hw_data_json) if internal_snapshot.hw_data_json else []
    sw_data = json.loads(internal_snapshot.sw_data_json) if internal_snapshot.sw_data_json else []
    risk_level = internal_snapshot.risk_level or "UNKNOWN"
    score = internal_snapshot.score or 0
    total_assets = internal_snapshot.total_assets or 0
    total_osint = internal_snapshot.total_osint_hits or 0
    critical_osint = internal_snapshot.critical_osint_hits or 0

    t24 = datetime.utcnow() - timedelta(hours=24)
    recent_cves = session.query(CveItem).filter(CveItem.date_added >= t24).limit(200).all()

    hw_with_matches = [h for h in hw_data if h.get("OSINT Threat Matches", 0) > 0]
    hw_clean = [h for h in hw_data if h.get("OSINT Threat Matches", 0) == 0]
    sw_with_matches = [s for s in sw_data if s.get("Active OSINT Matches", 0) > 0]
    sw_clean = [s for s in sw_data if s.get("Active OSINT Matches", 0) == 0]

    if progress_callback:
        progress_callback(stage="asset_analysis", message=f"Analyzing {len(hw_data)} hardware and {len(sw_data)} software assets...", percent=5)

    asset_payload = []
    for hw in hw_data:
        name = hw.get("Identifier", "Unknown")
        ip = hw.get("IP Address", "N/A")
        os_info = hw.get("OS", "Unknown")
        risk = hw.get("OSINT Risk Score", 0)
        matches = hw.get("OSINT Threat Matches", 0)
        top_ref = hw.get("Top Threat Reference", "None")
        asset_payload.append(f"[HW] {name} ({ip}) | OS: {os_info} | OSINT Risk: {risk}/100 | Matches: {matches} | Top Ref: {top_ref}")

    for sw in sw_data:
        name = sw.get("Software Name", "Unknown")
        risk = sw.get("OSINT Risk Score", 0)
        matches = sw.get("Active OSINT Matches", 0)
        top_ref = sw.get("Top Threat Reference", "None")
        risk_level_sw = sw.get("risk_level", "LOW")
        asset_payload.append(f"[SW] {name} | Risk Level: {risk_level_sw} | OSINT Risk: {risk}/100 | Matches: {matches} | Top Ref: {top_ref}")

    cve_payload = []
    for c in recent_cves:
        cve_payload.append(f"CISA KEV - CVE: {c.cve_id} | Vendor: {c.vendor} | Product: {c.product} | Vuln: {c.vulnerability_name}")

    combined_payload = asset_payload + cve_payload

    if not combined_payload:
        if progress_callback:
            progress_callback(stage="complete", message="No asset data to analyze.", percent=100)
        return "No internal assets or CVE data available for analysis."

    if progress_callback:
        progress_callback(stage="correlation", message=f"Running OSINT correlation analysis ({len(combined_payload)} items)...", total_items=len(combined_payload), processed_items=0, percent=10)

    map_p = """You are an internal infrastructure security analyst performing OSINT correlation analysis.

For each asset listed below, identify:
- Specific CVEs or vulnerabilities that affect THIS EXACT asset (match vendor + product + version)
- Threat actors or campaigns known to target this technology
- Risk severity: CRITICAL if actively exploited, HIGH if CVE exists, MEDIUM if potential, LOW if no direct correlation
- Whether the asset is internet-facing or contains sensitive data (infer from type: firewall, server, SCADA = high value)

Preserve all CVE IDs, vendor names, product names, and version numbers exactly.
Group findings by asset. Be specific about which CVE applies to which asset version.
Do NOT list assets with zero correlations — only report assets with confirmed or high-probability matches."""

    reduce_p = """Compile an exhaustive Internal Asset Risk Correlation Report.

Structure your output as:

## Executive Internal Risk Summary
- Overall internal posture based on asset-OSINT correlations
- Number of assets at risk vs total assets
- Critical risk drivers (top 3 assets requiring immediate attention)

## Hardware Asset Threat Correlations
- Group by risk tier: CRITICAL > HIGH > MEDIUM
- For each asset: specific CVEs, threat actors, exploit availability, and business impact
- Include IP, OS version, and exact vulnerability references
- SCADA/RTU/ICS assets get dedicated section if present

## Software Asset Threat Correlations
- Group by risk tier: CRITICAL > HIGH > MEDIUM
- For each software: CVEs, known exploits, active campaigns, patch availability
- Include version-specific applicability

## Vulnerability Reference Matrix
- Deduplicated list of all CVEs correlated to our stack
- For each: affected asset(s), CVSS if available, exploit status, recommended action

## Patching & Hardening Recommendations
- Prioritized action items grouped by urgency
- Specific version upgrades or patches to apply
- Compensating controls if patches are unavailable
- Network segmentation recommendations for high-risk assets

Do NOT include global threat landscape or external OSINT — focus ONLY on correlations to our specific internal assets."""

    def _corr_progress(done, total_chunks, total_items, processed):
        if progress_callback:
            pct = int((done / total_chunks) * 79) + 10
            progress_callback(stage="correlation", message=f"Asset correlation map-reduce: chunk {done}/{total_chunks} ({total_items} items)", total_items=total_items, processed_items=processed, percent=pct)

    correlation_digest = _map_reduce_summarize(
        combined_payload, lambda x: x, map_p, reduce_p, config, chunk_size=15, progress_callback=_corr_progress
    )

    if not correlation_digest or "[WARN]" in correlation_digest:
        logger.error("generate_internal_risk_brief: map-reduce failed: %s", (correlation_digest or "None")[:200])
        if progress_callback:
            progress_callback(stage="error", message="Correlation processing failed.", percent=0)
        return "Internal brief generation failed during correlation analysis."

    master_sys_prompt = f"""You are a senior infrastructure security analyst preparing an Internal Asset Risk Brief for executive and technical leadership.

CONTEXT:
- Total Assets Monitored: {total_assets}
- Assets with OSINT Correlations: {len(hw_with_matches) + len(sw_with_matches)}
- Internal CIS Risk Level: {risk_level} (Score: {score})
- Critical OSINT Hits: {critical_osint}
- Total OSINT Correlations: {total_osint}

FORMATTING & TONE DIRECTIVES:
1. ASSET-CENTRIC: Every finding must be tied to a specific internal asset (name, IP, OS/version).
2. RISK PRIORITIZATION: Lead with CRITICAL and HIGH risk assets. Low-risk assets get a brief mention.
3. OPERATIONAL TRANSLATION: For every CVE/threat, state the business impact (e.g., "PA-5260 vulnerability could allow remote code execution on our core firewall, potentially compromising all network traffic").
4. ACTIONABLE: Every section must end with specific remediation steps.
5. VERSION-SPECIFIC: Only report CVEs that apply to the exact versions we run.

REQUIRED STRUCTURE:
## Executive Internal Risk Assessment (BLUF)
* 4-5 sentence summary of internal asset posture
* Top 3 critical risk assets requiring immediate leadership attention
* Overall risk trajectory (improving/stable/deteriorating)

## Critical Hardware Asset Vulnerabilities
* Dedicate a sub-section to each CRITICAL risk hardware asset
* Format: **[Asset Name]** (IP, OS Version) — Risk Score: X/100
  - Applicable CVEs with business impact
  - Threat actors/campaigns targeting this technology
  - Recommended action (patch version, upgrade path, or compensating control)

## SCADA/ICS/OT Asset Exposure (if applicable)
* Dedicated section for any SCADA, RTU, PLC, or OT assets
* Emphasize safety and operational continuity impact
* Recommend network segmentation if not already segmented

## Software Stack Vulnerability Analysis
* Group by risk tier (CRITICAL > HIGH > MEDIUM)
* For each: exact version applicability, CVE references, exploit status
* Patch availability and recommended version

## Deduplicated CVE Reference Table
* All correlated CVEs in a structured list
* Columns: CVE ID | Affected Asset | Severity | Exploit Status | Recommended Action

## Recommended Actions (Prioritized)
1. IMMEDIATE (next 24 hours): Critical patches, network isolation
2. SHORT-TERM (next 7 days): High-risk patches, config hardening
3. MEDIUM-TERM (next 30 days): Medium-risk items, architecture review

---
**OSINT CORRELATION DISCLAIMER:** This brief correlates external Open-Source Intelligence (OSINT) with our internal asset inventory to identify potential exposures. It does NOT represent confirmed breaches or active compromises.

**AI-GENERATED CONTENT:** This brief was generated by the internal NOC AIOps system. Review by a qualified security analyst is recommended before taking action.
"""

    if progress_callback:
        progress_callback(stage="synthesizing", message="Synthesizing internal risk brief...", percent=92)

    logger.info("generate_internal_risk_brief: calling LLM with master prompt")
    logger.info("generate_internal_risk_brief: master_prompt_length=%d correlation_digest_length=%d", len(master_sys_prompt), len(correlation_digest))
    logger.info("generate_internal_risk_brief: combined payload total=%d chars", len(master_sys_prompt) + len(correlation_digest))

    import time
    synthesis_start = time.time()
    try:
        response = call_llm([
            {"role": "system", "content": master_sys_prompt},
            {"role": "user", "content": correlation_digest}
        ], config, temperature=0.35)
    except Exception as e:
        elapsed = time.time() - synthesis_start
        logger.error("generate_internal_risk_brief: synthesis EXCEPTION after %.1fs: %s", elapsed, str(e), exc_info=True)
        if progress_callback:
            progress_callback(stage="error", message=f"LLM synthesis exception after {elapsed:.0f}s: {str(e)}", percent=0)
        return "Internal brief generation failed during synthesis."

    elapsed = time.time() - synthesis_start
    logger.info("generate_internal_risk_brief: LLM responded in %.1fs, response_type=%s", elapsed, type(response).__name__)

    if response and "[WARN]" not in response:
        logger.info("generate_internal_risk_brief: success, response_length=%d", len(response))
    else:
        logger.error("generate_internal_risk_brief: LLM returned error after %.1fs: %s", elapsed, response[:500] if response else "None (empty response)")
        if progress_callback:
            progress_callback(stage="error", message=f"LLM synthesis failed after {elapsed:.0f}s: {(response[:200] if response else 'empty response')}", percent=0)
        return "Internal brief generation failed during synthesis."

    if progress_callback:
        progress_callback(stage="complete", message="Internal brief generation complete.", percent=100)

    return response.strip()

def generate_aggregated_shift_summary(session, logs, timeframe_label, target_role="All"):
    config = get_llm_config(session)
    logger.info("generate_aggregated_shift_summary: config_found=%s logs_count=%d timeframe=%s role=%s",
                config is not None, len(logs) if logs else 0, timeframe_label, target_role)
    if not config:
        logger.warning("generate_aggregated_shift_summary: AI is disabled")
        return None

    if not logs:
        logger.warning("generate_aggregated_shift_summary: no logs provided")
        return f"No logs available to generate a {timeframe_label} summary."

    map_p = f"You are a log analyst for the '{target_role.upper()}' team. Read these shift log entries and extract factual records of: incidents detected, actions taken, tickets dispatched, escalations, and any ongoing issues. Output concise bullet points — do not praise or characterize the work quality, just report what happened."
    reduce_p = "Combine these extractions into a single chronological digest of events. Preserve all concrete facts: timestamps, asset names, ticket numbers, outage durations, and resolution actions. Do not add commentary about performance or team effectiveness."

    logger.info("generate_aggregated_shift_summary: running map-reduce on %d logs (chunk_size=20)", len(logs))
    log_digest = _map_reduce_summarize(
        logs,
        lambda l: f"[{(l.created_at.replace(tzinfo=ZoneInfo('UTC')).astimezone(LOCAL_TZ) if l.created_at else 'Unknown')}] {l.analyst}: {l.content}",
        map_p, reduce_p, config, chunk_size=20
    )
    logger.info("generate_aggregated_shift_summary: map-reduce digest_length=%d", len(log_digest) if log_digest else 0)

    master_sys_prompt = f"""You are a NOC shift log summarizer generating a factual summary for the {target_role.upper()} team for '{timeframe_label}'.

    Read the log entries and produce a neutral, data-driven summary. Do not praise performance, do not characterize work quality, do not use superlatives. Report only what the logs factually state.

    Structure the response in Markdown with these exact headers:

    ## {timeframe_label} Log Summary — {target_role.upper()}
    [2-3 sentences summarizing the scope: time period covered, number of entries, general nature of activity (e.g. "routine monitoring", "active outage remediation", "maintenance windows").]

    ## Events Logged
    [Bulleted list of each discrete event mentioned in the logs. Format: timestamp — action/item (e.g. "14:30 — Dispatched ticket #4512 for MAIN-1 circuit flap"). Include asset names, ticket IDs, outage durations if recorded.]

    ## Open Items
    [Bulleted list of any issues noted as ongoing, unresolved, or carried over. If none, state "No open items reported."]

    Stick strictly to what is in the logs. Do not infer events not recorded. Do not add praise or subjective assessment."""

    logger.info("generate_aggregated_shift_summary: calling final LLM for master summary")
    response = call_llm([
        {"role": "system", "content": master_sys_prompt},
        {"role": "user", "content": f"--- LOG DIGEST ---\n{log_digest}"}
    ], config, temperature=0.6)

    if response and "[WARN]" not in response:
        logger.info("generate_aggregated_shift_summary: success, response_length=%d", len(response))
    else:
        logger.error("generate_aggregated_shift_summary: LLM error: %s", response[:200] if response else "None")

    return response.strip() if response else "Summary generation failed."

def generate_briefing(articles, session):
    config = get_llm_config(session)
    if not config or not articles: return None

    map_p = "Summarize the overarching threat actor campaigns or vulnerabilities in these articles in 2 bullet points."
    reduce_p = """You are an All-Source Intelligence Director. Synthesize the provided intelligence summaries into a single, cohesive 2-paragraph situational briefing. 
    Highlight threat actor campaigns, systemic vulnerabilities, and geopolitical drivers. Write a fluid, authoritative narrative."""

    return _map_reduce_summarize(
        articles,
        lambda a: f"Title: {a.title} | Source: {a.source}",
        map_p, reduce_p, config, chunk_size=10
    )

def cross_reference_cves(cves, session):
    config = get_llm_config(session)
    if not config: return "ERROR: AI Engine is disabled."
    if not cves: return "CLEAR: Tech stack is clear. No active KEVs found."

    tech_stack = config.tech_stack if config.tech_stack else "SolarWinds, Cisco SD-WAN, Microsoft Office"

    sys_map = f"""Cross-reference these Actively Exploited Vulnerabilities (KEVs) against the internal stack.
    INTERNAL TECH STACK: {tech_stack}
    If a KEV targets a vendor/product in the TECH STACK, extract the CVE ID and impact. If none match, output 'CLEAR'."""

    raw_matches = []
    error_messages = []

    for chunk in chunk_list(cves, 8):
        cve_context = "\n".join([f"- {c.cve_id} ({c.vendor} {c.product}): {c.vulnerability_name}" for c in chunk])
        messages = [{"role": "system", "content": sys_map}, {"role": "user", "content": f"KEV Batch:\n{cve_context}"}]

        response = call_llm(messages, config, temperature=0.0)
        if not response: continue

        if "CLEAR" not in response.upper() and "[WARN]" not in response:
            raw_matches.append(response.replace("MATCH:", "").strip())
        elif "ERROR:" in response.upper() or "[WARN]" in response:
            error_messages.append("Batch timeout.")

    if not raw_matches: return "CLEAR: No active KEVs match internal infrastructure."

    sys_reduce = """You are a SOC Director. Review the raw vulnerability matches and write a unified, critical Security Alert. 
    Format with bullet points. Include CVE IDs, affected internal tech, and immediate required actions."""

    final_alert = call_llm([
        {"role": "system", "content": sys_reduce},
        {"role": "user", "content": "\n\n".join(raw_matches)}
    ], config, temperature=0.2)

    return f"MATCH DETECTED:\n\n{final_alert}"

def generate_feed_overview(articles, focus_prompt, session):
    config = get_llm_config(session)
    if not config or not articles: return None

    map_p = "You are a CTI Analyst. Extract 2 core threat themes from these headlines. Be incredibly concise. Bullet points only."
    reduce_p = f"""You are an Intelligence Director. Provide a high-level situational overview based on the provided intelligence themes.
    FOCUS: {focus_prompt}
    Write a cohesive 2-paragraph briefing summarizing the overarching threat narrative. Do not list items."""

    return _map_reduce_summarize(
        articles,
        lambda a: f"- {a.source}: {a.title}",
        map_p, reduce_p, config, chunk_size=10
    )

def generate_executive_weather_brief(analytics, p1_count, sys_config):
    if not sys_config or not sys_config.get('is_active'):
        return "AI is currently disabled in settings."

    dist_data = analytics.get('district_distribution', [])
    if hasattr(dist_data, 'empty'):
        # Legacy Pandas DataFrame fallback
        dist_counts = dist_data.to_dict().get('Count', {}) if not dist_data.empty else {}
    else:
        # Handles standard Python lists and dicts
        dist_counts = dist_data if dist_data else {}

    prompt = f"""
    Analyze this weather threat data for our electrical grid infrastructure and write a 2-paragraph Executive Weather Briefing.
    Focus on the most severe risks, the operational districts most impacted, and critical (Priority 1) exposures.

    Data:
    - Total Monitored Sites: {analytics.get('total_sites', 0)}
    - Total Sites at Risk: {analytics.get('at_risk_sites', 0)}
    - Highest Current Risk Level: {analytics.get('highest_risk', 'None')}
    - Critical (P1) Sites Exposed: {p1_count}
    - Exposed Sites by District: {dist_counts}

    Tone: Professional, urgent but measured, executive summary style. No pleasantries.
    """

    return call_llm([
        {"role": "system", "content": "You are a meteorological intelligence analyst for a major utility company."},
        {"role": "user", "content": prompt}
    ], sys_config, temperature=0.2)

def build_custom_intel_report(articles, objective, session, progress_callback=None):
    config = get_llm_config(session)
    if not config or not articles: return None

    map_p = f"""Extract EVERY technical detail, IOC, targeted system, and threat actor mentioned in the text.
    Align your extraction with the User Objective: {objective}
    Provide raw, concise bullet points. No intro."""

    reduce_p = f"""You are a Senior CTI Analyst. Compile the raw intelligence below into an EXHAUSTIVE, technical report.
    OBJECTIVE: {objective}
    REQUIRED STRUCTURE:
    ## Executive Threat Summary
    ## Identified Threat Actors & TTPs
    ## Indicators of Compromise (IOCs) & Vulnerabilities
    ## Defensive Posture & Remediation
    STRICT RULES: Use ONLY the provided data. Do not hallucinate."""

    def _format_article(a):
        content = getattr(a, 'full_content', None) or getattr(a, 'summary', '') or ''
        if content and len(content) > 200:
            text = truncate_text(content, 2000)
        else:
            text = truncate_text(content, 800)
        return f"SOURCE: {a.source} | TITLE: {a.title}\nCONTENT: {text}\n\n"

    return _map_reduce_summarize(
        articles,
        _format_article,
        map_p, reduce_p, config, chunk_size=8, progress_callback=progress_callback
    )

def generate_rolling_summary(session):
    config = get_llm_config(session)
    logger.info("generate_rolling_summary: config_found=%s", config is not None)
    if not config:
        logger.warning("generate_rolling_summary: AI is disabled")
        return None

    six_hours_ago = datetime.utcnow() - timedelta(hours=6)

    arts = session.query(Article).filter(Article.published_date >= six_hours_ago, Article.score >= 50).order_by(Article.score.desc()).limit(10).all()
    hazards = session.query(RegionalHazard).filter(RegionalHazard.updated_at >= six_hours_ago).limit(10).all()
    clouds = session.query(CloudOutage).filter(CloudOutage.updated_at >= six_hours_ago).limit(10).all()
    logger.info("generate_rolling_summary: articles=%d hazards=%d clouds=%d", len(arts), len(hazards), len(clouds))

    context = "--- CYBER THREATS ---\n"
    context += "\n".join([f"- {a.title}" for a in arts]) if arts else "None."
    context += "\n\n--- PHYSICAL HAZARDS ---\n"
    context += "\n".join([f"- {h.severity}: {h.title} in {h.location}" for h in hazards]) if hazards else "None."
    context += "\n\n--- CLOUD OUTAGES ---\n"
    context += "\n".join([f"- {c.provider} ({c.service}): {c.title}" for c in clouds]) if clouds else "None."

    sys_prompt = """You are a Senior NOC Director writing a live Shift Handover Briefing.
    Synthesize the provided Cyber, Physical, and Cloud telemetry into a cohesive, fast-paced 2-paragraph executive summary. 
    Highlight any converging threats or severe degradations. Do NOT just list the items; weave them into an authoritative narrative.
    End with a single bolded sentence assessing the overall 'Grid Status' (e.g., **Grid Status: Nominal**, **Grid Status: Elevated Risk due to X**)."""

    logger.info("generate_rolling_summary: calling LLM")
    response = call_llm([{"role": "system", "content": sys_prompt}, {"role": "user", "content": context}], config, temperature=0.2)
    if response and "[WARN]" not in response:
        logger.info("generate_rolling_summary: success, response_length=%d", len(response))
    else:
        logger.error("generate_rolling_summary: LLM error: %s", response[:200] if response else "None")
    return response.strip() if response else "Generation failed."

def generate_dynamic_scoring_report(session, intel):
    from datetime import datetime, timedelta

    config = get_llm_config(session)
    logger.info("generate_dynamic_scoring_report: config_found=%s", config is not None)
    if not config:
        logger.warning("generate_dynamic_scoring_report: AI is disabled")
        return None

    t48 = datetime.utcnow() - timedelta(hours=48)
    arts = intel.get('raw_cyber_articles', []) + intel.get('raw_phys_articles', [])
    crimes = intel.get('recent_crimes', [])
    logger.info("generate_dynamic_scoring_report: arts=%d crimes=%d unified_risk=%s",
                len(arts), len(crimes), intel.get('unified_risk', 'UNKNOWN'))

    recent_cves = session.query(CveItem).filter(CveItem.date_added >= t48).limit(15).all()
    logger.info("generate_dynamic_scoring_report: recent_cves=%d", len(recent_cves))

    if not arts and not crimes and not recent_cves:
        logger.info("generate_dynamic_scoring_report: no intel to brief")
        return "No active intelligence to brief at this time."

    if arts:
        map_p = "You are a CTI Analyst. Extract the core threats, vulnerabilities, threat actors, and their reporting SOURCES from these intelligence items. Output concise bullet points."
        reduce_p = "Combine these batch extractions into a single, comprehensive intelligence digest. Ensure ALL unique threats, vulnerabilities, and their reporting SOURCES are preserved."
        cyber_digest = _map_reduce_summarize(
            arts[:25],
            lambda a: f"Source: {a.source or 'OSINT'} | Category: {a.category} | Title: {a.title} | {truncate_text(a.summary, 300)}",
            map_p, reduce_p, config, chunk_size=8
        )
    else: cyber_digest = "No active OSINT intelligence to report."

    crimes_context = "\n".join([f"- FBI Class: {c.get('fbi_category', 'Unknown')} | {c['raw_title']} ({c['distance_miles']} mi from HQ)" for c in crimes[:15]]) if crimes else "No active perimeter crime incidents."
    cve_context = "\n".join([f"- CVE: {c.cve_id} ({c.vendor}): {c.vulnerability_name}" for c in recent_cves]) if recent_cves else "No major CVEs in 48h."

    compiled_intel = f"--- CYBER INTELLIGENCE DIGEST (48H) ---\n{cyber_digest}\n\n--- CISA VULNERABILITIES (48H) ---\n{cve_context}\n\n--- ACTIVE PERIMETER INCIDENTS (24H - HQ ONLY) ---\n{crimes_context}"

    master_sys_prompt = f"""You are a Senior Threat Intelligence Briefer for a NOC Executive Dashboard.
    Write an expansive, highly detailed 'Executive Intelligence Brief' based on the provided digest.

    CRITICAL DIRECTIVES: 
    1. Do NOT calculate any scores.
    2. Do NOT reference the CIS formula.
    3. Do NOT attempt to justify mathematical ratings. 
    4. The current system threat level is **{intel.get('unified_risk', 'UNKNOWN')}**. Ensure the tone matches this severity.
    Your ONLY job is to write a cohesive, real-world narrative of what is happening across the cyber and physical domains.

    Structure your response in Markdown with these EXACT headers:

    ## Cyber Intelligence Brief
    [Write long, expansive paragraphs detailing the specific cyber threats, their reporting SOURCES, identified threat actors, and CISA vulnerabilities. Group similar threats together to tell a flowing story of the digital landscape.]

    ##  Physical & Perimeter Security Brief
    [Write long, expansive paragraphs breaking down the perimeter incidents (explicitly using the FBI UCR definitions provided) and severe weather hazards. Explain their specific proximity risk to the Headquarters facility and personnel.]

    Be expansive, professional, highly readable, and authoritative."""

    logger.info("generate_dynamic_scoring_report: calling LLM with master prompt")
    response = call_llm([
        {"role": "system", "content": master_sys_prompt},
        {"role": "user", "content": compiled_intel}
    ], config, temperature=0.3)

    if response and "[WARN]" not in response:
        logger.info("generate_dynamic_scoring_report: success, response_length=%d", len(response))
    else:
        logger.error("generate_dynamic_scoring_report: LLM error: %s", response[:200] if response else "None")
    return response.strip() if response else "Brief generation failed."

def generate_siem_triage_summary(session, flat_results):
    import json
    config = get_llm_config(session)
    if not config: return "[WARN] AI is currently disabled in settings."

    compressed_data = json.dumps(flat_results[:30])

    sys_prompt = """You are a Tier 3 SOC Analyst. Review this extracted SIEM telemetry. 
    Provide a boardroom-ready Executive Summary of the threats, followed by a bulleted list of correlated IOCs or behavioral anomalies. 
    Do not explain what JSON is. Be concise and authoritative."""

    response = call_llm([
        {"role": "system", "content": sys_prompt},
        {"role": "user", "content": f"DATA:\n{compressed_data}"}
    ], config, temperature=0.2)

    return response.strip() if response else "Triage generation failed."

def generate_elastic_dsl(session, nl_query):
    config = get_llm_config(session)
    if not config: return "{}"

    sys_prompt = """You are an Elastic SIEM engineer. Output ONLY a valid Elasticsearch JSON query body based on the user's prompt. 
    Do NOT use markdown blocks (e.g., ```json). Do NOT explain the query. Just output the raw JSON. 
    Assume standard Elastic Common Schema (ECS) fields like 'source.ip', 'event.action', 'log.level', and '@timestamp'."""

    response = call_llm([
        {"role": "system", "content": sys_prompt},
        {"role": "user", "content": nl_query}
    ], config, temperature=0.1)

    if response:
        return response.replace("```json", "").replace("```", "").strip()
    return '{"query": {"match_all": {}}}'

def generate_daily_fusion_report(session):
    config = get_llm_config(session)
    if not config: return None

    LOCAL_TZ = ZoneInfo("America/Chicago")
    start_of_yesterday = (datetime.now(LOCAL_TZ) - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    utc_start = start_of_yesterday.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
    utc_end = (start_of_yesterday + timedelta(days=1)).astimezone(ZoneInfo("UTC")).replace(tzinfo=None)

    report_date_str = start_of_yesterday.strftime('%A, %B %d, %Y')

    articles = session.query(Article).filter(Article.published_date >= utc_start, Article.published_date < utc_end, Article.score >= 80.0).limit(15).all()
    if articles:
        map_p = "Summarize the key cyber threats in these headlines. Be brief."
        reduce_p = "Combine these summaries into a cohesive, highly technical 2-paragraph situational report. Bold specific threat actors and malware."
        cyber_summary = _map_reduce_summarize(articles, lambda a: f"- [{int(a.score)}] {a.title}", map_p, reduce_p, config, chunk_size=6)
    else: cyber_summary = "No critical intelligence alerts tracked yesterday."

    cves = session.query(CveItem).filter(CveItem.date_added >= utc_start, CveItem.date_added < utc_end).limit(20).all()
    if cves:
        map_p = "Extract the vendor, product, and vulnerability name from this list. Be extremely concise."
        reduce_p = "Write a brief summary of the new vulnerabilities added to the KEV catalog. You MUST integrate the specific CVE IDs directly into your narrative."
        cve_summary = _map_reduce_summarize(cves, lambda c: f"- {c.cve_id} ({c.vendor}): {c.vulnerability_name}", map_p, reduce_p, config, chunk_size=8)
    else: cve_summary = "No new KEVs added yesterday."

    hazards = session.query(RegionalHazard).filter(RegionalHazard.updated_at >= utc_start, RegionalHazard.updated_at < utc_end).limit(15).all()
    if hazards:
        map_p = "List the severe weather events and locations."
        reduce_p = "Summarize the physical threats and weather hazards from yesterday. Highlight the most severe classifications (e.g., Warnings, High Risk)."
        hazard_summary = _map_reduce_summarize(hazards, lambda h: f"- {h.severity}: {h.title} ({h.location})", map_p, reduce_p, config, chunk_size=6)
    else: hazard_summary = "Grid operated normally with no reported hazards."

    clouds = session.query(CloudOutage).filter(CloudOutage.updated_at >= utc_start, CloudOutage.updated_at < utc_end).limit(15).all()
    if clouds:
        map_p = "List the cloud provider, service, and geographic region affected."
        reduce_p = "Summarize the major tier-1 cloud service disruptions from yesterday. Explicitly mention the geographic regions impacted and resolution status."
        cloud_summary = _map_reduce_summarize(clouds, lambda c: f"- {c.provider} ({c.service}): {c.title}", map_p, reduce_p, config, chunk_size=5)
    else: cloud_summary = "No major tier-1 cloud outages reported."

    compiled_domains = f"""
    --- CYBER INTELLIGENCE ---
    {cyber_summary}

    --- VULNERABILITY LANDSCAPE (CISA KEV) ---
    {cve_summary}

    --- PHYSICAL INFRASTRUCTURE & WEATHER ---
    {hazard_summary}

    --- CLOUD SERVICES ---
    {cloud_summary}
    """

    master_sys_prompt = f"""You are the Senior Director of a Network Operations Center (NOC).
    Take the provided domain summaries and weave them into a single, seamless, and highly professional 'Daily Fusion Report' formatted in Markdown.

    REQUIREMENTS:
    1. Start with an 'Executive Summary (BLUF)' paragraph that captures the overarching threat landscape across all domains.
    2. Create clear, distinct headers for Cyber, Vulnerabilities, Infrastructure, and Cloud.
    3. Ensure smooth narrative transitions between the sections so it reads like a single cohesive document, not a disjointed list.
    4. Preserve all specific data points (CVE numbers, threat actor names, locations, cloud providers).
    5. Do not hallucinate or add external information.

    Title the report: #  NOC Daily Fusion Report: {report_date_str}"""

    master_report = call_llm([
        {"role": "system", "content": master_sys_prompt},
        {"role": "user", "content": compiled_domains}
    ], config, temperature=0.2)

    if not master_report or "[WARN]" in master_report:
        return start_of_yesterday, f"#  NOC Daily Fusion Report: {report_date_str}\n\n##  Cyber\n{cyber_summary}\n\n##  KEVs\n{cve_summary}\n\n##  Infrastructure\n{hazard_summary}\n\n##  Cloud\n{cloud_summary}"

    return start_of_yesterday, master_report
