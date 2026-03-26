import requests
import json
import uuid
import re
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import concurrent.futures

from src.database import SystemConfig, Article, CveItem, RegionalHazard, CloudOutage

# =====================================================================
# CORE LLM UTILITIES & MAP-REDUCE ENGINE
# =====================================================================

def get_llm_config(session):
    return session.query(SystemConfig).filter_by(is_active=True).first()

def call_llm(messages, config, temperature=0.1):
    """Universal function to call any OpenAI-compatible API with built-in Error UI surfacing."""
    headers = {"Content-Type": "application/json"}
    if config.llm_api_key:
        headers["Authorization"] = f"Bearer {config.llm_api_key}"
    
    payload = {
        "model": config.llm_model_name,
        "messages": messages,
        "temperature": temperature
    }
    
    url = config.llm_endpoint.rstrip('/') + "/chat/completions"
    
    try:
        # Increased timeout to 120 seconds to accommodate local LLM generation speeds
        response = requests.post(url, headers=headers, json=payload, timeout=120)
        response.raise_for_status()
        return response.json()['choices'][0]['message']['content']
    
    except requests.exceptions.Timeout:
        return "⚠️ **AI NETWORK ERROR:** Request timed out after 120 seconds. Is the LLM online?"
    except requests.exceptions.ConnectionError:
        return "⚠️ **AI NETWORK ERROR:** Connection Refused. Check your Endpoint URL."
    except Exception as e:
        return f"⚠️ **AI SYSTEM ERROR:** {str(e)}"

def chunk_list(data, size):
    """Helper generator to chunk lists to prevent LLM context-window overflow."""
    for i in range(0, len(data), size):
        yield data[i:i + size]

def truncate_text(text, max_chars=300):
    """Aggressively trims text to save local GPU VRAM/Context Window during Map phases."""
    if not text: return "No details provided."
    return text if len(text) <= max_chars else text[:max_chars] + "..."

def _map_reduce_summarize(items, formatter_func, map_prompt, reduce_prompt, config, chunk_size=6):
    """Universal Map-Reduce pipeline for safely processing large arrays of database objects."""
    if not items: return None
    
    batch_summaries = []
    
    # === TIER 1: MAP PHASE (Process in small chunks) ===
    for chunk in chunk_list(items, chunk_size):
        context = "\n".join([formatter_func(x) for x in chunk])
        resp = call_llm([
            {"role": "system", "content": map_prompt}, 
            {"role": "user", "content": context}
        ], config, temperature=0.1) # Low temp for strict fact extraction
        
        if resp and "⚠️" not in resp: 
            batch_summaries.append(resp)
            
    if not batch_summaries: return "AI failed to process batch."
    
    # === TIER 2: REDUCE PHASE (The Master Editor) ===
    if len(batch_summaries) > 1:
        final_context = "\n\n".join(batch_summaries)
        return call_llm([
            {"role": "system", "content": reduce_prompt}, 
            {"role": "user", "content": final_context}
        ], config, temperature=0.2) # Slightly higher temp for narrative fluidity
    else:
        return batch_summaries[0]


# =====================================================================
# TACTICAL SUMMARIES & BLUFS
# =====================================================================

def generate_bluf(article, session):
    """Generates a comprehensive, multi-domain BLUF using a single unified prompt to preserve self-attention."""
    config = get_llm_config(session)
    if not config: return None

    # Expanded truncation limit since we are doing a single context-aware call
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
    """Multi-Tier Synthesis for calculating overlap between disparate intelligence feeds."""
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

def generate_briefing(articles, session):
    """Multi-Tier Synthesis to compress a large feed into a tight 2-paragraph brief."""
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
    """Multi-Tier Synthesis: Chunks KEVs, checks stack, then writes a Master Alert."""
    config = get_llm_config(session)
    if not config: return "ERROR: AI Engine is disabled."
    if not cves: return "CLEAR: Tech stack is clear. No active KEVs found."
        
    tech_stack = config.tech_stack if config.tech_stack else "SolarWinds, Cisco SD-WAN, Microsoft Office"
    
    # MAP PHASE: Find Matches
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
            
        if "CLEAR" not in response.upper() and "⚠️" not in response:
            raw_matches.append(response.replace("MATCH:", "").strip())
        elif "ERROR:" in response.upper() or "⚠️" in response:
            error_messages.append("Batch timeout.")

    if not raw_matches: return "CLEAR: No active KEVs match internal infrastructure."

    # REDUCE PHASE: Master Editor Alert
    sys_reduce = """You are a SOC Director. Review the raw vulnerability matches and write a unified, critical Security Alert. 
    Format with bullet points. Include CVE IDs, affected internal tech, and immediate required actions."""
    
    final_alert = call_llm([
        {"role": "system", "content": sys_reduce}, 
        {"role": "user", "content": "\n\n".join(raw_matches)}
    ], config, temperature=0.2)

    return f"MATCH DETECTED:\n\n{final_alert}"

def generate_feed_overview(articles, focus_prompt, session):
    """Generates a macro-level overview using Map-Reduce for large feeds."""
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
    """Generates an executive briefing based on geospatial weather telemetry."""
    if not sys_config or not sys_config.get('is_active'):
        return "AI is currently disabled in settings."
    
    dist_counts = analytics['district_distribution'].to_dict().get('Count', {}) if not analytics['district_distribution'].empty else {}
    
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

def build_custom_intel_report(articles, objective, session):
    """Map-Reduce pipeline for EXHAUSTIVE, multi-article technical intelligence reports."""
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

    return _map_reduce_summarize(
        articles, 
        lambda a: f"SOURCE: {a.source} | TITLE: {a.title}\nCONTENT: {truncate_text(a.summary, 600)}\n\n", 
        map_p, reduce_p, config, chunk_size=3
    )
  
def generate_rolling_summary(session):
    """Generates a cohesive executive narrative scoped strictly to the last 6 hours."""
    from src.database import Article, RegionalHazard, CloudOutage 
    
    config = get_llm_config(session)
    if not config: return None
    
    six_hours_ago = datetime.utcnow() - timedelta(hours=6)
    
    # 1. Gather all domains
    arts = session.query(Article).filter(Article.published_date >= six_hours_ago, Article.score >= 50).order_by(Article.score.desc()).limit(10).all()
    hazards = session.query(RegionalHazard).filter(RegionalHazard.updated_at >= six_hours_ago).limit(10).all()
    clouds = session.query(CloudOutage).filter(CloudOutage.updated_at >= six_hours_ago).limit(10).all()

    # 2. Build Unified Context (Since 6hr volume is small, we compress it natively to save API calls)
    context = "--- CYBER THREATS ---\n"
    context += "\n".join([f"- {a.title}" for a in arts]) if arts else "None."
    context += "\n\n--- PHYSICAL HAZARDS ---\n"
    context += "\n".join([f"- {h.severity}: {h.title} in {h.location}" for h in hazards]) if hazards else "None."
    context += "\n\n--- CLOUD OUTAGES ---\n"
    context += "\n".join([f"- {c.provider} ({c.service}): {c.title}" for c in clouds]) if clouds else "None."

    # 3. Master Editor Prompt
    sys_prompt = """You are a Senior NOC Director writing a live Shift Handover Briefing.
    Synthesize the provided Cyber, Physical, and Cloud telemetry into a cohesive, fast-paced 2-paragraph executive summary. 
    Highlight any converging threats or severe degradations. Do NOT just list the items; weave them into an authoritative narrative.
    End with a single bolded sentence assessing the overall 'Grid Status' (e.g., **Grid Status: Nominal**, **Grid Status: Elevated Risk due to X**)."""

    response = call_llm([{"role": "system", "content": sys_prompt}, {"role": "user", "content": context}], config, temperature=0.2)
    return response.strip() if response else "Generation failed."
  
def generate_daily_fusion_report(session):
    """Multi-Tier Synthesis: Chunks data, summarizes domains, then uses a Master Editor for a seamless report."""
    config = get_llm_config(session)
    if not config: return None
    
    LOCAL_TZ = ZoneInfo("America/Chicago")
    start_of_yesterday = (datetime.now(LOCAL_TZ) - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    utc_start = start_of_yesterday.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
    utc_end = (start_of_yesterday + timedelta(days=1)).astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
    
    report_date_str = start_of_yesterday.strftime('%A, %B %d, %Y')
    
    from src.database import Article, CveItem, RegionalHazard, CloudOutage
    
    # ==========================================
    # TIER 1: DOMAIN-SPECIFIC MAP-REDUCE
    # ==========================================
    
    # 1. CYBER
    articles = session.query(Article).filter(Article.published_date >= utc_start, Article.published_date < utc_end, Article.score >= 80.0).limit(15).all()
    if articles:
        map_p = "Summarize the key cyber threats in these headlines. Be brief."
        reduce_p = "Combine these summaries into a cohesive, highly technical 2-paragraph situational report. Bold specific threat actors and malware."
        cyber_summary = _map_reduce_summarize(articles, lambda a: f"- [{int(a.score)}] {a.title}", map_p, reduce_p, config, chunk_size=6)
    else: cyber_summary = "No critical intelligence alerts tracked yesterday."

    # 2. VULNERABILITIES
    cves = session.query(CveItem).filter(CveItem.date_added >= utc_start, CveItem.date_added < utc_end).limit(20).all()
    if cves:
        map_p = "Extract the vendor, product, and vulnerability name from this list. Be extremely concise."
        reduce_p = "Write a brief summary of the new vulnerabilities added to the KEV catalog. You MUST integrate the specific CVE IDs directly into your narrative."
        cve_summary = _map_reduce_summarize(cves, lambda c: f"- {c.cve_id} ({c.vendor}): {c.vulnerability_name}", map_p, reduce_p, config, chunk_size=8)
    else: cve_summary = "No new KEVs added yesterday."

    # 3. INFRASTRUCTURE
    hazards = session.query(RegionalHazard).filter(RegionalHazard.updated_at >= utc_start, RegionalHazard.updated_at < utc_end).limit(15).all()
    if hazards:
        map_p = "List the severe weather events and locations."
        reduce_p = "Summarize the physical threats and weather hazards from yesterday. Highlight the most severe classifications (e.g., Warnings, High Risk)."
        hazard_summary = _map_reduce_summarize(hazards, lambda h: f"- {h.severity}: {h.title} ({h.location})", map_p, reduce_p, config, chunk_size=6)
    else: hazard_summary = "Grid operated normally with no reported hazards."

    # 4. CLOUD
    clouds = session.query(CloudOutage).filter(CloudOutage.updated_at >= utc_start, CloudOutage.updated_at < utc_end).limit(15).all()
    if clouds:
        map_p = "List the cloud provider, service, and geographic region affected."
        reduce_p = "Summarize the major tier-1 cloud service disruptions from yesterday. Explicitly mention the geographic regions impacted and resolution status."
        cloud_summary = _map_reduce_summarize(clouds, lambda c: f"- {c.provider} ({c.service}): {c.title}", map_p, reduce_p, config, chunk_size=5)
    else: cloud_summary = "No major tier-1 cloud outages reported."

    # ==========================================
    # TIER 2: THE MASTER EDITOR
    # ==========================================
    
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
    
    Title the report: # 📊 NOC Daily Fusion Report: {report_date_str}"""

    master_report = call_llm([
        {"role": "system", "content": master_sys_prompt}, 
        {"role": "user", "content": compiled_domains}
    ], config, temperature=0.2)

    if not master_report or "⚠️" in master_report:
        # Fallback to basic concatenation if the Master Editor fails
        return start_of_yesterday, f"# 📊 NOC Daily Fusion Report: {report_date_str}\n\n## 📰 Cyber\n{cyber_summary}\n\n## 🪲 KEVs\n{cve_summary}\n\n## 🗺️ Infrastructure\n{hazard_summary}\n\n## ☁️ Cloud\n{cloud_summary}"

    return start_of_yesterday, master_report
