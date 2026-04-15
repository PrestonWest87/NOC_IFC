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

def generate_unified_risk_brief(session, global_intel, internal_snapshot):
    """Generates an exhaustive executive summary in a SINGLE FAST PASS using pre-calculated matrices."""
    import json
    from src.llm import call_llm
    
    config = get_llm_config(session)
    if not config: return "AI is currently disabled in settings."

    global_risk = global_intel.get('unified_risk', 'UNKNOWN')
    
    # --- 1. Extract Pre-Calculated Data ---
    hw_data = json.loads(internal_snapshot.hw_data_json) if internal_snapshot and internal_snapshot.hw_data_json else []
    sw_data = json.loads(internal_snapshot.sw_data_json) if internal_snapshot and internal_snapshot.sw_data_json else []
    
    # Since the Python backend already correlated and sorted these by severity,
    # we just take the top 10 most critical to feed the LLM context directly.
    top_hw = hw_data[:10]
    top_sw = sw_data[:10]
    
    cyber_arts = global_intel.get('raw_cyber_articles', [])[:6]
    phys_arts = global_intel.get('raw_phys_articles', [])[:5]
    crimes = global_intel.get('recent_crimes', [])[:5]

    # --- 2. Format Context for the LLM ---
    hw_context = "\n".join([f"- {hw['Identifier']} ({hw['OS']}): {hw['OSINT Threat Matches']} Active Exploit/OSINT Matches. Top Threat Reference: {hw['Top Threat Reference']}" for hw in top_hw]) if top_hw else "No hardware assets currently exposed to active OSINT threats."
    
    sw_context = "\n".join([f"- {sw['Software Name']}: {sw['Active OSINT Matches']} Active Exploit/OSINT Matches. Top Threat Reference: {sw['Top Threat Reference']}" for sw in top_sw]) if top_sw else "No software assets currently exposed to active OSINT threats."
    
    cyber_context = "\n".join([f"- {a.title} ({a.source})" for a in cyber_arts]) if cyber_arts else "No critical global cyber OSINT reported."
    
    phys_context = "\n".join([f"- {a.title} ({a.source})" for a in phys_arts]) if phys_arts else "No significant regional physical threats reported."
    
    crime_context = "\n".join([f"- {c['raw_title']} ({c['distance_miles']} miles away) [FBI Cat: {c.get('fbi_category', 'Unknown')}]" for c in crimes]) if crimes else "No active perimeter crimes logged."

    # --- 3. Build the Master Context String ---
    compiled_intel = f"""
    === MACRO THREAT POSTURE ===
    Overall Global Risk Level: {global_risk}
    Global Cyber Intel Brief: {global_intel.get('cyber_brief', 'N/A')}
    Global Physical Intel Brief: {global_intel.get('physical_brief', 'N/A')}
    
    Internal Risk Level: {internal_snapshot.risk_level if internal_snapshot else 'UNKNOWN'}
    Internal Total Assets: {internal_snapshot.total_assets if internal_snapshot else 0}
    Internal Assets with Active OSINT Exploits: {internal_snapshot.total_osint_hits if internal_snapshot else 0}
    
    === INTERNAL ATTACK SURFACE (TOP PRE-CALCULATED EXPOSURES) ===
    --- HARDWARE ---
    {hw_context}
    
    --- SOFTWARE ---
    {sw_context}
    
    === GLOBAL THREAT LANDSCAPE (TOP ACTIVE THREATS) ===
    --- CYBER OSINT ---
    {cyber_context}
    
    --- PHYSICAL OSINT & CRIMES ---
    {phys_context}
    {crime_context}
    """

    # --- 4. Single Pass LLM Execution ---
    master_sys_prompt = f"""You are the Chief Information Security Officer (CISO) delivering an exhaustive, boardroom-ready Unified Risk Brief.
    
    CRITICAL DIRECTIVES:
    1. Assess the Macro Threat Posture provided and set the tone accordingly. Explain the convergence of the Global and Internal risk levels.
    2. Use the provided "Top Pre-Calculated Exposures" to explicitly name the exact internal hardware and software assets exposed to OSINT threats. Detail exactly what exploits or threats are correlating with our internal systems.
    3. Break down the Global Cyber Threat landscape and directly tie it back to why it matters to the organization given our internal exposures.
    4. Address the Physical and Perimeter security posture, citing specific crime incidents and OSINT hazards.
    5. Structure the response in professional Markdown with these exact headers:
        ## Executive Summary (BLUF)
        ## Internal Attack Surface & OSINT Exposures
        ## Global Cyber Threat Landscape
        ## Physical & Perimeter Security Posture
        ## Strategic Recommendations
    6. Do NOT include any specific point calculations, raw scoring metrics, or mathematical equations. Focus purely on operational impact.
    7. Do NOT use generic filler. Be highly specific using the exact asset names, threat references, and numbers provided. Use expansive, detailed paragraphs and bulleted lists where appropriate to ensure the report is dense with actionable intelligence.
    """

    response = call_llm([
        {"role": "system", "content": master_sys_prompt},
        {"role": "user", "content": compiled_intel}
    ], config, temperature=0.3)
    
    return response.strip() if response else "Brief generation failed."

def generate_aggregated_shift_summary(session, logs, timeframe_label, target_role="All"):
    """Generates a role-bound weekly or monthly summary using Map-Reduce to handle large log volumes."""
    config = get_llm_config(session)
    if not config: return None
    
    if not logs:
        return f"No logs available to generate a {timeframe_label} summary."
        
    # ==========================================
    # TIER 1: MAP-REDUCE THE SHIFT LOGS
    # ==========================================
    map_p = f"You are analyzing logs for the '{target_role.upper()}' department. Extract the most critical incidents, outages, resolutions, and ongoing operational issues from these shift log entries. Ignore routine noise. Output concise bullet points."
    reduce_p = "Combine these batch extractions into a single, comprehensive incident digest, preserving all unique critical events and timelines."
    
    log_digest = _map_reduce_summarize(
        logs,
        lambda l: f"[{l.created_at.strftime('%Y-%m-%d %H:%M')}] {l.analyst}: {l.content}",
        map_p, reduce_p, config, chunk_size=20
    )
    
    # ==========================================
    # TIER 2: THE MASTER EDITOR
    # ==========================================
    master_sys_prompt = f"""You are a NOC Operations Manager for the {target_role.upper()} department.
    Write an Executive '{timeframe_label}' Shift Summary specifically detailing the operations of the {target_role.upper()} team based on the provided log digest.
    
    Structure the response in Markdown with these EXACT headers:
    
    ## 📅 {timeframe_label} Operational Overview: {target_role.upper()}
    [Write a 2-3 paragraph executive narrative of the team's operational tempo, major incidents, and overall stability during this period.]
    
    ## 🚨 Critical Incidents & Resolutions
    [Provide bullet points of the most impactful outages or incidents handled by this team and explicitly detail how they were resolved.]
    
    ## 🔄 Ongoing / Unresolved Issues
    [List any issues that appear to span across multiple shifts or remain active based on the logs. If none, state 'No major ongoing issues explicitly tracked.']
    
    Be professional, highly readable, and authoritative. Do NOT hallucinate incidents not present in the digest."""
    
    response = call_llm([
        {"role": "system", "content": master_sys_prompt},
        {"role": "user", "content": f"--- LOG DIGEST ---\n{log_digest}"}
    ], config, temperature=0.25)
    
    return response.strip() if response else "Summary generation failed."

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

def generate_dynamic_scoring_report(session, intel):
    """Generates an expansive intelligence brief without calculating or justifying scores."""
    from src.database import CveItem
    from datetime import datetime, timedelta
    
    config = get_llm_config(session)
    if not config: return None
    
    t48 = datetime.utcnow() - timedelta(hours=48)
    arts = intel.get('raw_cyber_articles', []) + intel.get('raw_phys_articles', [])
    crimes = intel.get('recent_crimes', [])
    
    # Grab the recent CVEs so the LLM can write about them
    recent_cves = session.query(CveItem).filter(CveItem.date_added >= t48).limit(15).all()
    
    if not arts and not crimes and not recent_cves:
        return "No active intelligence to brief at this time."

    # ==========================================
    # TIER 1: CYBER INTELLIGENCE MAP-REDUCE
    # ==========================================
    if arts:
        map_p = "You are a CTI Analyst. Extract the core threats, vulnerabilities, threat actors, and their reporting SOURCES from these intelligence items. Output concise bullet points."
        reduce_p = "Combine these batch extractions into a single, comprehensive intelligence digest. Ensure ALL unique threats, vulnerabilities, and their reporting SOURCES are preserved."
        cyber_digest = _map_reduce_summarize(
            arts[:25], 
            lambda a: f"Source: {a.source or 'OSINT'} | Category: {a.category} | Title: {a.title} | {truncate_text(a.summary, 300)}", 
            map_p, reduce_p, config, chunk_size=8
        )
    else: cyber_digest = "No active OSINT intelligence to report."

    # ==========================================
    # INFRASTRUCTURE CONTEXT (Crimes, CVEs)
    # ==========================================
    crimes_context = "\n".join([f"- FBI Class: {c.get('fbi_category', 'Unknown')} | {c['raw_title']} ({c['distance_miles']} mi from HQ)" for c in crimes[:15]]) if crimes else "No active perimeter crime incidents."
    cve_context = "\n".join([f"- CVE: {c.cve_id} ({c.vendor}): {c.vulnerability_name}" for c in recent_cves]) if recent_cves else "No major CVEs in 48h."

    compiled_intel = f"--- CYBER INTELLIGENCE DIGEST (48H) ---\n{cyber_digest}\n\n--- CISA VULNERABILITIES (48H) ---\n{cve_context}\n\n--- ACTIVE PERIMETER INCIDENTS (24H - HQ ONLY) ---\n{crimes_context}"

    # ==========================================
    # TIER 2: THE MASTER FUSION BRIEFER
    # ==========================================
    master_sys_prompt = f"""You are a Senior Threat Intelligence Briefer for a NOC Executive Dashboard.
    Write an expansive, highly detailed 'Executive Intelligence Brief' based on the provided digest.
    
    CRITICAL DIRECTIVES: 
    1. Do NOT calculate any scores.
    2. Do NOT reference the CIS formula.
    3. Do NOT attempt to justify mathematical ratings. 
    4. The current system threat level is **{intel.get('unified_risk', 'UNKNOWN')}**. Ensure the tone matches this severity.
    Your ONLY job is to write a cohesive, real-world narrative of what is happening across the cyber and physical domains.
    
    Structure your response in Markdown with these EXACT headers:
    
    ## 🛡️ Cyber Intelligence Brief
    [Write long, expansive paragraphs detailing the specific cyber threats, their reporting SOURCES, identified threat actors, and CISA vulnerabilities. Group similar threats together to tell a flowing story of the digital landscape.]
    
    ## ⚡ Physical & Perimeter Security Brief
    [Write long, expansive paragraphs breaking down the perimeter incidents (explicitly using the FBI UCR definitions provided) and severe weather hazards. Explain their specific proximity risk to the Headquarters facility and personnel.]
    
    Be expansive, professional, highly readable, and authoritative."""

    response = call_llm([
        {"role": "system", "content": master_sys_prompt}, 
        {"role": "user", "content": compiled_intel}
    ], config, temperature=0.3)
    
    return response.strip() if response else "Brief generation failed."
  
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
