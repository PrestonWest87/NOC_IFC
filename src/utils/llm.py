import logging
import requests
import json
from types import SimpleNamespace
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from src.models.schema import SystemConfig, Article, CveItem, RegionalHazard, CloudOutage

logger = logging.getLogger(__name__)
LOCAL_TZ = ZoneInfo("America/Chicago")

def get_llm_config(session):
    config = session.query(SystemConfig).filter_by(is_active=True).first()
    logger.debug("get_llm_config: found=%s endpoint=%s model=%s", config is not None,
                 config.llm_endpoint if config else 'N/A',
                 config.llm_model_name if config else 'N/A')
    return config

def call_llm(messages, config, temperature=0.1):
    if isinstance(config, dict):
        config = SimpleNamespace(**config)
    headers = {"Content-Type": "application/json"}
    if config.llm_api_key:
        headers["Authorization"] = f"Bearer {config.llm_api_key}"

    payload = {
        "model": config.llm_model_name,
        "messages": messages,
        "temperature": temperature
    }

    url = config.llm_endpoint.rstrip('/') + "/chat/completions"
    logger.debug("call_llm: url=%s model=%s messages_count=%d", url, config.llm_model_name, len(messages))

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=120)
        response.raise_for_status()
        result = response.json()['choices'][0]['message']['content']
        logger.debug("call_llm: success, response_length=%d", len(result))
        return result

    except requests.exceptions.Timeout:
        logger.error("call_llm: timeout after 120s to %s", url)
        return "[WARN] **AI NETWORK ERROR:** Request timed out after 120 seconds. Is the LLM online?"
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

def _map_reduce_summarize(items, formatter_func, map_prompt, reduce_prompt, config, chunk_size=6):
    if not items: return None

    batch_summaries = []

    for chunk in chunk_list(items, chunk_size):
        context = "\n".join([formatter_func(x) for x in chunk])
        resp = call_llm([
            {"role": "system", "content": map_prompt},
            {"role": "user", "content": context}
        ], config, temperature=0.1)

        if resp and "[WARN]" not in resp:
            batch_summaries.append(resp)

    if not batch_summaries: return "AI failed to process batch."

    if len(batch_summaries) > 1:
        final_context = "\n\n".join(batch_summaries)
        return call_llm([
            {"role": "system", "content": reduce_prompt},
            {"role": "user", "content": final_context}
        ], config, temperature=0.2)
    else:
        return batch_summaries[0]

def generate_bluf(article, session):
    config = get_llm_config(session)
    if not config: return None

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

def generate_unified_risk_brief(session, global_intel, internal_snapshot):
    """Generates an exhaustive, unembellished OSINT risk brief translated for an executive audience."""
    import json

    config = get_llm_config(session)
    if not config:
        logger.warning("generate_unified_risk_brief: AI is disabled, skipping")
        return "AI is currently disabled in settings."

    global_risk = global_intel.get('unified_risk', 'UNKNOWN')
    internal_risk = internal_snapshot.risk_level if internal_snapshot else 'NONE'

    logger.info("generate_unified_risk_brief: global_risk=%s internal_risk=%s", global_risk, internal_risk)

    t48 = datetime.utcnow() - timedelta(hours=48)

    recent_cves = session.query(CveItem).filter(CveItem.date_added >= t48).limit(30).all()
    active_hazards = session.query(RegionalHazard).filter(RegionalHazard.updated_at >= t48).limit(30).all()
    cloud_outages = session.query(CloudOutage).filter(CloudOutage.updated_at >= t48).limit(20).all()

    hw_data = json.loads(internal_snapshot.hw_data_json) if internal_snapshot and internal_snapshot.hw_data_json else []
    sw_data = json.loads(internal_snapshot.sw_data_json) if internal_snapshot and internal_snapshot.sw_data_json else []
    top_hw = hw_data[:20]
    top_sw = sw_data[:20]

    cyber_arts = global_intel.get('raw_cyber_articles', [])[:30]
    phys_arts = global_intel.get('raw_phys_articles', [])[:20]
    crimes = global_intel.get('recent_crimes', [])[:20]

    cyber_payload = []
    for a in cyber_arts:
        cyber_payload.append(f"OSINT Article - Title: {a.title} | Source: {a.source} | Summary: {truncate_text(a.summary, 300)}")
    for c in recent_cves:
        cyber_payload.append(f"CISA KEV - CVE: {c.cve_id} | Vendor: {c.vendor} | Product: {c.product} | Vuln: {c.vulnerability_name}")
    for cl in cloud_outages:
        state = "Resolved" if cl.is_resolved else "Active/Ongoing"
        cyber_payload.append(f"Cloud Outage - Provider: {cl.provider} | Service: {cl.service} | Status: {state} | Details: {cl.title}")

    if cyber_payload:
        map_p = "Extract factual data points regarding threat actors, vulnerabilities (CVEs), cloud service disruptions, and active exploits. DO NOT embellish. Use strict bullet points."
        reduce_p = "Compile an exhaustive, purely factual Cyber Threat Intelligence digest. Preserve all CVE IDs, specific threat actor names, targeted vendors, and cloud providers. Do not extrapolate risks; report only what is explicitly stated in the data."
        cyber_digest = _map_reduce_summarize(
            cyber_payload, lambda x: x, map_p, reduce_p, config, chunk_size=15
        )
    else:
        cyber_digest = "No active cyber OSINT, KEVs, or cloud outages reported in the last 48 hours."

    phys_payload = []
    for a in phys_arts:
        phys_payload.append(f"Physical Intel - Title: {a.title} | Source: {a.source}")
    for h in active_hazards:
        phys_payload.append(f"Weather/Hazard - Alert: {h.title} | Severity: {h.severity} | Location: {h.location} | Details: {truncate_text(h.description, 200)}")
    for c in crimes:
        phys_payload.append(f"Perimeter Crime - Type: {c.get('raw_title', 'Unknown')} | Distance from HQ: {c.get('distance_miles', 0)} miles | FBI Category: {c.get('fbi_category', 'Unknown')}")

    if phys_payload:
        map_p = "Extract precise factual details regarding weather severity, regional infrastructure hazards, and perimeter crimes (including distance and FBI categories). Be purely objective."
        reduce_p = "Compile an exhaustive physical risk digest. Categorize strictly into: 1) Severe Weather/Geospatial Hazards and 2) Local Perimeter Crimes. Retain exact distances, locations, and severity classifications. DO NOT embellish."
        phys_digest = _map_reduce_summarize(
            phys_payload, lambda x: x, map_p, reduce_p, config, chunk_size=15
        )
    else:
        phys_digest = "No significant weather hazards, regional disruptions, or perimeter crimes reported."

    hw_context = "\n".join([f"- {hw.get('Identifier', 'Unknown')} ({hw.get('OS', 'Unknown')}): {hw.get('OSINT Threat Matches', 0)} Matches. Threat Ref: {hw.get('Top Threat Reference', 'None')}" for hw in top_hw if hw.get('OSINT Threat Matches', 0) > 0]) or "No hardware vulnerabilities correlated with active OSINT."
    sw_context = "\n".join([f"- {sw.get('Software Name', 'Unknown')}: {sw.get('Active OSINT Matches', 0)} Matches. Threat Ref: {sw.get('Top Threat Reference', 'None')}" for sw in top_sw if sw.get('Active OSINT Matches', 0) > 0]) or "No software vulnerabilities correlated with active OSINT."

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
    """

    master_sys_prompt = f"""You are the Chief Information Security Officer (CISO) delivering a high-impact, Unified OSINT Risk Digest to the Board of Directors and non-technical executives.

    CRITICAL FORMATTING & TONE DIRECTIVES:
    1. VISUAL HIERARCHY: DO NOT use wall-of-text paragraphs. You MUST use bolding for emphasis, bulleted lists for all data points, and blockquotes for critical warnings. Make the report highly scannable.
    2. OPERATIONAL TRANSLATION: For every vulnerability or threat, explicitly state the "So What?" (e.g., instead of just listing "ZDI-26-339", explain that it "could allow unauthorized users to gain administrative control over our Windows fleet, leading to data exfiltration").
    3. MANDATORY DISCLAIMER: The very first thing under the Executive Summary must be this exact blockquote:
        **OSINT CORRELATION DISCLAIMER:** This brief correlates external Open-Source Intelligence (OSINT) with our internal asset types to provide situational awareness. It highlights potential external exposures and does NOT represent confirmed internal breaches or active system compromises.
    4. THREAT LEVEL TERMINOLOGY: When referring to threat levels or risk levels, you MUST strictly use the terms: Low, Guarded, Elevated, High, or Severe. Do NOT use colors (e.g., yellow, blue, red) to describe threat levels.
    5. EXPAND THE NARRATIVE: Do not just regurgitate the data. Synthesize it. Group similar threats together (e.g., group all ransomware actors, group all weather events) and explain their overarching threat to business continuity, personnel safety, or infrastructure.

    REQUIRED STRUCTURE:
    ## Executive OSINT Summary (BLUF)
    [Insert the Mandatory Disclaimer here]
    * Provide a 3-4 sentence high-level narrative explaining the convergence of the Global and Internal risk levels (using only the terminology: Low, Guarded, Elevated, High, Severe).
    * Follow with a bulleted list of the "Top 3 Immediate Concerns" across all domains.

    ## Internal Asset Threat Correlations (OSINT Overlaps)
    * Use a structured bulleted list for each exposed asset.
    * Format as: **[Asset Name]**: [Vulnerability/CVE] - *[Specific Business/Operational Impact]*

    ## Global Cyber & Cloud Threat Landscape
    * Break this into two sub-bulleted sections: **Active Cyber Threats** (Ransomware, Malicious Campaigns) and **Cloud & Infrastructure Disruptions**.
    * Detail the specific threat actors, CISA KEVs, and affected cloud providers. Explain how these trends threaten our specific industry or supply chain.

    ## Physical, Weather & Perimeter Posture
    * Break into two sub-bulleted sections: **Regional Weather Hazards** and **Local Perimeter Crimes**.
    * List exact distances, severity levels, and FBI categories. Explain the threat to facility operations, power stability, and personnel safety.

    ## Strategic Defensive Recommendations
    * Provide 3-5 highly actionable, executive-level directives (e.g., "Initiate emergency patching for Adobe products," "Review facility lockdown procedures due to perimeter crime spike").
    """

    logger.info("generate_unified_risk_brief: calling LLM with master prompt")
    response = call_llm([
        {"role": "system", "content": master_sys_prompt},
        {"role": "user", "content": compiled_intel}
    ], config, temperature=0.35)

    if response and "[WARN]" not in response:
        logger.info("generate_unified_risk_brief: success, response_length=%d", len(response))
    else:
        logger.error("generate_unified_risk_brief: LLM returned error: %s", response[:200] if response else "None")

    return response.strip() if response else "Brief generation failed."

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

    map_p = f"You are analyzing logs for the '{target_role.upper()}' department. Extract the most critical incidents, outages, resolutions, and ongoing operational issues from these shift log entries. Ignore routine noise. Output concise bullet points."
    reduce_p = "Combine these batch extractions into a single, comprehensive incident digest, preserving all unique critical events and timelines."

    logger.info("generate_aggregated_shift_summary: running map-reduce on %d logs (chunk_size=20)", len(logs))
    log_digest = _map_reduce_summarize(
        logs,
        lambda l: f"[{(l.created_at.replace(tzinfo=ZoneInfo('UTC')).astimezone(LOCAL_TZ) if l.created_at else 'Unknown')}] {l.analyst}: {l.content}",
        map_p, reduce_p, config, chunk_size=20
    )
    logger.info("generate_aggregated_shift_summary: map-reduce digest_length=%d", len(log_digest) if log_digest else 0)

    master_sys_prompt = f"""You are a NOC Operations Manager for the {target_role.upper()} department.
    Write an Executive '{timeframe_label}' Shift Summary specifically detailing the operations of the {target_role.upper()} team based on the provided log digest.

    Structure the response in Markdown with these EXACT headers:

    ##  {timeframe_label} Operational Overview: {target_role.upper()}
    [Write a 2-3 paragraph executive narrative of the team's operational tempo, major incidents, and overall stability during this period.]

    ## [ALERT] Critical Incidents & Resolutions
    [Provide bullet points of the most impactful outages or incidents handled by this team and explicitly detail how they were resolved.]

    ##  Ongoing / Unresolved Issues
    [List any issues that appear to span across multiple shifts or remain active based on the logs. If none, state 'No major ongoing issues explicitly tracked.']

    Be professional, highly readable, and authoritative. Do NOT hallucinate incidents not present in the digest."""

    logger.info("generate_aggregated_shift_summary: calling final LLM for master summary")
    response = call_llm([
        {"role": "system", "content": master_sys_prompt},
        {"role": "user", "content": f"--- LOG DIGEST ---\n{log_digest}"}
    ], config, temperature=0.25)

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

def build_custom_intel_report(articles, objective, session):
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
