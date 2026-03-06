import requests
import json
import uuid
import re
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from src.database import SystemConfig, Article

def get_llm_config(session):
    return session.query(SystemConfig).filter_by(is_active=True).first()

def call_llm(messages, config, temperature=0.1):
    """Universal function to call any OpenAI-compatible API. 
    Temperature is set very low (0.1) to prevent the Phi model from hallucinating facts."""
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
        response = requests.post(url, headers=headers, json=payload, timeout=180)
        response.raise_for_status()
        return response.json()['choices'][0]['message']['content']
    except Exception as e:
        print(f"LLM API Error: {e}")
        return None

def generate_bluf(article, session):
    """Generates a highly structured Bottom Line Up Front for a single article."""
    config = get_llm_config(session)
    if not config: return None
    
    system_prompt = """You are a Senior OSINT Analyst delivering a brief to a Network Operations Center. 
Extract the most critical, actionable details from the provided text. Maintain a clinical, objective, and highly technical tone. 
You MUST format your response EXACTLY using the following Markdown structure. Do not add conversational filler.

**Incident:** [1-2 sentence objective summary of what happened]
**Threat Vectors:** [List specific malware names, CVEs, physical weapons, or vulnerabilities. If none, state "Unspecified"]
**Target Sector:** [Specific industry, organization, or geographic location affected]
**Operational Posture:** [1 actionable defensive step or monitoring recommendation based on the text]"""

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Title: {article.title}\nSummary: {article.summary}"}
    ]
    # Temperature 0.1 ensures Phi sticks strictly to the formatting template
    return call_llm(messages, config, temperature=0.1)

def analyze_cascading_impacts(articles, session):
    """Looks for intersecting weather/infrastructure events."""
    config = get_llm_config(session)
    if not config or not articles: return None
    
    context = "\n".join([f"- {a.title}: {a.summary[:200]}" for a in articles])
    system_prompt = """You are an infrastructure risk modeling AI monitoring the Central US grid and regional networks. 
Review the following recent events. Identify any direct or secondary intersecting risks (e.g., severe weather overlapping with power/telecom outages, or physical security vulnerabilities). 

Output your analysis strictly under these two headers:
**Identified Intersections:** [Use bullet points to list overlapping threats]
**Cascading Risk Assessment:** [A short, clinical paragraph detailing the potential fallout]

If no overlaps exist, output exactly: "No cascading physical or cyber intersections identified currently." """

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Recent Events:\n{context}"}
    ]
    return call_llm(messages, config, temperature=0.1)

def generate_briefing(articles, session):
    """Reads top articles and writes a synthesized brief."""
    config = get_llm_config(session)
    if not config or not articles: 
        return None
    
    context = "\n\n".join([f"Title: {a.title}\nSummary: {a.summary[:300]}\nSource: {a.source}" for a in articles])
    system_prompt = """You are a Lead Intelligence Analyst. Synthesize the provided critical infrastructure news events into a single, cohesive 2-paragraph morning briefing. 
Highlight connections between regional physical events (like weather or grid status) and cyber threats. Write a fluid, authoritative narrative. Do not use bullet points."""
    
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Here are the top events:\n\n{context}"}
    ]
    return call_llm(messages, config, temperature=0.3)
  
def cross_reference_cves(cves, session):
    """Checks recent CVEs against the dynamically configured NOC tech stack."""
    config = get_llm_config(session)
    if not config or not cves: return None
    
    # --- NEW: Pull stack from the database, fallback to defaults if empty ---
    tech_stack = config.tech_stack if config.tech_stack else "SolarWinds, Cisco SD-WAN, Microsoft Office, Verizon, Cisco"
    
    cve_context = "\n".join([f"- {c.cve_id} ({c.vendor} {c.product}): {c.vulnerability_name}" for c in cves])
    
    system_prompt = f"""You are a NOC Security Auditor. Cross-reference the following newly exploited CVEs against this specific internal tech stack: {tech_stack}.
    
    If ANY of the CVEs match or likely impact the technologies in the stack, generate a critical alert detailing the CVE and the affected internal system. 
    If NO CVEs match the stack, output exactly: "Tech stack is clear. No active KEVs match internal infrastructure." """
    
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Recent KEVs:\n{cve_context}"}
    ]
    return call_llm(messages, config, temperature=0.1)

def generate_feed_overview(articles, focus_prompt, session):
    """Generates a macro-level overview of a batch of articles."""
    config = get_llm_config(session)
    if not config or not articles: return None

    # Keep context tight for the small LLM: Just Score, Title, and Source
    context = "\n".join([f"- [{int(a.score)}] {a.source}: {a.title}" for a in articles])

    system_prompt = f"""You are a NOC Intelligence Director. Your task is to provide a high-level situational overview based on the provided list of recent articles.
    
    FOCUS: {focus_prompt}
    
    Write a cohesive, 2-3 paragraph briefing summarizing the overarching themes, notable threat actors, and primary systems currently in the news cycle. 
    Do NOT list the articles individually. Synthesize the broader narrative based on the provided titles."""

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"RAW DATA:\n{context}"}
    ]
    
    return call_llm(messages, config, temperature=0.2)

def build_custom_intel_report(articles, objective, session):
    """Generates an EXHAUSTIVE technical intelligence report strictly bound to the selected articles."""
    config = get_llm_config(session)
    if not config or not articles: return None
    
    context_payload = ""
    for a in articles:
        clean_summary = a.summary.replace('\n', ' ') if a.summary else "No summary."
        context_payload += f"--- SOURCE: {a.source} | DATE: {a.published_date.strftime('%Y-%m-%d')} ---\n"
        context_payload += f"TITLE: {a.title}\nCONTENT: {clean_summary}\n\n"
        
    system_prompt = f"""You are a Senior Cyber Intelligence Analyst. Your task is to write a highly technical, EXHAUSTIVE, and lengthy intelligence report based STRICTLY on the provided raw article data and the user's objective. 

Do not summarize briefly; extract EVERY available technical detail, timeline, and quote from the source text.

USER OBJECTIVE: {objective}

REQUIRED REPORT STRUCTURE (Use exact Markdown headers):
## Executive Summary
(A comprehensive overview of the threat, vulnerability, or incident detailed in the articles)

## Affected Systems, Software & Versions
(List EVERY specific software name, hardware appliance, operating system, protocol, architecture, and exact version number mentioned in the text. Be exhaustive.)

## Indicators of Compromise (IOCs) & Attack Vectors
(Extract all IP addresses, file hashes, domains, CVE numbers, and specific attack signatures or tactics mentioned. If none are explicitly stated, write "No explicit IOCs provided in the source data.")

## Remediation & Mitigation Steps
(Detail every specific patch, workaround, defensive action, or configuration change recommended in the text)

## Detailed Technical Analysis
(A lengthy, deep-dive analysis of the attack vector, threat actor tactics, vulnerabilities, and potential impacts based on the text)

STRICT RULES:
1. NO HALLUCINATIONS: You must ONLY use the information provided in the raw article data below.
2. DO NOT invent IOCs or version numbers. 
3. Cite your sources inline using the provided Source names.
4. Output ONLY the Markdown report."""

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"RAW ARTICLE DATA:\n{context_payload}"}
    ]
    
    return call_llm(messages, config, temperature=0.1)
  
def generate_rolling_summary(session):
    """Generates a continuous, rolling situational narrative using a miniaturized chunked strategy."""
    from src.database import Article, RegionalHazard, CloudOutage 
    from datetime import datetime, timedelta
    
    config = get_llm_config(session)
    if not config: return None
    
    twenty_four_hours_ago = datetime.utcnow() - timedelta(days=1)
    master_report = ""
    
    # =====================================================================
    # CHUNK 1: CYBER INTEL
    # =====================================================================
    arts = session.query(Article).filter(
        Article.published_date >= twenty_four_hours_ago, 
        Article.score >= 50
    ).order_by(Article.score.desc()).limit(10).all()
    
    master_report += "**📰 Cyber Intelligence:** "
    if arts:
        context = "\n".join([f"- {a.source}: {a.title}" for a in arts])
        prompt = f"You are a NOC Analyst. Write a 1-sentence summary of the following high-threat cyber intelligence events from the last 24 hours. Be extremely concise.\n\nRAW DATA:\n{context}"
        response = call_llm([{"role": "user", "content": prompt}], config, temperature=0.1)
        master_report += f"{response.strip() if response else 'Generation failed.'}\n\n"
    else:
        master_report += "No high-threat cyber intelligence tracked in the last 24 hours.\n\n"

    # =====================================================================
    # CHUNK 2: REGIONAL HAZARDS
    # =====================================================================
    hazards = session.query(RegionalHazard).filter(RegionalHazard.updated_at >= twenty_four_hours_ago).all()
    
    master_report += "**🗺️ Regional Hazards:** "
    if hazards:
        context = "\n".join([f"- {h.severity}: {h.title} in {h.location}" for h in hazards])
        prompt = f"You are a Physical Security Dispatcher. Write a 1-sentence summary of the following weather and physical hazards from the last 24 hours. Do not invent weather.\n\nRAW DATA:\n{context}"
        response = call_llm([{"role": "user", "content": prompt}], config, temperature=0.1)
        master_report += f"{response.strip() if response else 'Generation failed.'}\n\n"
    else:
        master_report += "The regional physical grid is clear.\n\n"

    # =====================================================================
    # CHUNK 3: CLOUD OUTAGES
    # =====================================================================
    clouds = session.query(CloudOutage).filter(CloudOutage.updated_at >= twenty_four_hours_ago).all()
    
    master_report += "**☁️ Cloud Services:** "
    if clouds:
        context = "\n".join([f"- {c.provider}: {c.title}" for c in clouds])
        prompt = f"You are a Network Operations Engineer. Write a 1-sentence summary of the following cloud provider outages from the last 24 hours.\n\nRAW DATA:\n{context}"
        response = call_llm([{"role": "user", "content": prompt}], config, temperature=0.1)
        master_report += f"{response.strip() if response else 'Generation failed.'}\n"
    else:
        master_report += "All monitored tier-1 cloud providers are operating normally.\n"

    return master_report.strip()
        
def generate_daily_fusion_report(session):
    """Chunks yesterday's data by category and generates a master briefing."""
    config = get_llm_config(session)
    if not config: return None
    
    # Define "Yesterday" boundaries (Midnight to Midnight)
    LOCAL_TZ = ZoneInfo("America/Chicago")
    now_local = datetime.now(LOCAL_TZ)
    yesterday_local = now_local - timedelta(days=1)
    
    start_of_yesterday = yesterday_local.replace(hour=0, minute=0, second=0, microsecond=0)
    end_of_yesterday = start_of_yesterday + timedelta(days=1)
    
    # Convert back to UTC for database querying
    utc_start = start_of_yesterday.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
    utc_end = end_of_yesterday.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
    
    report_date_str = start_of_yesterday.strftime('%A, %B %d, %Y')
    master_report = f"# 📊 Daily NOC Fusion Report: {report_date_str}\n\n"
    
    # =====================================================================
    # CHUNK 1: RSS CYBER INTELLIGENCE (Score > 80)
    # =====================================================================
    from src.database import Article, CveItem, RegionalHazard, CloudOutage
    articles = session.query(Article).filter(
        Article.published_date >= utc_start, 
        Article.published_date < utc_end,
        Article.score >= 80.0
    ).order_by(Article.score.desc()).limit(15).all()
    
    master_report += "## 📰 1. High-Priority Cyber Intelligence\n"
    if articles:
        context = "\n".join([f"- [{int(a.score)}] {a.title}: {a.summary[:200]}" for a in articles])
        prompt = f"You are a NOC Executive Analyst. Summarize the following high-priority cyber intelligence events from yesterday into a concise, professional 2-3 paragraph situational report. Focus on threat actor activity and major breaches. DO NOT use markdown headers, just paragraphs.\n\nRaw Data:\n{context}"
        response = call_llm([{"role": "system", "content": prompt}], config, temperature=0.2)
        master_report += f"{response if response else 'AI generation failed for this section.'}\n\n"
    else:
        master_report += "*No intelligence alerts scored above the critical 80 threshold yesterday.*\n\n"

    # =====================================================================
    # CHUNK 2: VULNERABILITIES (CISA KEV)
    # =====================================================================
    cves = session.query(CveItem).filter(
        CveItem.date_added >= utc_start, 
        CveItem.date_added < utc_end
    ).all()
    
    master_report += "## 🪲 2. Known Exploited Vulnerabilities (KEV)\n"
    if cves:
        context = "\n".join([f"- {c.cve_id} ({c.vendor} {c.product}): {c.vulnerability_name}" for c in cves])
        prompt = f"You are a Security Auditor. Review the following vulnerabilities that were added to the CISA Known Exploited list yesterday. Write a brief summary paragraph of the risk landscape, followed by a bulleted list of the specific technologies affected.\n\nRaw Data:\n{context}"
        response = call_llm([{"role": "system", "content": prompt}], config, temperature=0.1)
        master_report += f"{response if response else 'AI generation failed for this section.'}\n\n"
    else:
        master_report += "*No new actively exploited vulnerabilities were cataloged by CISA yesterday.*\n\n"

    # =====================================================================
    # CHUNK 3: REGIONAL HAZARDS
    # =====================================================================
    hazards = session.query(RegionalHazard).filter(
        RegionalHazard.updated_at >= utc_start, 
        RegionalHazard.updated_at < utc_end
    ).all()
    
    master_report += "## 🗺️ 3. Regional Physical Infrastructure\n"
    if hazards:
        context = "\n".join([f"- {h.severity} {h.title} affecting {h.location}" for h in hazards])
        prompt = f"You are a Physical Security Dispatcher. Summarize the following weather and physical hazards from yesterday affecting the regional grid. Keep it brief and focused on potential impacts to power or travel.\n\nRaw Data:\n{context}"
        response = call_llm([{"role": "system", "content": prompt}], config, temperature=0.2)
        master_report += f"{response if response else 'AI generation failed for this section.'}\n\n"
    else:
        master_report += "*The regional physical grid remained clear with no major hazard alerts.*\n\n"

    # =====================================================================
    # CHUNK 4: CLOUD OUTAGES
    # =====================================================================
    outages = session.query(CloudOutage).filter(
        CloudOutage.updated_at >= utc_start, 
        CloudOutage.updated_at < utc_end
    ).all()
    
    master_report += "## ☁️ 4. Cloud Services & Backbone\n"
    if outages:
        context = "\n".join([f"- {o.provider} ({o.service}): {o.title}. Resolved: {o.is_resolved}" for o in outages])
        prompt = f"You are a Network Operations Engineer. Summarize the following cloud provider outages (AWS, GCP, Azure, Cisco) from yesterday. Note which systems were affected and if they were resolved.\n\nRaw Data:\n{context}"
        response = call_llm([{"role": "system", "content": prompt}], config, temperature=0.1)
        master_report += f"{response if response else 'AI generation failed for this section.'}\n\n"
    else:
        master_report += "*No major outages were reported across monitored tier-1 cloud providers yesterday.*\n\n"

    return start_of_yesterday, master_report