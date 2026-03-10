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

# =====================================================================
# TACTICAL SUMMARIES & BLUFS
# =====================================================================

def generate_bluf(article, session):
    """Generates a highly structured BLUF for a single article."""
    config = get_llm_config(session)
    if not config: return None
    
    system_prompt = """You are a Tactical OSINT Analyst. Extract the actionable intelligence from the provided text. Maintain a clinical, objective, and highly technical tone. 
You MUST format your response EXACTLY using the following Markdown structure. Do not add conversational filler.

**Incident:** [1-2 sentence objective summary]
**Threat Actor / TTPs:** [Specific actors, malware, or tactics. If none, state "Unspecified"]
**Target Vector:** [Specific industry, system, or geographic location]
**Intelligence Posture:** [1 actionable defensive or monitoring recommendation]"""

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Title: {article.title}\nSummary: {article.summary}"}
    ]
    return call_llm(messages, config, temperature=0.1)

def analyze_cascading_impacts(articles, session):
    """Looks for intersecting weather/infrastructure/cyber events using chunking."""
    config = get_llm_config(session)
    if not config or not articles: return None
    
    system_prompt = """You are a Strategic Threat Intelligence Analyst monitoring critical infrastructure. 
Review the events and identify converging threats (e.g., severe weather overlapping with cyber vulnerabilities). 
Output your analysis strictly under these two headers:
**Converging Threat Vectors:** [Bullet points of overlapping risks]
**Cascading Fallout Assessment:** [Short paragraph detailing potential operational degradation]
If no overlaps exist, output: "No cascading operational intersections identified." """

    # Map-Reduce Strategy for large lists
    context = "\n".join([f"- {a.title}: {a.summary[:150]}" for a in articles[:15]]) # Hard cap to prevent overflow
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Recent Events:\n{context}"}
    ]
    return call_llm(messages, config, temperature=0.1)

def generate_briefing(articles, session):
    """Reads top articles and writes a synthesized brief."""
    config = get_llm_config(session)
    if not config or not articles: return None
    
    context = "\n\n".join([f"Title: {a.title}\nSource: {a.source}" for a in articles[:20]])
    system_prompt = """You are an All-Source Intelligence Director. Synthesize the provided intelligence events into a single, cohesive 2-paragraph situational briefing. 
Highlight threat actor campaigns, systemic vulnerabilities, and geopolitical drivers. Write a fluid, authoritative narrative."""
    
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Raw Intelligence:\n\n{context}"}
    ]
    return call_llm(messages, config, temperature=0.3)
  
def cross_reference_cves(cves, session):
    """Checks recent CVEs against the tech stack using safe chunking."""
    config = get_llm_config(session)
    if not config: return "ERROR: AI Engine is disabled."
    if not cves: return "CLEAR: Tech stack is clear. No active KEVs found."
        
    tech_stack = config.tech_stack if config.tech_stack else "SolarWinds, Cisco SD-WAN, Microsoft Office"
    
    system_prompt = f"""You are a Cyber Threat Intelligence (CTI) Analyst. Cross-reference these Actively Exploited Vulnerabilities (KEVs) against the internal stack.
INTERNAL TECH STACK: {tech_stack}

INSTRUCTIONS:
1. If a KEV targets a vendor/product in the TECH STACK, output a critical alert starting with "MATCH:" followed by the CVE ID and impact.
2. If NO direct matches exist, output exactly: "CLEAR: No active KEVs match internal infrastructure." """

    all_matches = []
    error_messages = []
    
    # Process in extremely safe chunks of 15 CVEs
    for chunk in chunk_list(cves, 15):
        cve_context = "\n".join([f"- {c.cve_id} ({c.vendor} {c.product}): {c.vulnerability_name}" for c in chunk])
        messages = [{"role": "system", "content": system_prompt}, {"role": "user", "content": f"KEV Batch:\n{cve_context}"}]
        
        response = call_llm(messages, config, temperature=0.1)
        if not response: continue
            
        if "MATCH:" in response.upper():
            all_matches.append(response.replace("MATCH:", "").strip())
        elif "ERROR:" in response.upper() or "⚠️" in response:
            error_messages.append("Batch timeout.")

    if all_matches:
        return "MATCH:\n" + "\n\n---\n\n".join(all_matches)
    elif error_messages:
        return "ERROR: Network timeouts occurred during KEV scan."
    else:
        return "CLEAR: No active KEVs match internal infrastructure."

def generate_feed_overview(articles, focus_prompt, session):
    """Generates a macro-level overview using Map-Reduce for large feeds."""
    config = get_llm_config(session)
    if not config or not articles: return None

    # Step 1: Map (Extract key themes from batches of 20)
    batch_summaries = []
    for chunk in chunk_list(articles, 20):
        context = "\n".join([f"- {a.source}: {a.title}" for a in chunk])
        sys_map = "You are a CTI Analyst. Extract 2-3 core threat themes or systemic risks from these headlines. Be incredibly concise. Bullet points only."
        resp = call_llm([{"role": "system", "content": sys_map}, {"role": "user", "content": context}], config, temperature=0.1)
        if resp: batch_summaries.append(resp)

    # Step 2: Reduce (Synthesize the extracted themes)
    if not batch_summaries: return "Failed to process intelligence feed."
    
    final_context = "\n".join(batch_summaries)
    sys_reduce = f"""You are an Intelligence Director. Provide a high-level situational overview based on the provided intelligence themes.
FOCUS: {focus_prompt}
Write a cohesive 2-paragraph briefing summarizing the overarching threat narrative, major actors, and systemic risks. Do not list items."""

    return call_llm([{"role": "system", "content": sys_reduce}, {"role": "user", "content": final_context}], config, temperature=0.3)

def build_custom_intel_report(articles, objective, session):
    """Map-Reduce pipeline for EXHAUSTIVE, multi-article technical intelligence reports."""
    config = get_llm_config(session)
    if not config or not articles: return None
    
    # Step 1: Map (Extract facts from articles 3 at a time to preserve deep context)
    extracted_facts = []
    for i, chunk in enumerate(chunk_list(articles, 3)):
        chunk_text = ""
        for a in chunk:
            clean_summary = a.summary.replace('\n', ' ') if a.summary else "No summary."
            chunk_text += f"SOURCE: {a.source} | TITLE: {a.title}\nCONTENT: {clean_summary}\n\n"
            
        sys_map = f"""You are an Intelligence Collector. Extract EVERY technical detail, IOC (IPs, hashes, CVEs), targeted system, and threat actor mentioned in the text.
Align your extraction with the User Objective: {objective}
Provide raw, concise bullet points. Do not write an intro or conclusion."""
        
        resp = call_llm([{"role": "system", "content": sys_map}, {"role": "user", "content": chunk_text}], config, temperature=0.1)
        if resp: extracted_facts.append(f"--- BATCH {i+1} INTELLIGENCE ---\n{resp}")

    # Step 2: Reduce (Format into final report)
    if not extracted_facts: return "AI failed to extract actionable intelligence."
    
    compiled_facts = "\n\n".join(extracted_facts)
    sys_reduce = f"""You are a Senior Cyber Threat Intelligence Analyst. Compile the raw intelligence below into an EXHAUSTIVE, highly technical intelligence report.
OBJECTIVE: {objective}

REQUIRED STRUCTURE:
## Executive Threat Summary
(Comprehensive overview of the threat landscape based on the data)

## Identified Threat Actors & TTPs
(Detail all attackers, motivations, and specific Tactics, Techniques, and Procedures)

## Indicators of Compromise (IOCs) & Vulnerabilities
(List all extracted CVEs, hashes, infrastructure, and targeted systems)

## Defensive Posture & Remediation
(All recommended mitigations or operational alerts)

STRICT RULES: Use ONLY the provided data. Do not hallucinate."""

    return call_llm([{"role": "system", "content": sys_reduce}, {"role": "user", "content": f"RAW INTELLIGENCE NUGGETS:\n{compiled_facts}"}], config, temperature=0.2)
  
def generate_rolling_summary(session):
    """Generates a rapid situational narrative scoped strictly to the last 6 hours."""
    from src.database import Article, RegionalHazard, CloudOutage 
    
    config = get_llm_config(session)
    if not config: return None
    
    # --- EFFICIENCY UPGRADE: 6-Hour Context Window ---
    six_hours_ago = datetime.utcnow() - timedelta(hours=6)
    master_report = ""
    
    # CHUNK 1: CYBER INTEL
    arts = session.query(Article).filter(Article.published_date >= six_hours_ago, Article.score >= 50).order_by(Article.score.desc()).limit(10).all()
    master_report += "**📰 Shift Threat Intel (Last 6h):** "
    if arts:
        context = "\n".join([f"- {a.title}" for a in arts])
        prompt = f"Summarize the main attack types and targets in exactly one sentence. Start your sentence with 'Active cyber threats include'. Do not write anything else.\n\nHEADLINES:\n{context}"
        response = call_llm([{"role": "user", "content": prompt}], config, temperature=0.0)
        master_report += f"{response.strip() if response else 'Generation failed.'}\n\n"
    else: master_report += "No high-threat cyber intelligence tracked in the current shift.\n\n"

    # CHUNK 2: REGIONAL HAZARDS
    hazards = session.query(RegionalHazard).filter(RegionalHazard.updated_at >= six_hours_ago).all()
    master_report += "**🗺️ Physical Infrastructure (Last 6h):** "
    if hazards:
        context = "\n".join([f"- {h.severity}: {h.title} in {h.location}" for h in hazards])
        prompt = f"Summarize these weather alerts in exactly one sentence. Start your sentence with 'Regional physical infrastructure is threatened by'. Do not explain the text. Do not offer advice.\n\nALERTS:\n{context}"
        response = call_llm([{"role": "user", "content": prompt}], config, temperature=0.0)
        master_report += f"{response.strip() if response else 'Generation failed.'}\n\n"
    else: master_report += "The regional physical grid is clear.\n\n"

    # CHUNK 3: CLOUD OUTAGES
    clouds = session.query(CloudOutage).filter(CloudOutage.updated_at >= six_hours_ago).all()
    master_report += "**☁️ Cloud Services (Last 6h):** "
    if clouds:
        context = "\n".join([f"- {c.provider}: {c.title}" for c in clouds])
        prompt = f"Summarize these cloud outages in exactly one sentence. Start your sentence with 'Monitored cloud platforms are tracking'. Do not add conversational filler. Do not critique the text.\n\nOUTAGES:\n{context}"
        response = call_llm([{"role": "user", "content": prompt}], config, temperature=0.0)
        master_report += f"{response.strip() if response else 'Generation failed.'}\n"
    else: master_report += "All monitored tier-1 cloud providers are operating normally.\n"

    master_report = master_report.replace("Here is the summary:", "").replace("Summary:", "")
    return master_report.strip()
  
def generate_daily_fusion_report(session):
    """Chunks yesterday's data by category and generates a master briefing."""
    config = get_llm_config(session)
    if not config: return None
    
    LOCAL_TZ = ZoneInfo("America/Chicago")
    start_of_yesterday = (datetime.now(LOCAL_TZ) - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    utc_start = start_of_yesterday.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
    utc_end = (start_of_yesterday + timedelta(days=1)).astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
    
    report_date_str = start_of_yesterday.strftime('%A, %B %d, %Y')
    master_report = f"# 📊 Daily NOC Fusion Report: {report_date_str}\n\n"
    
    from src.database import Article, CveItem, RegionalHazard, CloudOutage
    
    # CYBER
    articles = session.query(Article).filter(Article.published_date >= utc_start, Article.published_date < utc_end, Article.score >= 80.0).limit(15).all()
    master_report += "## 📰 1. High-Priority Cyber Intelligence\n"
    if articles:
        context = "\n".join([f"- [{int(a.score)}] {a.title}" for a in articles])
        prompt = f"You are a CTI Director. Summarize these critical threat events into a cohesive 2-paragraph situational report focusing on threat actors and impact.\n{context}"
        response = call_llm([{"role": "system", "content": prompt}], config, temperature=0.2)
        master_report += f"{response if response else 'Generation failed.'}\n\n"
    else: master_report += "*No critical intelligence alerts tracked yesterday.*\n\n"

    # VULNERABILITIES
    cves = session.query(CveItem).filter(CveItem.date_added >= utc_start, CveItem.date_added < utc_end).limit(20).all()
    master_report += "## 🪲 2. Known Exploited Vulnerabilities (KEV)\n"
    if cves:
        context = "\n".join([f"- {c.cve_id} ({c.vendor}): {c.vulnerability_name}" for c in cves])
        prompt = f"You are a Vulnerability Analyst. Write a brief summary paragraph of the new exploited vulnerabilities added to the KEV catalog.\n{context}"
        response = call_llm([{"role": "system", "content": prompt}], config, temperature=0.1)
        master_report += f"{response if response else 'Generation failed.'}\n\n"
    else: master_report += "*No new KEVs added yesterday.*\n\n"

    # INFRASTRUCTURE
    hazards = session.query(RegionalHazard).filter(RegionalHazard.updated_at >= utc_start, RegionalHazard.updated_at < utc_end).limit(10).all()
    master_report += "## 🗺️ 3. Physical Infrastructure & Weather\n"
    if hazards:
        context = "\n".join([f"- {h.severity}: {h.title} ({h.location})" for h in hazards])
        prompt = f"You are a Critical Infrastructure Analyst. Summarize the physical threats and weather hazards from yesterday.\n{context}"
        response = call_llm([{"role": "system", "content": prompt}], config, temperature=0.1)
        master_report += f"{response if response else 'Generation failed.'}\n\n"
    else: master_report += "*Grid operated normally with no reported hazards.*\n\n"

    # CLOUD
    clouds = session.query(CloudOutage).filter(CloudOutage.updated_at >= utc_start, CloudOutage.updated_at < utc_end).limit(10).all()
    master_report += "## ☁️ 4. Cloud Services Disruptions\n"
    if clouds:
        context = "\n".join([f"- {c.provider} ({c.service}): {c.title}" for c in clouds])
        prompt = f"You are a Systems Analyst. Summarize the major tier-1 cloud service disruptions from yesterday.\n{context}"
        response = call_llm([{"role": "system", "content": prompt}], config, temperature=0.1)
        master_report += f"{response if response else 'Generation failed.'}\n"
    else: master_report += "*No major tier-1 cloud outages reported.*\n"

    return start_of_yesterday, master_report