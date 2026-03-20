import requests
import json
import uuid
import re
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from src.database import SystemConfig, Article
import concurrent.futures

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

def truncate_text(text, max_chars=250):
    """Aggressively trims text to save local GPU VRAM/Context Window."""
    if not text: return "No details provided."
    return text if len(text) <= max_chars else text[:max_chars] + "..."

def _map_reduce_summarize(items, formatter_func, map_prompt, reduce_prompt, config, chunk_size=6):
    """Universal Map-Reduce pipeline to prevent GPU timeouts on large daily reports."""
    if not items: return None
    
    batch_summaries = []
    # MAP PHASE: Process in very small chunks
    for chunk in chunk_list(items, chunk_size):
        context = "\n".join([formatter_func(x) for x in chunk])
        resp = call_llm([{"role": "system", "content": map_prompt}, {"role": "user", "content": context}], config, temperature=0.1)
        if resp and "⚠️" not in resp: 
            batch_summaries.append(resp)
            
    if not batch_summaries: return "AI failed to process batch."
    
    # REDUCE PHASE: If multiple batches, summarize the summaries
    if len(batch_summaries) > 1:
        final_context = "\n\n".join(batch_summaries)
        return call_llm([{"role": "system", "content": reduce_prompt}, {"role": "user", "content": final_context}], config, temperature=0.2)
    else:
        return batch_summaries[0]


# =====================================================================
# TACTICAL SUMMARIES & BLUFS
# =====================================================================

def generate_bluf(article, session):
    """Generates a structured, multi-domain BLUF using concurrent prompt chunking."""
    from src.llm import get_llm_config, call_llm # Ensure these are imported
    
    config = get_llm_config(session)
    if not config: return None

    # Truncate once to ensure we stay within context windows
    article_context = f"Title: {article.title}\nSummary: {str(article.summary)[:600]}"

    # CHUNK 1: The Multi-Domain Prompts
    # Designed to handle Geopolitics, Cyber, and Physical hazards dynamically
    prompts = {
        "Core Event": "You are a Global Intelligence Analyst. Summarize the core event of the provided text in exactly one clinical, objective sentence.",
        "Cascading Impact": "You are a Global Intelligence Analyst. Identify the primary target, affected sector, or regional blast radius in exactly one concise sentence.",
        "Strategic Posture": "You are a Global Intelligence Analyst. Provide exactly one actionable recommendation, defensive pivot, or monitoring suggestion based on this event."
    }

    def ask_llm(section_title, sys_prompt):
        """Helper function to execute a single chunk."""
        messages = [
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": article_context}
        ]
        response = call_llm(messages, config, temperature=0.1)
        return f"**{section_title}:** {response.strip() if response else 'N/A'}"

    # CHUNK 2: Concurrent Execution
    # Fires all 3 prompts simultaneously so generation takes 2 seconds instead of 6
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        future_to_section = {
            executor.submit(ask_llm, title, prompt): title 
            for title, prompt in prompts.items()
        }
        
        for future in concurrent.futures.as_completed(future_to_section):
            section = future_to_section[future]
            try:
                results[section] = future.result()
            except Exception as e:
                print(f"BLUF Chunk Error ({section}): {e}")
                results[section] = f"**{section}:** Analysis failed."

    # CHUNK 3: Assembly
    # Reassemble the pieces in the correct order
    final_bluf = f"{results.get('Core Event')}\n{results.get('Cascading Impact')}\n{results.get('Strategic Posture')}"
    
    return final_bluf

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

    # Map-Reduce Strategy for large lists (Heavily truncated to save GPU)
    context = "\n".join([f"- {a.title}: {truncate_text(a.summary, 150)}" for a in articles[:10]]) 
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Recent Events:\n{context}"}
    ]
    return call_llm(messages, config, temperature=0.1)

def generate_briefing(articles, session):
    """Reads top articles and writes a synthesized brief."""
    config = get_llm_config(session)
    if not config or not articles: return None
    
    context = "\n\n".join([f"Title: {a.title}\nSource: {a.source}" for a in articles[:10]]) # Reduced from 20 to 10
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
    
    system_prompt = f"""You are a Cyber Threat Intelligence Analyst. Cross-reference these Actively Exploited Vulnerabilities (KEVs) against the internal stack.
INTERNAL TECH STACK: {tech_stack}

INSTRUCTIONS:
1. If a KEV targets a vendor/product in the TECH STACK, output a critical alert starting with "MATCH:" followed by the CVE ID and impact.
2. If NO direct matches exist, output exactly: "CLEAR: No active KEVs match internal infrastructure." """

    all_matches = []
    error_messages = []
    
    # Reduced chunk size from 15 to 8 for local GPU stability
    for chunk in chunk_list(cves, 8):
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

    # Step 1: Map (Reduced chunk size from 20 to 10)
    batch_summaries = []
    for chunk in chunk_list(articles, 10):
        context = "\n".join([f"- {a.source}: {a.title}" for a in chunk])
        sys_map = "You are a CTI Analyst. Extract 2 core threat themes from these headlines. Be incredibly concise. Bullet points only."
        resp = call_llm([{"role": "system", "content": sys_map}, {"role": "user", "content": context}], config, temperature=0.1)
        if resp and "⚠️" not in resp: batch_summaries.append(resp)

    # Step 2: Reduce
    if not batch_summaries: return "Failed to process intelligence feed."
    
    final_context = "\n".join(batch_summaries)
    sys_reduce = f"""You are an Intelligence Director. Provide a high-level situational overview based on the provided intelligence themes.
FOCUS: {focus_prompt}
Write a cohesive 2-paragraph briefing summarizing the overarching threat narrative. Do not list items."""

    return call_llm([{"role": "system", "content": sys_reduce}, {"role": "user", "content": final_context}], config, temperature=0.3)

def build_custom_intel_report(articles, objective, session):
    """Map-Reduce pipeline for EXHAUSTIVE, multi-article technical intelligence reports."""
    config = get_llm_config(session)
    if not config or not articles: return None
    
    # Step 1: Map (Extract facts from articles 2 at a time to preserve GPU memory)
    extracted_facts = []
    for i, chunk in enumerate(chunk_list(articles, 2)):
        chunk_text = ""
        for a in chunk:
            chunk_text += f"SOURCE: {a.source} | TITLE: {a.title}\nCONTENT: {truncate_text(a.summary, 600)}\n\n"
            
        sys_map = f"""Extract EVERY technical detail, IOC, targeted system, and threat actor mentioned in the text.
Align your extraction with the User Objective: {objective}
Provide raw, concise bullet points. No intro."""
        
        resp = call_llm([{"role": "system", "content": sys_map}, {"role": "user", "content": chunk_text}], config, temperature=0.1)
        if resp and "⚠️" not in resp: extracted_facts.append(f"--- BATCH {i+1} INTELLIGENCE ---\n{resp}")

    # Step 2: Reduce
    if not extracted_facts: return "AI failed to extract actionable intelligence."
    
    compiled_facts = "\n\n".join(extracted_facts)
    sys_reduce = f"""You are a Senior CTI Analyst. Compile the raw intelligence below into an EXHAUSTIVE, technical report.
OBJECTIVE: {objective}

REQUIRED STRUCTURE:
## Executive Threat Summary
## Identified Threat Actors & TTPs
## Indicators of Compromise (IOCs) & Vulnerabilities
## Defensive Posture & Remediation

STRICT RULES: Use ONLY the provided data. Do not hallucinate."""

    return call_llm([{"role": "system", "content": sys_reduce}, {"role": "user", "content": f"RAW INTELLIGENCE NUGGETS:\n{compiled_facts}"}], config, temperature=0.2)
  
def generate_rolling_summary(session):
    """Generates a rapid situational narrative scoped strictly to the last 6 hours."""
    from src.database import Article, RegionalHazard, CloudOutage 
    
    config = get_llm_config(session)
    if not config: return None
    
    six_hours_ago = datetime.utcnow() - timedelta(hours=6)
    master_report = ""
    
    # CHUNK 1: CYBER INTEL
    arts = session.query(Article).filter(Article.published_date >= six_hours_ago, Article.score >= 50).order_by(Article.score.desc()).limit(8).all()
    master_report += "**📰 Shift Threat Intel (Last 6h):** "
    if arts:
        context = "\n".join([f"- {a.title}" for a in arts])
        prompt = f"Summarize the main attack types in exactly one sentence starting with 'Active cyber threats include'.\n\nHEADLINES:\n{context}"
        response = call_llm([{"role": "user", "content": prompt}], config, temperature=0.0)
        master_report += f"{response.strip() if response and '⚠️' not in response else 'Generation failed.'}\n\n"
    else: master_report += "No high-threat cyber intelligence tracked in the current shift.\n\n"

    # CHUNK 2: REGIONAL HAZARDS
    hazards = session.query(RegionalHazard).filter(RegionalHazard.updated_at >= six_hours_ago).limit(8).all()
    master_report += "**🗺️ Physical Infrastructure (Last 6h):** "
    if hazards:
        context = "\n".join([f"- {h.severity}: {h.title} in {h.location}" for h in hazards])
        prompt = f"Summarize these weather alerts in exactly one sentence starting with 'Regional physical infrastructure is threatened by'.\n\nALERTS:\n{context}"
        response = call_llm([{"role": "user", "content": prompt}], config, temperature=0.0)
        master_report += f"{response.strip() if response and '⚠️' not in response else 'Generation failed.'}\n\n"
    else: master_report += "The regional physical grid is clear.\n\n"

    # CHUNK 3: CLOUD OUTAGES (Updated for Geographic Tags)
    clouds = session.query(CloudOutage).filter(CloudOutage.updated_at >= six_hours_ago).limit(8).all()
    master_report += "**☁️ Cloud Services (Last 6h):** "
    if clouds:
        context = "\n".join([f"- {c.provider} ({c.service}): {c.title}" for c in clouds])
        prompt = f"Summarize these cloud outages in exactly one sentence starting with 'Monitored cloud platforms are tracking'. Include the geographic regions mentioned.\n\nOUTAGES:\n{context}"
        response = call_llm([{"role": "user", "content": prompt}], config, temperature=0.0)
        master_report += f"{response.strip() if response and '⚠️' not in response else 'Generation failed.'}\n"
    else: master_report += "All monitored tier-1 cloud providers are operating normally.\n"

    master_report = master_report.replace("Here is the summary:", "").replace("Summary:", "")
    return master_report.strip()
  
def generate_daily_fusion_report(session):
    """Chunks yesterday's data by category and generates a master briefing using Map-Reduce."""
    config = get_llm_config(session)
    if not config: return None
    
    LOCAL_TZ = ZoneInfo("America/Chicago")
    start_of_yesterday = (datetime.now(LOCAL_TZ) - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    utc_start = start_of_yesterday.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
    utc_end = (start_of_yesterday + timedelta(days=1)).astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
    
    report_date_str = start_of_yesterday.strftime('%A, %B %d, %Y')
    master_report = f"# 📊 Daily NOC Fusion Report: {report_date_str}\n\n"
    
    from src.database import Article, CveItem, RegionalHazard, CloudOutage
    
    # --- HELPER MAP-REDUCE TO PREVENT TIMEOUTS ON HUGE DAILY LOADS ---
    
    # CYBER
    articles = session.query(Article).filter(Article.published_date >= utc_start, Article.published_date < utc_end, Article.score >= 80.0).limit(12).all()
    master_report += "## 📰 1. High-Priority Cyber Intelligence\n"
    if articles:
        map_p = "Summarize the key cyber threats in these headlines. Be brief."
        reduce_p = "You are a CTI Director. Combine these summaries into a cohesive 2-paragraph situational report."
        resp = _map_reduce_summarize(articles, lambda a: f"- [{int(a.score)}] {a.title}", map_p, reduce_p, config, chunk_size=6)
        master_report += f"{resp}\n\n"
    else: master_report += "*No critical intelligence alerts tracked yesterday.*\n\n"

    # VULNERABILITIES
    cves = session.query(CveItem).filter(CveItem.date_added >= utc_start, CveItem.date_added < utc_end).limit(15).all()
    master_report += "## 🪲 2. Known Exploited Vulnerabilities (KEV)\n"
    if cves:
        map_p = "Extract the vendor, product, and vulnerability name from this list. Be extremely concise."
        reduce_p = "You are a Vulnerability Analyst. Write a brief summary paragraph of the new exploited vulnerabilities added to the KEV catalog. You MUST include the specific CVE IDs in your summary."
        resp = _map_reduce_summarize(cves, lambda c: f"- {c.cve_id} ({c.vendor}): {c.vulnerability_name}", map_p, reduce_p, config, chunk_size=8)
        master_report += f"{resp}\n\n"
    else: master_report += "*No new KEVs added yesterday.*\n\n"

    # INFRASTRUCTURE
    hazards = session.query(RegionalHazard).filter(RegionalHazard.updated_at >= utc_start, RegionalHazard.updated_at < utc_end).limit(12).all()
    master_report += "## 🗺️ 3. Physical Infrastructure & Weather\n"
    if hazards:
        map_p = "List the severe weather events and locations."
        reduce_p = "You are a Critical Infrastructure Analyst. Summarize the physical threats and weather hazards from yesterday in one paragraph."
        resp = _map_reduce_summarize(hazards, lambda h: f"- {h.severity}: {h.title} ({h.location})", map_p, reduce_p, config, chunk_size=6)
        master_report += f"{resp}\n\n"
    else: master_report += "*Grid operated normally with no reported hazards.*\n\n"

    # CLOUD (Now respects regional tags)
    clouds = session.query(CloudOutage).filter(CloudOutage.updated_at >= utc_start, CloudOutage.updated_at < utc_end).limit(10).all()
    master_report += "## ☁️ 4. Cloud Services Disruptions\n"
    if clouds:
        map_p = "List the cloud provider, service, and geographic region affected."
        reduce_p = "You are a Systems Analyst. Summarize the major tier-1 cloud service disruptions from yesterday. Explicitly mention the geographic regions impacted."
        resp = _map_reduce_summarize(clouds, lambda c: f"- {c.provider} ({c.service}): {c.title}", map_p, reduce_p, config, chunk_size=5)
        master_report += f"{resp}\n"
    else: master_report += "*No major tier-1 cloud outages reported.*\n"

    return start_of_yesterday, master_report
