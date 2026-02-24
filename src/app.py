import streamlit as st
import pandas as pd
import math
import time
from sqlalchemy import text
from src.database import SessionLocal, Article, FeedSource, Keyword, LLMSettings, engine
from src.train_model import train 
from src.scheduler import fetch_feeds
from src.llm_engine import generate_executive_briefing

st.set_page_config(page_title="RSS Filter", layout="wide")

def get_db():
    return SessionLocal()

session = get_db()

# --- THE PERFORMANCE FIX: Callback Function ---
def change_status(art_id, new_feedback, bubble_status=None):
    art = session.query(Article).filter(Article.id == art_id).first()
    if art:
        art.human_feedback = new_feedback
        if bubble_status is not None:
            art.is_bubbled = bubble_status
        session.commit()

# --- Sidebar Navigation ---
st.sidebar.title("RSS Filter")
page = st.sidebar.radio("Navigation", ["Dashboard", "LLM Briefing", "Training Data", "Configuration"])

# ================= DASHBOARD =================
if page == "Dashboard":
    col_title, col_btn = st.columns([3, 1])
    col_title.title("📰 News Dashboard")
    
    if col_btn.button("🔄 Force Fetch Feeds"):
        with st.spinner("Fetching latest feeds... this may take a moment."):
            fetch_feeds(source="User Force") 
            st.success("Fetch complete!")
            time.sleep(1)
            st.rerun()

    view_mode = st.radio(
        "Filter", 
        ["Priority Queue", "Saved Articles", "All Articles (Archive)"], 
        horizontal=True
    )
    
    # --- VIEW 1: PRIORITY QUEUE (INBOX) ---
    if view_mode == "Priority Queue":
        st.caption("Review Queue: Articles flagged by your keywords and ML model.")
        
        articles = session.query(Article).filter(
            Article.is_bubbled == True, 
            Article.human_feedback == 0
        ).order_by(Article.published_date.desc()).limit(30).all()

        if not articles:
            st.success("🎉 You are all caught up! No pending articles.")
        else:
            if len(articles) == 30:
                st.info("Showing the top 30 pending articles. More will load as you clear these.")

        for art in articles:
            score_color = "red" if art.score > 80 else "orange" if art.score > 50 else "blue"
            
            with st.expander(f":{score_color}[[{int(art.score)}]] {art.title}", expanded=True):
                col_meta, col_link = st.columns([3, 1])
                date_str = art.published_date.strftime('%Y-%m-%d %H:%M') if art.published_date else "Unknown"
                col_meta.caption(f"📅 {date_str} | 📡 {art.source} | 🏷️ {art.keywords_found}")
                col_link.markdown(f"[Read Article]({art.link})")
                
                st.write(art.summary)
                
                c1, c2, c3 = st.columns([1, 1, 4])
                
                # Rebranded Buttons
                c1.button("✅ Keep", key=f"ack_{art.id}", on_click=change_status, args=(art.id, 2))
                c2.button("❌ Dismiss", key=f"dis_{art.id}", on_click=change_status, args=(art.id, 1))

    # --- VIEW 2: SAVED ARTICLES ---
    elif view_mode == "Saved Articles":
        st.subheader("✅ Saved Articles")
        st.caption("Articles you or the AI have marked as important.")
        
        total_ack = session.query(Article).filter(Article.human_feedback == 2).count()
        
        col_c, col_i = st.columns([1, 4])
        limit = col_c.selectbox("Show", [20, 50, 100], key="ack_limit")
        
        articles = session.query(Article)\
            .filter(Article.human_feedback == 2)\
            .order_by(Article.published_date.desc())\
            .limit(limit)\
            .all()
        
        if not articles:
            st.info("No saved articles yet.")

        for art in articles:
            with st.expander(f"✅ [[{int(art.score)}]] {art.title}"):
                st.caption(f"Source: {art.source}")
                st.write(art.summary)
                st.markdown(f"[Read Article]({art.link})")
                
                st.button("Remove from Saved", key=f"undo_{art.id}", on_click=change_status, args=(art.id, 0))

    # --- VIEW 3: ALL ARTICLES (ARCHIVE) ---
    elif view_mode == "All Articles (Archive)":
        st.subheader("🗄️ Feed Archive")
        
        total_articles = session.query(Article).count()
        col_controls, col_info = st.columns([1, 3])
        
        with col_controls:
            items_per_page = st.selectbox("Articles per page", [20, 50, 100], index=0)
            
        total_pages = math.ceil(total_articles / items_per_page)
        if total_pages < 1: total_pages = 1
        
        with col_controls:
            current_page = st.number_input("Page Number", min_value=1, max_value=total_pages, value=1)
            
        with col_info:
            st.write("") 
            st.write("") 
            st.caption(f"Showing page **{current_page}** of **{total_pages}** ({total_articles} total articles)")

        offset = (current_page - 1) * items_per_page
        
        articles = session.query(Article)\
            .order_by(Article.published_date.desc())\
            .offset(offset)\
            .limit(items_per_page)\
            .all()
        
        st.divider()

        for art in articles:
            score_color = "red" if art.score > 50 else "orange" if art.score > 20 else "gray"
            
            with st.expander(f":{score_color}[[{int(art.score)}]] {art.title}"):
                col_meta, col_link = st.columns([3, 1])
                date_str = art.published_date.strftime('%Y-%m-%d %H:%M') if art.published_date else "Unknown"
                col_meta.caption(f"📅 {date_str} | 📡 {art.source}")
                col_link.markdown(f"[Read Article]({art.link})")
                
                st.write(art.summary)
                
                c1, c2 = st.columns([1, 6])
                c1.button("Flag as Important", key=f"archive_crit_{art.id}", on_click=change_status, args=(art.id, 0, True))

# ================= LLM BRIEFING =================
elif page == "LLM Briefing":
    st.title("🤖 AI Executive Briefing")
    st.caption("Generate a synthesized intelligence report based on current high-priority items. (Optional Feature)")
    
    top_articles = session.query(Article).filter(
        Article.is_bubbled == True, 
        Article.human_feedback == 0
    ).order_by(Article.score.desc()).limit(15).all()
    
    st.info(f"Currently tracking {len(top_articles)} critical unread items for analysis.")
    
    if st.button("✨ Generate Briefing", type="primary"):
        if not top_articles:
            st.warning("No high-priority items available to summarize.")
        else:
            llm_settings = session.query(LLMSettings).first()
            if not llm_settings:
                st.error("LLM Settings not initialized. Please visit Configuration tab.")
            else:
                with st.spinner(f"Analyzing threats using {llm_settings.provider} ({llm_settings.model_name})..."):
                    briefing_text = generate_executive_briefing(top_articles, llm_settings)
                    
                st.divider()
                st.markdown(briefing_text)

# ================= TRAINING DATA =================
elif page == "Training Data":
    st.title("🧠 Smart Filter Training")
    
    count_pos = session.query(Article).filter(Article.human_feedback == 2).count()
    count_neg = session.query(Article).filter(Article.human_feedback == 1).count()
    total = count_pos + count_neg
    
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Samples", total)
    c2.metric("Positives (Keep)", count_pos)
    c3.metric("Negatives (Dismiss)", count_neg)
    
    st.divider()
    
    st.subheader("Model Management")
    if st.button("🚀 Retrain Model Now", type="primary"):
        if total < 10:
            st.error("Not enough data! Please review at least 10 articles.")
        else:
            with st.spinner("Training neural pathways..."):
                try:
                    train() 
                    st.success("Model retrained successfully! The next scheduled fetch will use the new brain.")
                except Exception as e:
                    st.error(f"Training failed: {e}")

    st.divider()
    st.subheader("Labeled Dataset")
    df = pd.read_sql(session.query(Article).filter(Article.human_feedback != 0).statement, session.bind)
    st.dataframe(df)

# ================= CONFIGURATION =================
elif page == "Configuration":
    st.title("⚙️ System Settings")
    
    tab1, tab2, tab3, tab4 = st.tabs(["Keywords (Rule-Based)", "RSS Sources", "LLM Settings", "Danger Zone"])
    
    with tab1:
        st.subheader("Manage Keywords")
        st.info("Format: `keyword, weight` (one per line). If weight is omitted, defaults to 10.")
        
        with st.form("bulk_kw"):
            raw_text = st.text_area("Bulk Add Keywords", placeholder="infrastructure, 80\npower grid, 50\ntelecom")
            if st.form_submit_button("Add Keywords"):
                lines = raw_text.split('\n')
                added_count = 0
                skipped_count = 0
                
                for line in lines:
                    if not line.strip(): continue
                    parts = line.split(',')
                    word = parts[0].strip().lower()
                    weight = 10
                    if len(parts) > 1:
                        try:
                            weight = int(parts[1].strip())
                        except ValueError:
                            pass 
                    
                    exists = session.query(Keyword).filter_by(word=word).first()
                    if not exists:
                        session.add(Keyword(word=word, weight=weight))
                        added_count += 1
                    else:
                        skipped_count += 1
                
                session.commit()
                if added_count > 0: st.success(f"✅ Added {added_count} keywords.")
                if skipped_count > 0: st.warning(f"⚠️ Skipped {skipped_count} duplicates.")
                st.rerun()
        
        st.divider()
        st.write("### Active Keywords")
        keywords = session.query(Keyword).order_by(Keyword.weight.desc()).all()
        for k in keywords:
            col1, col2, col3 = st.columns([3, 1, 1])
            col1.code(k.word)
            col2.write(f"Weight: **{k.weight}**")
            if col3.button("🗑️", key=f"del_kw_{k.id}"):
                session.delete(k)
                session.commit()
                st.rerun()

    with tab2:
        st.subheader("Manage RSS Feeds")
        st.info("Format: `URL, Name` (one per line).")
        
        with st.form("bulk_feed"):
            raw_text = st.text_area("Bulk Add Feeds", placeholder="https://site.com/feed, Tech News")
            if st.form_submit_button("Add Sources"):
                lines = raw_text.split('\n')
                added_count = 0
                skipped_count = 0
                for line in lines:
                    if not line.strip(): continue
                    parts = line.split(',')
                    url = parts[0].strip()
                    name = parts[1].strip() if len(parts) > 1 else "New Feed"
                    
                    exists = session.query(FeedSource).filter_by(url=url).first()
                    if not exists:
                        session.add(FeedSource(url=url, name=name))
                        added_count += 1
                    else:
                        skipped_count += 1
                
                session.commit()
                if added_count > 0: st.success(f"✅ Added {added_count} feeds.")
                st.rerun()

        st.divider()
        st.write("### Active Feeds")
        sources = session.query(FeedSource).all()
        for s in sources:
            with st.expander(f"{s.name}"):
                st.text(s.url)
                if st.button("Delete Feed", key=f"del_src_{s.id}"):
                    session.delete(s)
                    session.commit()
                    st.rerun()

    with tab3:
        st.subheader("LLM Integration Settings")
        st.info("Configuring an LLM allows you to generate optional Executive Briefings. If left blank or unconfigured, the rest of the app functions normally.")
        llm_settings = session.query(LLMSettings).first()
        
        if llm_settings:
            with st.form("llm_config_form"):
                provider_options = ["Local (Ollama)", "OpenAI", "Gemini"]
                current_idx = provider_options.index(llm_settings.provider) if llm_settings.provider in provider_options else 0
                
                provider = st.selectbox("Provider", provider_options, index=current_idx)
                
                model_name = st.text_input("Model Name", value=llm_settings.model_name, 
                                           help="e.g., 'llama3' for Ollama, 'gpt-4o' for OpenAI, 'gemini-1.5-pro' for Gemini")
                
                base_url = st.text_input("Base URL (For Local/Ollama)", value=llm_settings.base_url,
                                         help="Use 'http://host.docker.internal:11434/v1' to access Ollama running on your host machine from inside Docker.")
                
                api_key = st.text_input("API Key (For OpenAI/Gemini)", value=llm_settings.api_key if llm_settings.api_key else "", type="password")
                
                if st.form_submit_button("Save LLM Settings"):
                    llm_settings.provider = provider
                    llm_settings.model_name = model_name
                    llm_settings.base_url = base_url
                    llm_settings.api_key = api_key
                    session.commit()
                    st.success("LLM Configuration Saved!")
                    time.sleep(1)
                    st.rerun()

    with tab4:    
        st.divider()
        with st.expander("⚠️ Danger Zone", expanded=False):
            st.error("These actions are irreversible!")
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**Clear History**")
                st.caption("Deletes articles but keeps Feeds/Keywords.")
                if st.button("🗑️ Delete All Articles"):
                    try:
                        session.execute(text("TRUNCATE TABLE articles RESTART IDENTITY CASCADE;"))
                        session.commit()
                        st.success("All articles deleted.")
                        time.sleep(1)
                        st.rerun()
                    except Exception as e:
                        st.error(f"Error: {e}")

            with col2:
                st.write("**Factory Reset**")
                st.caption("Wipes EVERYTHING.")
                if st.button("☢️ FULL RESET"):
                    try:
                        session.execute(text("TRUNCATE TABLE articles, feed_sources, keywords, llm_settings RESTART IDENTITY CASCADE;"))
                        session.commit()
                        st.success("System reset.")
                        time.sleep(1)
                        st.rerun()
                    except Exception as e:
                        st.error(f"Error: {e}")

session.close()