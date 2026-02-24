import traceback

def generate_executive_briefing(articles, settings):
    if not articles:
        return "No high-priority articles available to summarize."

    # Build the prompt
    prompt = (
        "You are an expert intelligence analyst. Provide a concise, professional executive briefing "
        "summarizing the following high-priority alerts. Group similar events together and highlight "
        "potential impacts or threats. Use clear formatting.\n\n"
    )
    
    for i, art in enumerate(articles, 1):
        prompt += f"[{i}] TITLE: {art.title}\nSOURCE: {art.source}\nSUMMARY: {art.summary}\n\n"

    try:
        if settings.provider == "Local (Ollama)" or settings.provider == "OpenAI":
            try:
                import openai
            except ImportError:
                return "🚨 The 'openai' library is not installed. Please add it to requirements.txt and rebuild."
            
            # Use dummy key for local Ollama, real key for OpenAI
            api_key = "ollama" if settings.provider == "Local (Ollama)" else settings.api_key
            base_url = settings.base_url if settings.provider == "Local (Ollama)" else None
            
            if settings.provider == "OpenAI" and not api_key:
                return "🚨 OpenAI API Key is missing. Please configure it in the Settings tab."

            client = openai.OpenAI(base_url=base_url, api_key=api_key)
            response = client.chat.completions.create(
                model=settings.model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3
            )
            return response.choices[0].message.content

        elif settings.provider == "Gemini":
            try:
                import google.generativeai as genai
            except ImportError:
                return "🚨 The 'google-generativeai' library is not installed. Please add it to requirements.txt and rebuild."
            
            if not settings.api_key:
                return "🚨 Gemini API Key is missing. Please configure it in the Settings tab."

            genai.configure(api_key=settings.api_key)
            model = genai.GenerativeModel(settings.model_name)
            response = model.generate_content(prompt)
            return response.text

    except Exception as e:
        error_details = traceback.format_exc()
        return f"🚨 Error generating briefing with {settings.provider}: {str(e)}\n\nCheck your API keys, model names, and network connection."