using NocIfc.Application.Abstractions.Llm;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Settings;

namespace NocIfc.Application.Features.Threat;

public sealed record ArticleBlufResult(bool Success, string? Bluf, string? Message);

public sealed class GenerateArticleBlufCommands(
    ThreatArticleQueries articles,
    IAiSmtpSettingsStore aiSettings,
    ILlmChatCompletionClient llm)
{
    public async Task<ArticleBlufResult> GenerateAsync(int articleId, CancellationToken cancellationToken)
    {
        if (articleId <= 0)
        {
            return new ArticleBlufResult(false, null, "Article not found.");
        }

        var article = (await articles.GetByIdsAsync([articleId], cancellationToken)).FirstOrDefault();
        if (article is null)
        {
            return new ArticleBlufResult(false, null, "Article not found.");
        }
        var config = await aiSettings.GetAsync(cancellationToken);
        if (config?.IsActive != true)
        {
            return new ArticleBlufResult(false, null, "AI generation failed.");
        }

        var fullContent = article.FullContent;
        var articleText = !string.IsNullOrEmpty(fullContent) && fullContent.Length > 200
            ? $"Title: {article.Title}\nContent: {fullContent[..Math.Min(fullContent.Length, 3000)]}"
            : $"Title: {article.Title}\nSummary: {(article.Summary ?? "")[..Math.Min((article.Summary ?? "").Length, 1500)]}";
        var systemPrompt = """
            You are a Senior Threat Intelligence Analyst providing a BLUF (Bottom Line Up Front) for a NOC dashboard.
            Analyze the intelligence and output EXACTLY four concise, hard-hitting bullet points.
            Do NOT include conversational filler. Use this exact markdown structure:
            - **Core Event:** [1 sentence detailing the specific threat, actor, or incident. Bold key entities.]
            - **Impact Radius:** [1 sentence identifying targeted sectors, affected software versions, or systemic blast radius.]
            - **Technical Details:** [1 sentence extracting known CVEs, TTPs, or technical mechanisms. If none are mentioned, state 'N/A'.]
            - **Actionable Posture:** [1 sentence detailing a defensive pivot, monitoring recommendation, or immediate mitigation step.]
            """;

        var provider = string.IsNullOrWhiteSpace(config.LlmProvider)
            ? "openai_compatible"
            : config.LlmProvider.Trim().ToLowerInvariant();
        var key = await aiSettings.GetSavedLlmApiKeyForProviderAsync(provider, cancellationToken);
        var contextWindow = Math.Max(1, config.LlmContextWindow ?? 128_000);
        var completion = await llm.CompleteAsync(
            new LlmProviderSettings(provider, config.LlmEndpoint ?? "", key, config.LlmModelName ?? ""),
            [new LlmChatMessage("system", systemPrompt), new LlmChatMessage("user", articleText)],
            0.1,
            Math.Max(1, Math.Min(contextWindow / 2, 8192)),
            TimeSpan.FromSeconds(300),
            cancellationToken);
        var bluf = completion.Success && !string.IsNullOrWhiteSpace(completion.Content)
            ? completion.Content.Trim()
            : null;
        if (string.IsNullOrEmpty(bluf) || bluf.Contains("[WARN]", StringComparison.Ordinal))
        {
            return new ArticleBlufResult(false, null, "AI generation failed.");
        }
        if (!await articles.SaveAiBlufAsync(articleId, bluf, cancellationToken))
        {
            return new ArticleBlufResult(false, null, "Article not found.");
        }
        return new ArticleBlufResult(true, bluf, null);
    }
}
