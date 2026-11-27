using System.Globalization;
using System.Text.RegularExpressions;
using NocIfc.Application.Abstractions.Llm;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Settings;
using NocIfc.Application.Features.Threat;
using NocIfc.Domain.Threat;

namespace NocIfc.Application.Features.Reporting;

public sealed record CustomReportGenerationInput(
    string Target,
    int DaysBack,
    IReadOnlyList<int> ArticleIds,
    string Objective,
    string Analyst);

public sealed record CustomReportProgress(string Stage, string Message, int Percent);

public sealed record CustomReportGenerationResult(bool Success, string? Content, string? Message);

public sealed class CustomReportCommands(
    ThreatArticleQueries articles,
    ThreatHuntingQueries hunting,
    IAiSmtpSettingsStore aiSettings,
    ILlmChatCompletionClient llm)
{
    private static readonly TimeZoneInfo CentralTimeZone = TimeZoneInfo.FindSystemTimeZoneById("America/Chicago");
    private static readonly Regex NoThreatNoise = new(
        "no[\\s_-]*threat|there\\s+are\\s+no\\s+threat|not\\s+contain.*threat|no\\s+specific\\s+threat|does\\s+not\\s+contain.*threat|only\\s+news\\s+articles|can\\s+extract\\s+some\\s+general|if\\s+you[\\s']?d\\s+like|let\\s+me\\s+know|here\\s+are\\s+the\\s+extracted|note\\s+that\\s+the\\s+other|i\\s+can\\s+provide\\s+a\\s+general",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public async Task<CustomReportGenerationResult> GenerateAsync(
        CustomReportGenerationInput input,
        Action<CustomReportProgress> reportProgress,
        CancellationToken cancellationToken)
    {
        var target = (input.Target ?? "").Trim();
        var objective = input.Objective ?? "";
        var analyst = input.Analyst ?? "Unknown";
        if (input.DaysBack is < 1 or > 30
            || target.Length > 500
            || input.ArticleIds.Count > 100
            || objective.Length > 4000
            || analyst.Length > 120
            || input.ArticleIds.Any(id => id <= 0))
        {
            throw new ArgumentException("Custom report criteria exceed their allowed bounds.");
        }

        var articleIds = input.ArticleIds.Distinct().ToArray();
        var hasTarget = target.Length > 0;
        if (!hasTarget && articleIds.Length == 0)
        {
            return new CustomReportGenerationResult(false, null, "Please enter a target entity or select articles.");
        }
        if (hasTarget && ThreatHuntingQueries.ParseSearchTerms(target).Count == 0)
        {
            return new CustomReportGenerationResult(false, null, "Please enter at least one valid search term.");
        }

        reportProgress(new CustomReportProgress("searching", "Searching for matching articles...", 5));
        var selectedArticles = articleIds.Length > 0
            ? await articles.GetByIdsAsync(articleIds, cancellationToken)
            : await hunting.SearchArticlesAsync(target, input.DaysBack, cancellationToken);
        if (selectedArticles.Count == 0)
        {
            reportProgress(new CustomReportProgress("error", "No articles found.", 0));
            return new CustomReportGenerationResult(false, null, "No articles found for the given target.");
        }

        var config = await aiSettings.GetAsync(cancellationToken);
        if (config?.IsActive != true)
        {
            reportProgress(new CustomReportProgress("error", "AI report generation failed.", 0));
            return new CustomReportGenerationResult(false, null, "Report generation failed or AI is disabled.");
        }

        reportProgress(new CustomReportProgress(
            "generating", $"Processing {selectedArticles.Count} articles through AI...", 20));
        var provider = string.IsNullOrWhiteSpace(config.LlmProvider)
            ? "openai_compatible"
            : config.LlmProvider.Trim().ToLowerInvariant();
        var key = await aiSettings.GetSavedLlmApiKeyForProviderAsync(provider, cancellationToken);
        var llmSettings = new LlmProviderSettings(
            provider, config.LlmEndpoint ?? "", key, config.LlmModelName ?? "");
        var contextWindow = Math.Max(1, config.LlmContextWindow ?? 128_000);
        var maxTokens = Math.Max(1, Math.Min(contextWindow / 2, 8192));
        var chunkSize = Math.Max(8, (int)(8 * Math.Max(1d, contextWindow / 128_000d)));
        var reportTargetLabel = hasTarget ? target : "Not specified";
        var mapPrompt = $"""
            You are supporting a senior cyber threat intelligence analyst.
            Extract the significant, source-supported facts from the supplied articles for a later
            analytic assessment. Preserve attribution, dates, named tools, vulnerabilities, targets,
            observed activity, and explicit recommendations. Distinguish reported facts from claims
            or assessments and retain the source title for each important fact.

            User objective: {objective}
            Target or report consumer: {reportTargetLabel}

            Return a compact evidence digest, not a finished report. Do not invent facts, fill gaps,
            or turn every noun into an IOC. Bullets are acceptable at this intermediate stage.
            """;
        var reducePrompt = $"""
            You are a senior cyber threat intelligence analyst writing a finished report
            for an operational intelligence audience. Use only the evidence digest below. The report
            consumer/target is: {reportTargetLabel}.

            User objective: {objective}

            Write a coherent analytic report in Markdown. This must read like an intelligence product,
            not an extraction table or a list of categories:

            1. Start with `## Executive Assessment` and write 2-4 connected paragraphs. State what is
               happening, who is responsible or suspected, why it matters to the target, and the
               confidence/limitations of the assessment.
            2. Use `## Key Findings`, `## Threat Activity and Tradecraft`, `## Targeting and Exposure`,
               `## Defensive Priorities`, and `## Sources and Caveats` as useful. Combine or omit a
               section when the evidence does not support it.
            3. Use paragraphs for analysis and transitions. Use bullets only for a short set of
               actionable priorities or clearly discrete technical indicators. Never create a long
               inventory under headings such as threat actors, TTPs, IOCs, or targeted systems.
            4. Explain the operational significance of technical details and connect related facts.
               Do not merely repeat them. Attribute claims (for example, "the reporting assesses...")
               and identify unknowns rather than presenting allegations as established fact.
            5. End with a concise overall risk judgment and the most important next action. Do not
               mention this prompt, the evidence digest, or apologize.

            STRICT RULES: Use ONLY the supplied evidence. Do not hallucinate CVEs, dates, victims,
            locations, capabilities, or relationships. If a requested detail is not supported, say so.
            """;

        var chunks = selectedArticles.Chunk(chunkSize).ToArray();
        var summaries = new List<string>();
        for (var index = 0; index < chunks.Length; index++)
        {
            var done = index + 1;
            var percent = (int)(done / (double)chunks.Length * 75) + 20;
            reportProgress(new CustomReportProgress(
                "generating", $"AI map-reduce: chunk {done}/{chunks.Length}", percent));
            var context = string.Join("\n", chunks[index].Select(FormatArticle));
            var map = await CompleteAsync(
                llmSettings,
                [new LlmChatMessage("system", mapPrompt), new LlmChatMessage("user", context)],
                0.1,
                maxTokens,
                cancellationToken);
            if (map.Length > 0 && !map.Contains("[WARN]", StringComparison.Ordinal) && !NoThreatNoise.IsMatch(map))
            {
                summaries.Add(map);
            }
        }

        if (summaries.Count == 0)
        {
            reportProgress(new CustomReportProgress("error", "AI report generation failed.", 0));
            return new CustomReportGenerationResult(false, null, "Report generation failed or AI is disabled.");
        }

        reportProgress(new CustomReportProgress(
            "generating", $"AI map-reduce: chunk {chunks.Length}/{chunks.Length}", 95));
        var report = await CompleteAsync(
            llmSettings,
            [new LlmChatMessage("system", reducePrompt), new LlmChatMessage("user", string.Join("\n\n", summaries))],
            0.2,
            maxTokens,
            cancellationToken);
        if (report.Length == 0 || report.Contains("[WARN]", StringComparison.Ordinal))
        {
            reportProgress(new CustomReportProgress("error", "AI report generation failed.", 0));
            return new CustomReportGenerationResult(false, null, "Report generation failed or AI is disabled.");
        }

        reportProgress(new CustomReportProgress("assembling", "Assembling final report...", 95));
        var now = TimeZoneInfo.ConvertTime(DateTimeOffset.UtcNow, CentralTimeZone);
        var zoneName = now.Offset == TimeSpan.FromHours(-5) ? "CDT" : "CST";
        var date = $"{now.ToString("dddd, MMMM dd, yyyy 'at' hh:mm tt", CultureInfo.InvariantCulture)} {zoneName}";
        var reportTarget = hasTarget ? target : string.Join(", ", articleIds);
        var content = $"# 📋 NOC Custom Intel Report\n**Target:** {reportTarget}\n**Date:** {date}\n**Analyst:** {analyst}\n\n---\n\n{report}";
        reportProgress(new CustomReportProgress("complete", "Report generation complete.", 100));
        return new CustomReportGenerationResult(true, content, null);
    }

    private async Task<string> CompleteAsync(
        LlmProviderSettings settings,
        IReadOnlyList<LlmChatMessage> messages,
        double temperature,
        int maxTokens,
        CancellationToken cancellationToken)
    {
        var result = await llm.CompleteAsync(
            settings, messages, temperature, maxTokens, TimeSpan.FromSeconds(300), cancellationToken);
        return result.Success && !string.IsNullOrWhiteSpace(result.Content)
            ? result.Content.Trim()
            : $"[WARN] {result.Error ?? "The model endpoint returned an empty response."}";
    }

    private static string FormatArticle(ThreatArticle article)
    {
        var content = string.IsNullOrEmpty(article.FullContent) ? article.Summary ?? "" : article.FullContent;
        var maximumLength = content.Length > 200 ? 2000 : 800;
        var text = content.Length == 0
            ? "No details provided."
            : content.Length <= maximumLength ? content : content[..maximumLength] + "...";
        return $"SOURCE: {article.Source} | TITLE: {article.Title}\nCONTENT: {text}\n\n";
    }
}
