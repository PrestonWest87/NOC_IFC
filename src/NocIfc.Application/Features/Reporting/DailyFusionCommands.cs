using System.Globalization;
using NocIfc.Application.Abstractions.Llm;
using NocIfc.Application.Abstractions.Reporting;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Settings;
using NocIfc.Domain.Reporting;

namespace NocIfc.Application.Features.Reporting;

public sealed record DailyFusionGenerationResult(bool Success, string? Date, string? Content, string? Message);

public sealed class DailyFusionCommands(
    IDailyBriefingStore briefings,
    IAiSmtpSettingsStore aiSettings,
    ILlmChatCompletionClient llm)
{
    private static readonly TimeZoneInfo CentralTimeZone = TimeZoneInfo.FindSystemTimeZoneById("America/Chicago");

    public async Task<DailyFusionGenerationResult> GenerateAsync(CancellationToken cancellationToken)
    {
        var config = await aiSettings.GetAsync(cancellationToken);
        if (config?.IsActive != true)
        {
            return new DailyFusionGenerationResult(false, null, null, "Report generation failed or AI is disabled.");
        }

        var nowCentral = TimeZoneInfo.ConvertTime(DateTimeOffset.UtcNow, CentralTimeZone);
        var reportDate = DateOnly.FromDateTime(nowCentral.DateTime).AddDays(-1);
        var reportDateLocal = reportDate.ToDateTime(TimeOnly.MinValue, DateTimeKind.Unspecified);
        var nextDateLocal = reportDate.AddDays(1).ToDateTime(TimeOnly.MinValue, DateTimeKind.Unspecified);
        var startUtc = TimeZoneInfo.ConvertTimeToUtc(reportDateLocal, CentralTimeZone);
        var endUtc = TimeZoneInfo.ConvertTimeToUtc(nextDateLocal, CentralTimeZone);
        var dateLabel = reportDateLocal.ToString("dddd, MMMM dd, yyyy", CultureInfo.InvariantCulture);
        var inputs = await briefings.GetGenerationInputsAsync(startUtc, endUtc, DateTime.UtcNow, cancellationToken);
        var llmSettings = await GetLlmSettingsAsync(config, cancellationToken);
        var contextWindow = config.LlmContextWindow ?? 128_000;
        var maxTokens = Math.Max(1, Math.Min(contextWindow / 2, 8192));

        var cyberSummary = inputs.Articles.Count == 0
            ? "No critical intelligence alerts tracked yesterday."
            : await SummarizeAsync(inputs.Articles, 6,
                "Summarize the key cyber threats in these headlines. Be brief.",
                "Combine these summaries into a cohesive, highly technical 2-paragraph situational report. Bold specific threat actors and malware.",
                article => $"- [{(int)(article.Score ?? 0)}] {article.Title ?? "None"}",
                llmSettings, maxTokens, 0.1, 0.2, cancellationToken);
        var cveSummary = inputs.Cves.Count == 0
            ? "No new KEVs added yesterday."
            : await SummarizeAsync(inputs.Cves, 8,
                "Extract the vendor, product, and vulnerability name from this list. Be extremely concise.",
                "Write a brief summary of the new vulnerabilities added to the KEV catalog. You MUST integrate the specific CVE IDs directly into your narrative.",
                cve => $"- {cve.CveId ?? "None"} ({cve.Vendor ?? "None"}): {cve.VulnerabilityName ?? "None"}",
                llmSettings, maxTokens, 0.1, 0.2, cancellationToken);
        var hazardSummary = inputs.Hazards.Count == 0
            ? "Grid operated normally with no reported hazards."
            : await SummarizeAsync(inputs.Hazards, 6,
                "List the severe weather events and locations.",
                "Summarize the physical threats and weather hazards from yesterday. Highlight the most severe classifications (e.g., Warnings, High Risk).",
                hazard => $"- {hazard.Severity ?? "None"}: {hazard.Title ?? "None"} ({hazard.Location ?? "None"})",
                llmSettings, maxTokens, 0.1, 0.2, cancellationToken);
        var cloudSummary = inputs.CloudOutages.Count == 0
            ? "No major tier-1 cloud outages reported."
            : await SummarizeAsync(inputs.CloudOutages, 5,
                "List the cloud provider, service, and geographic region affected.",
                "Summarize the major tier-1 cloud service disruptions from yesterday. Explicitly mention the geographic regions impacted and resolution status.",
                outage => $"- {outage.Provider ?? "None"} ({outage.Service ?? "None"}): {outage.Title ?? "None"}",
                llmSettings, maxTokens, 0.1, 0.2, cancellationToken);

        var compiledDomains = $"""
            --- CYBER INTELLIGENCE ---
            {cyberSummary}

            --- VULNERABILITY LANDSCAPE (CISA KEV) ---
            {cveSummary}

            --- PHYSICAL INFRASTRUCTURE & WEATHER ---
            {hazardSummary}

            --- CLOUD SERVICES ---
            {cloudSummary}
            """;
        var masterPrompt = $"""
            You are the Senior Director of a Network Operations Center (NOC).
            Take the provided domain summaries and weave them into a single, seamless, and highly professional 'Daily Fusion Report' formatted in Markdown.

            REQUIREMENTS:
            1. Start with an 'Executive Summary (BLUF)' paragraph that captures the overarching threat landscape across all domains.
            2. Create clear, distinct headers for Cyber, Vulnerabilities, Infrastructure, and Cloud.
            3. Ensure smooth narrative transitions between the sections so it reads like a single cohesive document, not a disjointed list.
            4. Preserve all specific data points (CVE numbers, threat actor names, locations, cloud providers).
            5. Do not hallucinate or add external information.

            Title the report: #  NOC Daily Fusion Report: {dateLabel}
            """;
        var report = await CompleteAsync(llmSettings,
            [new LlmChatMessage("system", masterPrompt), new LlmChatMessage("user", compiledDomains)],
            0.2, maxTokens, cancellationToken);
        if (string.IsNullOrEmpty(report) || report.Contains("[WARN]", StringComparison.Ordinal))
        {
            report = $"#  NOC Daily Fusion Report: {dateLabel}\n\n##  Cyber\n{cyberSummary}\n\n##  KEVs\n{cveSummary}\n\n##  Infrastructure\n{hazardSummary}\n\n##  Cloud\n{cloudSummary}";
        }

        await briefings.SaveAsync(reportDateLocal, report, DateTime.UtcNow, cancellationToken);
        return new DailyFusionGenerationResult(true, reportDate.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), report, null);
    }

    private async Task<string> SummarizeAsync<T>(
        IReadOnlyList<T> items,
        int chunkSize,
        string mapPrompt,
        string reducePrompt,
        Func<T, string> format,
        LlmProviderSettings settings,
        int maxTokens,
        double mapTemperature,
        double reduceTemperature,
        CancellationToken cancellationToken)
    {
        var summaries = new List<string>();
        foreach (var chunk in items.Chunk(chunkSize))
        {
            var response = await CompleteAsync(settings,
                [new LlmChatMessage("system", mapPrompt), new LlmChatMessage("user", string.Join('\n', chunk.Select(format)))],
                mapTemperature, maxTokens, cancellationToken);
            if (!string.IsNullOrWhiteSpace(response) && !response.Contains("[WARN]", StringComparison.Ordinal))
            {
                summaries.Add(response.Trim());
            }
        }
        if (summaries.Count == 0) return "AI failed to process batch.";
        if (summaries.Count == 1) return summaries[0];
        return await CompleteAsync(settings,
            [new LlmChatMessage("system", reducePrompt), new LlmChatMessage("user", string.Join("\n\n", summaries))],
            reduceTemperature, maxTokens, cancellationToken);
    }

    private async Task<LlmProviderSettings> GetLlmSettingsAsync(
        AiSmtpSettings config,
        CancellationToken cancellationToken)
    {
        var provider = string.IsNullOrWhiteSpace(config.LlmProvider)
            ? "openai_compatible"
            : config.LlmProvider.Trim().ToLowerInvariant();
        var key = await aiSettings.GetSavedLlmApiKeyForProviderAsync(provider, cancellationToken);
        return new LlmProviderSettings(provider, config.LlmEndpoint ?? "", key, config.LlmModelName ?? "");
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
            : $"[WARN] **AI REQUEST ERROR:** {result.Error ?? "The model endpoint returned an empty response."}";
    }
}
