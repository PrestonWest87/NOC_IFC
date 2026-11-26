using NocIfc.Application.Abstractions.Llm;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Domain.AIOps;
using NocIfc.Domain.Identity;

namespace NocIfc.Application.Features.AIOps;

public static class AiopsSitrepReportBuilder
{
    public static string Build(AiopsRcaAnalysisResult analysis)
    {
        var alertCount = analysis.Clustered.Values.Sum(cluster => cluster.Alerts.Count);
        var report = new System.Text.StringBuilder(
            $"### Global Situation Report (SitRep)\n\n" +
            $"**Active Infrastructure Alerts:** {alertCount} | **Cloud Outages:** {analysis.ActiveCloudOutageCount} | " +
            $"**Grid/Weather Anomalies:** {analysis.ActiveWeatherHazardCount}\n\n");
        if (alertCount == 0)
        {
            return report.Append("[OK] **Grid Operational:** No active un-correlated infrastructure alerts detected.\n").ToString();
        }

        report.Append("#### Intelligence Causal Clusters\n");
        foreach (var (site, cluster) in analysis.Clustered)
        {
            var rootCause = analysis.RootCause[site];
            var icon = rootCause.Score >= 80 ? "[CRIT]" : rootCause.Score >= 50 ? "[HIGH]" : "[MEDIUM]";
            report.Append($"**{icon} {site} [{rootCause.Priority}]**\n")
                .Append($"- **Impact:** {cluster.Alerts.Count} nodes offline across {cluster.DomainsAffected.Count} topology layers ({rootCause.BlastRadius}).\n")
                .Append($"- **Patient Zero:** `{rootCause.PatientZero}` (Cascade Delay: {rootCause.CascadeDelay})\n")
                .Append($"- **Root Cause:** {rootCause.Cause}\n\n");
        }
        return report.ToString();
    }
}

public sealed class AiopsSitrepQueries(
    AiopsRcaAnalysisQueries analysis,
    IAiSmtpSettingsStore aiSettings,
    ILlmChatCompletionClient llm)
{
    private const string SystemPrompt = "You are an elite NOC AIOps Engine. Summarize the following deterministic IT SitRep into a technical 2-sentence executive summary. Do not use pleasantries.";

    public async Task<string?> GenerateAsync(
        AuthenticatedUser user,
        CancellationToken cancellationToken)
    {
        var snapshot = await analysis.AnalyzeSitrepAsync(user, cancellationToken);
        if (snapshot is null) return null;
        var report = AiopsSitrepReportBuilder.Build(snapshot);
        if (snapshot.Clustered.Count == 0) return report;

        var config = await aiSettings.GetAsync(cancellationToken);
        if (config?.IsActive != true) return report;
        var provider = string.IsNullOrWhiteSpace(config.LlmProvider)
            ? "openai_compatible"
            : config.LlmProvider.Trim().ToLowerInvariant();
        var apiKey = await aiSettings.GetSavedLlmApiKeyForProviderAsync(provider, cancellationToken);
        var maxTokens = Math.Max(1, Math.Min((config.LlmContextWindow ?? 128_000) / 2, 8192));
        var completion = await llm.CompleteAsync(
            new LlmProviderSettings(provider, config.LlmEndpoint ?? "", apiKey, config.LlmModelName ?? ""),
            [new LlmChatMessage("system", SystemPrompt), new LlmChatMessage("user", report)],
            0.1,
            maxTokens,
            TimeSpan.FromSeconds(300),
            cancellationToken);
        return completion.Success
            && !string.IsNullOrWhiteSpace(completion.Content)
            && !completion.Content.Contains("[WARN]", StringComparison.Ordinal)
                ? $"### AI Executive Summary\n> {completion.Content.Trim()}\n\n---\n\n{report}"
                : report;
    }
}
