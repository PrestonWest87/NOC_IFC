using System.Globalization;
using System.Text;
using NocIfc.Application.Abstractions.AIOps;
using NocIfc.Application.Abstractions.Llm;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Abstractions.Threat;
using NocIfc.Application.Features.Identity;
using NocIfc.Application.Features.Settings;
using NocIfc.Domain.AIOps;
using NocIfc.Domain.Identity;
using NocIfc.Domain.Threat;

namespace NocIfc.Application.Features.AIOps;

public sealed record AiopsScoringRationaleArticle(
    string? Source,
    string? Category,
    string? Title,
    string? Summary);

public sealed record AiopsScoringRationaleCrime(
    string? FbiCategory,
    string? RawTitle,
    string? DistanceMiles);

public sealed record AiopsScoringRationaleInput(
    string? UnifiedRisk,
    IReadOnlyList<AiopsScoringRationaleArticle> CyberArticles,
    IReadOnlyList<AiopsScoringRationaleArticle> PhysicalArticles,
    IReadOnlyList<AiopsScoringRationaleCrime> RecentCrimes);

public sealed record AiopsSitrepActionResult(bool Success, string Content);

public sealed class AiopsSitrepActionCommands(
    IAiopsSitrepActionStore data,
    IAiSmtpSettingsStore aiSettings,
    IApplicationSettingsStore applicationSettings,
    ICisaKevStore cisaKev,
    SiteTypeQueries siteTypes,
    ILlmChatCompletionClient llm)
{
    private const string RollingSummarySystemPrompt = """
        You are a Senior NOC Director writing the NOC IFS BRIEF for shift handover.
        Synthesize the provided Cyber, Physical, and Cloud telemetry into exactly two cohesive executive paragraphs.
        Lead with the most important cyber developments, then explain physical hazards and cloud/service impacts with specific locations and providers when available.
        Describe how threats converge operationally; do not merely list telemetry and do not invent facts.
        End with a single bolded sentence assessing the overall Grid Status, using this exact form: **Grid Status: [Nominal or Elevated Risk due to specific converging threats]**.
        """;

    private const string ScoringMapPrompt = "You are a CTI Analyst. Extract the core threats, vulnerabilities, threat actors, and their reporting SOURCES from these intelligence items. Output concise bullet points.";
    private const string ScoringReducePrompt = "Combine these batch extractions into a single, comprehensive intelligence digest. Ensure ALL unique threats, vulnerabilities, and their reporting SOURCES are preserved.";

    public static string? RequiredPermission(string action) => action switch
    {
        "refresh_briefing" => "Action: Generate Reports",
        "scoring_rationale" => "Action: Trigger AI Functions",
        "security_audit" => "Action: Run RCA Analysis",
        _ => null,
    };

    public async Task<bool> HasGlobalSiteAccessAsync(
        AuthenticatedUser user,
        CancellationToken cancellationToken)
    {
        if (user.IsAdministrator) return true;
        var allSiteTypes = await siteTypes.ExecuteAsync(cancellationToken);
        return new HashSet<string>(user.AllowedSiteTypes, StringComparer.Ordinal).IsSupersetOf(allSiteTypes);
    }

    public async Task<AiopsSitrepActionResult> RefreshBriefingAsync(CancellationToken cancellationToken)
    {
        var config = await aiSettings.GetAsync(cancellationToken);
        if (config?.IsActive != true) return new AiopsSitrepActionResult(false, "Generation failed.");

        var nowUtc = DateTime.UtcNow;
        var inputs = await data.GetRollingBriefInputsAsync(nowUtc.AddHours(-24), nowUtc, cancellationToken);
        var context = BuildRollingContext(inputs);
        var response = await CompleteAsync(config,
            [new LlmChatMessage("system", RollingSummarySystemPrompt), new LlmChatMessage("user", context)],
            0.2,
            cancellationToken);
        if (string.IsNullOrWhiteSpace(response)
            || response.Contains("[WARN]", StringComparison.Ordinal)
            || response.Contains("Generation failed", StringComparison.Ordinal))
        {
            return new AiopsSitrepActionResult(false, response ?? "Generation failed.");
        }
        await data.SaveRollingSummaryAsync(response.Trim(), DateTime.UtcNow, cancellationToken);
        return new AiopsSitrepActionResult(true, response.Trim());
    }

    public async Task<AiopsSitrepActionResult> GenerateScoringRationaleAsync(
        AiopsScoringRationaleInput input,
        CancellationToken cancellationToken)
    {
        var config = await aiSettings.GetAsync(cancellationToken);
        if (config?.IsActive != true) return new AiopsSitrepActionResult(false, "Generation failed.");
        var nowUtc = DateTime.UtcNow;
        var articles = input.CyberArticles.Concat(input.PhysicalArticles).Take(25).ToArray();
        var crimes = input.RecentCrimes.Take(15).ToArray();
        var recentCves = await cisaKev.GetRecentAsync(15, nowUtc.AddHours(-48), cancellationToken);
        if (articles.Length == 0 && crimes.Length == 0 && recentCves.Count == 0)
        {
            return new AiopsSitrepActionResult(true, "No active intelligence to brief at this time.");
        }

        var cyberDigest = articles.Length == 0
            ? "No active OSINT intelligence to report."
            : await SummarizeArticlesAsync(config, articles, cancellationToken);
        var crimesContext = crimes.Length == 0
            ? "No active perimeter crime incidents."
            : string.Join('\n', crimes.Select(crime =>
                $"- FBI Class: {crime.FbiCategory ?? "Unknown"} | {crime.RawTitle ?? "None"} ({crime.DistanceMiles ?? "None"} mi from HQ)"));
        var cveContext = recentCves.Count == 0
            ? "No major CVEs in 48h."
            : string.Join('\n', recentCves.Select(cve =>
                $"- CVE: {cve.CveId ?? "None"} ({cve.Vendor ?? "None"}): {cve.VulnerabilityName ?? "None"}"));
        var compiledIntel = $"--- CYBER INTELLIGENCE DIGEST (48H) ---\n{cyberDigest}\n\n--- CISA VULNERABILITIES (48H) ---\n{cveContext}\n\n--- ACTIVE PERIMETER INCIDENTS (24H - HQ ONLY) ---\n{crimesContext}";
        var prompt = $"""
            You are a Senior Threat Intelligence Briefer for a NOC Executive Dashboard.
            Write an expansive, highly detailed 'Executive Intelligence Brief' based on the provided digest.

            CRITICAL DIRECTIVES:
            1. Do NOT calculate any scores.
            2. Do NOT reference the CIS formula.
            3. Do NOT attempt to justify mathematical ratings.
            4. The current system threat level is **{input.UnifiedRisk ?? "UNKNOWN"}**. Ensure the tone matches this severity.
            Your ONLY job is to write a cohesive, real-world narrative of what is happening across the cyber and physical domains.

            Structure your response in Markdown with these EXACT headers:

            ## Cyber Intelligence Brief
            [Write long, expansive paragraphs detailing the specific cyber threats, their reporting SOURCES, identified threat actors, and CISA vulnerabilities. Group similar threats together to tell a flowing story of the digital landscape.]

            ##  Physical & Perimeter Security Brief
            [Write long, expansive paragraphs breaking down the perimeter incidents (explicitly using the FBI UCR definitions provided) and severe weather hazards. Explain their specific proximity risk to the Headquarters facility and personnel.]

            Be expansive, professional, highly readable, and authoritative.
            """;
        var response = await CompleteAsync(config,
            [new LlmChatMessage("system", prompt), new LlmChatMessage("user", compiledIntel)],
            0.3,
            cancellationToken);
        if (string.IsNullOrWhiteSpace(response)) response = "Brief generation failed.";
        var success = !response.Contains("[WARN]", StringComparison.Ordinal)
            && !response.Contains("Brief generation failed", StringComparison.Ordinal);
        return new AiopsSitrepActionResult(success, response.Trim());
    }

    public async Task<string> GenerateSecurityAuditAsync(CancellationToken cancellationToken)
    {
        var config = await aiSettings.GetAsync(cancellationToken);
        if (config?.IsActive != true) return "ERROR: AI Engine is disabled.";
        var cves = await cisaKev.GetRecentAsync(50, DateTime.MinValue, cancellationToken);
        if (cves.Count == 0) return "CLEAR: Tech stack is clear. No active KEVs found.";
        var applicationConfig = await applicationSettings.GetAsync(cancellationToken);
        var techStack = string.IsNullOrEmpty(applicationConfig?.TechStack)
            ? "SolarWinds, Cisco SD-WAN, Microsoft Office"
            : applicationConfig.TechStack;
        var mapPrompt = $"""
            Cross-reference these Actively Exploited Vulnerabilities (KEVs) against the internal stack.
            INTERNAL TECH STACK: {techStack}
            If a KEV targets a vendor/product in the TECH STACK, extract the CVE ID and impact. If none match, output 'CLEAR'.
            """;
        var matches = new List<string>();
        foreach (var chunk in cves.Chunk(8))
        {
            var context = string.Join('\n', chunk.Select(cve =>
                $"- {cve.CveId ?? "None"} ({cve.Vendor ?? "None"} {cve.Product ?? "None"}): {cve.VulnerabilityName ?? "None"}"));
            var response = await CompleteAsync(config,
                [new LlmChatMessage("system", mapPrompt), new LlmChatMessage("user", $"KEV Batch:\n{context}")],
                0,
                cancellationToken);
            if (!string.IsNullOrEmpty(response)
                && !response.Contains("CLEAR", StringComparison.OrdinalIgnoreCase)
                && !response.Contains("[WARN]", StringComparison.Ordinal))
            {
                matches.Add(response.Replace("MATCH:", "", StringComparison.Ordinal).Trim());
            }
        }
        if (matches.Count == 0) return "CLEAR: No active KEVs match internal infrastructure.";

        const string reducePrompt = "You are a SOC Director. Review the raw vulnerability matches and write a unified, critical Security Alert. Format with bullet points. Include CVE IDs, affected internal tech, and immediate required actions.";
        var final = await CompleteAsync(config,
            [new LlmChatMessage("system", reducePrompt), new LlmChatMessage("user", string.Join("\n\n", matches))],
            0.2,
            cancellationToken);
        return $"MATCH DETECTED:\n\n{final}";
    }

    private async Task<string> SummarizeArticlesAsync(
        AiSmtpSettings config,
        IReadOnlyList<AiopsScoringRationaleArticle> articles,
        CancellationToken cancellationToken)
    {
        var summaries = new List<string>();
        foreach (var chunk in articles.Chunk(8))
        {
            var context = string.Join('\n', chunk.Select(article =>
            {
                var source = string.IsNullOrEmpty(article.Source) ? "OSINT" : article.Source;
                var summary = string.IsNullOrEmpty(article.Summary)
                    ? "No details provided."
                    : article.Summary.Length <= 300 ? article.Summary : article.Summary[..300] + "...";
                return $"Source: {source} | Category: {article.Category ?? "None"} | Title: {article.Title ?? "None"} | {summary}";
            }));
            var response = await CompleteAsync(config,
                [new LlmChatMessage("system", ScoringMapPrompt), new LlmChatMessage("user", context)],
                0.1,
                cancellationToken);
            if (!string.IsNullOrWhiteSpace(response) && !response.Contains("[WARN]", StringComparison.Ordinal))
            {
                summaries.Add(response.Trim());
            }
        }
        if (summaries.Count == 0) return "AI failed to process batch.";
        if (summaries.Count == 1) return summaries[0];
        return await CompleteAsync(config,
            [new LlmChatMessage("system", ScoringReducePrompt), new LlmChatMessage("user", string.Join("\n\n", summaries))],
            0.2,
            cancellationToken);
    }

    private async Task<string> CompleteAsync(
        AiSmtpSettings config,
        IReadOnlyList<LlmChatMessage> messages,
        double temperature,
        CancellationToken cancellationToken)
    {
        var provider = string.IsNullOrWhiteSpace(config.LlmProvider)
            ? "openai_compatible"
            : config.LlmProvider.Trim().ToLowerInvariant();
        var apiKey = await aiSettings.GetSavedLlmApiKeyForProviderAsync(provider, cancellationToken);
        var maxTokens = Math.Max(1, Math.Min((config.LlmContextWindow ?? 128_000) / 2, 8192));
        var response = await llm.CompleteAsync(
            new LlmProviderSettings(provider, config.LlmEndpoint ?? "", apiKey, config.LlmModelName ?? ""),
            messages,
            temperature,
            maxTokens,
            TimeSpan.FromSeconds(300),
            cancellationToken);
        return response.Success && !string.IsNullOrWhiteSpace(response.Content)
            ? response.Content.Trim()
            : $"[WARN] **AI REQUEST ERROR:** {response.Error ?? "The model endpoint returned an empty response."}";
    }

    private static string BuildRollingContext(AiopsRollingBriefInputs inputs)
    {
        var context = new StringBuilder("--- CYBER THREATS ---\n");
        context.Append(inputs.ArticleTitles.Count == 0
            ? "None."
            : string.Join('\n', inputs.ArticleTitles.Select(article => $"- {article ?? "None"}")));
        context.Append("\n\n--- PHYSICAL HAZARDS ---\n");
        context.Append(inputs.Hazards.Count == 0
            ? "None."
            : string.Join('\n', inputs.Hazards.Select(hazard =>
                $"- {hazard.Severity ?? "None"}: {hazard.Title ?? "None"} in {hazard.Location ?? "None"}. Details: {hazard.Description ?? "No additional details."}")));
        context.Append("\n\n--- CLOUD OUTAGES ---\n");
        context.Append(inputs.CloudOutages.Count == 0
            ? "None."
            : string.Join('\n', inputs.CloudOutages.Select(outage =>
                $"- {outage.Provider ?? "None"} ({outage.Service ?? "None"}): {outage.Title ?? "None"}")));
        return context.ToString();
    }
}
