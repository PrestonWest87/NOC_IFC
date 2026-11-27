using System.Text.Json;
using System.Text.Json.Serialization;
using NocIfc.Application.Abstractions.Dashboard;
using NocIfc.Application.Abstractions.Llm;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Settings;
using NocIfc.Application.Features.Threat;

namespace NocIfc.Application.Features.Dashboard;

public sealed record BriefGenerationProgress(
    [property: JsonPropertyName("stage")] string Stage,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("total_items")] int TotalItems,
    [property: JsonPropertyName("processed_items")] int ProcessedItems,
    [property: JsonPropertyName("percent")] int Percent,
    [property: JsonPropertyName("error")] string? Error);

public sealed record BriefGenerationResult(bool Success, string? Brief, string? Message);

public sealed class UnifiedBriefGenerationCommands(
    ExecutiveIntelQueries executiveIntel,
    InternalRiskQueries internalRisk,
    CisaKevQueries cisaKev,
    DashboardQueries dashboard,
    ThreatStatusQueries threatStatus,
    IOperationalDashboardStore dashboardStore,
    IAiSmtpSettingsStore aiSettings,
    ILlmChatCompletionClient llm)
{
    private const int MapChunkSize = 15;
    private static readonly TimeZoneInfo CentralTimeZone = TimeZoneInfo.FindSystemTimeZoneById("America/Chicago");

    private const string CyberMapPrompt = """
        Extract factual data points regarding threat actors, vulnerabilities (CVEs), cloud service disruptions, and active exploits. Provide reason why an item is applicable. DO NOT embellish. Use strict bullet points.
        IMPORTANT: If the input contains NO cyber threats, CVEs, threat actors, security vulnerabilities, or CI-relevant content, respond with ONLY the word NO_THREATS and nothing else. Do NOT describe what articles are about. Do NOT summarize non-threat content. Just output: NO_THREATS
        """;

    private const string CyberReducePrompt = "Compile an exhaustive, purely factual Cyber Threat Intelligence digest. Preserve all CVE IDs, specific threat actor names, targeted vendors, and cloud providers. Do not extrapolate risks; report only what is explicitly stated in the data. Provide reason why item is applicable.";
    private const string PhysicalMapPrompt = "Extract precise factual details regarding weather severity, regional infrastructure hazards, and perimeter crimes (including distance and FBI categories). Be purely objective.";
    private const string PhysicalReducePrompt = "Compile an exhaustive physical risk digest. Categorize strictly into: 1) Severe Weather/Geospatial Hazards and 2) Local Perimeter Crimes. Retain exact distances, locations, and severity classifications. DO NOT embellish.";

    public async Task<BriefGenerationResult> GenerateAsync(
        Action<BriefGenerationProgress> reportProgress,
        CancellationToken cancellationToken)
    {
        Report("gathering", "Gathering telemetry data...", 0);
        var config = await aiSettings.GetAsync(cancellationToken);
        if (config?.IsActive != true)
        {
            return Fail("AI is currently disabled in settings.");
        }

        var now = DateTime.UtcNow;
        var global = await executiveIntel.GetAsync(cancellationToken);
        var internalSnapshot = await internalRisk.GetLatestAsync(cancellationToken);
        var cves = await cisaKev.GetRecentAsync(200, 1, cancellationToken);
        var hazards = (await dashboard.GetHazardsAsync(30, cancellationToken))
            .Where(hazard => hazard.UpdatedAt >= now.AddHours(-24))
            .Take(30)
            .ToArray();
        var outages = (await threatStatus.GetCloudOutagesAsync(false, 1, cancellationToken))
            .Take(20)
            .ToArray();

        var cyberPayload = global.RawCyberArticles.Take(150)
            .Select(entry => entry.Article)
            .Select(article => $"OSINT Article - Title: {article.Title ?? "None"} | Source: {article.Source ?? "None"} | Summary: {Truncate(article.Summary, 1200)}")
            .Concat(cves.Select(cve => $"CISA KEV - CVE: {cve.CveId ?? "None"} | Vendor: {cve.Vendor ?? "None"} | Product: {cve.Product ?? "None"} | Vuln: {cve.VulnerabilityName ?? "None"}"))
            .Concat(outages.Select(outage => $"Cloud Outage - Provider: {outage.Provider ?? "None"} | Service: {outage.Service ?? "None"} | Status: {(outage.IsResolved == true ? "Resolved" : "Active/Ongoing")} | Details: {outage.Title ?? "None"}"))
            .ToArray();

        var physicalPayload = global.RawPhysicalArticles.Take(100)
            .Select(article => $"Physical Intel - Title: {article.Title ?? "None"} | Source: {article.Source ?? "None"}")
            .Concat(hazards.Select(hazard => $"Weather/Hazard - Alert: {hazard.Title ?? hazard.HazardType ?? "None"} | Severity: {hazard.Severity ?? "Unknown"} | Location: {hazard.Location ?? "Multiple regions"} | Details: {Truncate(hazard.Description, 220)}"))
            .Concat(global.RecentCrimes.Take(20).Select(crime =>
                $"Perimeter Crime - Type: {crime.Incident.RawTitle ?? "Unknown"} | Distance from HQ: {crime.Incident.DistanceMiles?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "0"} miles | FBI Category: {crime.FbiCategory}"))
            .ToArray();

        var contextWindow = Math.Max(1, config.LlmContextWindow ?? 128_000);
        var maxTokens = Math.Max(1, Math.Min(contextWindow / 2, 8192));
        var llmSettings = await GetLlmSettingsAsync(config, cancellationToken);
        var cyberDigest = cyberPayload.Length == 0
            ? "No active cyber OSINT, KEVs, or cloud outages reported in the last 48 hours."
            : await SummarizeAsync(cyberPayload, CyberMapPrompt, CyberReducePrompt,
                "cyber_map", 1, 49, llmSettings, maxTokens, contextWindow, reportProgress, cancellationToken);
        if (IsFailedSummary(cyberDigest)) return Fail("Unified brief cyber evidence could not be processed.");

        var physicalDigest = physicalPayload.Length == 0
            ? "No significant weather hazards, regional disruptions, or perimeter crimes reported."
            : await SummarizeAsync(physicalPayload, PhysicalMapPrompt, PhysicalReducePrompt,
                "phys_map", 50, 49, llmSettings, maxTokens, contextWindow, reportProgress, cancellationToken);
        if (IsFailedSummary(physicalDigest)) return Fail("Unified brief physical evidence could not be processed.");

        var internalData = FormatInternalExposure(internalSnapshot?.HardwareData, internalSnapshot?.SoftwareData);
        var compiledIntel = $"""
            === MACRO THREAT POSTURE ===
            Global OSINT Risk Level: {global.UnifiedRisk}
            Internal Exposure Level: {internalSnapshot?.RiskLevel ?? "NONE"}

            === DEEP CYBER OSINT DIGEST (Includes KEVs & Cloud Outages) ===
            {cyberDigest}

            === DEEP PHYSICAL OSINT DIGEST (Includes Weather & Perimeter Crimes) ===
            {physicalDigest}

            === INTERNAL ASSET EXPOSURE (OSINT CORRELATIONS) ===
            --- HARDWARE ---
            {internalData.Hardware}

            --- SOFTWARE ---
            {internalData.Software}

            --- DEDUPLICATED VULNERABILITY REFERENCES ---
            {internalData.VulnerabilityReferences}
            """;
        var masterPrompt = $"""
            You are an intelligence analyst preparing a Unified OSINT Risk Digest for executive leadership.

            FORMATTING & TONE DIRECTIVES:
            1. VISUAL HIERARCHY: Use bolding for emphasis, bulleted lists for data points, and blockquotes for notable warnings.
            2. OPERATIONAL TRANSLATION: For every vulnerability or threat, briefly state the business relevance.
            3. THREAT LEVEL TERMINOLOGY: Use Low, Guarded, Elevated, High, or Severe. Do NOT use colors to describe threat levels.
            4. EXPAND THE NARRATIVE: Synthesize and group similar threats; explain relevance to continuity, personnel safety, or infrastructure.
            5. WORDING PRECISION — INTERNAL CYBER RISK: Use "continued attention" rather than "immediate attention".

            REQUIRED STRUCTURE:
            ## Executive OSINT Summary (BLUF)
            Provide a 5-6 sentence narrative explaining the convergence of the Global and Internal risk levels, followed by the top concerns.

            ## Internal Asset Threat Correlations (OSINT Overlaps)
            Format each exposed asset as **[Asset Name]**: [Vulnerability/CVE] - Reason applicable - *[Business/Operational Impact]*.

            ## Global Cyber & Cloud Threat Landscape
            Include Active Cyber Threats and Cloud & Infrastructure Disruptions. Detail threat actors, CISA KEVs, cloud providers, and industry or supply-chain relevance.

            ## Physical, Weather & Perimeter Posture
            Include Regional Weather Hazards and Local Perimeter Crimes, retaining distances, severity, and FBI categories.

            ## Strategic Recommendations
            Provide 3-5 recommended next steps.
            """;

        Report("synthesizing", "Synthesizing executive brief...", 99);
        var final = await CompleteAsync(llmSettings,
            [new LlmChatMessage("system", masterPrompt), new LlmChatMessage("user", compiledIntel)],
            0.5, maxTokens, cancellationToken);
        if (string.IsNullOrWhiteSpace(final) || final.Contains("[WARN]", StringComparison.Ordinal)
            || final.Contains("Brief generation failed", StringComparison.Ordinal))
        {
            return Fail("Brief generation failed.");
        }

        var brief = $"""
            ---
            **OSINT CORRELATION DISCLAIMER:** This brief correlates external Open-Source Intelligence (OSINT) with our internal asset types to provide situational awareness. It highlights potential external exposures and does NOT represent confirmed internal breaches or active system compromises.

            **AI-GENERATED CONTENT:** This brief was generated by the internal NOC AIOps system using automated intelligence analysis. This report has not been thoroughly reviewed by a Human Security Analyst. Some content in this report may not be applicable to our organization or may be mitigated by security controls.

            ---
            {final.Trim()}
            """;
        if (!await dashboardStore.SaveUnifiedBriefAsync(brief, DateTime.UtcNow, cancellationToken))
        {
            return Fail("Unified brief could not be saved.");
        }

        Report("complete", "Brief generation complete.", 100);
        return new BriefGenerationResult(true, brief, null);

        BriefGenerationResult Fail(string message)
        {
            Report("error", message, 0, message);
            return new BriefGenerationResult(false, null, message);
        }

        void Report(string stage, string message, int percent, string? error = null, int total = 0, int processed = 0) =>
            reportProgress(new BriefGenerationProgress(stage, message, total, processed, percent, error));
    }

    private async Task<string> SummarizeAsync(
        IReadOnlyList<string> items,
        string mapPrompt,
        string reducePrompt,
        string stage,
        int progressStart,
        int progressSpan,
        LlmProviderSettings settings,
        int maxTokens,
        int contextWindow,
        Action<BriefGenerationProgress> reportProgress,
        CancellationToken cancellationToken)
    {
        var chunkSize = Math.Max(1, (int)(15 * Math.Max(1d, contextWindow / 128_000d)));
        var chunks = items.Chunk(chunkSize).ToArray();
        var summaries = new List<string>();
        for (var index = 0; index < chunks.Length; index++)
        {
            var completed = index + 1;
            var percent = progressStart + (int)(completed / (double)chunks.Length * progressSpan);
            reportProgress(new BriefGenerationProgress(
                stage,
                $"{(stage == "cyber_map" ? "Cyber intelligence" : "Physical intelligence")} map-reduce: chunk {completed}/{chunks.Length} ({items.Count} items)",
                items.Count,
                index * chunkSize,
                percent,
                null));
            var response = await CompleteAsync(
                settings,
                [new LlmChatMessage("system", mapPrompt), new LlmChatMessage("user", string.Join('\n', chunks[index]))],
                0.1,
                maxTokens,
                cancellationToken);
            if (!string.IsNullOrWhiteSpace(response) && !response.Contains("[WARN]", StringComparison.Ordinal))
            {
                summaries.Add(response.Trim());
            }
        }

        if (summaries.Count == 0) return "[WARN] AI batch processing produced no usable summaries.";
        if (summaries.Count == 1) return summaries[0];
        return await CompleteAsync(
            settings,
            [new LlmChatMessage("system", reducePrompt), new LlmChatMessage("user", string.Join("\n\n", summaries))],
            0.2,
            maxTokens,
            cancellationToken);
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
        var response = await llm.CompleteAsync(
            settings, messages, temperature, maxTokens, TimeSpan.FromSeconds(300), cancellationToken);
        return response.Success && !string.IsNullOrWhiteSpace(response.Content)
            ? response.Content.Trim()
            : $"[WARN] **AI REQUEST ERROR:** {response.Error ?? "The model endpoint returned an empty response."}";
    }

    private static string Truncate(string? value, int maximumLength)
    {
        if (string.IsNullOrEmpty(value)) return "No details provided.";
        return value.Length <= maximumLength ? value : value[..maximumLength] + "...";
    }

    private static (string Hardware, string Software, string VulnerabilityReferences) FormatInternalExposure(
        JsonElement? hardware,
        JsonElement? software)
    {
        var hardwareLines = new List<string>();
        var softwareLines = new List<string>();
        var references = new HashSet<string>(StringComparer.Ordinal);
        AddAssets(hardware, true, hardwareLines, references);
        AddAssets(software, false, softwareLines, references);
        var hardwareText = hardwareLines.Count == 0
            ? "No hardware vulnerabilities correlated with active OSINT."
            : string.Join('\n', hardwareLines);
        var softwareText = softwareLines.Count == 0
            ? "No software vulnerabilities correlated with active OSINT."
            : string.Join('\n', softwareLines);
        var referenceText = references.Count == 0
            ? "No specific vulnerability references correlate at this time."
            : string.Join('\n', references.OrderBy(reference => reference, StringComparer.Ordinal).Select(reference => $"- {reference}"));
        return (hardwareText, softwareText, referenceText);
    }

    private static void AddAssets(
        JsonElement? source,
        bool hardware,
        List<string> lines,
        HashSet<string> references)
    {
        if (source is not { ValueKind: JsonValueKind.Array } data) return;
        var matchField = hardware ? "OSINT Threat Matches" : "Active OSINT Matches";
        var nameField = hardware ? "Identifier" : "Software Name";
        foreach (var asset in data.EnumerateArray().Take(20))
        {
            if (asset.ValueKind != JsonValueKind.Object) continue;
            var matches = ReadInteger(asset, matchField);
            var name = ReadJsonValue(asset, nameField, "Unknown");
            var detail = hardware ? ReadJsonValue(asset, "OS", "Unknown") : null;
            var reference = ReadJsonValue(asset, "Top Threat Reference", "None");
            if (matches > 0)
            {
                lines.Add(hardware
                    ? $"- {name} ({detail}): {matches} Matches. Threat Ref: {reference}"
                    : $"- {name}: {matches} Matches. Threat Ref: {reference}");
            }
            if (!string.IsNullOrWhiteSpace(reference) && reference != "None") references.Add(reference);
        }
    }

    private static int ReadInteger(JsonElement source, string key) =>
        source.TryGetProperty(key, out var value) && value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var parsed)
            ? parsed
            : 0;

    private static string ReadJsonValue(JsonElement source, string key, string fallback)
    {
        if (!source.TryGetProperty(key, out var value) || value.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return fallback;
        }
        return value.ValueKind == JsonValueKind.String ? value.GetString() ?? fallback : value.ToString();
    }

    private static bool IsFailedSummary(string summary) =>
        summary.Contains("[WARN]", StringComparison.Ordinal)
        || summary.Contains("AI failed to process batch", StringComparison.Ordinal);
}
