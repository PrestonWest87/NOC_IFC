using System.Text.Json;
using NocIfc.Application.Abstractions.Dashboard;
using NocIfc.Application.Abstractions.Llm;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Abstractions.Threat;
using NocIfc.Application.Features.Settings;
using NocIfc.Application.Features.Threat;
using NocIfc.Domain.Dashboard;
using NocIfc.Domain.Threat;

namespace NocIfc.Application.Features.Dashboard;

public sealed class InternalBriefGenerationCommands(
    InternalRiskQueries internalRisk,
    ICisaKevStore cisaKev,
    IOperationalDashboardStore dashboardStore,
    IAiSmtpSettingsStore aiSettings,
    ILlmChatCompletionClient llm)
{
    private const int ChunkSize = 15;

    private const string MapPrompt = """
        You are an internal infrastructure security analyst performing OSINT correlation analysis.

        For each asset listed below, identify:
        - Specific CVEs or vulnerabilities that affect THIS EXACT asset (match vendor + product + version)
        - Threat actors or campaigns known to target this technology
        - Risk severity: CRITICAL if actively exploited, HIGH if CVE exists, MEDIUM if potential, LOW if no direct correlation
        - Whether the asset is internet-facing or contains sensitive data (infer from type: firewall, server, SCADA = high value)

        Preserve all CVE IDs, vendor names, product names, and version numbers exactly.
        Group findings by asset. Be specific about which CVE applies to which asset version.
        Do NOT list assets with zero correlations — only report assets with confirmed or high-probability matches.

        IMPORTANT: If the input contains NO assets with CVE correlations, security vulnerabilities, or threat matches, respond with ONLY the word NO_THREATS and nothing else. Do NOT describe what assets are about. Do NOT explain that no correlations were found. Just output: NO_THREATS
        """;

    private const string ReducePrompt = """
        Compile an exhaustive Internal Asset Risk Correlation Report.

        Structure your output as:

        ## Executive Internal Risk Summary
        - Overall internal posture based on asset-OSINT correlations
        - Number of assets at risk vs total assets
        - Critical risk drivers (top 3 assets requiring immediate attention)

        ## Hardware Asset Threat Correlations
        - Group by risk tier: CRITICAL > HIGH > MEDIUM
        - For each asset: specific CVEs, threat actors, exploit availability, and business impact
        - Include IP, OS version, and exact vulnerability references
        - SCADA/RTU/ICS assets get dedicated section if present

        ## Software Asset Threat Correlations
        - Group by risk tier: CRITICAL > HIGH > MEDIUM
        - For each software: CVEs, known exploits, active campaigns, patch availability
        - Include version-specific applicability

        ## Vulnerability Reference Matrix
        - Deduplicated list of all CVEs correlated to our stack
        - For each: affected asset(s), CVSS if available, exploit status, recommended action

        ## Patching & Hardening Recommendations
        - Prioritized action items grouped by urgency
        - Specific version upgrades or patches to apply
        - Compensating controls if patches are unavailable
        - Network segmentation recommendations for high-risk assets

        Do NOT include global threat landscape or external OSINT — focus ONLY on correlations to our specific internal assets.
        """;

    private const string MasterPrompt = """
        You are a senior infrastructure security analyst preparing an Internal Asset Risk Brief for executive and technical leadership.

        CONTEXT:
        - Total Assets Monitored: {0}
        - Assets with OSINT Correlations: {1}
        - Internal CIS Risk Level: {2} (Score: {3})
        - Critical OSINT Hits: {4}
        - Total OSINT Correlations: {5}

        FORMATTING & TONE DIRECTIVES:
        1. ASSET-CENTRIC: Every finding must be tied to a specific internal asset (name, IP, OS/version).
        2. RISK PRIORITIZATION: Lead with CRITICAL and HIGH risk assets. Low-risk assets get a brief mention.
        3. OPERATIONAL TRANSLATION: For every CVE/threat, state the business impact.
        4. ACTIONABLE: Every section must end with specific remediation steps.
        5. VERSION-SPECIFIC: Only report CVEs that apply to the exact versions we run.

        REQUIRED STRUCTURE:
        ## Executive Internal Risk Assessment (BLUF)
        * 4-5 sentence summary of internal asset posture
        * Top 3 critical risk assets requiring immediate leadership attention
        * Overall risk trajectory (improving/stable/deteriorating)

        ## Critical Hardware Asset Vulnerabilities
        * Dedicate a sub-section to each CRITICAL risk hardware asset
        * Format: **[Asset Name]** (IP, OS Version) — Risk Score: X/100
          - Applicable CVEs with business impact
          - Threat actors/campaigns targeting this technology
          - Recommended action (patch version, upgrade path, or compensating control)

        ## SCADA/ICS/OT Asset Exposure (if applicable)
        * Dedicated section for any SCADA, RTU, PLC, or OT assets
        * Emphasize safety and operational continuity impact
        * Recommend network segmentation if not already segmented

        ## Software Stack Vulnerability Analysis
        * Group by risk tier (CRITICAL > HIGH > MEDIUM)
        * For each: exact version applicability, CVE references, exploit status
        * Patch availability and recommended version

        ## Deduplicated CVE Reference Table
        * All correlated CVEs in a structured list
        * Columns: CVE ID | Affected Asset | Severity | Exploit Status | Recommended Action

        ## Recommended Actions (Prioritized)
        1. IMMEDIATE (next 24 hours): Critical patches, network isolation
        2. SHORT-TERM (next 7 days): High-risk patches, config hardening
        3. MEDIUM-TERM (next 30 days): Medium-risk items, architecture review

        ---
        **OSINT CORRELATION DISCLAIMER:** This brief correlates external Open-Source Intelligence (OSINT) with our internal asset inventory to identify potential exposures. It does NOT represent confirmed breaches or active compromises.

        **AI-GENERATED CONTENT:** This brief was generated by the internal NOC AIOps system. Review by a qualified security analyst is recommended before taking action.
        """;

    public async Task<BriefGenerationResult> GenerateAsync(
        Action<BriefGenerationProgress> reportProgress,
        CancellationToken cancellationToken)
    {
        Report("gathering", "Gathering internal asset data...", 0);
        var snapshot = await internalRisk.GetLatestAsync(cancellationToken);
        if (snapshot is null)
        {
            return Fail("No internal risk snapshot available. Trigger an internal risk calculation first.");
        }
        var config = await aiSettings.GetAsync(cancellationToken);
        if (config?.IsActive != true) return Fail("AI is currently disabled in settings.");

        var cves = await cisaKev.GetRecentAsync(200, DateTime.UtcNow.AddDays(-1), cancellationToken);
        var hardware = ReadAssets(snapshot.HardwareData);
        var software = ReadAssets(snapshot.SoftwareData);
        Report("asset_analysis", $"Analyzing {hardware.Count} hardware and {software.Count} software assets...", 5);

        var payload = hardware.Select(FormatHardware)
            .Concat(software.Select(FormatSoftware))
            .Concat(cves.Select(cve =>
                $"CISA KEV - CVE: {cve.CveId ?? "None"} | Vendor: {cve.Vendor ?? "None"} | Product: {cve.Product ?? "None"} | Vuln: {cve.VulnerabilityName ?? "None"}"))
            .ToArray();
        if (payload.Length == 0)
        {
            return Fail("No internal asset or recent CVE data is available for analysis.");
        }

        var provider = string.IsNullOrWhiteSpace(config.LlmProvider)
            ? "openai_compatible"
            : config.LlmProvider.Trim().ToLowerInvariant();
        var key = await aiSettings.GetSavedLlmApiKeyForProviderAsync(provider, cancellationToken);
        var settings = new LlmProviderSettings(provider, config.LlmEndpoint ?? "", key, config.LlmModelName ?? "");
        var contextWindow = Math.Max(1, config.LlmContextWindow ?? 128_000);
        var maxTokens = Math.Max(1, Math.Min(contextWindow / 2, 8192));
        Report("correlation", $"Running OSINT correlation analysis ({payload.Length} items)...", 10, total: payload.Length);
        var chunkSize = Math.Max(1, (int)(ChunkSize * Math.Max(1d, contextWindow / 128_000d)));
        var chunks = payload.Chunk(chunkSize).ToArray();
        var summaries = new List<string>();
        for (var index = 0; index < chunks.Length; index++)
        {
            var done = index + 1;
            Report("correlation", $"Asset correlation map-reduce: chunk {done}/{chunks.Length} ({payload.Length} items)...",
                (int)(done / (double)chunks.Length * 79) + 10,
                total: payload.Length,
                processed: index * chunkSize);
            var response = await CompleteAsync(
                settings,
                [new LlmChatMessage("system", MapPrompt), new LlmChatMessage("user", string.Join('\n', chunks[index]))],
                0.1,
                maxTokens,
                cancellationToken);
            if (string.IsNullOrWhiteSpace(response) || response.Contains("[WARN]", StringComparison.Ordinal)
                || DashboardQueries.IsInternalRiskBriefFailureNotice(response))
            {
                var detail = (response ?? "No correlation result returned.").Trim();
                if (detail.StartsWith("[WARN]", StringComparison.Ordinal)) detail = detail[6..].Trim();
                return Fail($"Internal asset correlation failed; no complete brief was saved. {detail}");
            }
            summaries.Add(response.Trim());
        }

        var correlationDigest = summaries.Count == 1
            ? summaries[0]
            : await CompleteAsync(
                settings,
                [new LlmChatMessage("system", ReducePrompt), new LlmChatMessage("user", string.Join("\n\n", summaries))],
                0.2,
                maxTokens,
                cancellationToken);
        if (string.IsNullOrWhiteSpace(correlationDigest) || correlationDigest.Contains("[WARN]", StringComparison.Ordinal)
            || DashboardQueries.IsInternalRiskBriefFailureNotice(correlationDigest))
        {
            var detail = (correlationDigest ?? "No correlation result returned.").Trim();
            if (detail.StartsWith("[WARN]", StringComparison.Ordinal)) detail = detail[6..].Trim();
            return Fail($"Internal asset correlation failed; no complete brief was saved. {detail}");
        }

        Report("synthesizing", "Synthesizing internal risk brief...", 92);
        var prompt = string.Format(
            System.Globalization.CultureInfo.InvariantCulture,
            MasterPrompt,
            snapshot.TotalAssets ?? 0,
            CountMatches(hardware, "OSINT Threat Matches") + CountMatches(software, "Active OSINT Matches"),
            snapshot.RiskLevel ?? "UNKNOWN",
            snapshot.Score ?? 0,
            snapshot.CriticalOsintHits ?? 0,
            snapshot.TotalOsintHits ?? 0);
        var final = await CompleteAsync(
            settings,
            [new LlmChatMessage("system", prompt), new LlmChatMessage("user", correlationDigest)],
            0.35,
            maxTokens,
            cancellationToken);
        if (string.IsNullOrWhiteSpace(final) || final.Contains("[WARN]", StringComparison.Ordinal)
            || DashboardQueries.IsInternalRiskBriefFailureNotice(final))
        {
            return Fail("Internal brief generation returned incomplete output; no report was saved.");
        }
        if (!await dashboardStore.SaveInternalBriefAsync(final.Trim(), DateTime.UtcNow, cancellationToken))
        {
            return Fail("Internal brief could not be saved.");
        }

        Report("complete", "Internal brief generation complete.", 100);
        return new BriefGenerationResult(true, final.Trim(), null);

        BriefGenerationResult Fail(string message)
        {
            Report("error", message, 0, message);
            return new BriefGenerationResult(false, null, message);
        }

        void Report(string stage, string message, int percent, string? error = null, int total = 0, int processed = 0) =>
            reportProgress(new BriefGenerationProgress(stage, message, total, processed, percent, error));
    }

    private static List<JsonElement> ReadAssets(JsonElement data) =>
        data.ValueKind == JsonValueKind.Array ? data.EnumerateArray().ToList() : [];

    private static string FormatHardware(JsonElement asset) =>
        $"[HW] {Read(asset, "Identifier", "Unknown")} ({Read(asset, "IP Address", "N/A")}) | OS: {Read(asset, "OS", "Unknown")} | OSINT Risk: {Read(asset, "OSINT Risk Score", "0")}/100 | Matches: {Read(asset, "OSINT Threat Matches", "0")} | Top Ref: {Read(asset, "Top Threat Reference", "None")}";

    private static string FormatSoftware(JsonElement asset) =>
        $"[SW] {Read(asset, "Software Name", "Unknown")} | Risk Level: {Read(asset, "risk_level", "LOW")} | OSINT Risk: {Read(asset, "OSINT Risk Score", "0")}/100 | Matches: {Read(asset, "Active OSINT Matches", "0")} | Top Ref: {Read(asset, "Top Threat Reference", "None")}";

    private static string Read(JsonElement source, string property, string fallback) =>
        source.ValueKind == JsonValueKind.Object && source.TryGetProperty(property, out var value)
            && value.ValueKind is not (JsonValueKind.Null or JsonValueKind.Undefined)
                ? value.ValueKind == JsonValueKind.String ? value.GetString() ?? fallback : value.ToString()
                : fallback;

    private static int CountMatches(IReadOnlyList<JsonElement> assets, string property) =>
        assets.Count(asset => asset.ValueKind == JsonValueKind.Object && asset.TryGetProperty(property, out var matches)
            && matches.ValueKind == JsonValueKind.Number && matches.TryGetInt32(out var count) && count > 0);

    private async Task<string> CompleteAsync(
        LlmProviderSettings settings,
        IReadOnlyList<LlmChatMessage> messages,
        double temperature,
        int maxTokens,
        CancellationToken cancellationToken)
    {
        var completion = await llm.CompleteAsync(
            settings, messages, temperature, maxTokens, TimeSpan.FromSeconds(300), cancellationToken);
        return completion.Success && !string.IsNullOrWhiteSpace(completion.Content)
            ? completion.Content.Trim()
            : $"[WARN] **AI REQUEST ERROR:** {completion.Error ?? "The model endpoint returned an empty response."}";
    }
}
