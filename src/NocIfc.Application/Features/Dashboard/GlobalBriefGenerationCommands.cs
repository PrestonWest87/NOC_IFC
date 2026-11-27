using System.Text.RegularExpressions;
using NocIfc.Application.Abstractions.Dashboard;
using NocIfc.Application.Abstractions.Llm;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Abstractions.Threat;
using NocIfc.Application.Features.Settings;
using NocIfc.Application.Features.Threat;
using NocIfc.Domain.Dashboard;
using NocIfc.Domain.Threat;

namespace NocIfc.Application.Features.Dashboard;

public sealed class GlobalBriefGenerationCommands(
    ExecutiveIntelQueries executiveIntel,
    ICisaKevStore cisaKev,
    DashboardQueries dashboard,
    ThreatStatusQueries threatStatus,
    IOperationalDashboardStore dashboardStore,
    IAiSmtpSettingsStore aiSettings,
    ILlmChatCompletionClient llm)
{
    private static readonly string[] CiKeywords =
    [
        "critical infrastructure", "water", "wastewater", "electric", "power grid", "power",
        "oil", "gas", "pipeline", "energy", "telecom", "nuclear", "dams", "dam",
        "transportation", "rail", "port", "aviation", "chemical", "healthcare", "hospital",
        "food", "agriculture", "defense", "military", "government", "federal", "municipal",
        "scada", "ics", "ot", "operational technology", "supervisory control", "grid",
        "substation", "transmission", "distribution", "natural gas", "petroleum", "refinery",
        "lng", "propane", "sewage", "drinking water", "treatment plant", "water authority",
        "electric authority", "power authority",
    ];

    private static readonly string[] AptKeywords =
    [
        "apt", "apt1", "apt28", "apt29", "apt38", "lazarus", "cozy bear", "fancy bear",
        "sandworm", "turla", "darkside", "revil", "blackcat", "alphv", "cl0p", "clop",
        "lockbit", "ransomware", "nation-state", "state-sponsored", "kyberpandit", "volt typhoon",
        "salt typhoon", "flax typhoon", "brass typhoon", "kimsuky", "gamaredon", "apt41",
        "winnti", "stone panda", "mustang panda", "earth preta", "aqua blizzard", "bluebreeze",
        "voodoo bear",
    ];

    private static readonly (string Name, string[] Keywords)[] Sectors =
    [
        ("ICS/SCADA/OT", ["scada", "ics", "ot network", "operational technology", "supervisory control", "plc", "rtu", "siemens", "rockwell", "schneider", "ge electric", "abb", "honeywell", "emerson", "wonderware", "allen-bradley", "substation", "grid control"]),
        ("Oil & Gas", ["oil", "gas pipeline", "pipeline", "petroleum", "refinery", "lng", "propane", "barrel", "crude", "drilling"]),
        ("Electric/Power Grid", ["electric", "power grid", "power company", "energy supplier", "energy company", "grid", "transmission", "distribution", "generat", "utility", "outage"]),
        ("Water & Wastewater", ["water", "wastewater", "sewage", "drinking water", "treatment plant"]),
        ("Telecommunications", ["telecom", "telecommunications", "broadband", "isp", "cellular", "5g", "mobile network", "satellite"]),
        ("Transportation", ["transportation", "rail", "railway", "port", "aviation", "airport", "shipping", "freight", "logistics", "train", "maritime"]),
        ("Healthcare", ["healthcare", "hospital", "medical", "health", "pharma", "biotech", "clinic", "patient"]),
        ("Government", ["government", "federal", "municipal", "state department", "dhs", "cisa", "fbi", "nsa", "white house", "congress", "ministry", "embassy", "agency"]),
        ("Defense", ["defense", "military", "pentagon", "dod", "army", "navy", "air force", "defense contractor", "weapon"]),
        ("Financial Services", ["financial", "bank", "finance", "fintech", "payment", "swift", "stock", "exchange", "crypto", "bitcoin", "blockchain", "swiss"]),
        ("IT/Technology", ["microsoft", "google", "aws", "azure", "cloud", "saas", "data center", "github", "openai", "anthropic", "check point", "cisco", "vmware", "oracle", "linux", "kernel", "android", "apple", "samsung"]),
    ];

    private static readonly string[] ActorNames =
    [
        "lazarus", "cozy bear", "fancy bear", "sandworm", "turla", "darkside", "revil",
        "blackcat", "alphv", "cl0p", "clop", "lockbit", "volt typhoon", "salt typhoon",
        "flax typhoon", "brass typhoon", "kimsuky", "gamaredon", "apt41", "winnti",
        "mustang panda", "earth preta", "voodoo bear", "kyberpandit", "chaos ransomware",
        "china-nexus", "china-linked", "russia-linked", "krebston", "kremlin-backed",
        "iran-linked", "north korea",
    ];

    private static readonly string[] ArkansasCounties =
    [
        "arkansas", "ashley", "baxter", "benton", "boone", "bradley", "carroll", "chicot",
        "clark", "clay", "cleburne", "cleveland", "columbia", "conway", "craighead", "crawford",
        "crittenden", "cross", "dallas", "desha", "drew", "faulkner", "franklin", "fulton",
        "garland", "grant", "greene", "hempstead", "hot spring", "howard", "independence", "izard",
        "jackson", "jefferson", "johnson", "lafayette", "lawrence", "lee", "lincoln", "little river",
        "logan", "lonoke", "madison", "marion", "miller", "mississippi", "monroe", "montgomery",
        "nevada", "newton", "ouachita", "perry", "phillips", "pike", "poinsett", "polk", "pope",
        "prairie", "pulaski", "randolph", "saline", "scott", "searcy", "sebastian", "sevier",
        "sharp", "st. francis", "stone", "union", "van buren", "washington", "woodruff", "yell",
    ];

    private static readonly Regex AptPattern = new(@"\bapt[\s-]?\d+\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex UsPattern = new(
        @"\b(?:united\s+states|u\.s\.|american|domestic|homeland|dhs|cisa|fbi|nsa|white\s+house|state\s+department|texas|california|florida|new\s+york|chicago|washington\s+dc|colorado|oklahoma|ohio|virginia)\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex CvePattern = new(@"CVE-\d{4}-\d+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public async Task<BriefGenerationResult> GenerateAsync(
        Action<BriefGenerationProgress> reportProgress,
        CancellationToken cancellationToken)
    {
        Report("gathering", "Gathering global threat intelligence...", 0);
        var config = await aiSettings.GetAsync(cancellationToken);
        if (config?.IsActive != true) return Fail("AI is currently disabled in settings.");

        var now = DateTime.UtcNow;
        var since = now.AddHours(-24);
        var intel = await executiveIntel.GetAsync(cancellationToken);
        var articles = await executiveIntel.GetRecentScoredArticlesAsync(24, 250, cancellationToken);
        var cves = await cisaKev.GetRecentAsync(300, since, cancellationToken);
        var outages = (await threatStatus.GetCloudOutagesAsync(false, 1, cancellationToken)).Take(30).ToArray();
        var hazards = (await dashboard.GetHazardsAsync(100, cancellationToken))
            .Where(hazard => hazard.UpdatedAt >= since && IsArkansasHazard(hazard.Location))
            .Take(30)
            .ToArray();

        Report("filtering", "Filtering articles for relevance...", 1);
        var ciArticles = articles.Where(article => ContainsAny(ArticleText(article), CiKeywords)).ToArray();
        var ciIds = ciArticles.Select(article => article.Id).ToHashSet();
        var aptArticles = articles.Where(article => !ciIds.Contains(article.Id)
            && ContainsAny(ArticleText(article), AptKeywords)).ToArray();
        var nonCiArticles = articles.Where(article => !ciIds.Contains(article.Id)).ToArray();
        var usArticles = new List<ThreatArticle>();
        var globalArticles = new List<ThreatArticle>();
        var seen = new HashSet<int>();
        foreach (var article in ciArticles.Concat(aptArticles))
        {
            if (!seen.Add(article.Id)) continue;
            (UsPattern.IsMatch(ArticleText(article)) ? usArticles : globalArticles).Add(article);
        }
        foreach (var article in nonCiArticles)
        {
            if (!seen.Add(article.Id)) continue;
            (UsPattern.IsMatch(ArticleText(article)) ? usArticles : globalArticles).Add(article);
        }

        var contextWindow = Math.Max(1, config.LlmContextWindow ?? 128_000);
        var maxTokens = Math.Max(1, Math.Min(contextWindow / 2, 8192));
        var settings = await GetLlmSettingsAsync(config, cancellationToken);
        var cyberPayload = usArticles.Select(article => $"[US] {article.Title ?? "None"} | {article.Source ?? "None"} | {ArticleContent(article, contextWindow)}")
            .Concat(globalArticles.Select(article => $"[GLOBAL] {article.Title ?? "None"} | {article.Source ?? "None"} | {ArticleContent(article, contextWindow)}"))
            .Concat(cves.Select(cve => $"KEV: {cve.CveId ?? "None"} {cve.Vendor ?? "None"}/{cve.Product ?? "None"} - {cve.VulnerabilityName ?? "None"}"))
            .Concat(outages.Select(outage => $"Cloud: {outage.Provider ?? "None"}/{outage.Service ?? "None"} {(outage.IsResolved == true ? "Resolved" : "Down")} - {outage.Title ?? "None"}"))
            .ToArray();

        if (cyberPayload.Length == 0)
        {
            const string noData = "No significant threat intelligence data available in the last 24 hours.";
            return await SaveBriefAsync(noData, reportProgress, cancellationToken);
        }

        Report("cyber_map", $"Processing intelligence ({cyberPayload.Length} items)...", 5, total: cyberPayload.Length);
        var cyberMaps = await MapAsync(cyberPayload, GlobalMapPrompt, 8, settings, maxTokens, contextWindow,
            "cyber_map", 5, 89, reportProgress, cancellationToken);
        if (cyberMaps.Count == 0) return Fail("Intelligence processing failed.");

        var consolidatedHazards = ConsolidateHazards(hazards);
        var crimes = intel.RecentCrimes.Take(50).Select(crime => new GlobalCrime(
            crime.Incident.RawTitle ?? "Unknown",
            crime.Incident.DistanceMiles ?? 0,
            crime.FbiCategory,
            crime.Incident.Severity ?? "Unknown")).ToArray();
        var physicalPayload = consolidatedHazards
            .Select(hazard => $"HAZARD: {hazard.Title} | Severity: {hazard.Severity} | Location: {hazard.Location} | {hazard.Description}")
            .Concat(crimes.Select(crime => $"CRIME: {crime.Title} | Distance: {crime.DistanceMiles}mi | Category: {crime.Category} | Severity: {crime.Severity}"))
            .ToArray();
        IReadOnlyList<string> physicalMaps = ["No hazards or perimeter crimes reported."];
        if (physicalPayload.Length > 0)
        {
            Report("phys_map", $"Processing physical intelligence ({physicalPayload.Length} items)...", 90, total: physicalPayload.Length);
            physicalMaps = await MapAsync(physicalPayload, PhysicalMapPrompt, 6, settings, maxTokens, contextWindow,
                "phys_map", 90, 8, reportProgress, cancellationToken);
            if (physicalMaps.Count == 0) return Fail("Physical intelligence processing failed.");
        }

        Report("synthesizing", "Assembling brief from map outputs...", 96);
        var report = Assemble(cyberMaps, physicalMaps, cves, consolidatedHazards, crimes);
        var summary = await GenerateBlufAsync(report, settings, contextWindow, cancellationToken);
        if (!string.IsNullOrWhiteSpace(summary) && !summary.Contains("[WARN]", StringComparison.Ordinal))
        {
            report = ReplaceExecutiveSummary(report, summary.Trim());
        }
        if (report.Length < 100) return Fail("Brief assembly produced insufficient output.");
        return await SaveBriefAsync(report, reportProgress, cancellationToken);

        BriefGenerationResult Fail(string message)
        {
            Report("error", message, 0, message);
            return new BriefGenerationResult(false, null, message);
        }

        void Report(string stage, string message, int percent, string? error = null, int total = 0, int processed = 0) =>
            reportProgress(new BriefGenerationProgress(stage, message, total, processed, percent, error));
    }

    private async Task<BriefGenerationResult> SaveBriefAsync(
        string report,
        Action<BriefGenerationProgress> reportProgress,
        CancellationToken cancellationToken)
    {
        if (!await dashboardStore.SaveGlobalBriefAsync(report, DateTime.UtcNow, cancellationToken))
        {
            reportProgress(new BriefGenerationProgress("error", "Global brief could not be saved.", 0, 0, 0, "Global brief could not be saved."));
            return new BriefGenerationResult(false, null, "Global brief could not be saved.");
        }
        reportProgress(new BriefGenerationProgress("complete", "Global brief generation complete.", 0, 0, 100, null));
        return new BriefGenerationResult(true, report, null);
    }

    private async Task<IReadOnlyList<string>> MapAsync(
        IReadOnlyList<string> items,
        string mapPrompt,
        int baseChunkSize,
        LlmProviderSettings settings,
        int maxTokens,
        int contextWindow,
        string stage,
        int progressStart,
        int progressSpan,
        Action<BriefGenerationProgress> reportProgress,
        CancellationToken cancellationToken)
    {
        var chunkSize = Math.Max(baseChunkSize, (int)(baseChunkSize * Math.Max(1d, contextWindow / 128_000d)));
        var chunks = items.Chunk(chunkSize).ToArray();
        var outputs = new List<string>();
        for (var index = 0; index < chunks.Length; index++)
        {
            var done = index + 1;
            var percent = progressStart + (int)(done / (double)chunks.Length * progressSpan);
            reportProgress(new BriefGenerationProgress(
                stage,
                stage == "cyber_map" ? $"Intelligence map: chunk {done}/{chunks.Length}" : $"Physical intel: chunk {done}/{chunks.Length}",
                items.Count,
                index * chunkSize,
                Math.Min(98, percent),
                null));
            var response = await CompleteAsync(
                settings,
                [new LlmChatMessage("system", mapPrompt), new LlmChatMessage("user", string.Join('\n', chunks[index]))],
                0.3,
                maxTokens,
                cancellationToken);
            if (!string.IsNullOrWhiteSpace(response) && !response.Contains("[WARN]", StringComparison.Ordinal))
            {
                outputs.Add(response.Trim());
            }
        }
        return outputs;
    }

    private async Task<string> GenerateBlufAsync(
        string report,
        LlmProviderSettings settings,
        int contextWindow,
        CancellationToken cancellationToken)
    {
        var summary = report.Length <= 12_000 ? report : report[..12_000];
        return await CompleteAsync(settings,
            [
                new LlmChatMessage("system", "You are a NOC intelligence analyst. Write a 5-6 sentence BLUF for a threat brief. Include specific threats, actors, CVEs, and affected sectors. Highlight OT/SCADA/ICS. Explain what is known, what is inferred, and the two most important operational actions. Do not use headings, bullets, colors, or boilerplate. Be direct and specific."),
                new LlmChatMessage("user", summary),
            ],
            0.3,
            Math.Max(1, Math.Min(contextWindow / 4, 512)),
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

    private static List<GlobalBriefItem> Classify(IReadOnlyList<string> outputs)
    {
        var items = new List<GlobalBriefItem>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var output in outputs)
        {
            foreach (var line in output.Split('\n'))
            {
                var text = line.Trim().TrimStart('-', '*', '•').Trim();
                if (text.Length < 15 || text.Contains("NO_THREATS", StringComparison.OrdinalIgnoreCase)
                    || text.StartsWith("[WARN]", StringComparison.Ordinal)
                    || text.StartsWith("**") && text.EndsWith("**"))
                {
                    continue;
                }
                if (!seen.Add(text)) continue;
                var lower = text.ToLowerInvariant();
                var sector = Sectors.FirstOrDefault(entry => entry.Keywords.Any(keyword => lower.Contains(keyword, StringComparison.Ordinal))).Name ?? "General";
                var actors = ActorNames.Where(actor => lower.Contains(actor, StringComparison.Ordinal)).Select(NormalizeActor).Distinct(StringComparer.Ordinal).ToArray();
                var aptMatches = AptPattern.Matches(text).Select(match => match.Value.ToUpperInvariant());
                actors = actors.Concat(aptMatches).Distinct(StringComparer.Ordinal).ToArray();
                var cves = CvePattern.Matches(text).Select(match => match.Value.ToUpperInvariant()).Distinct(StringComparer.Ordinal).ToArray();
                items.Add(new GlobalBriefItem(text, sector, actors, cves, UsPattern.IsMatch(text)));
            }
        }
        return items;
    }

    private static string Assemble(
        IReadOnlyList<string> cyberMaps,
        IReadOnlyList<string> physicalMaps,
        IReadOnlyList<CisaKevEntry> kevItems,
        IReadOnlyList<GlobalHazard> hazards,
        IReadOnlyList<GlobalCrime> crimes)
    {
        var items = Classify(cyberMaps);
        var usItems = items.Where(item => item.IsUs).ToArray();
        var globalItems = items.Where(item => !item.IsUs).ToArray();
        var sectorGroups = usItems.GroupBy(item => item.Sector, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.ToArray(), StringComparer.Ordinal);
        var actorGroups = items.SelectMany(item => item.Actors.Select(actor => (actor, item)))
            .GroupBy(pair => pair.actor, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.Select(pair => pair.item).Distinct().ToArray(), StringComparer.Ordinal);
        var allCves = items.SelectMany(item => item.Cves).Distinct(StringComparer.Ordinal).ToArray();
        var threatLevel = actorGroups.Count >= 3 && allCves.Length >= 5
            ? "HIGH"
            : actorGroups.Count >= 2 || allCves.Length >= 3 || items.Count >= 5 ? "ELEVATED" : "MODERATE";

        var parts = new List<string> { "## Executive Summary (BLUF)", $"**THREAT LEVEL: {threatLevel}**" };
        var bullets = new List<string>();
        if (actorGroups.Count > 0) bullets.Add($"Active threat actors tracked: **{string.Join(", ", actorGroups.Keys.Order(StringComparer.Ordinal).Take(5))}**");
        if (sectorGroups.Count > 1) bullets.Add($"Targeted CI sectors: **{string.Join(", ", sectorGroups.Keys.Order(StringComparer.Ordinal).Take(5))}**");
        if (allCves.Length > 0) bullets.Add($"**{allCves.Length} CVE indicators** tracked in the current threat landscape");
        if (usItems.Length > 0) bullets.Add($"**{usItems.Length} US domestic threats** identified across: {string.Join(", ", usItems.Select(item => item.Sector).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).Take(4))}");
        if (globalItems.Length > 0) bullets.Add($"**{globalItems.Length} international threats** under active monitoring");
        if (bullets.Count == 0) bullets.Add($"**{items.Count} total threat indicators** processed across the intelligence cycle");
        parts.Add(string.Join('\n', bullets.Select(bullet => $"- {bullet}")));

        if (usItems.Length > 0)
        {
            parts.Add("## US Critical Infrastructure Threat Assessment");
            foreach (var sector in sectorGroups.Keys.Order(StringComparer.Ordinal))
            {
                parts.Add($"### {sector}");
                parts.Add(string.Join('\n', sectorGroups[sector].Take(15).Select(item => $"- {item.Text}")));
            }
        }
        if (actorGroups.Count > 0)
        {
            parts.Add("## Advanced Persistent Threat (APT) & Nation-State Activity");
            foreach (var actor in actorGroups.Keys.Order(StringComparer.Ordinal))
            {
                parts.Add($"### {actor}");
                parts.Add(string.Join('\n', actorGroups[actor].Take(10).Select(item => $"- {item.Text}")));
            }
        }
        var nonActorGlobal = globalItems.Where(item => item.Actors.Count == 0).Take(25).ToArray();
        if (nonActorGlobal.Length > 0)
        {
            parts.Add("## Global Threat Landscape");
            parts.Add(string.Join('\n', nonActorGlobal.Select(item => $"- {item.Text}")));
        }
        if (allCves.Length > 0 || items.Any(item => item.Sector is "IT/Technology" or "Financial Services"))
        {
            parts.Add("## Vulnerability & Exploit Intelligence");
            if (allCves.Length > 0)
            {
                parts.Add("### CISA Known Exploited Vulnerabilities");
                var lookup = kevItems.Where(item => !string.IsNullOrWhiteSpace(item.CveId))
                    .ToDictionary(item => item.CveId!.ToUpperInvariant(), StringComparer.Ordinal);
                parts.Add(string.Join('\n', allCves.Take(25).Select(cve => lookup.TryGetValue(cve, out var kev)
                    ? $"- **{cve}** — {kev.Vendor}/{kev.Product}: {kev.VulnerabilityName}"
                    : $"- **{cve}**")));
            }
            parts.Add("### Ransomware & Cybercriminal Operations");
            var ransomware = items.Where(item => item.Actors.Any(actor => RansomwareActors.Contains(actor, StringComparer.Ordinal)))
                .Take(10).ToArray();
            parts.Add(ransomware.Length == 0
                ? "- No named ransomware operations tracked in current window."
                : string.Join('\n', ransomware.Select(item => $"- {item.Text}")));
        }
        parts.Add("## Local Weather & Perimeter Posture");
        parts.Add(FormatPhysicalPosture(physicalMaps, hazards, crimes));
        parts.Add("## Operational Assessment & Priority Actions");
        if (allCves.Length > 0) parts.Add($"- **Patch exposure:** Validate {allCves.Length} tracked CVE indicators against internet-facing, government, and OT-adjacent assets; prioritize CISA KEVs.");
        if (actorGroups.Count > 0) parts.Add("- **Threat actor monitoring:** Hunt for actor-associated infrastructure, authentication anomalies, and unusual data movement before treating OSINT as evidence of compromise.");
        if (hazards.Count > 0) parts.Add("- **Continuity and personnel safety:** Confirm backup power, cooling, communications, and response contingencies for facilities in hazard areas.");
        if (crimes.Count > 0) parts.Add("- **Perimeter posture:** Review access-control alerts, camera coverage, guard procedures, and law-enforcement coordination for incidents in the monitored radius.");
        if (allCves.Length == 0 && actorGroups.Count == 0 && hazards.Count == 0 && crimes.Count == 0)
            parts.Add("- Continue routine monitoring and validate significant indicators with internal telemetry.");
        return string.Join("\n\n", parts);
    }

    private static string FormatPhysicalPosture(
        IReadOnlyList<string> mapOutputs,
        IReadOnlyList<GlobalHazard> hazards,
        IReadOnlyList<GlobalCrime> crimes)
    {
        var lines = new List<string>();
        lines.AddRange(hazards.Count == 0
            ? ["### Regional Weather Hazards", "- No significant weather hazards reported in the last 24 hours."]
            : ["### Regional Weather Hazards", .. hazards.Select(hazard => $"- **{hazard.Title}** ({hazard.Severity}): {hazard.AreaCount} areas; {hazard.Location}. Impact: {hazard.Description}")]);
        lines.AddRange(crimes.Count == 0
            ? ["### Local Perimeter Crimes", "- No perimeter crime incidents reported within the monitored radius."]
            : ["### Local Perimeter Crimes", .. crimes.GroupBy(crime => crime.Category, StringComparer.Ordinal).OrderBy(group => group.Key, StringComparer.Ordinal)
                .Select(group => $"- **{group.Key}**: {group.Count()} incident(s), {group.Min(item => item.DistanceMiles):F2} mi nearest; severity {string.Join(", ", group.Select(item => item.Severity).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal))}.")]);
        if (mapOutputs.Count > 0 && hazards.Count == 0 && crimes.Count == 0)
        {
            lines.Add("Physical map output:");
            lines.AddRange(mapOutputs.SelectMany(output => output.Split('\n')).Where(line => line.Length > 0).Take(10));
        }
        return string.Join('\n', lines);
    }

    private static string ReplaceExecutiveSummary(string report, string summary)
    {
        const string heading = "## Executive Summary (BLUF)";
        var index = report.IndexOf(heading, StringComparison.Ordinal);
        if (index < 0) return report;
        var insertAt = index + heading.Length;
        return report[..insertAt] + "\n" + summary.Trim() + report[insertAt..];
    }

    private async Task<IReadOnlyList<string>> MapAsync(
        IReadOnlyList<string> items,
        string mapPrompt,
        int baseChunkSize,
        double temperature,
        LlmProviderSettings settings,
        int maxTokens,
        int contextWindow,
        string stage,
        int progressStart,
        int progressSpan,
        Action<BriefGenerationProgress> reportProgress,
        CancellationToken cancellationToken)
    {
        var chunkSize = Math.Max(baseChunkSize, (int)(baseChunkSize * Math.Max(1d, contextWindow / 128_000d)));
        var chunks = items.Chunk(chunkSize).ToArray();
        var outputs = new List<string>();
        for (var index = 0; index < chunks.Length; index++)
        {
            var done = index + 1;
            reportProgress(new BriefGenerationProgress(
                stage,
                $"{(stage == "cyber_map" ? "Intelligence" : "Physical intel")} map: chunk {done}/{chunks.Length}",
                items.Count,
                index * chunkSize,
                Math.Min(98, progressStart + (int)(done / (double)chunks.Length * progressSpan)),
                null));
            var response = await CompleteAsync(
                settings,
                [new LlmChatMessage("system", mapPrompt), new LlmChatMessage("user", string.Join('\n', chunks[index]))],
                temperature,
                maxTokens,
                cancellationToken);
            if (!string.IsNullOrWhiteSpace(response) && !response.Contains("[WARN]", StringComparison.Ordinal))
                outputs.Add(response.Trim());
        }
        return outputs;
    }

    private static bool ContainsAny(string value, IReadOnlyList<string> keywords) =>
        keywords.Any(keyword => value.Contains(keyword, StringComparison.Ordinal));

    private static string ArticleText(ThreatArticle article) => $"{article.Title ?? ""} {article.Summary ?? ""}".ToLowerInvariant();

    private static string ArticleContent(ThreatArticle article, int contextWindow)
    {
        var maxSummary = contextWindow < 4000 ? 400 : 800;
        var maxContent = contextWindow < 4000 ? 600 : 1200;
        return !string.IsNullOrEmpty(article.FullContent) && article.FullContent.Length > 200
            ? Truncate(article.FullContent, maxContent)
            : Truncate(article.Summary, maxSummary);
    }

    private static string Truncate(string? text, int limit) => string.IsNullOrEmpty(text)
        ? "No details provided."
        : text.Length <= limit ? text : text[..limit] + "...";

    private static bool IsArkansasHazard(string? location)
    {
        var normalized = Regex.Replace(location ?? "", @"\bcounty\b", "", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return ArkansasCounties.Any(county => Regex.IsMatch(
            normalized, $@"\b{Regex.Escape(county)}\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));
    }

    private static GlobalHazard[] ConsolidateHazards(IReadOnlyList<DashboardRegionalHazard> hazards) =>
        hazards.GroupBy(hazard => $"{(hazard.HazardType ?? hazard.Title ?? "Weather Hazard").Trim()}\0{(hazard.Severity ?? "Unknown").Trim()}", StringComparer.OrdinalIgnoreCase)
            .Select(group =>
            {
                var first = group.First();
                var locations = group.Select(item => item.Location)
                    .Where(value => !string.IsNullOrWhiteSpace(value))
                    .Distinct(StringComparer.Ordinal)
                    .OrderBy(value => value, StringComparer.Ordinal)
                    .ToArray();
                return new GlobalHazard(
                    (first.HazardType ?? first.Title ?? "Weather Hazard").Trim(),
                    (first.Severity ?? "Unknown").Trim(),
                    string.Join("; ", locations),
                    Truncate(group.Select(item => item.Description).FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)), 220),
                    locations.Length);
            })
            .ToArray();

    private static string NormalizeActor(string value) => value.ToLowerInvariant() switch
    {
        "lazarus group" or "lazarus" => "LAZARUS",
        "cozy bear" => "COZY BEAR",
        "fancy bear" => "FANCY BEAR",
        _ => value.ToUpperInvariant(),
    };

    private sealed record GlobalBriefItem(string Text, string Sector, IReadOnlyList<string> Actors, IReadOnlyList<string> Cves, bool IsUs);
    private sealed record GlobalHazard(string Title, string Severity, string Location, string Description, int AreaCount);
    private sealed record GlobalCrime(string Title, double DistanceMiles, string Category, string Severity);

    private static readonly string[] RansomwareActors = ["LOCKBIT", "BLACKCAT", "ALPHV", "CLOP", "DARKSIDE", "REVIL", "CHAOS RANSOMWARE"];
    private static readonly string GlobalMapPrompt = """
        For EACH threat item, extract these key facts as bullet points:
        - THREAT: [actor if known] targeting [specific target/product] using [method/technique]
        - SECTOR: [which CI sector: Energy, Water, Telecom, Healthcare, Transport, Gov, Defense, Finance, IT, Oil&Gas, SCADA/ICS/OT, or General]
        - CVE: [CVE-ID if any, with product name]
        - SCOPE: [US domestic or International]
        - SEVERITY: [Critical/High/Medium/Low]
        Include every detail from the source. No filler. One bullet set per item.

        IMPORTANT RULES:
        1. If the input contains NO cyber threats, CVEs, threat actors, security vulnerabilities, or CI-relevant content, respond with ONLY the word NO_THREATS and nothing else. Do NOT describe what articles are about. Do NOT summarize non-threat content. Just output: NO_THREATS
        2. SKIP any items about weather, severe weather alerts, natural disasters, heat warnings, storms, flooding, or environmental hazards. These are processed separately. Do not include them in your output.
        """;
    private static readonly string PhysicalMapPrompt = """
        Extract EVERY detail from each item. For weather hazards:
        TYPE: [exact hazard type]
        SEVERITY: [exact severity level from NWS]
        LOCATION: [exact counties/regions affected]
        TIMESTAMP: [issue and expiry times]
        IMPACT: [potential infrastructure impact]

        For perimeter crimes:
        TYPE: [exact crime category]
        LOCATION: [specific area or zone]
        DISTANCE: [distance from facility in miles]
        SEVERITY: [threat level]
        TIME: [when reported]

        Be specific with every number, location name, and time. No generalizations. Combine multiple entries for the same hazard type.
        """;
}
