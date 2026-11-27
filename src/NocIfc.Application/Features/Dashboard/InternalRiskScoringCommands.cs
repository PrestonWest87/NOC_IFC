using System.Text.Json;
using System.Text.RegularExpressions;
using NocIfc.Application.Abstractions.Dashboard;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Abstractions.Threat;
using NocIfc.Domain.Dashboard;
using NocIfc.Domain.Settings;
using NocIfc.Domain.Threat;

namespace NocIfc.Application.Features.Dashboard;

public sealed record InternalRiskScoringResult(
    int Score,
    string RiskLevel,
    int TotalAssets,
    int TotalHardwareLoaded,
    int TotalSoftwareLoaded,
    int TotalOsintHits,
    int CriticalOsintHits,
    JsonElement HardwareData,
    JsonElement SoftwareData,
    string ScoringMode,
    int AutoCriticality,
    int Criticality,
    int AutoLethality,
    int Lethality);

public sealed class InternalRiskScoringCommands(
    IInternalRiskStore snapshots,
    IThreatArticleStore articles,
    ICisaKevStore cves,
    IRiskScoringSettingsStore riskSettings)
{
    private static readonly HashSet<string> StopWords = new(
        ["and", "the", "for", "with", "system", "server", "software", "application", "platform", "tool", "device"],
        StringComparer.Ordinal);
    private static readonly HashSet<string> IgnoreNames = new(
    [
        "apps", "app store", "books", "calculator", "calendar", "canvas", "chess", "clock",
        "computer", "connect", "console", "contacts", "customer support", "dashboard", "docs",
        "facetime", "family", "file", "games", "home", "installer", "keynote", "launchpad",
        "login", "mail", "maps", "messages", "music", "network", "news", "notes", "numbers",
        "pages", "paint", "passwords", "phone", "photos", "podcasts", "preferences", "preview",
        "print", "protector", "reader", "reminders", "screenshot", "script editor", "settings",
        "siri", "slides", "software update", "stress", "system settings", "terminal", "terminals",
        "time", "tips", "utilities", "voice memos", "weather", "wish", "xbox",
    ], StringComparer.Ordinal);
    private static readonly HashSet<string> CommonNouns = new(
    [
        "apt", "npm", "yum", "pip", "brew", "mac", "windows", "linux", "android", "zoom", "cups",
        "ssh", "ftp", "telnet", "sudo", "mount", "ufw", "make", "tracker", "patch", "bash", "cron",
        "less", "office", "info", "youtube", "surface", "google",
    ], StringComparer.Ordinal);
    private static readonly HashSet<string> StrongCyberKeywords = new(
        ["vulnerability", "cve", "malware", "ransomware", "phishing", "zero-day", "0-day", "exploit", "rce", "ddos", "cyber", "hacked", "botnet"],
        StringComparer.Ordinal);
    private static readonly HashSet<string> WeakCyberKeywords = new(
        ["breach", "patch", "flaw", "leak", "bug", "actor", "bypass"], StringComparer.Ordinal);
    private static readonly Regex WordPattern = new(@"\b[a-z0-9]{2,}\b", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex TriggerPattern = new(@"\b[a-z]{3,}\b", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly string ProximityKeywords = string.Join("|",
        StrongCyberKeywords.Concat(["flaw", "bug", "bypass", "patch"]).Select(Regex.Escape));
    private static readonly Regex AptCollision = Collision(@"\b(?:advanced persistent threat|apt\s*(?:group|actor|campaign|hacker|attack|malware|botnet))\b");
    private static readonly Regex MacCollision = Collision(@"\b(?:mac\s*(?:address|spoofing|layer|protocol))\b");
    private static readonly Regex SurfaceCollision = Collision(@"\b(?:attack\s*surface|surface\s*area)\b");
    private static readonly Regex OfficeCollision = Collision(@"\b(?:office\s*of)\b");

    public async Task<InternalRiskScoringResult> GenerateAndSaveAsync(CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        var inventory = await snapshots.GetAssetInventoryAsync(cancellationToken);
        var hardware = DeduplicateHardware(inventory.HardwareAssets);
        var software = DeduplicateSoftware(inventory.SoftwareAssets);
        var recentArticles = await articles.GetRecentForInternalRiskAsync(500, now.AddDays(-30), cancellationToken);
        var recentCves = await cves.GetRecentAsync(300, DateTime.MinValue, cancellationToken);
        var settings = await riskSettings.GetAsync(cancellationToken);
        var maps = BuildAssetMaps(hardware, software);
        var byTrigger = maps.GroupBy(map => map.Trigger, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.ToArray(), StringComparer.Ordinal);

        MatchArticles(recentArticles, byTrigger);
        MatchCves(recentCves, byTrigger);
        var calculated = CalculateScore(maps, hardware.Count, software.Count, settings);
        var snapshot = new InternalRiskSnapshotEntry(
            0,
            now,
            calculated.Score,
            calculated.RiskLevel,
            calculated.TotalAssets,
            calculated.TotalOsintHits,
            calculated.CriticalOsintHits,
            calculated.HardwareData,
            calculated.SoftwareData,
            calculated.ScoringMode);
        await snapshots.SaveSnapshotAsync(snapshot, cancellationToken);
        return calculated;
    }

    private static IReadOnlyList<InternalRiskHardwareAsset> DeduplicateHardware(
        IReadOnlyList<InternalRiskHardwareAsset> assets) =>
        assets.Where(asset => !string.IsNullOrEmpty(asset.IpAddress))
            .GroupBy(asset => asset.IpAddress!, StringComparer.Ordinal)
            .Select(group => group.Last())
            .ToArray();

    private static IReadOnlyList<InternalRiskSoftwareAsset> DeduplicateSoftware(
        IReadOnlyList<InternalRiskSoftwareAsset> assets) =>
        assets.Where(asset => !string.IsNullOrEmpty(asset.Name))
            .GroupBy(asset => asset.Name!.Trim().ToLowerInvariant(), StringComparer.Ordinal)
            .Select(group => group.Last())
            .ToArray();

    private static IReadOnlyList<AssetSearchMap> BuildAssetMaps(
        IReadOnlyList<InternalRiskHardwareAsset> hardware,
        IReadOnlyList<InternalRiskSoftwareAsset> software)
    {
        var maps = new List<AssetSearchMap>();
        foreach (var asset in hardware)
        {
            var name = FirstTruthy(asset.OperatingSystem, asset.OsProduct).Trim().ToLowerInvariant();
            var vendor = (asset.OsVendor ?? "").Trim().ToLowerInvariant();
            var version = (asset.OsVersion ?? "").Trim().ToLowerInvariant();
            if (!IsSearchableName(name)) continue;
            var trigger = GetTriggerToken(name) ?? GetTriggerToken(vendor);
            if (trigger is null) continue;
            maps.Add(new AssetSearchMap(true, name, trigger, BuildPatterns(name, vendor, version), asset, null));
        }

        foreach (var asset in software)
        {
            var name = (asset.Name ?? "").Trim().ToLowerInvariant();
            if (!IsSearchableName(name)) continue;
            var trigger = GetTriggerToken(name);
            if (trigger is null) continue;
            maps.Add(new AssetSearchMap(false, name, trigger, BuildPatterns(name, "", ""), null, asset));
        }
        return maps;
    }

    private static bool IsSearchableName(string name) =>
        name.Length >= 2 && !IgnoreNames.Contains(name);

    private static string? GetTriggerToken(string value)
    {
        string? longest = null;
        foreach (Match match in TriggerPattern.Matches(value))
        {
            var token = match.Value;
            if (!StopWords.Contains(token) && (longest is null || token.Length > longest.Length))
            {
                longest = token;
            }
        }
        return longest;
    }

    private static IReadOnlyList<Regex> BuildPatterns(string name, string vendor, string version)
    {
        var options = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Singleline | RegexOptions.Compiled;
        var escapedName = Regex.Escape(name);
        var patterns = new List<Regex>();
        if (CommonNouns.Contains(name))
        {
            var pattern = string.IsNullOrEmpty(version)
                ? $@"(?:\b(?:{ProximityKeywords})\b.{{0,100}}\b{escapedName}\b)|(?:\b{escapedName}\b.{{0,100}}\b(?:{ProximityKeywords})\b)"
                : $@"(?:\b(?:{ProximityKeywords})\b.{{0,100}}\b{escapedName}\b.{{0,50}}\b{Regex.Escape(version)}\b)";
            patterns.Add(new Regex(pattern, options));
            return patterns;
        }

        if (!string.IsNullOrEmpty(version))
        {
            patterns.Add(new Regex($@"\b{escapedName}\b.{{0,50}}\b{Regex.Escape(version)}\b", options));
            if (!string.IsNullOrEmpty(vendor) && !name.Contains(vendor, StringComparison.Ordinal))
            {
                patterns.Add(new Regex($@"\b{Regex.Escape(vendor)}\b.{{0,50}}\b{Regex.Escape(version)}\b", options));
            }
        }
        else
        {
            patterns.Add(new Regex($@"\b{escapedName}\b", options));
        }
        return patterns;
    }

    private static void MatchArticles(
        IReadOnlyList<ThreatArticle> articles,
        IReadOnlyDictionary<string, AssetSearchMap[]> byTrigger)
    {
        foreach (var article in articles)
        {
            if (article.Score.GetValueOrDefault() < 40) continue;
            var text = $"{article.Title ?? "None"} {article.Summary ?? ""}".ToLowerInvariant();
            var words = Tokenize(text);
            var strongHits = words.Count(StrongCyberKeywords.Contains);
            var weakHits = words.Count(WeakCyberKeywords.Contains);
            if (strongHits == 0 && weakHits < 2) continue;

            var matchCount = 0;
            var title = article.Title ?? "None";
            foreach (var trigger in words)
            {
                if (!byTrigger.TryGetValue(trigger, out var assets)) continue;
                foreach (var asset in assets)
                {
                    if (matchCount >= 5) break;
                    if (CollisionFor(asset.RawName)?.IsMatch(text) == true) continue;
                    if (!asset.Patterns.Any(pattern => pattern.IsMatch(text))) continue;
                    asset.Matches.Add(new RiskMatch(title, article.Score >= 80));
                    matchCount++;
                }
                if (matchCount >= 5) break;
            }
        }
    }

    private static void MatchCves(
        IReadOnlyList<CisaKevEntry> cves,
        IReadOnlyDictionary<string, AssetSearchMap[]> byTrigger)
    {
        foreach (var cve in cves)
        {
            var product = cve.Product ?? "None";
            var vendor = (cve.Vendor ?? "None").ToLowerInvariant();
            var text = $"{product} {cve.Description ?? "None"}".ToLowerInvariant();
            var words = Tokenize(text);
            words.Add(vendor);
            var matchCount = 0;
            foreach (var trigger in words)
            {
                if (!byTrigger.TryGetValue(trigger, out var assets)) continue;
                foreach (var asset in assets)
                {
                    if (matchCount >= 3) break;
                    if (asset.IsHardware && asset.Hardware is { } hardware)
                    {
                        var hardwareVendor = (hardware.OsVendor ?? "").ToLowerInvariant();
                        var hardwareProduct = FirstTruthy(hardware.OperatingSystem, hardware.OsProduct).ToLowerInvariant();
                        if (hardwareVendor.Length > 0 && hardwareProduct.Length > 0
                            && vendor.Contains(hardwareVendor, StringComparison.Ordinal)
                            && product.Contains(hardwareProduct, StringComparison.OrdinalIgnoreCase))
                        {
                            asset.Matches.Add(new RiskMatch($"CISA KEV: {cve.CveId ?? "None"}", true));
                            matchCount++;
                            continue;
                        }
                    }
                    if (CollisionFor(asset.RawName)?.IsMatch(text) == true) continue;
                    if (!asset.Patterns.Any(pattern => pattern.IsMatch(text))) continue;
                    asset.Matches.Add(new RiskMatch($"CISA KEV: {cve.CveId ?? "None"}", true));
                    matchCount++;
                }
                if (matchCount >= 3) break;
            }
        }
    }

    private static InternalRiskScoringResult CalculateScore(
        IReadOnlyList<AssetSearchMap> maps,
        int hardwareCount,
        int softwareCount,
        RiskScoringSettings? settings)
    {
        var uniqueTitles = new HashSet<string>(StringComparer.Ordinal);
        var criticalTitles = new HashSet<string>(StringComparer.Ordinal);
        var annotatedHardware = new List<Dictionary<string, object?>>();
        var annotatedSoftware = new List<Dictionary<string, object?>>();
        foreach (var asset in maps)
        {
            foreach (var match in asset.Matches)
            {
                uniqueTitles.Add(match.Title);
                if (match.IsCritical) criticalTitles.Add(match.Title);
            }

            var uniqueMatches = DistinctMatches(asset.Matches);
            if (uniqueMatches.Count == 0) continue;
            var riskScore = Math.Min(uniqueMatches.Count * 25, 100);
            var topThreat = uniqueMatches[0].Title;
            if (asset.IsHardware && asset.Hardware is { } hardware)
            {
                var displayName = string.IsNullOrEmpty(hardware.AssetName)
                    ? $"Device ({hardware.IpAddress})"
                    : hardware.AssetName;
                var os = $"{(string.IsNullOrEmpty(hardware.OperatingSystem) ? "Unknown" : hardware.OperatingSystem)} {hardware.OsVersion ?? ""}".Trim();
                annotatedHardware.Add(new Dictionary<string, object?>(StringComparer.Ordinal)
                {
                    ["Identifier"] = displayName,
                    ["IP Address"] = hardware.IpAddress,
                    ["OS"] = os,
                    ["OSINT Risk Score"] = riskScore,
                    ["OSINT Threat Matches"] = uniqueMatches.Count,
                    ["Top Threat Reference"] = topThreat,
                    ["risk_score"] = riskScore,
                    ["osint_threat_matches"] = uniqueMatches.Count,
                });
            }
            else if (asset.Software is { } software)
            {
                annotatedSoftware.Add(new Dictionary<string, object?>(StringComparer.Ordinal)
                {
                    ["Software Name"] = software.Name,
                    ["OSINT Risk Score"] = riskScore,
                    ["Active OSINT Matches"] = uniqueMatches.Count,
                    ["Top Threat Reference"] = topThreat,
                    ["osint_threat_matches"] = uniqueMatches.Count,
                    ["risk_level"] = riskScore >= 75 ? "HIGH" : riskScore >= 40 ? "MEDIUM" : "LOW",
                });
            }
        }

        annotatedHardware = annotatedHardware.OrderByDescending(asset => (int)asset["OSINT Risk Score"]!).ToList();
        annotatedSoftware = annotatedSoftware.OrderByDescending(asset => (int)asset["OSINT Risk Score"]!).ToList();
        var totalAssets = hardwareCount + softwareCount;
        var percentAtRisk = totalAssets > 0
            ? (annotatedHardware.Count + annotatedSoftware.Count) / (double)totalAssets * 100
            : 0;
        var autoLethality = criticalTitles.Count > 10 ? 5
            : criticalTitles.Count > 5 ? 4
            : criticalTitles.Count > 0 ? 3
            : uniqueTitles.Count > 10 ? 2 : 1;
        var autoCriticality = percentAtRisk > 30 ? 5
            : percentAtRisk > 20 ? 4
            : percentAtRisk > 10 ? 3
            : percentAtRisk > 5 ? 2 : 1;
        var scoringMode = settings?.ScoringMode;
        if (string.IsNullOrEmpty(scoringMode)) scoringMode = "auto";
        var criticality = scoringMode == "manual"
            ? Math.Clamp(settings?.InternalCriticalityOverride ?? 0, 1, 5)
            : autoCriticality;
        var lethality = scoringMode == "manual"
            ? Math.Clamp(settings?.InternalLethalityOverride ?? 0, 1, 5)
            : autoLethality;
        var systemCountermeasures = Math.Clamp(settings?.SysCountermeasures ?? 3, 1, 5);
        var networkCountermeasures = Math.Clamp(settings?.NetCountermeasures ?? 3, 1, 5);
        var rawScore = criticality + lethality - systemCountermeasures - networkCountermeasures;
        if (scoringMode == "hybrid") rawScore += settings?.InternalRiskOffset ?? 0;
        var score = Math.Clamp(rawScore, -8, 8);
        var riskLevel = score >= 6 ? "RED"
            : score >= 3 ? "ORANGE"
            : score >= -1 ? "YELLOW"
            : score >= -4 ? "BLUE" : "GREEN";

        return new InternalRiskScoringResult(
            score,
            riskLevel,
            totalAssets,
            hardwareCount,
            softwareCount,
            uniqueTitles.Count,
            criticalTitles.Count,
            JsonSerializer.SerializeToElement(annotatedHardware),
            JsonSerializer.SerializeToElement(annotatedSoftware),
            scoringMode,
            autoCriticality,
            criticality,
            autoLethality,
            lethality);
    }

    private static List<RiskMatch> DistinctMatches(IReadOnlyList<RiskMatch> matches)
    {
        var indices = new Dictionary<string, int>(StringComparer.Ordinal);
        var unique = new List<RiskMatch>();
        foreach (var match in matches)
        {
            if (indices.TryGetValue(match.Title, out var index)) unique[index] = match;
            else
            {
                indices[match.Title] = unique.Count;
                unique.Add(match);
            }
        }
        return unique;
    }

    private static HashSet<string> Tokenize(string text) =>
        WordPattern.Matches(text).Select(match => match.Value).ToHashSet(StringComparer.Ordinal);

    private static string FirstTruthy(string? first, string? second) =>
        !string.IsNullOrEmpty(first) ? first : second ?? "";

    private static Regex? CollisionFor(string rawName) => rawName switch
    {
        "apt" => AptCollision,
        "mac" => MacCollision,
        "surface" => SurfaceCollision,
        "office" => OfficeCollision,
        _ => null,
    };

    private static Regex Collision(string pattern) =>
        new(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private sealed class AssetSearchMap(
        bool isHardware,
        string rawName,
        string trigger,
        IReadOnlyList<Regex> patterns,
        InternalRiskHardwareAsset? hardware,
        InternalRiskSoftwareAsset? software)
    {
        public bool IsHardware { get; } = isHardware;
        public string RawName { get; } = rawName;
        public string Trigger { get; } = trigger;
        public IReadOnlyList<Regex> Patterns { get; } = patterns;
        public InternalRiskHardwareAsset? Hardware { get; } = hardware;
        public InternalRiskSoftwareAsset? Software { get; } = software;
        public List<RiskMatch> Matches { get; } = [];
    }

    private sealed record RiskMatch(string Title, bool IsCritical);
}
