using NocIfc.Application.Abstractions.Dashboard;
using NocIfc.Domain.Dashboard;
using NocIfc.Domain.Threat;

namespace NocIfc.Application.Features.Dashboard;

public sealed class ExecutiveIntelQueries(IExecutiveIntelStore intel)
{
    private static readonly string[] CyberCategories =
    ["Cyber: Exploits & Vulns", "Cyber: Malware & Threats", "ICS/OT & SCADA", "Cloud & IT Infrastructure"];
    private static readonly string[] PhysicalCategories =
    ["Physical Security & Crime", "Severe Weather & Natural Hazards", "Geopolitics & Policy"];
    private static readonly string[] GridCrimeCategories =
    [
        "Perimeter Breach/Vandalism", "Violent Proximity Threat", "Asset/Copper Theft Risk",
        "Trespassing/Suspicious Activity", "Public Disturbance/Narcotics",
    ];
    private static readonly string[] GeopoliticalNoiseWords =
        ["troop", "missile", "election", "ballot", "warfare", "kinetic", "embassy"];
    private static readonly string[] ThreatActorKeywords =
        ["volt typhoon", "sandworm", "dragos", "chernovite", "apt", "lazarus"];
    private static readonly string[] RansomwareKeywords = ["ransomware", "encryption", "extortion", "breach"];
    private static readonly string[] UtilityKeywords =
        ["grid", "power", "utility", "energy", "bes", "electric", "scada", "ics", "miso", "spp", "cooperative"];
    private static readonly string[] ArkansasKeywords =
        ["arkansas", "little rock", "pulaski", "benton", "entergy", "cooperative"];
    private static readonly string[] PhysicalThreatKeywords =
        ["terror", "attack", "grid", "substation", "sabotage", "vandalism", "infrastructure", "transformer", "sniper", "shoot", "explosive"];
    private static readonly string[] CriticalVendors =
        ["SEL", "SCHWEITZER", "SIEMENS", "SCHNEIDER", "GE ", "ABB", "ROCKWELL", "EMERSON", "HONEYWELL", "OMRON"];
    private static readonly string[] PersonCrimeTerms =
        ["assault", "shoot", "homicide", "murder", "violent", "robbery", "kidnap", "battery", "weapon", "gun", "stab"];
    private static readonly string[] SocietyCrimeTerms =
        ["suspicious", "disturbance", "narcotic", "drug", "loiter", "trespass"];
    private static readonly string[] PropertyCrimeTerms =
        ["vandalism", "theft", "burglary", "arson", "property", "copper", "breach", "damage", "stolen"];

    public async Task<ExecutiveIntelReport> GetAsync(CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        var inputs = await intel.GetInputsAsync(now.AddHours(-24), now, cancellationToken);
        var history = inputs.ScoreHistory;
        var averageCyber = history.Count == 0 ? 0 : history.Average(point => point.CyberPoints ?? 0);
        var averagePhysical = history.Count == 0 ? 0 : history.Average(point => point.PhysicalPoints ?? 0);
        var settings = inputs.RiskSettings;
        var baselineCyber = settings?.BaselineOverrideCyber is > 0
            ? settings.BaselineOverrideCyber.Value
            : history.Count > 0 ? Math.Max(averageCyber, 20) : 20;
        var baselinePhysical = settings?.BaselineOverridePhys is > 0
            ? settings.BaselineOverridePhys.Value
            : history.Count > 0 ? Math.Max(averagePhysical, 25) : 25;

        var pureCyber = ProcessCyberArticles(inputs.CyberCandidates);
        var purePhysical = ProcessPhysicalArticles(inputs.PhysicalCandidates);
        var icsAdvisories = inputs.RecentArticles
            .Where(article => Contains(article.Source, "ICS") || Contains(article.Source, "CISA"))
            .Select(article => new IcsAdvisory(
                ContainsAny((article.Title ?? "").ToUpperInvariant(), CriticalVendors),
                Contains(article.Title, "KEV") || Contains(article.Title, "EXPLOITED IN THE WILD")))
            .ToArray();

        var kevCount = icsAdvisories.Count(advisory => advisory.IsKev);
        var criticalIcsCount = icsAdvisories.Count(advisory => advisory.IsCritical);
        var aptCount = pureCyber.Count(article => article.IsAptRelated);
        var ransomwareCount = pureCyber.Count(article => article.IsRansomware);
        var utilityCount = pureCyber.Count(article => article.IsUtilityRelated);
        var cveCount = inputs.RecentCves.Count;
        var evidence = new List<string>();

        var autoCyberLethality = 1;
        if (kevCount > 0)
        {
            autoCyberLethality = 5;
            evidence.Add($"**KEV Active Exploits:** {kevCount} Known Exploited Vulnerabilities. Attacker could gain root/admin or cause DoS. (L=5)");
        }
        else if (cveCount > 10)
        {
            autoCyberLethality = 4;
            evidence.Add($"**High CVE Volume:** {cveCount} recent CVEs. Exploits likely available. (L=4)");
        }
        else if (cveCount > 5)
        {
            autoCyberLethality = 3;
            evidence.Add($"**Moderate CVE Volume:** {cveCount} recent CVEs. Potential for targeted attacks. (L=3)");
        }
        else if (cveCount > 0)
        {
            autoCyberLethality = 3;
            evidence.Add($"**CVE Activity:** {cveCount} CVEs. No known exploits but potential for root/admin access. (L=3)");
        }
        else if (pureCyber.Count > 5)
        {
            autoCyberLethality = 2;
            evidence.Add($"**Elevated Cyber Activity:** {pureCyber.Count} threats. Potential for user-level access. (L=2)");
        }
        else
        {
            evidence.Add("**Routine Cyber Activity:** Normal probing and known low-risk activity. (L=1)");
        }

        var autoCyberCriticality = 2;
        if (criticalIcsCount > 0 || utilityCount > 0)
        {
            autoCyberCriticality = 5;
            evidence.Add("**Critical Infrastructure Target:** OT/SCADA or Utility sector targeted. Core services at risk. (C=5)");
        }
        else if (icsAdvisories.Length > 0)
        {
            autoCyberCriticality = 4;
            evidence.Add($"**ICS/SCADA Targeting:** {icsAdvisories.Length} ICS advisories. Email, web, database servers at risk. (C=4)");
        }
        else if (aptCount > 0 || ransomwareCount > 0)
        {
            autoCyberCriticality = 4;
            evidence.Add($"**APT/Ransomware Activity:** {aptCount} APT, {ransomwareCount} Ransomware campaigns. Critical systems targeted. (C=4)");
        }
        else if (pureCyber.Count > 3)
        {
            autoCyberCriticality = 3;
            evidence.Add($"**Elevated Threat Activity:** {pureCyber.Count} threats to less critical applications. (C=3)");
        }
        else
        {
            evidence.Add("**General Cyber Activity:** Business systems potentially affected. (C=2)");
        }

        var systemCountermeasures = Math.Clamp(settings?.SysCountermeasures ?? 3, 1, 5);
        var networkCountermeasures = Math.Clamp(settings?.NetCountermeasures ?? 3, 1, 5);
        var classifiedCrimes = inputs.RecentCrimes.Select(ClassifyCrime).ToArray();
        var personCrimes = classifiedCrimes.Count(crime => crime.FbiCategory == "Crimes Against Persons");
        var propertyCrimes = classifiedCrimes.Count(crime => crime.FbiCategory == "Crimes Against Property");
        var societyCrimes = classifiedCrimes.Count(crime => crime.FbiCategory == "Crimes Against Society");
        var totalCrimes = personCrimes + propertyCrimes + societyCrimes;

        var autoPhysicalLethality = 1;
        if (personCrimes >= 5 || propertyCrimes >= 10)
        {
            autoPhysicalLethality = 5;
        }
        else if (personCrimes >= 3 || propertyCrimes >= 6)
        {
            autoPhysicalLethality = 4;
        }
        else if (personCrimes >= 1 || propertyCrimes >= 3)
        {
            autoPhysicalLethality = 3;
        }
        else if (totalCrimes >= 5)
        {
            autoPhysicalLethality = 2;
        }

        var weatherWeight = Math.Min(inputs.ActiveWarningCount * 1.5, 15) / 15;
        var physicalOsintScore = Math.Min(
            purePhysical.Sum(article => article.Score is >= 80 ? 10 : 2), 20) / 20.0;
        var autoPhysicalCriticality = 2;
        if (purePhysical.Count >= 3 || weatherWeight >= 0.8)
        {
            autoPhysicalCriticality = 5;
        }
        else if (purePhysical.Count >= 1 || weatherWeight >= 0.4)
        {
            autoPhysicalCriticality = 4;
        }
        else if (physicalOsintScore > 0)
        {
            autoPhysicalCriticality = 3;
        }

        var scoringMode = string.IsNullOrEmpty(settings?.ScoringMode) ? "auto" : settings.ScoringMode;
        var cyberCriticality = autoCyberCriticality;
        var cyberLethality = autoCyberLethality;
        var physicalCriticality = autoPhysicalCriticality;
        var physicalLethality = autoPhysicalLethality;
        var globalOffset = settings?.GlobalRiskOffset ?? 0;
        if (scoringMode == "manual")
        {
            cyberCriticality = ClampOverride(settings?.CyberCriticalityOverride);
            cyberLethality = ClampOverride(settings?.CyberLethalityOverride);
            physicalCriticality = ClampOverride(settings?.PhysicalCriticalityOverride);
            physicalLethality = ClampOverride(settings?.PhysicalLethalityOverride);
            evidence.Insert(0, $"**Scoring Mode: Manual Override** — C={cyberCriticality}, L={cyberLethality}, P_C={physicalCriticality}, P_L={physicalLethality} applied from config overrides");
        }
        else if (scoringMode == "hybrid")
        {
            var signedOffset = globalOffset >= 0 ? $"+{globalOffset}" : globalOffset.ToString();
            evidence.Insert(0, $"**Scoring Mode: Hybrid (offset={signedOffset})** — Auto-computed with {signedOffset} offset");
        }
        else
        {
            scoringMode = string.IsNullOrEmpty(scoringMode) ? "auto" : scoringMode;
            evidence.Insert(0, "**Scoring Mode: Auto** — Fully algorithmic CIS scoring");
        }

        var cyberScorePoints = cyberCriticality + cyberLethality - systemCountermeasures - networkCountermeasures;
        var physicalScorePoints = physicalCriticality + physicalLethality - systemCountermeasures - networkCountermeasures;
        if (scoringMode == "hybrid")
        {
            cyberScorePoints = Math.Clamp(cyberScorePoints + globalOffset, -8, 8);
            physicalScorePoints = Math.Clamp(physicalScorePoints + globalOffset, -8, 8);
        }
        var cyberLevel = ScoreLevel(cyberScorePoints);
        var physicalLevel = ScoreLevel(physicalScorePoints);
        var unifiedLevel = RiskWeight(cyberLevel) >= RiskWeight(physicalLevel) ? cyberLevel : physicalLevel;
        await intel.SaveDailyThreatScoreAsync(
            now.Date, cyberScorePoints, physicalScorePoints, baselineCyber, baselinePhysical, cancellationToken);

        return new ExecutiveIntelReport(
            FormatCentralTime(now),
            unifiedLevel,
            physicalLevel,
            $"**CIS Score: {physicalScorePoints}** | C={physicalCriticality}, L={physicalLethality}, S={systemCountermeasures}, N={networkCountermeasures} | {personCrimes} violent, {propertyCrimes} property, {purePhysical.Count} OSINT, {inputs.ActiveWarningCount} alerts",
            cyberLevel,
            $"**CIS Score: {cyberScorePoints}** | C={cyberCriticality}, L={cyberLethality}, S={systemCountermeasures}, N={networkCountermeasures} | {pureCyber.Count} threats, {icsAdvisories.Length} ICS, {cveCount} CVEs",
            cyberScorePoints,
            classifiedCrimes,
            pureCyber,
            purePhysical,
            evidence,
            cyberScorePoints,
            physicalScorePoints,
            baselineCyber,
            baselinePhysical,
            scoringMode,
            new ExecutiveRiskOverrides(
                new ExecutiveRiskOverride(autoCyberCriticality, cyberCriticality),
                new ExecutiveRiskOverride(autoCyberLethality, cyberLethality),
                new ExecutiveRiskOverride(autoPhysicalCriticality, physicalCriticality),
                new ExecutiveRiskOverride(autoPhysicalLethality, physicalLethality)));
    }

    private static List<ExecutiveIntelArticle> ProcessCyberArticles(IReadOnlyList<ThreatArticle> articles)
    {
        var result = new List<ExecutiveIntelArticle>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var article in articles)
        {
            var text = $"{article.Title ?? ""} {article.Summary ?? ""}".ToLowerInvariant();
            if (ContainsAny(text, GeopoliticalNoiseWords)
                && !ContainsAny(text, ["infrastructure", "grid", "scada"]))
            {
                continue;
            }
            var titleStub = (article.Title ?? "")[..Math.Min(50, (article.Title ?? "").Length)].ToLowerInvariant();
            if (!seen.Add(titleStub))
            {
                continue;
            }
            result.Add(new ExecutiveIntelArticle(
                article,
                ContainsAny(text, UtilityKeywords),
                ContainsAny(text, ThreatActorKeywords),
                ContainsAny(text, RansomwareKeywords)));
        }
        return result;
    }

    private static List<ThreatArticle> ProcessPhysicalArticles(IReadOnlyList<ThreatArticle> articles)
    {
        var result = new List<ThreatArticle>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var article in articles)
        {
            var text = $"{article.Title ?? ""} {article.Summary ?? ""}".ToLowerInvariant();
            var source = (article.Source ?? "").ToLowerInvariant();
            if (source.Contains("cisa", StringComparison.Ordinal)
                || text.Contains("cyber", StringComparison.Ordinal)
                || text.Contains("cve-", StringComparison.Ordinal)
                || source.Contains("ics-cert", StringComparison.Ordinal))
            {
                continue;
            }
            var titleStub = (article.Title ?? "")[..Math.Min(50, (article.Title ?? "").Length)].ToLowerInvariant();
            if (seen.Contains(titleStub))
            {
                continue;
            }
            if (ContainsAny(text, ArkansasKeywords) && ContainsAny(text, PhysicalThreatKeywords))
            {
                seen.Add(titleStub);
                result.Add(article);
            }
        }
        return result;
    }

    private static ExecutiveIntelCrime ClassifyCrime(CrimeIncidentEntry incident)
    {
        var text = $"{incident.RawTitle ?? ""} {incident.Category ?? ""}".ToLowerInvariant();
        var category = ContainsAny(text, PersonCrimeTerms)
            ? "Crimes Against Persons"
            : ContainsAny(text, SocietyCrimeTerms)
                ? "Crimes Against Society"
                : ContainsAny(text, PropertyCrimeTerms)
                    ? "Crimes Against Property"
                    : "Crimes Against Society";
        return new ExecutiveIntelCrime(incident, category);
    }

    private static bool ContainsAny(string value, IEnumerable<string> terms) =>
        terms.Any(term => value.Contains(term, StringComparison.Ordinal));

    private static bool Contains(string? value, string term) =>
        (value ?? "").Contains(term, StringComparison.OrdinalIgnoreCase);

    private static int ClampOverride(int? value) => Math.Clamp(value ?? 0, 1, 5);

    private static string ScoreLevel(int score) => score switch
    {
        >= 6 => "RED",
        >= 3 => "ORANGE",
        >= -1 => "YELLOW",
        >= -4 => "BLUE",
        _ => "GREEN",
    };

    private static int RiskWeight(string level) => level switch
    {
        "RED" => 5,
        "ORANGE" => 4,
        "YELLOW" => 3,
        "BLUE" => 2,
        _ => 1,
    };

    private static string FormatCentralTime(DateTime utc)
    {
        var zone = TimeZoneInfo.FindSystemTimeZoneById("America/Chicago");
        var local = TimeZoneInfo.ConvertTimeFromUtc(DateTime.SpecifyKind(utc, DateTimeKind.Utc), zone);
        return $"{local:HH:mm:ss} {(zone.IsDaylightSavingTime(local) ? "CDT" : "CST")}";
    }

    private sealed record IcsAdvisory(bool IsCritical, bool IsKev);
}
