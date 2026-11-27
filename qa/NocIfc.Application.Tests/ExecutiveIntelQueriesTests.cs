using NocIfc.Application.Abstractions.Dashboard;
using NocIfc.Application.Features.Dashboard;
using NocIfc.Domain.Dashboard;
using NocIfc.Domain.Settings;
using NocIfc.Domain.Threat;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class ExecutiveIntelQueriesTests
{
    [Fact]
    public async Task BuildsCisExecutiveIntelFromCyberPhysicalCveHazardAndCrimeInputs()
    {
        var store = new StubStore
        {
            Inputs = new ExecutiveIntelInputs(
                new RiskScoringSettings("auto", null, null, null, null, null, null, null, null, 0, 0, 3, 3),
                [],
                [Article(1, "Volt Typhoon ransomware targets power grid", "Critical utility attack", 85, "Cyber: Malware & Threats", "Threat Intel")],
                [Article(2, "SEL KEV exploited in the wild", "CISA advisory", 90, "ICS/OT & SCADA", "CISA Advisories")],
                [Article(3, "Arkansas substation vandalism", "Physical infrastructure", 85, "Physical Security & Crime", "Local News")],
                [new CisaKevEntry(1, "CVE-2026-1234", "Vendor", "Product", "Vulnerability", DateTime.UtcNow, "Description", "Patch", "2026-12-01")],
                [new CrimeIncidentEntry("crime-1", "Violent Proximity Threat", "Assault near facility", DateTime.UtcNow, 0.4, "High", 34.7, -92.3)],
                2),
        };
        var report = await new ExecutiveIntelQueries(store).GetAsync(CancellationToken.None);

        Assert.Equal("ORANGE", report.CyberScore);
        Assert.Equal("YELLOW", report.PhysicalScore);
        Assert.Equal("ORANGE", report.UnifiedRisk);
        Assert.Equal(4, report.CurrentCyberPoints);
        Assert.Equal(1, report.CurrentPhysicalPoints);
        Assert.Equal(20, report.BaselineCyber);
        Assert.Equal(25, report.BaselinePhysical);
        Assert.Contains("1 CVEs", report.CyberBrief, StringComparison.Ordinal);
        var cyber = Assert.Single(report.RawCyberArticles);
        Assert.True(cyber.IsUtilityRelated);
        Assert.True(cyber.IsAptRelated);
        Assert.True(cyber.IsRansomware);
        Assert.Equal("Crimes Against Persons", Assert.Single(report.RecentCrimes).FbiCategory);
        Assert.Equal(4, store.CyberPoints);
        Assert.Equal(1, store.PhysicalPoints);
        Assert.Equal(0, store.RecordDateUtc.Hour);
        Assert.True(report.Timestamp.EndsWith("CST", StringComparison.Ordinal)
            || report.Timestamp.EndsWith("CDT", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ReportingAliasUsesNoCrimeOrWeatherInputs()
    {
        var store = new StubStore
        {
            Inputs = EmptyInputs(new RiskScoringSettings("auto", null, null, null, null, null, null, null, null, 0, 0, 3, 3)) with
            {
                RecentCrimes = [new CrimeIncidentEntry("crime-1", "Violent Proximity Threat", "Assault", DateTime.UtcNow, 0.5, "High", 34.7, -92.3)],
                ActiveWarningCount = 8,
            },
        };

        var report = await new ExecutiveIntelQueries(store).GetForReportingAsync(CancellationToken.None);

        Assert.Empty(report.RecentCrimes);
        Assert.Equal(-3, report.CurrentPhysicalPoints);
        Assert.Contains("0 alerts", report.PhysicalBrief, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ManualAndHybridScoringApplyOverridesAndOffsets()
    {
        var manualStore = new StubStore
        {
            Inputs = EmptyInputs(new RiskScoringSettings("manual", null, null, 1, 5, 4, 4, null, null, 0, 0, 3, 3)),
        };
        var manual = await new ExecutiveIntelQueries(manualStore).GetAsync(CancellationToken.None);
        Assert.Equal("manual", manual.ScoringMode);
        Assert.Equal(0, manual.CurrentCyberPoints);
        Assert.Equal(2, manual.AppliedOverrides.CyberCriticality.Auto);
        Assert.Equal(1, manual.AppliedOverrides.CyberCriticality.Used);
        Assert.Contains("Manual Override", manual.EvidenceLog[0], StringComparison.Ordinal);

        var hybridStore = new StubStore
        {
            Inputs = new ExecutiveIntelInputs(
                new RiskScoringSettings("hybrid", null, null, null, null, null, null, null, null, -3, 0, 3, 3),
                [],
                [Article(1, "Critical utility threat", "power grid SCADA exploit", 85, "Cyber: Malware & Threats", "Threat Intel")],
                [Article(2, "SEL KEV incident", "exploited", 90, "ICS/OT & SCADA", "CISA Feed")],
                [], [], [], 0),
        };
        var hybrid = await new ExecutiveIntelQueries(hybridStore).GetAsync(CancellationToken.None);
        Assert.Contains("Hybrid (offset=-3)", hybrid.EvidenceLog[0], StringComparison.Ordinal);
        Assert.Equal(1, hybrid.CurrentCyberPoints);
        Assert.Equal("YELLOW", hybrid.CyberScore);
    }

    private static ExecutiveIntelInputs EmptyInputs(RiskScoringSettings settings) =>
        new(settings, [], [], [], [], [], [], 0);

    private static ThreatArticle Article(
        int id,
        string title,
        string summary,
        double score,
        string category,
        string source) => new(
        id, title, $"https://example.test/{id}", summary, DateTime.UtcNow, source, score,
        category, [], false, null, null, null, false, DateTime.UtcNow, "complete", 1, null, null);

    private sealed class StubStore : IExecutiveIntelStore
    {
        public ExecutiveIntelInputs Inputs { get; init; } = EmptyInputs(new RiskScoringSettings("auto", null, null, null, null, null, null, null, null, 0, 0, 3, 3));
        public int CyberPoints { get; private set; }
        public int PhysicalPoints { get; private set; }
        public DateTime RecordDateUtc { get; private set; }

        public Task<ExecutiveIntelInputs> GetInputsAsync(DateTime sinceUtc, DateTime nowUtc, CancellationToken cancellationToken) =>
            Task.FromResult(Inputs);

        public Task<IReadOnlyList<ThreatArticle>> GetRecentScoredArticlesAsync(
            DateTime sinceUtc, int limit, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<ThreatArticle>>([]);

        public Task SaveDailyThreatScoreAsync(
            DateTime recordDateUtc,
            int cyberPoints,
            int physicalPoints,
            double cyberBaseline,
            double physicalBaseline,
            CancellationToken cancellationToken)
        {
            RecordDateUtc = recordDateUtc;
            CyberPoints = cyberPoints;
            PhysicalPoints = physicalPoints;
            return Task.CompletedTask;
        }
    }
}
