using System.Text.Json;
using NocIfc.Application.Features.AIOps;
using NocIfc.Domain.AIOps;
using NocIfc.Domain.Settings;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class AiopsRcaAnalysisEngineTests
{
    private static readonly DateTime Now = new(2026, 11, 26, 18, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void NormalizesLegacyDomainAndRanksPowerPatientZero()
    {
        var alert = Alert(1, "ups-1", "Central NOC", "Down", "UPS", "Utility", 1, Now);
        var result = new AiopsRcaAnalysisEngine().Analyze(
            [alert], [], [Location("Central NOC", "Central")], EmptyContext(), false, Now);

        Assert.Equal("INTERNET", AiopsRcaAnalysisEngine.NormalizeDomainHint("PRIMARY_INTERNET"));
        Assert.Null(AiopsRcaAnalysisEngine.NormalizeDomainHint("Unmapped Device Class"));
        Assert.Equal(1, result.Clustered["Central NOC"].PatientZero?.Id);
        Assert.Contains("POWER_SUPPLIES", result.Clustered["Central NOC"].DomainsAffected);
        Assert.StartsWith("Catastrophic Facilities/Power Failure", result.RootCause["Central NOC"].Cause);
        Assert.Equal(100, result.RootCause["Central NOC"].Score);
        Assert.StartsWith("P1 - CRITICAL", result.RootCause["Central NOC"].Priority);
    }

    [Fact]
    public void IdentifiesFleetOutageWhenFiveSitesShareProviderAndCommsDependency()
    {
        var alerts = Enumerable.Range(1, 5)
            .Select(index => Alert(index, $"router-{index}", $"Site {index}", "Down", "Router", "FiberCo", 3, Now.AddSeconds(index)))
            .ToArray();
        var result = new AiopsRcaAnalysisEngine().Analyze(alerts, [], [], EmptyContext(), false, Now);

        var fleet = Assert.Single(result.FleetOutages);
        Assert.Equal("FiberCo", fleet.Provider);
        Assert.Equal(5, fleet.AffectedSites.Count);
        Assert.Equal("Regional Carrier Outage (FiberCo)", result.RootCause["Site 1"].Cause);
        Assert.Equal(100, result.RootCause["Site 1"].Score);
    }

    [Fact]
    public void CorrelatesCloudAndWeatherAndProducesChronicInsightsOnlyWhenIncluded()
    {
        var alert = Alert(1, "Azure-router-1", "Central NOC", "Down", "Router", "AS123 Azure FiberCo", 4, Now);
        var history = Enumerable.Range(1, 6)
            .Select(index => new AiopsHistoricalAlertEntry(
                "flapping-node", "Router", "Central NOC", Payload("Central NOC", "FiberCo", "Central", 4), "Down"))
            .Append(new AiopsHistoricalAlertEntry(
                "flapping-node", "Router", "Central NOC", null, "Resolved"))
            .ToArray();
        var context = new AiopsRcaAnalysisContext(
            [new AiopsCloudOutageEntry("Azure")],
            [new AiopsWeatherHazardEntry("Tornado Warning", "Central District")],
            [new AiopsBgpAnomalyEntry("AS123")],
            history);
        var engine = new AiopsRcaAnalysisEngine();
        var location = Location("Central NOC", "Central");

        var fullAccess = engine.Analyze([alert], [], [location], context, true, Now);
        var partialAccess = engine.Analyze([alert], [], [location], context, false, Now);

        Assert.StartsWith("Upstream Cloud Dependency Failure (Azure)", fullAccess.RootCause["Central NOC"].Cause);
        Assert.Contains(fullAccess.RootCause["Central NOC"].Evidence, evidence => evidence.StartsWith("Regional Correlation:"));
        Assert.Equal(6, fullAccess.ChronicInsights?.OffendingNodes.Single().IncidentCount);
        Assert.Contains(fullAccess.ChronicInsights?.Forecast ?? [], item => item.StartsWith("[CRITICAL]"));
        Assert.False(partialAccess.CanViewChronicInsights);
        Assert.Null(partialAccess.ChronicInsights);
    }

    private static AiopsRcaAnalysisContext EmptyContext() => new([], [], [], []);

    private static AiopsAlertEntry Alert(
        int id,
        string node,
        string site,
        string status,
        string deviceType,
        string primaryComms,
        int alertLevel,
        DateTime receivedAt) => new(
            id, "Down", "Critical", node, "192.0.2.1", status, null, "test", null,
            Payload(site, primaryComms, "Central", alertLevel, deviceType), site, receivedAt, null,
            false, false, false, false, null, deviceType, "network", null, null, null, null, null);

    private static string Payload(string site, string primaryComms, string district, int alertLevel, string nodeType = "") =>
        JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["Custom_Properties_Universal"] = new Dictionary<string, object?>
            {
                ["Site"] = site,
                ["Primary_Comms"] = primaryComms,
                ["Secondary_Comms"] = "AS123",
                ["District"] = district,
                ["Alert_Level"] = alertLevel,
            },
            ["Node_Details"] = new Dictionary<string, object?> { ["MachineType"] = nodeType },
            ["Performance_Metrics"] = new Dictionary<string, object?> { ["PercentLoss"] = "100%", ["CPULoad"] = "45%" },
            ["Normalized_Alert_Level"] = alertLevel,
        });

    private static MonitoredLocationEntry Location(string name, string district) => new(
        1, name, 34.8, -92.2, "NOC", district, "P1-Critical", null, null, false,
        null, null, null, null, null, null, null, null);
}
