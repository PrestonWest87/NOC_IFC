using NocIfc.Application.Features.AIOps;
using NocIfc.Domain.AIOps;
using NocIfc.Domain.Settings;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class AiopsSitrepReportBuilderTests
{
    private static readonly DateTime Now = new(2026, 11, 26, 18, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void ReturnsOperationalStatusWhenNoUncorrelatedAlertsExist()
    {
        var context = new AiopsRcaAnalysisContext(
            [new AiopsCloudOutageEntry("Azure")],
            [new AiopsWeatherHazardEntry("Tornado Warning", "Central")],
            [],
            []);
        var analysis = new AiopsRcaAnalysisEngine().Analyze([], [], [], context, false, Now, false);

        var report = AiopsSitrepReportBuilder.Build(analysis);

        Assert.Contains("**Active Infrastructure Alerts:** 0 | **Cloud Outages:** 1 | **Grid/Weather Anomalies:** 1", report);
        Assert.Contains("[OK] **Grid Operational:** No active un-correlated infrastructure alerts detected.", report);
        Assert.DoesNotContain("Intelligence Causal Clusters", report);
    }

    [Fact]
    public void ListsDeterministicCausalClusterDetails()
    {
        var alert = new AiopsAlertEntry(
            1, "Down", "Critical", "router-1", "192.0.2.1", "Down", null, "timeout", null,
            """{"Custom_Properties_Universal":{"Site":"Central NOC","Primary_Comms":"FiberCo","District":"Central"},"Node_Details":{"MachineType":"Router"},"Performance_Metrics":{"PercentLoss":"100%"}}""",
            "Central NOC", Now, null, false, false, false, false, null, "Router", "network",
            null, null, null, null, null);
        var context = new AiopsRcaAnalysisContext(
            [new AiopsCloudOutageEntry("router")],
            [new AiopsWeatherHazardEntry("Tornado Warning", "Central District")],
            [],
            []);
        var location = new MonitoredLocationEntry(
            1, "Central NOC", 34.8, -92.2, "NOC", "Central", "P1-Critical", null, null, false,
            null, null, null, null, null, null, null, null);
        var analysis = new AiopsRcaAnalysisEngine().Analyze([alert], [], [location], context, false, Now, false);

        var report = AiopsSitrepReportBuilder.Build(analysis);

        Assert.Contains("**Active Infrastructure Alerts:** 1 | **Cloud Outages:** 1 | **Grid/Weather Anomalies:** 1", report);
        Assert.Contains("#### Intelligence Causal Clusters", report);
        Assert.Contains("**Patient Zero:** `router-1` (Cascade Delay: Simultaneous)", report);
        Assert.Contains("**Root Cause:** Upstream Cloud Dependency Failure (router)", report);
    }
}
