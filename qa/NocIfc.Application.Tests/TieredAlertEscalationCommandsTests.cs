using NocIfc.Application.Features.AIOps;
using NocIfc.Domain.AIOps;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class TieredAlertEscalationCommandsTests
{
    [Theory]
    [InlineData("{\"Normalized_Alert_Level\":\"P1-High\"}", "p1-high")]
    [InlineData("{\"Custom_Properties_Universal\":{\"Alert_Level\":\"P2 Low\"}}", "p2-low")]
    [InlineData("{\"Normalized_Alert_Level\":\"Priority 4\"}", "p4")]
    [InlineData("{}", "unknown")]
    [InlineData("not json", "unknown")]
    public void ResolvesAlertTierFromSolarWindsPayload(string rawPayload, string expected) =>
        Assert.Equal(expected, TieredAlertEscalationCommands.GetTier(Alert(rawPayload)));

    [Theory]
    [InlineData("2026-05-01T11:59:00Z", true)]
    [InlineData("2026-05-01T12:00:00Z", true)]
    [InlineData("2026-05-02T13:00:00Z", false)]
    [InlineData("2026-05-01T01:00:00Z", false)]
    public void UsesCentralWeekdayBusinessWindow(string value, bool expected) =>
        Assert.Equal(expected, TieredAlertEscalationCommands.IsBusinessHours(DateTime.Parse(value).ToUniversalTime()));

    private static AiopsAlertEntry Alert(string rawPayload) => new(
        1, "Down", "High", "node-a", "10.0.0.1", "Down", null, "details", null, rawPayload,
        "Central NOC", DateTime.UtcNow, null, false, false, false, false, null, "Router", "network",
        null, null, null, null, null);
}
